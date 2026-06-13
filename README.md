# ShellBreaker — Standalone Scanner

Detects Java webshells (file-based and fileless/memory) in `.class` and `.jsp` files.
Uses a hybrid pipeline: ResNet50 opcode-image model + rule engine + optional dynamic
analysis via a Java agent attached to Docker Tomcat.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Setup](#setup)
3. [Scanning .class files](#scanning-class-files)
4. [Scanning .jsp files](#scanning-jsp-files)
5. [Dynamic analysis (Java agent)](#dynamic-analysis-java-agent)
6. [Verdict tiers](#verdict-tiers)
7. [Output format](#output-format)
8. [Run as API server](#run-as-api-server)
9. [Detection performance](#detection-performance)
10. [How it works](#how-it-works)

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | |
| JDK | 21 | `javap` must be on PATH — test: `javap -version` |
| Docker | any recent | Only needed for JSP scanning |
| Docker Compose | v2 | Only needed for JSP scanning |

---

## Setup

```bash
# 1. Create virtualenv and install Python deps
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. (JSP scanning only) Start Docker Tomcat
docker compose up -d

# 3. Verify Tomcat is ready (should print "Tomcat started")
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/
```

The Tomcat container mounts `./jsp_workspace/webapps/` as its ROOT webapp and
`./agent/` for the Java agent. It starts once and stays running across scans.

---

## Scanning .class files

No Docker needed. Just point at a file or directory:

```bash
# Scan a directory recursively
.venv/bin/python scripts/scan_bulk.py /path/to/classes/ --out results

# Scan specific files
.venv/bin/python scripts/scan_bulk.py Shell.class Filter.class --out results

# Scan multiple directories at once
.venv/bin/python scripts/scan_bulk.py /opt/tomcat/webapps/ /tmp/upload/ --out results
```

Quick single-file check with full detail:

```bash
.venv/bin/python scripts/05_inference_api.py /path/to/Suspicious.class
```

---

## Scanning .jsp files

Docker Tomcat must be running (`docker compose up -d`).

```bash
# JSP files in a directory
.venv/bin/python scripts/scan_bulk.py /path/to/webapps/ --out results

# Mixed .class + .jsp
.venv/bin/python scripts/scan_bulk.py /opt/tomcat/webapps/ --out results
```

**How JSP scanning works:**

1. ShellBreaker copies each `.jsp` into the Tomcat container's ROOT webapp.
2. It triggers Tomcat's Jasper compiler via an HTTP GET — Jasper compiles the JSP
   to a `.class` synchronously and the HTTP response is the completion signal.
3. `javap` runs inside the container to extract bytecode (`docker exec javap -c -p -verbose`).
4. The bytecode goes through the same ML + rule pipeline as any `.class` file.
5. If Jasper cannot compile (missing taglibs, app-specific imports), ShellBreaker
   falls back to a source-level text scan of the raw `.jsp`.

**Two-pass compilation:** ShellBreaker tries the original JSP first, then strips
HTML/taglib noise and retries with only the `<%@ page %>` directives and `<% %>`
scriptlet blocks — this catches shells that hide inside otherwise-invalid JSPs.

**Speed:** ~2 files/sec including compile + disassemble overhead.

---

## Dynamic analysis (Java agent)

The Java agent instruments Tomcat's JVM at startup and intercepts dangerous API
calls made by JSP-compiled code at request time:

| Intercepted API | Label |
|---|---|
| `Runtime.exec()` | `api:runtime_exec` |
| `ProcessBuilder.start()` | `api:processbuilder` |
| `ClassLoader.defineClass()` | `api:defineClass` |
| `FileOutputStream.<init>` | `api:file_write` |
| `FileWriter.<init>` | `api:file_write` |
| `PrintWriter.<init>` | `api:file_write` |
| `Socket.<init>` | `api:socket` |
| `ServerSocket.<init>` | `api:socket` |

When any of these are called from a `org.apache.jsp.*` class (i.e. from compiled
JSP code), the hit is written to `agent/sb_agent.log`. ShellBreaker reads this
log after each HTTP trigger and escalates the verdict accordingly:

- `exec` or `defineClass` hit → verdict escalates to **CONFIRMED**
- `file_write` or `socket` hit → verdict escalates to at least **HIGH**

**Building the agent** (only needed if you change the Java source):

```bash
cd agent/
bash build.sh
# Produces:
#   shellbreaker-logger.jar  — Logger only, loaded into bootstrap classloader
#   shellbreaker-agent.jar   — Agent + ASM transformer, stays in app classloader
```

The `docker-compose.yml` already points `JAVA_OPTS` at the pre-built JARs in
`./agent/`. Just restart Tomcat after rebuilding:

```bash
docker compose restart tomcat
```

**Limitation:** Dynamic analysis only fires if the shell executes on a plain
`GET` request with no parameters. Shells gated on a secret password or specific
POST body will not trigger during the compilation probe.

---

## Verdict tiers

| Tier | Meaning | Recommended action |
|---|---|---|
| **CONFIRMED** | High-confidence webshell — dangerous APIs confirmed in bytecode or at runtime | Isolate and remediate immediately |
| **HIGH** | Likely webshell — strong static indicators | Escalate for analyst review |
| **MEDIUM** | Suspicious — weak indicators or heuristic match | Queue for manual review |
| **BENIGN** | No threat detected | No action required |

Detection paths shown in output:

| `detection_path` | Meaning |
|---|---|
| `fileless+dynamic` | Memory shell (implements Servlet/Filter/Listener) — dynamic hits confirmed |
| `fileless` | Memory shell detected by bytecode interface analysis |
| `ml_high` | ML model exceeded HIGH threshold (≥ 0.85) |
| `ml_medium` | ML model exceeded MEDIUM threshold (≥ 0.50) |
| `jsp_source` | JSP source-level rule match (compile failed or not attempted) |
| `dynamic` | Dynamic hit only, no static detection |

---

## Output format

Both `scan_bulk.py` and the API return the same fields:

| Field | Description |
|---|---|
| `verdict` | `CONFIRMED / HIGH / MEDIUM / BENIGN` |
| `tier` | Same as verdict |
| `detection_path` | Which analysis path fired |
| `ml_score` | ResNet50 sigmoid output (0–1), empty for source-only scan |
| `rule_risk` | Highest rule risk level triggered |
| `rules_triggered` | Semicolon-separated list of rule labels |
| `imports` | Non-standard class imports extracted from JSP source |
| `description` | Analyst-facing one-liner: shell type + capabilities detected |

Example console output for a flagged file:

```
  File    : addTicketView.jsp (compiled from JSP)
  Verdict : CONFIRMED [CONFIRMED]
  Summary : JSP webshell (source-based detection) — OS command execution;
            arbitrary file write (dropper/file manager); char-array string
            obfuscation (evasion); matches known webshell signature (fingerprint)
  Path    : jsp_source (CONFIRMED)
  ML score: 0.9991
  Rules   : [CRITICAL] api:runtime_exec; api:exec_call; api:file_write;
             api:char_array_obf; tool:fingerprint
```

---

## Run as API server

```bash
.venv/bin/python scripts/05_inference_api.py
# → POST http://localhost:8080/predict  (multipart: file=<.class or .jsp bytes>)
# → GET  http://localhost:8080/docs     (Swagger UI)
```

---

## Detection performance

### JSP webshell evaluation (this release)

Evaluated on **280 real-world JSP webshells** + **500 benign `.class` files**:

| Metric | Score |
|---|---|
| **Accuracy** | **99.0%** |
| **Precision** | **99.3%** |
| **Recall** | **97.9%** |
| **F1 Score** | **98.6%** |
| **Specificity** | **99.6%** |
| **False Positive Rate** | **0.4%** |

Confusion matrix:

```
                   Predicted WEBSHELL   Predicted BENIGN
Actual WEBSHELL         274 (97.9%)          6 (2.1%)
Actual BENIGN             2 (0.4%)         498 (99.6%)
```

The 6 missed shells are multi-stage stager pages (pure `response.sendRedirect()`
or zero-scriptlet templates) whose payload lives in a separate file — they are
undetectable by isolated static analysis regardless of tool.

The 2 false positives are `MatrixUtils` (legitimate `setAccessible` in Apache
Commons Math) and `NevilleInterpolator` (class name contains the substring
"evil"). Both are MEDIUM verdicts, not CONFIRMED/HIGH.

### .class file baseline evaluation

Evaluated on **6,452 `.class` files** (958 webshells, 5,494 benign):

| Metric | Score |
|---|---|
| Accuracy | 96.3% |
| Recall (webshell) | 99.9% |
| Precision | 80.3% |
| False positive rate | 4.3% |
| F1 | 89.0% |

Cross-validation on file-based webshells (3 runs, 80/20 split):

| Metric | Mean | Std |
|---|---|---|
| Accuracy | 99.25% | ±0.59% |
| Precision | 99.25% | ±0.72% |
| Recall | 98.98% | ±0.68% |
| F1 | 99.11% | ±0.70% |
| AUC-ROC | 99.88% | ±0.14% |

---

## How it works

```
.jsp file                          .class file
    │                                   │
    ▼                                   │
[Tomcat Jasper]  ← HTTP GET trigger     │
    │ compile                           │
    ▼                                   │
.class (in container)                   │
    │                                   │
    ▼                                   ▼
[javap -c -p -verbose]         [javap -c -p -verbose]
    │                                   │
    └──────────────┬────────────────────┘
                   ▼
        [Opcode bigram matrix]
        149×149 co-occurrence
               │
               ▼
        [ResNet50 model]
        sigmoid → ML score
               │
               ▼
        [Rule engine]
        source patterns +
        interface detection +
        dynamic agent hits
               │
               ▼
        [Verdict + description]
        CONFIRMED / HIGH / MEDIUM / BENIGN
```

**ML model:** ResNet50 trained on 149×149 opcode adjacency (bigram co-occurrence)
matrices normalised to grayscale images. Threshold: 0.50 (MEDIUM), 0.85 (HIGH).

**Rule engine:** ~18 source patterns (exec, defineClass, reflection, file I/O,
sockets, OGNL/EL, known tool fingerprints) + interface-based fileless detection
(HttpServlet, Filter, ServletContextListener) + dynamic hit labels from the agent.

**Java agent:** ASM 9.7 ClassFileTransformer injects a `Logger.log()` call at
the entry of each targeted method. Logger uses a `ThreadLocal` re-entry guard
and writes to a flat log file via `java.nio.file.Files.write()` (avoids
recursion into the intercepted `FileOutputStream`). Only calls originating from
`org.apache.jsp.*` classes are recorded.
