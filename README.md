# ShellBreaker — Standalone Scanner

Detects Java webshells and memory (fileless) webshells in `.class` files.
No internet required. No lab, no Docker, no Java agent needed.

## Requirements

- Python 3.10+
- JDK 21 (`javap` must be on PATH — test with `javap -version`)

## Setup (one time)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Scan a directory

```bash
.venv/bin/python scripts/scan_bulk.py /path/to/classes/ --out results
```

Outputs:
- `results.csv` — one row per file: path, verdict, tier, ml_score, rules fired
- `results.json` — summary counts + full list of flagged files

## Scan specific files

```bash
.venv/bin/python scripts/scan_bulk.py Shell.class Filter.class --out results
```

## Scan multiple directories

```bash
.venv/bin/python scripts/scan_bulk.py /opt/tomcat/webapps/ /tmp/upload/ --out results
```

## Single file (quick check)

```bash
.venv/bin/python scripts/05_inference_api.py /path/to/Suspicious.class
```

## Run as API server

```bash
.venv/bin/python scripts/05_inference_api.py
# → POST http://localhost:8080/predict  (multipart: file=<.class bytes>)
# → GET  http://localhost:8080/docs     (Swagger UI)
```

## Verdict tiers

| Tier | Meaning |
|---|---|
| CONFIRMED | High-confidence webshell — act immediately |
| HIGH | Likely webshell — investigate |
| MEDIUM | Suspicious — queue for review |
| BENIGN | No threat detected |
| ERROR | Could not disassemble (inner class, truncated bytecode) |

Detection uses two paths:
- **fileless** (memory webshell): injection interface detected → rules lead
- **file_based** (JSP/servlet webshell): no interface → ML model (ResNet50) leads

## Performance

~3 files/sec on CPU. 10,000 files ≈ 55 min.
On a GPU machine PyTorch auto-detects CUDA — expect 10–20× faster.
