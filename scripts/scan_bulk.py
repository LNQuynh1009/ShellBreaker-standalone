#!/usr/bin/env python3
"""
scan_bulk.py — Batch scanner for Java .class and .jsp files.

For .class files: runs the hybrid ML + rule detector directly.
For .jsp files:   extracts Java scriptlets, wraps in a minimal HttpServlet,
                  compiles with javac (no Docker needed), then runs the full
                  ML + rule detector on the resulting bytecode.

Outputs:
  <stem>.csv   — one row per file, all verdict details
  <stem>.json  — summary counts + list of flagged files

Usage:
    python scripts/scan_bulk.py /path/to/webapps/
    python scripts/scan_bulk.py /path/to/webapps/ --out results
    python scripts/scan_bulk.py shell.class evil.jsp --out quick
"""

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

# Ensure the system Docker socket is used so compile_jsp can reach Tomcat
os.environ.setdefault("DOCKER_HOST", "unix:///var/run/docker.sock")

# Real executable scriptlets: <% %>, <%! %>, <%= %> — excludes <%@ directives %>
_SCRIPTLET_RE = re.compile(r'<%(?!@)(=|!)?\s*\S', re.DOTALL)

# Dynamic hits from the Java agent that are strong malicious signals.
# NOTE: "defineClass" is intentionally excluded — Jasper calls ClassLoader.defineClass()
# for every JSP it compiles, so it fires on benign files and cannot be used as a
# dynamic signal (static bytecode rules already catch malicious defineClass usage).
_DANGER_DYNAMIC = {
    "runtime_exec", "processbuilder", "url_classloader",
    "unsafe_api", "script_engine", "groovy_cl", "in_memory_compile",
    "javassist", "bcel_codegen", "agent_api", "cl_hijack",
}

# Jasper-compiled benign JSPs score higher on the ML model than their local
# wrapper counterparts.  Require this floor for ML-only JSP detections to
# suppress FPs without losing TPs (empirical gap: all TPs ≥ 0.90, most FPs < 0.90).
_JSP_ML_FLOOR = 0.90

# Source-level dangerous patterns — used when bytecode compilation fails
_SRC_DANGER = [
    (re.compile(r'Runtime\.getRuntime|getRuntime\(\)\.exec'), "runtime_exec",     3),
    (re.compile(r'ProcessBuilder'),                           "processbuilder",   3),
    (re.compile(r'defineClass'),                              "defineClass",      3),
    (re.compile(r'sun\.misc\.Unsafe|sun/misc/Unsafe'),        "unsafe_api",       3),
    (re.compile(r'BASE64Decoder|BASE64Encoder'),              "base64_codec",     2),
    (re.compile(r'URLClassLoader'),                           "url_classloader",  2),
    (re.compile(r'ScriptEngine'),                             "script_engine",    2),
    (re.compile(r'GroovyClassLoader|GroovyShell'),            "groovy_cl",        2),
    (re.compile(r'JavaCompiler'),                             "in_memory_compile",3),
    (re.compile(r'ClassFileTransformer'),                     "agent_api",        3),
    (re.compile(r'setContextClassLoader'),                    "cl_hijack",        2),
    (re.compile(r'setAccessible\s*\('),                       "reflection_bypass",1),
    (re.compile(r'godzilla|behinder|regeorg|icescorpion|antsword|memshell',
                re.I),                                        "tool_fingerprint", 4),
    # Reflection-based exec: Class.forName("...Runtime").getMethod("exec")
    (re.compile(r'Class\.forName.*[Rr]untime.*getMethod|getMethod\s*\(\s*"exec"'),
                                                              "reflect_exec",     3),
    # JDBC DB-dump webshells: load JDBC driver + execute SQL via request params
    # Targeted enough — legitimate apps don't load oracle.jdbc inside a JSP scriptlet
    (re.compile(r'oracle\.jdbc|OracleDriver|com\.mysql\.jdbc\.Driver|com\.microsoft\.sqlserver'),
                                                              "jdbc_driver",      3),
    # File-write fallback: only reached when compilation fails, so FP risk is low
    # (benign files that compile are never checked by _source_verdict)
    (re.compile(r'FileOutputStream|FileWriter'),              "file_write",       2),
    # Embedded compiled Java class (CAFEBABE in base64): bytecode-dropper webshell
    (re.compile(r'yv66vg'),                                   "embedded_class",   5),
]

def _source_verdict(jsp_path: Path, source: str) -> dict:
    """Rule-based verdict from JSP source when bytecode compilation fails."""
    rules, score = [], 0
    for pattern, label, pts in _SRC_DANGER:
        if pattern.search(source):
            rules.append(f"src:{label}")
            score += pts
    if not rules:
        return {"verdict": "BENIGN", "tier": "BENIGN",
                "detection_path": "src_no_match", "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "dynamic_hits": []}
    risk = "HIGH" if score >= 6 else "MEDIUM"
    tier = "CONFIRMED" if score >= 8 else ("HIGH" if score >= 6 else "MEDIUM")
    return {"verdict": "WEBSHELL", "tier": tier,
            "detection_path": "src_rules",
            "ml_score": None,
            "rule": {"triggered": True, "rules": rules, "risk": risk, "score": score},
            "dynamic_hits": []}

from tqdm import tqdm

# ---------------------------------------------------------------------------
# Import detection engine (05_inference_api.py has a numeric prefix so we
# can't use a normal import statement)
# ---------------------------------------------------------------------------
_here = Path(__file__).parent

def _load_mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_mod        = _load_mod("inference_api",    _here / "05_inference_api.py")
_local      = _load_mod("compile_jsp_local", _here / "compile_jsp_local.py")
_tomcat_mod = _load_mod("compile_jsp",       _here / "compile_jsp.py")

Predictor         = _mod.Predictor
compile_jsp_local = _local.compile_jsp_local
_normalize        = _local._normalize

# ---------------------------------------------------------------------------
# Tomcat / dynamic-analysis mode — probe once at startup
# ---------------------------------------------------------------------------

def _init_dynamic_mode() -> bool:
    """Return True if Docker + Tomcat are available for dynamic JSP execution."""
    available = _tomcat_mod.try_ensure_tomcat()
    if available:
        print("  [JSP mode] Tomcat ready — dynamic analysis ENABLED (primary path)")
    else:
        print("  [JSP mode] Tomcat unavailable — static analysis only (fallback mode)")
    return available

_TOMCAT_AVAILABLE: bool = False   # set in main() after model load

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "path", "verdict", "tier", "detection_path",
    "ml_score", "rule_risk", "rule_score", "rules_triggered", "dynamic_hits",
]

TIER_ORDER = ["CONFIRMED", "HIGH", "MEDIUM", "BENIGN", "ERROR"]

_C = {
    "CONFIRMED": "\033[91m",
    "HIGH":      "\033[91m",
    "MEDIUM":    "\033[93m",
    "BENIGN":    "\033[92m",
    "ERROR":     "\033[90m",
}
RST = "\033[0m"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def collect_targets(inputs: list[Path]) -> tuple[list[Path], list[Path]]:
    """Return (class_files, jsp_files) found under each input path."""
    classes: list[Path] = []
    jsps:    list[Path] = []
    for p in inputs:
        if p.is_dir():
            c = sorted(p.rglob("*.class"))
            j = sorted(p.rglob("*.jsp"))
            print(f"  {p}  →  {len(c)} .class, {len(j)} .jsp files")
            classes.extend(c)
            jsps.extend(j)
        elif p.suffix == ".class" and p.exists():
            classes.append(p)
        elif p.suffix == ".jsp" and p.exists():
            jsps.append(p)
        else:
            print(f"  [skip] {p}  — not a .class/.jsp file or directory")
    return classes, jsps


def _static_jsp_fallback(jsp_path: Path, src: str, predictor) -> dict:
    """Local compilation + ML when Tomcat is unavailable or a single JSP fails."""
    class_path = None
    try:
        class_path = compile_jsp_local(jsp_path)
        if class_path is None:
            # Compilation failed — normalize (decode unicode/octal obfuscation) then check
            if _SCRIPTLET_RE.search(src):
                return _source_verdict(jsp_path, _normalize(src))
            return {"verdict": "BENIGN", "tier": "BENIGN",
                    "detection_path": "no_scriptlets", "ml_score": None,
                    "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                    "dynamic_hits": []}
        result = predictor.predict_local_jsp(class_path)
        result.setdefault("dynamic_hits", [])
        return result
    except Exception as e:
        return {"verdict": "ERROR", "tier": "ERROR", "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "dynamic_hits": [], "reason": str(e)}
    finally:
        if class_path and class_path.exists():
            class_path.unlink(missing_ok=True)


def _apply_jsp_ml_floor(result: dict) -> dict:
    """Suppress ML-only JSP detections below _JSP_ML_FLOOR.
    Rules and dynamic hits are unaffected — only pure ML calls get this treatment."""
    if (result.get("detection_path") == "file_based"
            and not result.get("rule", {}).get("triggered")
            and not result.get("dynamic_hits")
            and result.get("tier") in ("CONFIRMED", "HIGH")):
        ml = result.get("ml_score") or 0.0
        if ml < _JSP_ML_FLOOR:
            result = dict(result)
            result["verdict"] = "BENIGN"
            result["tier"]    = "BENIGN"
    return result


def _apply_dynamic_override(result: dict, dynamic_hits: list[str]) -> dict:
    """If the Java agent caught a dangerous runtime call, escalate to CONFIRMED."""
    danger = [h for h in dynamic_hits if h in _DANGER_DYNAMIC]
    if not danger:
        return result
    result = dict(result)
    result["dynamic_hits"] = dynamic_hits
    if result.get("tier") != "CONFIRMED":
        result["verdict"]        = "WEBSHELL"
        result["tier"]           = "CONFIRMED"
        result["detection_path"] = "dynamic:" + ",".join(danger)
    return result


def _scan_jsp(jsp_path: Path, src: str, predictor) -> dict:
    """Scan a single JSP: dynamic analysis (Tomcat) if available, else static."""
    if _TOMCAT_AVAILABLE:
        try:
            javap_text, dynamic_hits = _tomcat_mod.compile_jsp(jsp_path)
            result = predictor.predict_from_javap(jsp_path, javap_text)
            result = _apply_dynamic_override(result, dynamic_hits)
            return _apply_jsp_ml_floor(result)
        except RuntimeError as e:
            msg = str(e)
            if "no Java scriptlet" in msg or "pure template" in msg:
                return {"verdict": "BENIGN", "tier": "BENIGN",
                        "detection_path": "no_scriptlets", "ml_score": None,
                        "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                        "dynamic_hits": []}
            # Compilation failed via Tomcat — fall through to local
        except Exception:
            pass   # Docker/Tomcat hiccup — fall through to local

    # Static fallback (also used when Tomcat mode is off globally)
    return _apply_jsp_ml_floor(_static_jsp_fallback(jsp_path, src, predictor))


def _row(class_path: Path, result: dict) -> dict:
    rule = result.get("rule", {})
    return {
        "path":           str(class_path),
        "verdict":        result.get("verdict", "ERROR"),
        "tier":           result.get("tier", "ERROR"),
        "detection_path": result.get("detection_path", ""),
        "ml_score":       result.get("ml_score", ""),
        "rule_risk":      rule.get("risk", ""),
        "rule_score":     rule.get("score", ""),
        "rules_triggered": "; ".join(rule.get("rules", [])),
        "dynamic_hits":   "; ".join(result.get("dynamic_hits", [])),
    }


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def scan(class_files: list[Path], jsp_files: list[Path],
         out_stem: Path, predictor: Predictor) -> None:
    csv_path  = out_stem.with_suffix(".csv")
    json_path = out_stem.with_suffix(".json")

    total    = len(class_files) + len(jsp_files)
    counts:  dict[str, int] = {t: 0 for t in TIER_ORDER}
    flagged: list[dict]     = []
    errors:  list[str]      = []

    t0 = time.time()

    with open(csv_path, "w", newline="") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=CSV_FIELDS)
        writer.writeheader()

        bar = tqdm(total=total, unit="file", desc="Scanning", dynamic_ncols=True)

        # --- .class files ---
        for class_path in class_files:
            bar.set_postfix_str(class_path.name[:40], refresh=False)
            result = predictor.predict(class_path)
            tier   = result.get("tier", "ERROR")
            counts[tier] = counts.get(tier, 0) + 1
            row = _row(class_path, result)
            writer.writerow(row)
            csvf.flush()
            if tier in ("CONFIRMED", "HIGH"):
                flagged.append(row)
            elif tier == "ERROR":
                errors.append(str(class_path))
            bar.update(1)

        # --- .jsp files — dynamic-first, local static fallback ---
        for jsp_path in jsp_files:
            bar.set_postfix_str(jsp_path.name[:40], refresh=False)
            src = jsp_path.read_text(errors="replace")
            result = _scan_jsp(jsp_path, src, predictor)

            tier = result.get("tier", "ERROR")
            counts[tier] = counts.get(tier, 0) + 1
            row = _row(jsp_path, result)
            writer.writerow(row)
            csvf.flush()
            if tier in ("CONFIRMED", "HIGH"):
                flagged.append(row)
            elif tier == "ERROR":
                errors.append(str(jsp_path))
            bar.update(1)

        bar.close()

    elapsed = time.time() - t0

    # JSON summary
    summary = {
        "scanned":   total,
        "elapsed_s": round(elapsed, 1),
        "counts":    counts,
        "flagged":   flagged,
        "errors":    errors,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    json_path.write_text(json.dumps(summary, indent=2))

    # Console summary
    sep = "─" * 52
    print(f"\n  {sep}")
    print(f"  Scanned : {total} files  ({elapsed:.1f}s)")
    for tier in TIER_ORDER:
        n     = counts[tier]
        label = f"  {tier:<12}: {n}"
        print(f"{_C.get(tier, '')}{label}{RST}")
    print(f"  {sep}")
    print(f"  CSV  → {csv_path}")
    print(f"  JSON → {json_path}")

    if flagged:
        print(f"\n  Flagged detections (CONFIRMED / HIGH):")
        print(f"  {sep}")
        for row in flagged:
            c    = _C.get(row["tier"], "")
            path = row["path"]
            dpath = f"[{row['detection_path']}]" if row["detection_path"] else ""
            print(f"  {c}[{row['tier']}]{RST} {dpath} {path}")
            if row["rules_triggered"]:
                print(f"           rules : {row['rules_triggered']}")
            if row["ml_score"] != "":
                print(f"           ml    : {row['ml_score']}")
    else:
        print(f"\n  {_C['BENIGN']}No CONFIRMED or HIGH detections.{RST}")

    if errors:
        print(f"\n  {_C['ERROR']}{len(errors)} file(s) could not be processed (ERROR in CSV).{RST}")

    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Batch scan .class files for Java webshells (ML + rules).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  .venv/bin/python scripts/scan_bulk.py /opt/tomcat/webapps/
  .venv/bin/python scripts/scan_bulk.py /opt/tomcat/webapps/ --out /tmp/results
  .venv/bin/python scripts/scan_bulk.py Exploit.class Shell.class --out quick
        """,
    )
    ap.add_argument(
        "targets", nargs="+", metavar="PATH",
        help=".class/.jsp file(s) or directory to scan recursively",
    )
    ap.add_argument(
        "--out", default="scan_results", metavar="STEM",
        help="output file stem (default: scan_results → scan_results.csv + scan_results.json)",
    )
    args = ap.parse_args()

    inputs               = [Path(t) for t in args.targets]
    class_files, jsp_files = collect_targets(inputs)

    if not class_files and not jsp_files:
        print("No .class or .jsp files found.")
        sys.exit(1)

    print(f"\n  Total: {len(class_files)} .class + {len(jsp_files)} .jsp files to scan")
    print(f"  Output stem: {args.out}\n")

    predictor = Predictor()

    global _TOMCAT_AVAILABLE
    if jsp_files:
        _TOMCAT_AVAILABLE = _init_dynamic_mode()

    scan(class_files, jsp_files, Path(args.out), predictor)


if __name__ == "__main__":
    main()
