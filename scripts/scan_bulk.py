#!/usr/bin/env python3
"""
scan_bulk.py — Batch scanner for Java .class and .jsp files.

For .class files: runs the hybrid ML + rule detector directly.
For .jsp files:   compiles via Docker Tomcat (Jasper), then runs the full
                  ML + rule detector on the bytecode.  If compilation fails
                  (missing tag libraries, imported app classes, etc.) it falls
                  back to a source-level text scan so every JSP gets a verdict.

Outputs:
  <stem>.csv   — one row per input file, all verdict details
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
import sys
import time
from pathlib import Path

from tqdm import tqdm

# ---------------------------------------------------------------------------
# Import detection engine
# ---------------------------------------------------------------------------
_here = Path(__file__).parent

def _load_mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_mod                     = _load_mod("inference_api", _here / "05_inference_api.py")
Predictor                = _mod.Predictor
_compile_and_pick_worst  = _mod._compile_and_pick_worst   # handles compile + fallback

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "path", "verdict", "tier", "detection_path",
    "ml_score", "rule_risk", "rule_score", "rules_triggered", "imports", "description",
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
# File collection
# ---------------------------------------------------------------------------

def collect_targets(inputs: list[Path]) -> tuple[list[Path], list[Path]]:
    """Return (class_files, jsp_files) found under each input path."""
    classes: list[Path] = []
    jsps:    list[Path] = []

    for p in inputs:
        if p.is_dir():
            c = sorted(p.rglob("*.class"))
            j = sorted(p.rglob("*.jsp"))
            print(f"  {p}  ->  {len(c)} .class, {len(j)} .jsp files")
            classes.extend(c)
            jsps.extend(j)
        elif p.suffix == ".class" and p.exists():
            classes.append(p)
        elif p.suffix == ".jsp" and p.exists():
            jsps.append(p)
        else:
            print(f"  [skip] {p}  -- not a .class/.jsp file or directory")

    return classes, jsps


# ---------------------------------------------------------------------------
# Row builder
# ---------------------------------------------------------------------------

def _row(file_path: Path, result: dict) -> dict:
    rule = result.get("rule", {})
    return {
        "path":            str(file_path),
        "verdict":         result.get("verdict", "ERROR"),
        "tier":            result.get("tier", "ERROR"),
        "detection_path":  result.get("detection_path", ""),
        "ml_score":        result.get("ml_score", ""),
        "rule_risk":       rule.get("risk", ""),
        "rule_score":      rule.get("score", ""),
        "rules_triggered": "; ".join(rule.get("rules", [])),
        "imports":         "; ".join(result.get("imports") or []),
        "description":     result.get("description", ""),
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

    # Warm up Tomcat once before the progress bar starts.
    # We call _load_jsp_compiler() to populate the cached module, then call
    # ensure_tomcat() on it directly so _TOMCAT_READY is set for all later calls.
    if jsp_files:
        print(f"\n  JSP mode: {len(jsp_files)} file(s) — warming up Docker Tomcat ...")
        _mod._load_jsp_compiler()   # populates _mod._JSP_COMPILER_MOD
        try:
            _mod._JSP_COMPILER_MOD.ensure_tomcat()
        except SystemExit:
            print("  [ERROR] Tomcat not available. JSP files will use source scan fallback.")

    with open(csv_path, "w", newline="") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=CSV_FIELDS)
        writer.writeheader()

        bar = tqdm(total=total, unit="file", desc="Scanning", dynamic_ncols=True)

        # --- .class files ---
        for class_path in class_files:
            bar.set_postfix_str(class_path.name[:40], refresh=False)
            result = predictor.predict(class_path)
            _record(result, class_path, counts, flagged, errors, writer, csvf)
            bar.update(1)

        # --- .jsp files ---
        for jsp_path in jsp_files:
            bar.set_postfix_str(jsp_path.name[:40], refresh=False)
            try:
                result, _ = _compile_and_pick_worst(jsp_path, predictor)
            except Exception as e:
                result = {
                    "verdict": "ERROR", "tier": "ERROR", "ml_score": None,
                    "rule": {"triggered": False, "rules": [], "risk": "LOW", "score": 0},
                    "detection_path": "error", "reason": str(e),
                }

            _record(result, jsp_path, counts, flagged, errors, writer, csvf)
            bar.update(1)

        bar.close()

    elapsed = time.time() - t0

    summary = {
        "scanned":   total,
        "elapsed_s": round(elapsed, 1),
        "counts":    counts,
        "flagged":   flagged,
        "errors":    errors,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    json_path.write_text(json.dumps(summary, indent=2))

    sep = "-" * 52
    print(f"\n  {sep}")
    print(f"  Scanned : {total} files  ({elapsed:.1f}s)")
    for tier in TIER_ORDER:
        n     = counts[tier]
        label = f"  {tier:<12}: {n}"
        print(f"{_C.get(tier, '')}{label}{RST}")
    print(f"  {sep}")
    print(f"  CSV  -> {csv_path}")
    print(f"  JSON -> {json_path}")

    if flagged:
        print(f"\n  Flagged detections (CONFIRMED / HIGH):")
        print(f"  {sep}")
        for row in flagged:
            c     = _C.get(row["tier"], "")
            dpath = f"[{row['detection_path']}]" if row["detection_path"] else ""
            print(f"  {c}[{row['tier']}]{RST} {dpath} {row['path']}")
            if row["rules_triggered"]:
                print(f"           rules : {row['rules_triggered']}")
            if row["ml_score"] not in ("", None):
                print(f"           ml    : {row['ml_score']}")
            if row["imports"]:
                print(f"           imports: {row['imports']}")
            if row.get("description"):
                print(f"           note   : {row['description']}")
    else:
        print(f"\n  {_C['BENIGN']}No CONFIRMED or HIGH detections.{RST}")

    if errors:
        print(f"\n  {_C['ERROR']}{len(errors)} file(s) could not be processed (ERROR in CSV).{RST}")

    print()


def _record(result: dict, file_path: Path, counts: dict, flagged: list,
            errors: list, writer, csvf) -> None:
    tier = result.get("tier", "ERROR")
    counts[tier] = counts.get(tier, 0) + 1
    row = _row(file_path, result)
    writer.writerow(row)
    csvf.flush()
    if tier in ("CONFIRMED", "HIGH"):
        flagged.append(row)
    elif tier == "ERROR":
        errors.append(str(file_path))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Batch scan .class and .jsp files for Java webshells (ML + rules).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/scan_bulk.py /opt/tomcat/webapps/
  python scripts/scan_bulk.py /opt/tomcat/webapps/ --out /tmp/results
  python scripts/scan_bulk.py shell.class evil.jsp --out quick
        """,
    )
    ap.add_argument(
        "targets", nargs="+", metavar="PATH",
        help=".class / .jsp file(s) or directory to scan recursively",
    )
    ap.add_argument(
        "--out", default="scan_results", metavar="STEM",
        help="output file stem (default: scan_results)",
    )
    args = ap.parse_args()

    inputs = [Path(t) for t in args.targets]
    class_files, jsp_files = collect_targets(inputs)

    if not class_files and not jsp_files:
        print("No .class or .jsp files found.")
        sys.exit(1)

    print(f"\n  Total: {len(class_files)} .class + {len(jsp_files)} .jsp = "
          f"{len(class_files) + len(jsp_files)} files to scan")
    print(f"  Output stem: {args.out}\n")

    predictor = Predictor()
    scan(class_files, jsp_files, Path(args.out), predictor)


if __name__ == "__main__":
    main()
