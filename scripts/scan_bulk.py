#!/usr/bin/env python3
"""
scan_bulk.py — Batch scanner for Java .class files.

Recursively scans a directory (or list of files/dirs) for .class files,
runs the hybrid detector (ResNet50 + rules), and writes:
  <stem>.csv   — one row per file, all verdict details
  <stem>.json  — summary counts + list of flagged files

Usage:
    .venv/bin/python scripts/scan_bulk.py /path/to/classes/
    .venv/bin/python scripts/scan_bulk.py /path/to/classes/ --out results
    .venv/bin/python scripts/scan_bulk.py a.class b.class --out results
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
# Import detection engine (05_inference_api.py has a numeric prefix so we
# can't use a normal import statement)
# ---------------------------------------------------------------------------
_here = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("inference_api", _here / "05_inference_api.py")
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
Predictor = _mod.Predictor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "path", "verdict", "tier", "detection_path",
    "ml_score", "rule_risk", "rule_score", "rules_triggered",
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

def collect_class_files(inputs: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in inputs:
        if p.is_dir():
            found = sorted(p.rglob("*.class"))
            print(f"  {p}  →  {len(found)} .class files")
            out.extend(found)
        elif p.suffix == ".class" and p.exists():
            out.append(p)
        else:
            print(f"  [skip] {p}  — not a .class file or directory")
    return out


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
    }


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def scan(targets: list[Path], out_stem: Path, predictor: Predictor) -> None:
    csv_path  = out_stem.with_suffix(".csv")
    json_path = out_stem.with_suffix(".json")

    counts:  dict[str, int]  = {t: 0 for t in TIER_ORDER}
    flagged: list[dict]      = []   # CONFIRMED + HIGH rows for JSON/console
    errors:  list[str]       = []

    t0 = time.time()

    with open(csv_path, "w", newline="") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=CSV_FIELDS)
        writer.writeheader()

        bar = tqdm(targets, unit="file", desc="Scanning", dynamic_ncols=True)
        for class_path in bar:
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

    elapsed = time.time() - t0

    # JSON summary
    summary = {
        "scanned":   len(targets),
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
    print(f"  Scanned : {len(targets)} files  ({elapsed:.1f}s)")
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
        help=".class file(s) or directory to scan recursively",
    )
    ap.add_argument(
        "--out", default="scan_results", metavar="STEM",
        help="output file stem (default: scan_results → scan_results.csv + scan_results.json)",
    )
    args = ap.parse_args()

    inputs  = [Path(t) for t in args.targets]
    targets = collect_class_files(inputs)

    if not targets:
        print("No .class files found.")
        sys.exit(1)

    print(f"\n  Total: {len(targets)} files to scan")
    print(f"  Output stem: {args.out}\n")

    predictor = Predictor()
    scan(targets, Path(args.out), predictor)


if __name__ == "__main__":
    main()
