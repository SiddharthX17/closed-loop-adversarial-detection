"""
scripts/check_fp_rates.py

Offline diagnostic — shows which rules are firing on benign corpus
and at what rate. No file writes, CLI output only.

Usage:
    python scripts/check_fp_rates.py
    python scripts/check_fp_rates.py --min-rate 0.001   # only show rules above 0.1%
    python scripts/check_fp_rates.py --rules-dir rules/generated
"""

import argparse
from pathlib import Path

from pipeline.detection.engine import BASELINE_COLUMNS, DetectionEngine

BENIGN_CORPUS_DIR = Path("corpus/benign")
RULES_DIR = Path("rules/generated")

_BASELINE_KEY_MAP: dict[str, str] = {
    col.lower(): col for col in BASELINE_COLUMNS}


def _normalize_event(event: dict) -> dict:
    return {_BASELINE_KEY_MAP.get(k.lower(), k.lower()): v for k, v in event.items()}


def load_jsonl(path: Path) -> list[dict]:
    return [
        __import__("json").loads(line.lstrip("\ufeff"))
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def load_benign_events() -> list[dict]:
    events = []
    for jsonl_path in BENIGN_CORPUS_DIR.rglob("*.jsonl"):
        events.extend(load_jsonl(jsonl_path))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show per-rule FP rates against committed benign corpus"
    )
    parser.add_argument(
        "--min-rate", type=float, default=0.0,
        help="Only show rules with FP rate above this threshold (0.0 = show all firing rules)",
    )
    parser.add_argument(
        "--rules-dir", type=Path, default=RULES_DIR,
        help="Rules directory to scan (default: rules/ — includes rules/generated/ via rglob)",
    )
    parser.add_argument(
        "--show-zero", action="store_true",
        help="Also show rules with zero FP hits (hidden by default)",
    )
    args = parser.parse_args()

    print("Loading benign corpus...")
    benign_events = load_benign_events()
    if not benign_events:
        print("ERROR: no benign events found in corpus/benign/")
        return

    normalized = [_normalize_event(e) for e in benign_events]
    total = len(normalized)
    print(f"Loaded {total} benign events\n")

    rule_paths = sorted(args.rules_dir.rglob("*.yml"))
    if not rule_paths:
        print(f"No rules found in {args.rules_dir}")
        return

    engine = DetectionEngine(rules_dir=args.rules_dir, events=normalized)

    results = []
    for rule_path in rule_paths:
        result = engine.run_single_rule(
            rule_path.read_text(), events=normalized)
        fp_count = len(result.matched_events)
        fp_rate = fp_count / total
        results.append((rule_path.name, fp_count, fp_rate))

    # Sort by FP rate descending
    results.sort(key=lambda x: x[2], reverse=True)

    firing = [(n, c, r) for n, c, r in results if c > 0]
    silent = [(n, c, r) for n, c, r in results if c == 0]

    print(f"{'Rule':<70} {'FP hits':>8} {'FP rate':>8}")
    print("-" * 90)

    shown = 0
    for name, count, rate in firing:
        if rate >= args.min_rate:
            flag = " ⚠️ " if rate > 0.01 else "   "
            print(f"{flag}{name:<67} {count:>8} {rate:>8.2%}")
            shown += 1

    if shown == 0:
        print("  No rules firing above the specified threshold.")

    print("-" * 90)
    print(f"\nSummary:")
    print(f"  Rules scanned  : {len(results)}")
    print(f"  Rules firing   : {len(firing)}")
    print(f"  Rules silent   : {len(silent)}")
    print(f"  Benign events  : {total}")

    if firing:
        aggregate = sum(c for _, c, _ in firing) / total
        print(f"  Aggregate rate : {aggregate:.2%}")
        print(f"\n  ⚠️  marks rules exceeding 1% FP threshold (noise_gate limit)")

    if args.show_zero and silent:
        print(f"\nSilent rules (0 FP hits):")
        for name, _, _ in silent:
            print(f"  {name}")


if __name__ == "__main__":
    main()
