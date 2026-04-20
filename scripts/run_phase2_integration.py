"""
Phase 2 integration test — 2.14
Runs: emulator → detection engine → result parser → metrics tracker
Prints a gap report showing which techniques are covered and which rules missed.

Usage (from project root):
    python scripts/run_phase2_integration.py
"""

from pipeline.metrics.tracker import MetricsTracker
from pipeline.detection.result_parser import parse_results, get_gaps, get_covered
from pipeline.detection.engine import DetectionEngine
from pipeline.emulator.emulator import run_emulator
from dotenv import load_dotenv
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv()


RULES_DIR = Path("rules")
CORPUS_DIR = Path("corpus/attack")


def main():
    # ------------------------------------------------------------------ #
    # Step 1 — Run emulator across all techniques in techniques.yaml
    # ------------------------------------------------------------------ #
    print("\n=== STEP 1: EMULATOR ===")
    print("Generating attack log events from Atomic tests...")

    logs, stats = run_emulator(output_dir=None)

    print(f"Techniques attempted : {stats.techniques_attempted}")
    print(f"Techniques with events: {stats.techniques_with_events}")
    print(f"Tests attempted      : {stats.tests_attempted}")
    print(f"Tests skipped (no clean): {stats.tests_skipped_no_clean}")
    print(f"Tests skipped (unresolved vars): {stats.tests_skipped_unresolved}")
    print(f"Total events generated: {stats.events_generated}")

    if not logs:
        print("\nERROR: Emulator produced no events. Check procedure_interpreter "
              "and atomic_loader. Nothing to detect against — stopping.")
        sys.exit(1)

    # Per-technique event count
    print("\nEvents per technique:")
    for tid, events in logs.items():
        print(f"  {tid}: {len(events)} events")

    # ------------------------------------------------------------------ #
    # Step 2 — Convert LogEvents to dicts, run detection engine
    # ------------------------------------------------------------------ #
    print("\n=== STEP 2: DETECTION ENGINE ===")

    all_rule_results = []

    all_events = []
    for technique_id, log_events in logs.items():
        all_events.extend([e.model_dump() for e in log_events])

    engine = DetectionEngine(rules_dir=RULES_DIR, events=all_events)
    all_rule_results = engine.run()

    fired = sum(1 for r in all_rule_results if r.fired)
    skipped = sum(1 for r in all_rule_results if r.skipped)
    missed = sum(1 for r in all_rule_results if not r.fired and not r.skipped)
    print(f"  Total: {fired} fired / {missed} missed / {skipped} skipped"
          f" ({len(all_rule_results)} rules)")

    if not all_rule_results:
        print("\nERROR: Engine returned no results. Check rules_dir path and "
              "that rules/ contains .yml files.")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # Step 3 — Parse results into DetectionResult per technique
    # ------------------------------------------------------------------ #
    print("\n=== STEP 3: RESULT PARSER ===")

    detection_results = parse_results(all_rule_results)
    covered = get_covered(detection_results)
    gaps = get_gaps(detection_results)

    print(f"Techniques covered : {len(covered)}")
    print(f"Techniques with gaps: {len(gaps)}")

    # ------------------------------------------------------------------ #
    # Step 4 — Metrics tracker
    # ------------------------------------------------------------------ #
    print("\n=== STEP 4: METRICS ===")

    tracker = MetricsTracker()
    tracker.set_iteration(1)

    for result in detection_results:
        # Count fired, missed, matched events from breakdown
        rules_fired = len(result.fired_rules)
        rules_evaluated = result.total_rules
        matched = len(result.matched_events)
        total = sum(rb.match_count for rb in result.fired_rules)

        tracker.record_detection(
            technique_id=result.technique_id,
            rules_evaluated=rules_evaluated,
            rules_fired=rules_fired,
            total_events=total if total > 0 else 1,  # avoid div by zero
            matched_events=matched,
        )

    report = tracker.finalise_iteration()
    covered_ids = tracker.get_covered_techniques(iteration=1)
    uncovered_ids = tracker.get_uncovered_techniques(iteration=1)

    print(f"Covered   : {covered_ids}")
    print(f"Uncovered : {uncovered_ids}")

    # ------------------------------------------------------------------ #
    # Step 5 — Gap report
    # ------------------------------------------------------------------ #
    print("\n=== GAP REPORT ===")

    for result in detection_results:
        print(f"\n{result.technique_id}")
        print(f"  Covered : {result.covered}")
        print(f"  Summary : {result.summary()}")

        if result.fired_rules:
            print("  Fired rules:")
            for rb in result.fired_rules:
                print(f"    [HIT]  {rb.rule_title} ({rb.match_count} matches)")

        if result.missed_rules:
            print("  Missed rules:")
            for rb in result.missed_rules:
                print(f"    [MISS] {rb.rule_title}")

        if result.skipped_rules:
            print("  Skipped rules:")
            for rb in result.skipped_rules:
                print(f"    [SKIP] {rb.rule_title} — {rb.skip_reason}")

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
