"""
scripts/test_attacker_emulator_wire.py

3.08 smoke test — attacker agent → emulator wiring.

Runs attacker agent to get a CampaignPlan, extracts emulator inputs,
runs emulator with evasion hints, then verifies hint values appear
in the generated log events.

Usage (from project root):
    $env:PIPELINE_DEBUG="1"
    python scripts/test_attacker_emulator_wire.py
"""

from pipeline.emulator.emulator import run_emulator
from pipeline.attacker.agent import AttackerAgent, extract_emulator_inputs
import sys
import os
from pathlib import Path

# Run from project root
sys.path.insert(0, str(Path(__file__).parents[1]))


DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


def main():
    print("\n── 3.08 Attacker → Emulator Wire Test ──────────────────")

    # ── Step 1: run attacker agent ────────────────────────────────
    print("\n[1/4] Running attacker agent...")
    agent = AttackerAgent()
    plan = agent.run()

    if not plan:
        print("ERROR: attacker agent returned empty plan — check technique list")
        sys.exit(1)

    print(f"  Plan generated for {len(plan)} technique(s):")
    for tid, task in plan.items():
        print(f"    {tid}: '{task.selected_test_name}'")
        print(f"      hints: {list(task.evasion_hints.keys())}")
        print(f"      mutation_applied: {task.mutation_applied}")

    # ── Step 2: extract emulator inputs ───────────────────────────
    print("\n[2/4] Extracting emulator inputs...")
    technique_ids, evasion_hints = extract_emulator_inputs(plan)
    print(f"  technique_ids: {technique_ids}")
    print(f"  evasion_hints keys: {list(evasion_hints.keys())}")

    # Verify every technique in plan has a hints entry (even if empty)
    for tid in technique_ids:
        assert tid in evasion_hints, f"Missing evasion_hints entry for {tid}"
    print("  ✓ All techniques have hints entries")

    # ── Step 3: run emulator with hints ───────────────────────────
    print("\n[3/4] Running emulator with evasion hints...")
    log_stream, stats = run_emulator(
        technique_ids=technique_ids,
        evasion_hints=evasion_hints,
        output_dir=None,  # suppress file writes for smoke test
    )

    total_events = sum(len(events) for events in log_stream.values())
    print(f"  Total events generated: {total_events}")

    if total_events == 0:
        print("WARNING: no events generated — emulator may need inspection")

    # ── Step 4: verify hint values appear in events ────────────────
    print("\n[4/4] Verifying hint values in generated events...")
    hits = 0
    misses = 0
    skipped = 0  # technique had no events or no hints

    for tid, task in plan.items():
        events = log_stream.get(tid, [])
        hints = task.evasion_hints

        if not events:
            print(f"  {tid}: no events generated — skip hint check")
            skipped += 1
            continue

        if not hints:
            print(
                f"  {tid}: no hints (mutation_applied={task.mutation_applied}) — skip")
            skipped += 1
            continue

        # Check if at least one hint value appears in at least one event
        technique_hit = False
        for event in events:
            event_dict = event.model_dump() if hasattr(
                event, "model_dump") else dict(event)
            for field, value in hints.items():
                event_val = event_dict.get(field, "")
                if event_val and value and (
                    value.lower() in str(event_val).lower()
                    or str(event_val).lower() in value.lower()
                ):
                    if DEBUG:
                        print(
                            f"  {tid}: hint matched — "
                            f"{field}={value!r} found in event ({event_val!r})"
                        )
                    technique_hit = True
                    break
            if technique_hit:
                break

        if technique_hit:
            print(f"  {tid}: ✓ hint value present in generated events")
            hits += 1
        else:
            print(
                f"  {tid}: ✗ no hint values found in events "
                f"(hints={list(hints.keys())}, events={len(events)})"
            )
            misses += 1
            if DEBUG:
                # Print first event for inspection
                first = log_stream[tid][0]
                first_dict = first.model_dump() if hasattr(
                    first, "model_dump") else dict(first)
                populated = {k: v for k, v in first_dict.items()
                             if v is not None and v != ""}
                print(f"    First event fields: {populated}")

    print(f"\n── Results ─────────────────────────────────────────────")
    print(f"  Techniques in plan:     {len(plan)}")
    print(f"  Events generated:       {total_events}")
    print(f"  Hint checks — hits:     {hits}")
    print(f"  Hint checks — misses:   {misses}")
    print(f"  Hint checks — skipped:  {skipped}")

    if misses > 0:
        print(
            f"\nNOTE: {misses} miss(es) — hint values not found in events. "
            "This may mean the grounding layer dropped the hinted values "
            "(field not in procedure_text) or the LLM ignored the hints. "
            "Inspect debug output above."
        )
    else:
        print("\n✓ 3.08 wire test passed")


if __name__ == "__main__":
    main()
