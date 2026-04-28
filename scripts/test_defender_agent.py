"""
3.11 + 3.12 smoke test — defender agent wired to validation pipeline.

Uses T1036.005 — the confirmed live gap from the 2.14 integration test
(5 rules, 0 fired). Generates a candidate rule, runs it through the full
validation pipeline, and reports results.

Usage (from project root):
    $env:PIPELINE_DEBUG="1"
    python -m scripts.test_defender_agent
"""

from pipeline.data.stix_loader import get_loader
from pipeline.emulator.emulator import run_emulator
from pipeline.defender.agent import DefenderAgent, GapContext, find_existing_rule_paths
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))


TARGET_TECHNIQUE = "T1036.005"
CORPUS_ROOT = Path("corpus/benign")


def main():
    print("\n── 3.11/3.12 Defender Agent Smoke Test ─────────────────")

    # ── Step 1: get STIX metadata ─────────────────────────────────
    print(f"\n[1/5] Loading STIX metadata for {TARGET_TECHNIQUE}...")
    stix = get_loader()
    metadata = stix.lookup(TARGET_TECHNIQUE)

    if not metadata:
        print(f"ERROR: no STIX metadata for {TARGET_TECHNIQUE}")
        sys.exit(1)

    print(f"  technique_name: {metadata.technique_name}")
    print(f"  tactic:         {metadata.tactic}")

    # ── Step 2: emulate attack logs for T1036.005 ─────────────────
    print(f"\n[2/5] Emulating attack logs for {TARGET_TECHNIQUE}...")
    log_stream, stats = run_emulator(
        technique_ids=[TARGET_TECHNIQUE],
        output_dir=None,  # suppress file writes
    )

    attack_sample = log_stream.get(TARGET_TECHNIQUE, [])
    print(f"  Events generated: {len(attack_sample)}")

    if not attack_sample:
        print("WARNING: no attack events generated — defender agent will likely fail attack gate")

    # missed_events = serialised attack_sample (all missed since no rules fire on T1036.005)
    missed_events = [
        e.model_dump(exclude_none=True)
        for e in attack_sample
    ]

    # ── Step 3: find existing rules ───────────────────────────────
    print(f"\n[3/5] Scanning for existing rules for {TARGET_TECHNIQUE}...")
    existing_rule_paths = find_existing_rule_paths(TARGET_TECHNIQUE)
    print(f"  Found {len(existing_rule_paths)} existing rule(s):")
    for p in existing_rule_paths:
        print(f"    {p.name}")

    if not existing_rule_paths:
        print("  (no existing rules — defender will generate from scratch)")

    # ── Step 4: build GapContext ──────────────────────────────────
    print(f"\n[4/5] Building GapContext...")
    gap_context = GapContext(
        technique_id=TARGET_TECHNIQUE,
        technique_name=metadata.technique_name,
        tactic=metadata.tactic,
        missed_events=missed_events,
        existing_rule_paths=existing_rule_paths,
        attack_sample=attack_sample,       # list[LogEvent] — for validation
        corpus_root=CORPUS_ROOT,
    )
    print(f"  missed_events:       {len(gap_context.missed_events)}")
    print(f"  attack_sample:       {len(gap_context.attack_sample)} LogEvents")
    print(f"  corpus_root:         {gap_context.corpus_root}")

    # ── Step 5: run defender agent ────────────────────────────────
    print(f"\n[5/5] Running defender agent (max {2 + 1} attempts)...")
    agent = DefenderAgent(corpus_root=CORPUS_ROOT)
    rule_yaml, result = agent.run(gap_context)

    # ── Results ───────────────────────────────────────────────────
    print(f"\n── Results ─────────────────────────────────────────────")

    if rule_yaml and result and result.passed:
        print(f"  Status:        ✓ PASSED — all validation gates cleared")
        print(
            f"  FP rate:       {result.fp_rate:.1%}" if result.fp_rate is not None else "  FP rate:       N/A")
        print(f"\n  Generated rule:\n")
        print("  " + "\n  ".join(rule_yaml.splitlines()))
    else:
        print(f"  Status:        ✗ FAILED — all attempts exhausted")
        if result:
            gate = (
                "schema_linter" if result.lint_passed is False
                else "attack_gate" if result.attack_passed is False
                else "noise_gate" if result.noise_passed is False
                else "unknown"
            )
            print(f"  Last gate failed: {gate}")
            print(f"  Last feedback:    {result.feedback or 'none'}")

        print(
            "\n  NOTE: failure here is informative, not a code bug.\n"
            "  Common causes:\n"
            "  - Attack gate: emulated events don't contain observable patterns\n"
            "    the LLM can write a specific rule for\n"
            "  - Noise gate: rule is too broad for the benign corpus\n"
            "  - Schema linter: LLM used invalid field names (check defender prompt)\n"
            "  Run with PIPELINE_DEBUG=1 for full attempt trace."
        )

    print(f"\n── Gate breakdown ──────────────────────────────────────")
    print(f"  lint_passed:   {result.lint_passed if result else 'N/A'}")
    print(f"  attack_passed: {result.attack_passed if result else 'N/A'}")
    print(f"  noise_passed:  {result.noise_passed if result else 'N/A'}")


if __name__ == "__main__":
    main()
