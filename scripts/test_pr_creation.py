"""
3.14 live integration test — PR creator with a real validated rule.

Uses T1036.005 — the technique whose rule passed all validation gates
in the 3.11/3.12 defender agent smoke test.

Runs the full chain:
  emulate → defend → validate → create PR

Confirms:
  - PR opens in GitHub with correct title
  - Rule YAML committed to rules/ on the branch
  - Evidence events appear in PR body
  - Labels applied

Requires in .env:
  GITHUB_TOKEN — personal access token with repo scope
  GITHUB_REPO  — "owner/repo-name"

Usage (from project root):
  $env:PIPELINE_DEBUG="1"
  python -m scripts.test_pr_creation
"""

from pipeline.data.stix_loader import get_loader
from pipeline.emulator.emulator import run_emulator
from pipeline.github.pr_creator import PRCreator, PRResult
from pipeline.defender.agent import DefenderAgent, GapContext, find_existing_rule_paths
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))


TARGET_TECHNIQUE = "T1036.005"
CORPUS_ROOT = Path("corpus/benign")


def main():
    print("\n── 3.14 PR Creation Integration Test ───────────────────")

    # ── Step 1: STIX metadata ─────────────────────────────────────
    print(f"\n[1/6] Loading STIX metadata for {TARGET_TECHNIQUE}...")
    stix = get_loader()
    metadata = stix.lookup(TARGET_TECHNIQUE)
    if not metadata:
        print(f"ERROR: no STIX metadata for {TARGET_TECHNIQUE}")
        sys.exit(1)
    print(f"  technique_name: {metadata.technique_name}")

    # ── Step 2: emulate attack logs ───────────────────────────────
    print(f"\n[2/6] Emulating attack logs...")
    log_stream, _ = run_emulator(
        technique_ids=[TARGET_TECHNIQUE],
        output_dir=None,
    )
    attack_sample = log_stream.get(TARGET_TECHNIQUE, [])
    print(f"  Events generated: {len(attack_sample)}")

    if not attack_sample:
        print("ERROR: no events generated — cannot proceed")
        sys.exit(1)

    missed_events = [
        e.model_dump(exclude_none=True) for e in attack_sample
    ]

    # ── Step 3: find existing rules ───────────────────────────────
    print(f"\n[3/6] Scanning for existing rules...")
    existing_rule_paths = find_existing_rule_paths(TARGET_TECHNIQUE)
    print(f"  Found {len(existing_rule_paths)} rule(s)")

    # ── Step 4: run defender agent ────────────────────────────────
    print(f"\n[4/6] Running defender agent...")
    gap_context = GapContext(
        technique_id=TARGET_TECHNIQUE,
        technique_name=metadata.technique_name,
        tactic=metadata.tactic,
        missed_events=missed_events,
        existing_rule_paths=existing_rule_paths,
        attack_sample=attack_sample,
        corpus_root=CORPUS_ROOT,
    )

    agent = DefenderAgent(corpus_root=CORPUS_ROOT)
    rule_yaml, validation_result = agent.run(gap_context)

    if not rule_yaml or not validation_result or not validation_result.passed:
        print("ERROR: defender agent failed to produce a valid rule")
        if validation_result:
            print(f"  Last gate failed: {validation_result.gate_failed}")
            print(f"  Feedback: {validation_result.feedback}")
        sys.exit(1)

    print(f"  Rule validated — FP rate: {validation_result.fp_rate:.1%}")
    print(f"  Rule title: {rule_yaml.splitlines()[0]}")

    # ── Step 5: create PR ─────────────────────────────────────────
    print(f"\n[5/6] Creating GitHub PR...")
    try:
        creator = PRCreator()
    except EnvironmentError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    result = creator.create_pr(
        technique_id=TARGET_TECHNIQUE,
        technique_name=metadata.technique_name,
        rule_yaml=rule_yaml,
        missed_events=missed_events,
        validation_result=validation_result,
        fired_rules=[],
    )

    # ── Step 6: verify ────────────────────────────────────────────
    print(f"\n[6/6] Verifying PR...")
    print(f"  PR URL:        {result.pr_url}")
    print(f"  PR number:     #{result.pr_number}")
    print(f"  Branch:        {result.branch_name}")
    print(f"  Rule filename: {result.rule_filename}")

    # Sanity checks
    assert result.pr_url.startswith("https://github.com"), \
        f"Unexpected PR URL format: {result.pr_url}"
    assert result.branch_name == f"rule/{TARGET_TECHNIQUE}", \
        f"Branch name mismatch: {result.branch_name}"
    assert result.rule_filename.startswith(TARGET_TECHNIQUE), \
        f"Filename missing technique prefix: {result.rule_filename}"
    assert result.rule_filename.endswith(".yml"), \
        f"Filename missing .yml extension: {result.rule_filename}"

    print(f"\n── Results ─────────────────────────────────────────────")
    print(f"  ✓ PR created: {result.pr_url}")
    print(f"  ✓ Branch:     {result.branch_name}")
    print(f"  ✓ Rule file:  rules/{result.rule_filename}")
    print(f"\n  Open the PR and verify manually:")
    print(f"  - Rule YAML committed to rules/{result.rule_filename}")
    print(f"  - Evidence events visible in PR body")
    print(f"  - Labels: automated, detection-rule, {TARGET_TECHNIQUE}")
    print(f"  - Validation summary shows 0.0% FP rate")
    print(f"\n✓ 3.14 complete")


if __name__ == "__main__":
    main()
