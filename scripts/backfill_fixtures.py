"""
scripts/backfill_fixtures.py

One-time (or as-needed) backfill for rules that never went through
pr_creator.py — manually curated rules (task 2.12's 20 SigmaHQ rules)
never get a fixture via the live pipeline mechanism, since that write
only happens inside create_pr(). This script closes that gap directly.

For each rule found:
  1. Parse technique_id from the rule's `tags:` field
  2. Run the emulator fresh for that technique to generate attack evidence
  3. Run attack_gate against the rule + that evidence
  4. If it passes -> write the fixture (same path convention pr_creator.py
     uses: tests/fixtures/regression/{rule_filename_stem}/attack_sample.jsonl)
  5. If it does NOT pass -> flag loudly, do not write a fixture. This is
     real signal, not a backfill nuisance: a curated rule that doesn't
     fire against fresh emulator evidence has drifted from reality and
     deserves a look.

RULES_SOURCE_DIR is the one thing meant to be changed per Sid's request —
defaults to top-level rules/ (curated rules live directly here). Using
.glob() rather than .rglob() means rules/generated/ is naturally excluded
without needing special-case logic, matching "curated only" by construction.

VERIFY before trusting this end to end — written from project notes, not
a live source check:
  - run_emulator() signature: assumed run_emulator(technique_ids, evasion_hints,
    output_dir) -> dict[technique_id, list[LogEvent]] + EmulatorStats, per
    documented Phase 1 component. Adjust if the real signature differs.
  - attack_gate.run() signature: assumed run(rule_yaml, attack_sample) ->
    GateResult(passed, match_count, ...), per documented validation contract.
  - LogEvent -> dict conversion mirrors the same model_dump(exclude_none=True)
    pattern used elsewhere in orchestrator.py.

Usage:
    python scripts/backfill_fixtures.py
    python scripts/backfill_fixtures.py --rules-dir rules/some_other_folder
    python scripts/backfill_fixtures.py --dry-run
"""

import argparse
import json
import re
from pathlib import Path

import yaml

# Default scope: curated rules only. Change via --rules-dir, not by
# editing this constant, so the default stays self-documenting.
RULES_SOURCE_DIR = Path("rules")
FIXTURES_DIR = Path("tests/fixtures/regression")

TECHNIQUE_TAG_PATTERN = re.compile(
    r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def extract_technique_id(rule_path: Path) -> str | None:
    rule = yaml.safe_load(rule_path.read_text())
    for tag in rule.get("tags", []) or []:
        match = TECHNIQUE_TAG_PATTERN.match(str(tag))
        if match:
            return match.group(1).upper()
    return None


def events_to_dicts(events: list) -> list[dict]:
    return [
        e.model_dump(exclude_none=True) if hasattr(
            e, "model_dump") else dict(e)
        for e in events
    ]


def write_fixture(rule_path: Path, events: list[dict]) -> Path:
    fixture_dir = FIXTURES_DIR / rule_path.stem
    fixture_dir.mkdir(parents=True, exist_ok=True)
    fixture_path = fixture_dir / "attack_sample.jsonl"
    fixture_path.write_text("\n".join(json.dumps(e) for e in events))
    return fixture_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rules-dir", type=Path, default=RULES_SOURCE_DIR,
        help="Source directory to backfill fixtures for (default: rules/, curated rules only)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what would happen without writing any files or calling the emulator",
    )
    args = parser.parse_args()

    # Imports deferred until here — these pull in LLM clients and the full
    # emulator chain, no need to pay that cost for --dry-run or argparse errors.
    from pipeline.emulator.emulator import run_emulator
    from pipeline.validation.attack_gate import run as attack_gate_run

    rule_paths = sorted(args.rules_dir.glob("*.yml"))
    if not rule_paths:
        print(f"No rules found in {args.rules_dir}")
        return

    print(f"Found {len(rule_paths)} rule(s) in {args.rules_dir}\n")

    skipped_existing = []
    written = []
    failed_attack_gate = []
    no_technique_tag = []

    for rule_path in rule_paths:
        fixture_path = FIXTURES_DIR / rule_path.stem / "attack_sample.jsonl"
        if fixture_path.exists():
            skipped_existing.append(rule_path.name)
            continue

        technique_id = extract_technique_id(rule_path)
        if technique_id is None:
            no_technique_tag.append(rule_path.name)
            continue

        print(f"[{rule_path.name}] technique={technique_id}")

        if args.dry_run:
            print(
                f"  (dry-run) would emulate {technique_id} and test against this rule")
            continue

        # output_dir=None — suppresses corpus/attack/ writes, same pattern
        # used elsewhere for non-live/isolated runs.
        # run_emulator returns a 3-tuple: (log_stream, stats, emulation_history).
        log_stream, stats, _ = run_emulator(
            technique_ids=[technique_id],
            evasion_hints=None,
            evasion_hints_v2=None,
            # emulation_history={},
            output_dir=None,
        )
        raw_events = log_stream.get(technique_id, [])
        if not raw_events:
            print(f"  SKIP — emulator produced 0 events for {technique_id}")
            failed_attack_gate.append((rule_path.name, "no emulated events"))
            continue

        # attack_gate.run() expects list[dict], not list[LogEvent].
        # Same model_dump conversion used in orchestrator.py at the
        # create_pr call site.
        raw_events_dicts = [
            e.model_dump(exclude_none=True) if hasattr(
                e, "model_dump") else dict(e)
            for e in raw_events
        ]
        rule_yaml = rule_path.read_text()
        gate_result = attack_gate_run(rule_yaml, raw_events_dicts)

        if not gate_result.passed:
            print(
                f"  FLAGGED — rule did not fire against fresh {technique_id} evidence")
            failed_attack_gate.append(
                (rule_path.name, "attack_gate failed on fresh evidence"))
            continue

        written_path = write_fixture(rule_path, raw_events_dicts)
        print(f"  OK — fixture written to {written_path}")
        written.append(rule_path.name)

    print("\n── Backfill Summary ──────────────────────")
    print(f"  Fixtures written         : {len(written)}")
    print(f"  Already had a fixture     : {len(skipped_existing)}")
    print(f"  No attack.tXXXX tag found : {len(no_technique_tag)}")
    print(f"  Failed attack_gate        : {len(failed_attack_gate)}")
    if failed_attack_gate:
        print("\n  Rules that did NOT get a fixture (need manual review):")
        for name, reason in failed_attack_gate:
            print(f"    - {name}: {reason}")
    if no_technique_tag:
        print("\n  Rules with no parseable technique tag:")
        for name in no_technique_tag:
            print(f"    - {name}")


if __name__ == "__main__":
    main()
