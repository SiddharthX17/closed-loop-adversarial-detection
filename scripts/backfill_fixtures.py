"""
scripts/backfill_fixtures.py

One-time (or as-needed) backfill for rules that never went through
pr_creator.py — manually curated rules (task 2.12's 20 SigmaHQ rules)
never get a fixture via the live pipeline mechanism, since that write
only happens inside create_pr(). This script closes that gap directly.

REDESIGNED (v2): rule-aware candidate selection.

v1 called run_emulator() and accepted whatever test the emulator's generic
detection-value scoring (lolbin/obfuscation/network/etc buckets) happened
to land on. That scoring has no idea what fields the specific rule being
backfilled actually needs — so a fixture attempt frequently "failed" and
got flagged for manual review even when a *different* Atomic test for the
same technique would have satisfied the rule just fine.

v2 instead:
  1. Gathers the full cleaned candidate pool for the technique itself
     (same load -> clean -> filter-unresolved-vars steps _select_tests
     does internally — replicated here since that raw pool isn't exposed
     publicly by emulator.py)
  2. Extracts the rule's literal Sigma selection values
  3. Ranks candidates by whether those values plausibly appear in the
     candidate's own command text, using the same match tiers
     procedure_interpreter._ground_fields uses (verbatim -> basename ->
     basename-without-extension -> partial token match), so the ranking
     heuristic doesn't silently diverge from the real grounding logic
  4. Tries top-N ranked candidates in order via emulator._emulate_technique
     (pinned per-candidate via selected_test_guids), running attack_gate
     after each, stopping at the first pass

IMPORTANT — what this does NOT do (overfitting guardrail):
  Rule values are used ONLY to choose try-order among real, independently
  authored Atomic tests. They are never passed into interpret_procedure or
  build_log_event, and never influence what gets extracted from
  procedure_text. The grounding layer is untouched. A fixture is only ever
  written from a genuine, unmodified Atomic-test-derived emulation that
  organically satisfies attack_gate — never from evidence shaped to fit
  the rule. If that weren't true, attack_gate would be circular and
  worthless as regression evidence.

KNOWN DIVERGENCE from _ground_fields: real grounding restricts partial-
token matching to CommandLine/ParentCommandLine specifically. This ranking
scorer doesn't retain which Sigma field each value came from (it walks the
whole detection: block for relevance signal), so it applies partial-token
matching to any multi-word value. This is safe because this scorer only
decides try-ORDER, never pass/fail — the real _ground_fields gate
(untouched, called inside build_log_event via _emulate_technique) still
enforces its stricter rules downstream. Worst case of a bad ranking guess:
one wasted API call on a mediocre candidate, not a bad fixture.

TEST-SELECTION-HISTORY NOTE: this script calls _emulate_technique()
directly, NOT run_emulator(). Confirmed by reading emulator.py directly —
test_history.load()/save() happen ONLY inside run_emulator(), never in
_emulate_technique/_select_tests/_select_candidates. This script therefore
cannot write to data/test_selection_history.json. No snapshot/restore
needed.

KNOWN COUPLING: _emulate_technique, EmulatorStats, and reset_seen_tests
are underscore-prefixed internals of pipeline.emulator.emulator, not the
public run_emulator() interface. Imported directly here to get pin-only,
no-history-write execution. If that function's signature or behaviour
changes, this script needs a matching update — same category of risk
flagged in the original version's "VERIFY before trusting" section.

RULES_SOURCE_DIR is the one thing meant to be changed per Sid's request —
defaults to top-level rules/ (curated rules live directly here). Using
.glob() rather than .rglob() means rules/generated/ is naturally excluded
without needing special-case logic, matching "curated only" by construction.

Usage:
    python scripts/backfill_fixtures.py
    python scripts/backfill_fixtures.py --rules-dir rules/some_other_folder
    python scripts/backfill_fixtures.py --dry-run
    python scripts/backfill_fixtures.py --max-candidates 5
"""

import argparse
import json
import os
import re
from pathlib import Path

import yaml

# Default scope: curated rules only. Change via --rules-dir, not by
# editing this constant, so the default stays self-documenting.
RULES_SOURCE_DIR = Path("rules/generated/1")
FIXTURES_DIR = Path("tests/fixtures/regression")

TECHNIQUE_TAG_PATTERN = re.compile(
    r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# Same tier ordering as procedure_interpreter._ground_fields — kept
# consistent deliberately, see module docstring.
_PARTIAL_MATCH_MIN_TOKENS = 2

# Ranked candidates to try per rule before flagging for manual review.
# Matches the emulator's own _FALLBACK_POOL size — same bounded-cost logic,
# overridable via --max-candidates.
_DEFAULT_MAX_CANDIDATES = 3


def extract_technique_id(rule_path: Path) -> str | None:
    rule = yaml.safe_load(rule_path.read_text())
    for tag in rule.get("tags", []) or []:
        match = TECHNIQUE_TAG_PATTERN.match(str(tag))
        if match:
            return match.group(1).upper()
    return None


# ─── Rule value extraction ─────────────────────────────────────────────────

def _extract_sigma_values(rule_yaml_text: str) -> list[str]:
    """
    Pull every literal string value out of a Sigma rule's `detection:`
    block, skipping the `condition` key entirely (that's boolean logic,
    not a value to match against). Used only to rank candidate Atomic
    tests by relevance — never fed into extraction or grounding.
    """
    try:
        rule = yaml.safe_load(rule_yaml_text)
    except yaml.YAMLError:
        return []

    if not isinstance(rule, dict):
        return []

    detection = rule.get("detection", {})
    values: list[str] = []

    def _walk(node, key_hint: str | None = None):
        if key_hint == "condition":
            return
        if isinstance(node, dict):
            for k, v in node.items():
                _walk(v, key_hint=k)
        elif isinstance(node, list):
            for item in node:
                _walk(item, key_hint=key_hint)
        elif isinstance(node, str):
            values.append(node)
        # ints/bools/None: not useful for text matching, skip

    _walk(detection)
    return values


# ─── Candidate pool gathering ──────────────────────────────────────────────
# Mirrors emulator._select_tests's load -> clean -> filter steps, minus the
# generic detection-value scoring — we rank against the specific rule
# ourselves instead. Kept as a standalone loop rather than editing
# emulator.py, since that file is tested/locked and this script is not
# part of the live loop.

def _gather_candidates(technique_id: str) -> list[tuple[str, object]]:
    from pipeline.data.stix_loader import lookup_technique
    from pipeline.data.atomic_loader import load_tests_for_technique_with_fallback
    from pipeline.data.atomic_cleaner import clean_test

    metadata = lookup_technique(technique_id)
    if metadata is None:
        print(f"  no STIX metadata for {technique_id}")
        return []

    raw_tests = load_tests_for_technique_with_fallback(technique_id)
    if not raw_tests:
        return []

    cleaned_all: list[tuple[str, object]] = []
    for test in raw_tests:
        cleaned = clean_test(test, metadata)
        if cleaned is None or cleaned.has_unresolved_vars:
            continue
        cleaned_all.append((test.test_guid, cleaned))

    return cleaned_all


# ─── Rule-relevance scoring ─────────────────────────────────────────────────

def _score_candidate(rule_values: list[str], cleaned) -> tuple[float, list[str]]:
    """
    Score how well a cleaned Atomic test's own command text lines up with
    a rule's literal selection values. Match tiers deliberately mirror
    procedure_interpreter._ground_fields — see module docstring for the
    one known divergence (partial-token tier applied to any value here,
    not just CommandLine-like fields).

    Returns (score, matched_values) — matched_values is kept only for
    --dry-run transparency.
    """
    if not cleaned.commands:
        return 0.0, []

    text = " ".join(cleaned.commands).lower()
    score = 0.0
    matched: list[str] = []

    for value in rule_values:
        if not isinstance(value, str) or not value.strip():
            continue
        v_lower = value.lower()

        # Tier 1 — verbatim
        if v_lower in text:
            score += 1.0
            matched.append(value)
            continue

        # Tier 2 — basename (path-like values)
        basename = os.path.basename(value).lower()
        if basename and basename != v_lower and basename in text:
            score += 0.75
            matched.append(value)
            continue

        # Tier 3 — basename without extension
        basename_no_ext = os.path.splitext(basename)[0].lower()
        if basename_no_ext and basename_no_ext != v_lower and basename_no_ext in text:
            score += 0.5
            matched.append(value)
            continue

        # Tier 4 — partial token match (see KNOWN DIVERGENCE in module docstring)
        tokens = [t for t in v_lower.split() if len(t) > 4]
        if tokens:
            hits = sum(1 for t in tokens if t in text)
            if hits >= _PARTIAL_MATCH_MIN_TOKENS:
                score += 0.25
                matched.append(value)

    return score, matched


def _rank_candidates(
    rule_values: list[str],
    candidates: list[tuple[str, object]],
) -> list[tuple[str, object, float, list[str]]]:
    """
    Rank candidates by rule-relevance score, descending. Stable sort —
    ties keep loader order rather than random tiebreaking, so backfill
    runs are reproducible.
    """
    scored = [
        (guid, cleaned, *_score_candidate(rule_values, cleaned))
        for guid, cleaned in candidates
    ]
    scored.sort(key=lambda row: row[2], reverse=True)
    return scored


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
        help="Report ranked candidates without calling the emulator or writing files",
    )
    parser.add_argument(
        "--max-candidates", type=int, default=_DEFAULT_MAX_CANDIDATES,
        help=f"Ranked candidates to try per rule before flagging (default: {_DEFAULT_MAX_CANDIDATES})",
    )
    args = parser.parse_args()

    # Deferred until here, and only when not --dry-run — these pull in the
    # anthropic client (via procedure_interpreter, imported at module level
    # by emulator.py) and the full emulation chain. No need to pay that
    # cost for --dry-run or argparse errors.
    if not args.dry_run:
        from pipeline.emulator.emulator import (
            _emulate_technique, EmulatorStats, reset_seen_tests,
        )
        from pipeline.validation.attack_gate import run as attack_gate_run
        reset_seen_tests()  # clean slate — cosmetic, see module docstring

    rule_paths = sorted(args.rules_dir.glob("*.yml"))
    if not rule_paths:
        print(f"No rules found in {args.rules_dir}")
        return

    print(f"Found {len(rule_paths)} rule(s) in {args.rules_dir}\n")

    skipped_existing = []
    written = []
    failed_attack_gate = []
    no_technique_tag = []
    no_candidates = []

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

        rule_yaml = rule_path.read_text()
        rule_values = _extract_sigma_values(rule_yaml)

        candidates = _gather_candidates(technique_id)
        if not candidates:
            print(f"  SKIP — no usable Atomic tests found for {technique_id}")
            no_candidates.append((rule_path.name, "no cleaned candidates"))
            continue

        ranked = _rank_candidates(rule_values, candidates)
        top_n = ranked[: args.max_candidates]

        for i, (guid, cleaned, score, matched) in enumerate(top_n):
            preview = ", ".join(matched[:3]) + \
                ("…" if len(matched) > 3 else "")
            print(
                f"  candidate {i + 1}/{len(top_n)}: '{cleaned.test_name}' "
                f"score={score:.2f} matched=[{preview}]"
            )

        if args.dry_run:
            print(
                f"  (dry-run) would try {len(top_n)} candidate(s) above, in order\n")
            continue

        attempts: list[tuple[str, str]] = []  # (test_name, reason)
        fixture_written = False

        for guid, cleaned, score, matched in top_n:
            # output_dir not applicable here — _emulate_technique never
            # writes corpus/attack/ output itself (only run_emulator does,
            # via output_writer, after aggregating all techniques).
            events = _emulate_technique(
                technique_id,
                evasion_hints=None,
                stats=EmulatorStats(),
                selected_test_guids={technique_id: guid},
                evasion_hints_v2=None,
                history=None,
            )
            if not events:
                attempts.append(
                    (cleaned.test_name, "0 events after grounding"))
                continue

            raw_events_dicts = events_to_dicts(events)
            gate_result = attack_gate_run(rule_yaml, raw_events_dicts)

            if not gate_result.passed:
                attempts.append(
                    (cleaned.test_name, "attack_gate did not fire"))
                if os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true"):
                    # Same PIPELINE_DEBUG convention used project-wide.
                    # Shows the actual mismatch instead of just pass/fail —
                    # is it a missing field, wrong EventID, or a rule
                    # requiring artifacts this single-step extraction
                    # can never co-produce in one event?
                    print(
                        f"    [DEBUG] gate feedback: {gate_result.feedback()}")
                    print(
                        f"    [DEBUG] generated event(s):\n"
                        f"{json.dumps(raw_events_dicts, indent=2)}"
                    )
                continue

            written_path = write_fixture(rule_path, raw_events_dicts)
            print(
                f"  OK — fixture written to {written_path} (via '{cleaned.test_name}')")
            written.append(rule_path.name)
            fixture_written = True
            break

        if not fixture_written:
            print(
                f"  FLAGGED — no candidate satisfied attack_gate for {technique_id}")
            for name, reason in attempts:
                print(f"    - '{name}': {reason}")
            failed_attack_gate.append(
                (rule_path.name, f"{len(attempts)} candidate(s) tried, none passed"))

    print("\n── Backfill Summary ──────────────────────")
    print(f"  Fixtures written          : {len(written)}")
    print(f"  Already had a fixture     : {len(skipped_existing)}")
    print(f"  No attack.tXXXX tag found : {len(no_technique_tag)}")
    print(f"  No usable Atomic tests    : {len(no_candidates)}")
    print(f"  Failed attack_gate        : {len(failed_attack_gate)}")
    if failed_attack_gate:
        print("\n  Rules that did NOT get a fixture (need manual review):")
        for name, reason in failed_attack_gate:
            print(f"    - {name}: {reason}")
    if no_candidates:
        print("\n  Rules with no usable Atomic tests:")
        for name, reason in no_candidates:
            print(f"    - {name}: {reason}")
    if no_technique_tag:
        print("\n  Rules with no parseable technique tag:")
        for name in no_technique_tag:
            print(f"    - {name}")


if __name__ == "__main__":
    main()
