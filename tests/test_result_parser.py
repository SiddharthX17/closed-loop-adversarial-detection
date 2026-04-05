"""
test_result_parser.py — Unit tests for pipeline/detection/result_parser.py
===========================================================================
Run from project root:
    pytest tests/test_result_parser.py -v

Coverage targets
----------------
- extract_technique_id      : standard subtechnique, base technique, no match,
                              mixed case, deeply nested path
- _deduplicate_events       : same event twice, distinct events, empty lists
- parse_results             : empty input, single fired, single missed,
                              single skipped, mixed per technique,
                              multi-technique grouping, UNKNOWN grouping,
                              covered flag, gap property, skip_only property,
                              matched_events deduplication across rules
- get_gaps / get_covered    : correct filtering
- DetectionResult.summary() : smoke test output shape
"""

from __future__ import annotations

import pytest

from engine import RuleMatchResult
from result_parser import (
    DetectionResult,
    RuleBreakdown,
    _deduplicate_events,
    extract_technique_id,
    get_covered,
    get_gaps,
    parse_results,
)


# ---------------------------------------------------------------------------
# Helpers — build RuleMatchResult without touching the engine
# ---------------------------------------------------------------------------

def make_rule_result(
    rule_path: str = "rules/T1059.001-encoded-ps.yml",
    rule_id: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    rule_title: str = "Test Rule",
    fired: bool = False,
    matched_events: list[dict] | None = None,
    skipped: bool = False,
    skip_reason: str | None = None,
    sql_query: str | None = "SELECT * FROM logs WHERE 1=1",
) -> RuleMatchResult:
    return RuleMatchResult(
        rule_id=rule_id,
        rule_title=rule_title,
        rule_path=rule_path,
        fired=fired,
        matched_events=matched_events or [],
        skipped=skipped,
        skip_reason=skip_reason,
        sql_query=sql_query,
    )


def make_event(**kwargs) -> dict:
    base = {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": "cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# 1. extract_technique_id
# ---------------------------------------------------------------------------

class TestExtractTechniqueId:
    def test_subtechnique_id(self):
        assert extract_technique_id(
            "rules/T1059.001-encoded-powershell.yml") == "T1059.001"

    def test_base_technique_id(self):
        assert extract_technique_id(
            "rules/T1059-command-scripting.yml") == "T1059"

    def test_deeply_nested_path(self):
        assert extract_technique_id(
            "C:/project/rules/windows/T1547.001-registry-run-keys.yml"
        ) == "T1547.001"

    def test_no_technique_id_returns_unknown(self):
        assert extract_technique_id("rules/my-custom-rule.yml") == "UNKNOWN"

    def test_case_insensitive(self):
        # Technique IDs are uppercased on return regardless of filename case
        assert extract_technique_id("rules/t1059.001-test.yml") == "T1059.001"

    def test_stem_only_no_extension_confusion(self):
        # Path.stem strips the extension — T1059.001 should not be confused
        # with a file extension
        result = extract_technique_id("rules/T1059.001-test.yml")
        assert result == "T1059.001"

    def test_double_digit_subtechnique(self):
        assert extract_technique_id("rules/T1059.001-test.yml") == "T1059.001"

    def test_no_description_suffix(self):
        # Just the technique ID with no trailing description
        assert extract_technique_id("rules/T1059.yml") == "T1059"

    def test_windows_backslash_path(self):
        assert extract_technique_id(
            "rules\\windows\\T1112-registry-modification.yml"
        ) == "T1112"


# ---------------------------------------------------------------------------
# 2. _deduplicate_events
# ---------------------------------------------------------------------------

class TestDeduplicateEvents:
    def test_identical_events_deduped(self):
        e = make_event()
        result = _deduplicate_events([[e, e]])
        assert len(result) == 1

    def test_same_event_across_lists(self):
        e = make_event()
        result = _deduplicate_events([[e], [e]])
        assert len(result) == 1

    def test_distinct_events_preserved(self):
        e1 = make_event(CommandLine="cmd.exe /c whoami")
        e2 = make_event(CommandLine="powershell.exe -enc abc")
        result = _deduplicate_events([[e1], [e2]])
        assert len(result) == 2

    def test_empty_input(self):
        assert _deduplicate_events([]) == []

    def test_empty_sublists(self):
        assert _deduplicate_events([[], []]) == []

    def test_first_occurrence_wins_ordering(self):
        e1 = make_event(CommandLine="first")
        e2 = make_event(CommandLine="second")
        result = _deduplicate_events([[e1, e2], [e2]])
        assert result[0]["CommandLine"] == "first"
        assert result[1]["CommandLine"] == "second"

    def test_field_order_does_not_affect_hash(self):
        # Two dicts with same k/v pairs in different insertion order
        e1 = {"EventID": "1", "Image": "cmd.exe"}
        e2 = {"Image": "cmd.exe", "EventID": "1"}
        result = _deduplicate_events([[e1, e2]])
        assert len(result) == 1


# ---------------------------------------------------------------------------
# 3. parse_results
# ---------------------------------------------------------------------------

class TestParseResults:
    def test_empty_input_returns_empty(self):
        assert parse_results([]) == []

    # ── single rule outcomes ──────────────────────────────────────────────

    def test_fired_rule_covered(self):
        r = make_rule_result(fired=True, matched_events=[make_event()])
        results = parse_results([r])
        assert len(results) == 1
        assert results[0].covered is True
        assert results[0].gap is False

    def test_missed_rule_not_covered(self):
        r = make_rule_result(fired=False)
        results = parse_results([r])
        assert results[0].covered is False
        assert results[0].gap is True

    def test_skipped_rule_not_covered(self):
        r = make_rule_result(skipped=True, skip_reason="parse_error: bad YAML")
        results = parse_results([r])
        assert results[0].covered is False
        assert results[0].skip_only is True
        # skip_only is not a gap — no evaluable rules
        assert results[0].gap is False

    def test_skipped_rule_goes_into_skipped_list(self):
        r = make_rule_result(
            skipped=True, skip_reason="execution_error: no such column")
        results = parse_results([r])
        assert len(results[0].skipped_rules) == 1
        assert len(results[0].fired_rules) == 0
        assert len(results[0].missed_rules) == 0

    # ── rule breakdown fields ─────────────────────────────────────────────

    def test_fired_rule_breakdown_fields(self):
        event = make_event()
        r = make_rule_result(
            fired=True,
            matched_events=[event],
            rule_id="test-id",
            rule_title="Test Rule Title",
            sql_query="SELECT * FROM logs WHERE 1=1",
        )
        results = parse_results([r])
        breakdown = results[0].fired_rules[0]
        assert breakdown.rule_id == "test-id"
        assert breakdown.rule_title == "Test Rule Title"
        assert breakdown.match_count == 1
        assert breakdown.sql_query is not None

    def test_skip_reason_preserved_in_breakdown(self):
        reason = "execution_error: no such column: ParentCommandLine"
        r = make_rule_result(skipped=True, skip_reason=reason)
        results = parse_results([r])
        assert results[0].skipped_rules[0].skip_reason == reason

    # ── matched events ────────────────────────────────────────────────────

    def test_matched_events_populated(self):
        events = [make_event(CommandLine=f"cmd {i}") for i in range(3)]
        r = make_rule_result(fired=True, matched_events=events)
        results = parse_results([r])
        assert len(results[0].matched_events) == 3

    def test_matched_events_deduplicated_across_rules(self):
        shared_event = make_event(CommandLine="shared")
        unique_event = make_event(CommandLine="unique")
        r1 = make_rule_result(
            rule_path="rules/T1059.001-rule-a.yml",
            rule_id="rule-a",
            fired=True,
            matched_events=[shared_event, unique_event],
        )
        r2 = make_rule_result(
            rule_path="rules/T1059.001-rule-b.yml",
            rule_id="rule-b",
            fired=True,
            matched_events=[shared_event],  # same event as r1
        )
        results = parse_results([r1, r2])
        # shared_event + unique_event = 2 distinct events, not 3
        assert len(results[0].matched_events) == 2

    def test_missed_rule_has_no_matched_events(self):
        r = make_rule_result(fired=False)
        results = parse_results([r])
        assert results[0].matched_events == []

    # ── multi-technique grouping ──────────────────────────────────────────

    def test_multiple_techniques_produce_multiple_results(self):
        r1 = make_rule_result(
            rule_path="rules/T1059.001-ps-enc.yml", rule_id="r1")
        r2 = make_rule_result(
            rule_path="rules/T1547.001-run-key.yml", rule_id="r2")
        results = parse_results([r1, r2])
        assert len(results) == 2
        ids = {r.technique_id for r in results}
        assert ids == {"T1059.001", "T1547.001"}

    def test_same_technique_multiple_rules_grouped(self):
        r1 = make_rule_result(rule_path="rules/T1059.001-rule-a.yml", rule_id="r1",
                              fired=True, matched_events=[make_event()])
        r2 = make_rule_result(rule_path="rules/T1059.001-rule-b.yml", rule_id="r2",
                              fired=False)
        results = parse_results([r1, r2])
        assert len(results) == 1
        assert results[0].technique_id == "T1059.001"
        assert results[0].total_rules == 2
        assert len(results[0].fired_rules) == 1
        assert len(results[0].missed_rules) == 1

    def test_results_sorted_by_technique_id(self):
        r1 = make_rule_result(
            rule_path="rules/T1547.001-test.yml", rule_id="r1")
        r2 = make_rule_result(
            rule_path="rules/T1059.001-test.yml", rule_id="r2")
        r3 = make_rule_result(rule_path="rules/T1112-test.yml", rule_id="r3")
        results = parse_results([r1, r2, r3])
        ids = [r.technique_id for r in results]
        assert ids == sorted(ids)

    # ── UNKNOWN grouping ──────────────────────────────────────────────────

    def test_no_technique_id_grouped_as_unknown(self):
        r = make_rule_result(rule_path="rules/my-custom-rule.yml")
        results = parse_results([r])
        assert results[0].technique_id == "UNKNOWN"

    def test_multiple_unknown_rules_grouped_together(self):
        r1 = make_rule_result(
            rule_path="rules/custom-rule-a.yml", rule_id="r1")
        r2 = make_rule_result(
            rule_path="rules/custom-rule-b.yml", rule_id="r2")
        results = parse_results([r1, r2])
        assert len(results) == 1
        assert results[0].technique_id == "UNKNOWN"
        assert results[0].total_rules == 2

    # ── total_rules count ─────────────────────────────────────────────────

    def test_total_rules_counts_all_outcomes(self):
        fired = make_rule_result(rule_path="rules/T1059.001-a.yml",
                                 rule_id="r1", fired=True,
                                 matched_events=[make_event()])
        missed = make_rule_result(rule_path="rules/T1059.001-b.yml",
                                  rule_id="r2", fired=False)
        skipped = make_rule_result(rule_path="rules/T1059.001-c.yml",
                                   rule_id="r3", skipped=True,
                                   skip_reason="parse_error")
        results = parse_results([fired, missed, skipped])
        assert results[0].total_rules == 3


# ---------------------------------------------------------------------------
# 4. DetectionResult properties
# ---------------------------------------------------------------------------

class TestDetectionResultProperties:
    def test_gap_true_when_missed_rules_and_not_covered(self):
        dr = DetectionResult(
            technique_id="T1059.001",
            covered=False,
            missed_rules=[RuleBreakdown(
                "id", "title", "path", False, False, None, 0, None)],
        )
        assert dr.gap is True

    def test_gap_false_when_covered(self):
        dr = DetectionResult(
            technique_id="T1059.001",
            covered=True,
            fired_rules=[RuleBreakdown(
                "id", "title", "path", True, False, None, 1, None)],
        )
        assert dr.gap is False

    def test_gap_false_when_skip_only(self):
        # skip_only = no evaluable rules, so gap should be False
        dr = DetectionResult(
            technique_id="T1059.001",
            covered=False,
            skipped_rules=[RuleBreakdown(
                "id", "title", "path", False, True, "parse_error", 0, None)],
        )
        assert dr.gap is False
        assert dr.skip_only is True

    def test_skip_only_false_when_has_missed_rules(self):
        dr = DetectionResult(
            technique_id="T1059.001",
            covered=False,
            missed_rules=[RuleBreakdown(
                "id", "title", "path", False, False, None, 0, None)],
            skipped_rules=[RuleBreakdown(
                "id2", "title2", "path2", False, True, "err", 0, None)],
        )
        assert dr.skip_only is False

    def test_summary_contains_technique_id(self):
        dr = DetectionResult(technique_id="T1059.001", covered=True)
        assert "T1059.001" in dr.summary()

    def test_summary_contains_status(self):
        covered = DetectionResult(technique_id="T1059.001", covered=True)
        gap = DetectionResult(
            technique_id="T1059.001",
            covered=False,
            missed_rules=[RuleBreakdown(
                "id", "t", "p", False, False, None, 0, None)],
        )
        skip = DetectionResult(
            technique_id="T1059.001",
            covered=False,
            skipped_rules=[RuleBreakdown(
                "id", "t", "p", False, True, "err", 0, None)],
        )
        assert "COVERED" in covered.summary()
        assert "GAP" in gap.summary()
        assert "SKIP-ONLY" in skip.summary()


# ---------------------------------------------------------------------------
# 5. get_gaps / get_covered
# ---------------------------------------------------------------------------

class TestFilterHelpers:
    def _make_results(self) -> list[DetectionResult]:
        covered = DetectionResult(
            technique_id="T1059.001", covered=True,
            fired_rules=[RuleBreakdown(
                "id", "t", "p", True, False, None, 1, None)],
        )
        gap = DetectionResult(
            technique_id="T1547.001", covered=False,
            missed_rules=[RuleBreakdown(
                "id2", "t2", "p2", False, False, None, 0, None)],
        )
        skip_only = DetectionResult(
            technique_id="T1112", covered=False,
            skipped_rules=[RuleBreakdown(
                "id3", "t3", "p3", False, True, "err", 0, None)],
        )
        return [covered, gap, skip_only]

    def test_get_gaps_returns_only_gaps(self):
        results = self._make_results()
        gaps = get_gaps(results)
        assert len(gaps) == 1
        assert gaps[0].technique_id == "T1547.001"

    def test_get_gaps_excludes_skip_only(self):
        results = self._make_results()
        gaps = get_gaps(results)
        ids = {r.technique_id for r in gaps}
        assert "T1112" not in ids

    def test_get_covered_returns_only_covered(self):
        results = self._make_results()
        covered = get_covered(results)
        assert len(covered) == 1
        assert covered[0].technique_id == "T1059.001"

    def test_get_gaps_empty_input(self):
        assert get_gaps([]) == []

    def test_get_covered_empty_input(self):
        assert get_covered([]) == []
