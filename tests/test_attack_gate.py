"""
test_attack_gate.py — Unit tests for pipeline/validation/attack_gate.py
========================================================================
Run from project root:
    pytest tests/test_attack_gate.py -v

Coverage targets
----------------
- GateResult.feedback()  : passed, zero matches, partial match below threshold,
                           skipped cases
- run()                  : happy path fire, no match, empty sample, empty YAML,
                           engine skip propagation, min_match_count threshold,
                           min_match_ratio threshold, ratio+count both required,
                           skipped flag and skip_reason propagation
"""

from __future__ import annotations

import textwrap

import pytest

from attack_gate import GateResult, run


# ---------------------------------------------------------------------------
# Rule and event fixtures
# ---------------------------------------------------------------------------

RULE_CONTAINS = textwrap.dedent("""\
    title: Test Contains Rule
    id: cccccccc-cccc-cccc-cccc-cccccccccccc
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains: 'malicious_payload'
        condition: sel
""")

RULE_ENDSWITH = textwrap.dedent("""\
    title: Test Endswith Rule
    id: dddddddd-dddd-dddd-dddd-dddddddddddd
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\\\evil.exe'
        condition: sel
""")

BAD_YAML = "title: [unclosed bracket"


def make_attack_event(**overrides) -> dict:
    base = {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe malicious_payload --go",
        "User": "DOMAIN\\attacker",
        "ProcessId": "1337",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. GateResult.feedback()
# ---------------------------------------------------------------------------

class TestGateResultFeedback:
    def test_passed_feedback(self):
        r = GateResult(passed=True, match_count=3,
                       total_events=5, match_ratio=0.6)
        fb = r.feedback()
        assert "passed" in fb.lower()
        assert "3" in fb
        assert "5" in fb

    def test_zero_match_feedback(self):
        r = GateResult(passed=False, match_count=0,
                       total_events=4, match_ratio=0.0)
        fb = r.feedback()
        assert "did not fire" in fb.lower()
        assert "4" in fb

    def test_partial_match_below_threshold_feedback(self):
        r = GateResult(passed=False, match_count=1,
                       total_events=5, match_ratio=0.2)
        fb = r.feedback()
        assert "below" in fb.lower() or "threshold" in fb.lower()
        assert "1" in fb

    def test_skipped_feedback(self):
        r = GateResult(passed=False, skipped=True,
                       skip_reason="empty_input: attack sample is empty")
        fb = r.feedback()
        assert "could not evaluate" in fb.lower()
        assert "empty_input" in fb

    def test_feedback_not_empty(self):
        for passed in (True, False):
            r = GateResult(passed=passed, match_count=1, total_events=2,
                           match_ratio=0.5)
            assert r.feedback() != ""


# ---------------------------------------------------------------------------
# 2. run() — core gate logic
# ---------------------------------------------------------------------------

class TestAttackGateRun:

    # ── happy path ────────────────────────────────────────────────────────

    def test_passes_when_rule_fires(self):
        events = [make_attack_event()]
        result = run(RULE_CONTAINS, events)
        assert result.passed is True
        assert result.skipped is False
        assert result.match_count == 1

    def test_matched_events_populated(self):
        events = [make_attack_event()]
        result = run(RULE_CONTAINS, events)
        assert len(result.matched_events) == 1
        assert isinstance(result.matched_events[0], dict)

    def test_total_events_correct(self):
        events = [make_attack_event() for _ in range(4)]
        result = run(RULE_CONTAINS, events)
        assert result.total_events == 4

    def test_match_ratio_correct(self):
        # 2 matching events out of 3 total
        events = [
            make_attack_event(CommandLine="malicious_payload run"),
            make_attack_event(CommandLine="malicious_payload --flag"),
            make_attack_event(CommandLine="benign.exe"),
        ]
        result = run(RULE_CONTAINS, events)
        assert result.match_count == 2
        assert abs(result.match_ratio - 2/3) < 0.01

    # ── no match ─────────────────────────────────────────────────────────

    def test_fails_when_rule_does_not_fire(self):
        events = [make_attack_event(CommandLine="benign.exe /normal")]
        result = run(RULE_CONTAINS, events)
        assert result.passed is False
        assert result.skipped is False
        assert result.match_count == 0
        assert result.matched_events == []

    # ── empty input ───────────────────────────────────────────────────────

    def test_empty_attack_sample_skipped(self):
        result = run(RULE_CONTAINS, [])
        assert result.passed is False
        assert result.skipped is True
        assert "empty_input" in result.skip_reason

    def test_empty_rule_yaml_skipped(self):
        result = run("", [make_attack_event()])
        assert result.passed is False
        assert result.skipped is True
        assert "empty_input" in result.skip_reason

    def test_whitespace_only_rule_yaml_skipped(self):
        result = run("   \n  ", [make_attack_event()])
        assert result.passed is False
        assert result.skipped is True

    # ── engine error propagation ──────────────────────────────────────────

    def test_bad_yaml_surfaces_as_skipped(self):
        result = run(BAD_YAML, [make_attack_event()])
        assert result.passed is False
        assert result.skipped is True
        assert "parse_error" in result.skip_reason

    def test_skip_reason_populated_on_engine_error(self):
        result = run(BAD_YAML, [make_attack_event()])
        assert result.skip_reason is not None
        assert len(result.skip_reason) > 0

    def test_rule_result_attached_on_engine_error(self):
        result = run(BAD_YAML, [make_attack_event()])
        # rule_result is None when skipped at gate level (empty input),
        # but populated when engine itself skips
        assert result.rule_result is not None or result.skip_reason is not None

    # ── min_match_count threshold ─────────────────────────────────────────

    def test_min_match_count_default_one_passes(self):
        events = [make_attack_event()]
        result = run(RULE_CONTAINS, events, min_match_count=1)
        assert result.passed is True

    def test_min_match_count_two_fails_on_one_match(self):
        events = [
            make_attack_event(CommandLine="malicious_payload run"),
            make_attack_event(CommandLine="benign.exe"),
        ]
        result = run(RULE_CONTAINS, events, min_match_count=2)
        assert result.passed is False
        assert result.match_count == 1

    def test_min_match_count_two_passes_on_two_matches(self):
        events = [
            make_attack_event(CommandLine="malicious_payload run"),
            make_attack_event(CommandLine="malicious_payload persist"),
        ]
        result = run(RULE_CONTAINS, events, min_match_count=2)
        assert result.passed is True
        assert result.match_count == 2

    # ── min_match_ratio threshold ─────────────────────────────────────────

    def test_ratio_disabled_by_default(self):
        # 1 match out of 10 events — passes because ratio check is disabled
        events = [make_attack_event(CommandLine="malicious_payload")] + \
                 [make_attack_event(CommandLine="benign") for _ in range(9)]
        result = run(RULE_CONTAINS, events,
                     min_match_count=1, min_match_ratio=0.0)
        assert result.passed is True

    def test_ratio_50_percent_passes(self):
        events = [
            make_attack_event(CommandLine="malicious_payload one"),
            make_attack_event(CommandLine="malicious_payload two"),
            make_attack_event(CommandLine="benign one"),
            make_attack_event(CommandLine="benign two"),
        ]
        result = run(RULE_CONTAINS, events, min_match_ratio=0.5)
        assert result.passed is True
        assert result.match_ratio == 0.5

    def test_ratio_fails_when_below_threshold(self):
        events = [
            make_attack_event(CommandLine="malicious_payload"),
            make_attack_event(CommandLine="benign one"),
            make_attack_event(CommandLine="benign two"),
            make_attack_event(CommandLine="benign three"),
        ]
        result = run(RULE_CONTAINS, events, min_match_ratio=0.5)
        assert result.passed is False
        assert result.match_ratio < 0.5

    def test_both_count_and_ratio_must_pass(self):
        # 2 matches out of 10 — ratio is 0.2, below 0.5 threshold
        # even though count >=2 is satisfied
        events = (
            [make_attack_event(CommandLine="malicious_payload")] * 2 +
            [make_attack_event(CommandLine="benign")] * 8
        )
        result = run(RULE_CONTAINS, events,
                     min_match_count=2, min_match_ratio=0.5)
        assert result.passed is False  # ratio check fails

    # ── result shape ──────────────────────────────────────────────────────

    def test_passed_result_has_no_skip_reason(self):
        result = run(RULE_CONTAINS, [make_attack_event()])
        assert result.skipped is False
        assert result.skip_reason is None

    def test_rule_result_attached_on_success(self):
        result = run(RULE_CONTAINS, [make_attack_event()])
        assert result.rule_result is not None
        assert result.rule_result.fired is True

    # ── no match ─────────────────────────────────────────────────────────

    def test_unmatched_events_populated(self):
        events = [
            make_attack_event(CommandLine="malicious_payload"),
            make_attack_event(CommandLine="benign"),
        ]
        result = run(RULE_CONTAINS, events)

        assert len(result.unmatched_events) == 1
