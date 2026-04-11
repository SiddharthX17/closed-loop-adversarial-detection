"""
tests/test_validation_pipeline.py

Tests for pipeline/validation/validation_pipeline.py
Run from project root: pytest tests/test_validation_pipeline.py -v
"""

from pipeline.validation.validation_pipeline import ValidationResult, validate
from pipeline.emulator.log_builder import LogEvent
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_eid1_event(**kwargs) -> LogEvent:
    defaults = dict(
        timestamp="2024-01-01T10:00:00.000Z",
        host="WORKSTATION-01",
        user="jsmith",
        EventID=1,
        event_type="process_creation",
        Channel=SYSMON_CHANNEL,
        Image=r"C:\Windows\System32\cmd.exe",
        CommandLine="cmd.exe /c whoami",
        ParentImage=r"C:\Windows\explorer.exe",
        ParentCommandLine=r"C:\Windows\explorer.exe",
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


def _lint_pass():
    r = MagicMock()
    r.passed = True
    r.feedback = MagicMock(return_value=None)
    return r


def _lint_fail(feedback="Invalid field: BadField. Valid: Image, CommandLine"):
    r = MagicMock()
    r.passed = False
    r.feedback = MagicMock(return_value=feedback)  # callable
    return r


def _attack_pass():
    r = MagicMock()
    r.passed = True
    r.feedback = None
    r.skipped = False
    return r


def _attack_fail(feedback="Rule did not fire on attack sample"):
    r = MagicMock()
    r.passed = False
    r.feedback = feedback
    r.skipped = False
    return r


def _noise_pass(fp_rate=0.0, fp_count=0, total=100):
    r = MagicMock()
    r.passed = True
    r.feedback = None
    r.error = None
    r.fp_rate = fp_rate
    r.fp_count = fp_count
    r.total_events = total
    return r


def _noise_fail(fp_rate=0.06, fp_count=6, total=100, feedback="FP rate 6.0% exceeds threshold"):
    r = MagicMock()
    r.passed = False
    r.feedback = feedback
    r.error = None
    r.fp_rate = fp_rate
    r.fp_count = fp_count
    r.total_events = total
    return r


DUMMY_RULE = """
title: Test Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'cmd.exe'
    condition: selection
"""

# ---------------------------------------------------------------------------
# Gate 1 failure — schema_linter
# ---------------------------------------------------------------------------


class TestSchemaLinterGate:
    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    def test_fails_on_lint_failure(self, mock_lint, tmp_path):
        mock_lint.return_value = _lint_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.passed is False
        assert result.gate_failed == "schema_linter"

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    def test_feedback_propagated_from_linter(self, mock_lint, tmp_path):
        mock_lint.return_value = _lint_fail("Invalid field: BadField")
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.feedback == "Invalid field: BadField"

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    def test_attack_gate_not_called_on_lint_fail(self, mock_lint, tmp_path):
        mock_lint.return_value = _lint_fail()
        with patch("pipeline.validation.validation_pipeline.attack_gate.run") as mock_attack:
            validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
            mock_attack.assert_not_called()

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    def test_lint_passed_flag_set_false(self, mock_lint, tmp_path):
        mock_lint.return_value = _lint_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.lint_passed is False
        assert result.attack_passed is None
        assert result.noise_passed is None


# ---------------------------------------------------------------------------
# Gate 2 failure — attack_gate
# ---------------------------------------------------------------------------

class TestAttackGate:
    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_fails_on_attack_gate_failure(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.passed is False
        assert result.gate_failed == "attack_gate"

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_feedback_propagated_from_attack_gate(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_fail("Rule did not fire")
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.feedback == "Rule did not fire"

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_noise_gate_not_called_on_attack_fail(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_fail()
        with patch("pipeline.validation.validation_pipeline.noise_gate.run") as mock_noise:
            validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
            mock_noise.assert_not_called()

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_lint_passed_attack_failed_flags(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.lint_passed is True
        assert result.attack_passed is False
        assert result.noise_passed is None

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_attack_gate_receives_dicts_not_log_events(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_fail()
        validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        call_args = mock_attack.call_args
        sample_passed = call_args[0][1]
        assert isinstance(sample_passed, list)
        assert all(isinstance(e, dict) for e in sample_passed)

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    def test_attack_gate_skipped_rule_returns_failure(self, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        skipped_result = _attack_fail(
            "Rule could not be executed: unsupported_modifier: base64offset")
        mock_attack.return_value = skipped_result
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.passed is False
        assert result.gate_failed == "attack_gate"
        assert "could not be executed" in result.feedback.lower()


# ---------------------------------------------------------------------------
# Gate 3 failure — noise_gate
# ---------------------------------------------------------------------------

class TestNoiseGate:
    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_fails_on_noise_gate_failure(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.passed is False
        assert result.gate_failed == "noise_gate"

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_fp_metrics_populated_on_noise_fail(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_fail(
            fp_rate=0.06, fp_count=6, total=100)
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.fp_rate == 0.06
        assert result.fp_count == 6
        assert result.total_benign == 100

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_all_flags_set_on_noise_fail(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_fail()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.lint_passed is True
        assert result.attack_passed is True
        assert result.noise_passed is False


# ---------------------------------------------------------------------------
# Full pass
# ---------------------------------------------------------------------------

class TestFullPass:
    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_passes_when_all_gates_pass(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_pass()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.passed is True
        assert result.gate_failed is None
        assert result.feedback is None

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_all_flags_true_on_pass(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_pass()
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.lint_passed is True
        assert result.attack_passed is True
        assert result.noise_passed is True

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_fp_metrics_populated_on_pass(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_pass(
            fp_rate=0.005, fp_count=1, total=200)
        result = validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        assert result.fp_rate == 0.005
        assert result.fp_count == 1
        assert result.total_benign == 200

    @patch("pipeline.validation.validation_pipeline.schema_linter.validate")
    @patch("pipeline.validation.validation_pipeline.attack_gate.run")
    @patch("pipeline.validation.validation_pipeline.noise_gate.run")
    def test_all_three_gates_called_on_pass(self, mock_noise, mock_attack, mock_lint, tmp_path):
        mock_lint.return_value = _lint_pass()
        mock_attack.return_value = _attack_pass()
        mock_noise.return_value = _noise_pass()
        validate(DUMMY_RULE, [_make_eid1_event()], tmp_path)
        mock_lint.assert_called_once()
        mock_attack.assert_called_once()
        mock_noise.assert_called_once()


def test_integration_real_linter_rejects_bad_field(tmp_path):
    bad_rule = """
title: Bad Field Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NonExistentField|contains: 'malware.exe'
    condition: selection
"""
    from pipeline.emulator.log_builder import LogEvent
    result = validate(
        bad_rule,
        [_make_eid1_event()],
        tmp_path,
        supplement_with_generated=False,
    )
    assert result.passed is False
    assert result.gate_failed == "schema_linter"
