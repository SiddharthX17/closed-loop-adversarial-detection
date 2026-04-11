"""
tests/test_tracker.py

Tests for pipeline/metrics/tracker.py
Run from project root: pytest tests/test_tracker.py -v
"""

from pipeline.metrics.tracker import MetricsTracker, TechniqueMetrics, IterationReport
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tracker_with_detection(technique_id="T1059.001", **kwargs) -> MetricsTracker:
    t = MetricsTracker()
    defaults = dict(
        rules_evaluated=5,
        rules_fired=2,
        total_events=10,
        matched_events=8,
    )
    defaults.update(kwargs)
    t.record_detection(technique_id, **defaults)
    return t


# ---------------------------------------------------------------------------
# record_detection
# ---------------------------------------------------------------------------

class TestRecordDetection:
    def test_returns_technique_metrics(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5,
            rules_fired=3,
            total_events=10,
            matched_events=8,
        )
        assert isinstance(m, TechniqueMetrics)

    def test_covered_true_when_rules_fired(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5, rules_fired=1,
            total_events=10, matched_events=5,
        )
        assert m.covered is True

    def test_covered_false_when_no_rules_fired(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5, rules_fired=0,
            total_events=10, matched_events=0,
        )
        assert m.covered is False

    def test_recall_computed_correctly(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5, rules_fired=2,
            total_events=10, matched_events=7,
        )
        assert abs(m.recall - 0.7) < 0.001

    def test_recall_none_when_no_events(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5, rules_fired=0,
            total_events=0, matched_events=0,
        )
        assert m.recall is None

    def test_precision_computed_correctly(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=4, rules_fired=2,
            total_events=10, matched_events=8,
        )
        assert abs(m.precision - 0.5) < 0.001

    def test_missed_events_computed(self):
        t = MetricsTracker()
        m = t.record_detection(
            "T1059.001",
            rules_evaluated=5, rules_fired=2,
            total_events=10, matched_events=6,
        )
        assert m.missed_events == 4

    def test_fp_rate_none_until_validation_recorded(self):
        t = _tracker_with_detection()
        m = t.get_technique("T1059.001")
        assert m.fp_rate is None

    def test_multiple_techniques_stored_independently(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=2, total_events=10, matched_events=8)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=0, total_events=5, matched_events=0)
        assert t.get_technique("T1059.001").covered is True
        assert t.get_technique("T1547.001").covered is False


# ---------------------------------------------------------------------------
# record_validation
# ---------------------------------------------------------------------------

class TestRecordValidation:
    def test_attaches_fp_rate(self):
        t = _tracker_with_detection()
        t.record_validation("T1059.001", fp_rate=0.02,
                            fp_count=2, total_benign=100)
        m = t.get_technique("T1059.001")
        assert m.fp_rate == 0.02

    def test_attaches_gate_failed(self):
        t = _tracker_with_detection()
        t.record_validation("T1059.001", fp_rate=0.07,
                            gate_failed="noise_gate")
        m = t.get_technique("T1059.001")
        assert m.validation_gate_failed == "noise_gate"

    def test_silently_skips_unknown_technique(self):
        t = MetricsTracker()
        # Should not raise
        t.record_validation("T9999.999", fp_rate=0.01)

    def test_silently_skips_unknown_iteration(self):
        t = _tracker_with_detection()
        t.record_validation("T1059.001", fp_rate=0.01, iteration=99)


# ---------------------------------------------------------------------------
# finalise_iteration
# ---------------------------------------------------------------------------

class TestFinaliseIteration:
    def test_returns_iteration_report(self):
        t = _tracker_with_detection()
        report = t.finalise_iteration(output_dir=None)
        assert isinstance(report, IterationReport)

    def test_coverage_rate_computed(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=2, total_events=10, matched_events=8)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=0, total_events=5, matched_events=0)
        report = t.finalise_iteration(output_dir=None)
        assert report.total_techniques == 2
        assert report.covered_techniques == 1
        assert abs(report.coverage_rate - 0.5) < 0.001

    def test_mean_recall_computed(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=2, total_events=10, matched_events=8)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=1, total_events=10, matched_events=6)
        report = t.finalise_iteration(output_dir=None)
        assert abs(report.mean_recall - 0.7) < 0.001

    def test_mean_fp_rate_excludes_none(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=2, total_events=10, matched_events=8)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=1, total_events=10, matched_events=6)
        t.record_validation("T1059.001", fp_rate=0.02)
        # T1547.001 has no fp_rate — should not factor into mean
        report = t.finalise_iteration(output_dir=None)
        assert abs(report.mean_fp_rate - 0.02) < 0.001

    def test_output_dir_none_no_files_written(self, tmp_path):
        t = _tracker_with_detection()
        t.finalise_iteration(output_dir=None)
        assert not any(tmp_path.iterdir())

    def test_output_dir_writes_json(self, tmp_path):
        t = _tracker_with_detection()
        t.finalise_iteration(output_dir=tmp_path)
        files = list(tmp_path.glob("metrics_it*.json"))
        assert len(files) == 1

    def test_written_json_is_valid(self, tmp_path):
        t = _tracker_with_detection("T1059.001")
        t.record_validation("T1059.001", fp_rate=0.01,
                            fp_count=1, total_benign=100)
        t.finalise_iteration(output_dir=tmp_path)
        f = list(tmp_path.glob("metrics_it*.json"))[0]
        data = json.loads(f.read_text())
        assert "techniques" in data
        assert data["covered_techniques"] == 1

    def test_empty_iteration_returns_zero_coverage(self):
        t = MetricsTracker()
        report = t.finalise_iteration(output_dir=None)
        assert report.coverage_rate == 0.0
        assert report.total_techniques == 0


# ---------------------------------------------------------------------------
# Accessors and coverage_increased
# ---------------------------------------------------------------------------

class TestAccessors:
    def test_get_covered_techniques(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=1, total_events=10, matched_events=5)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=0, total_events=5, matched_events=0)
        assert t.get_covered_techniques() == ["T1059.001"]

    def test_get_uncovered_techniques(self):
        t = MetricsTracker()
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=1, total_events=10, matched_events=5)
        t.record_detection("T1547.001", rules_evaluated=3,
                           rules_fired=0, total_events=5, matched_events=0)
        assert t.get_uncovered_techniques() == ["T1547.001"]

    def test_coverage_increased_true(self):
        t = MetricsTracker()
        t.set_iteration(1)
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=0, total_events=10, matched_events=0)
        t.set_iteration(2)
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=1, total_events=10, matched_events=5)
        assert t.coverage_increased(from_iteration=1, to_iteration=2) is True

    def test_coverage_increased_false_when_same(self):
        t = MetricsTracker()
        t.set_iteration(1)
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=1, total_events=10, matched_events=5)
        t.set_iteration(2)
        t.record_detection("T1059.001", rules_evaluated=5,
                           rules_fired=1, total_events=10, matched_events=5)
        assert t.coverage_increased(from_iteration=1, to_iteration=2) is False

    def test_get_technique_returns_none_for_unknown(self):
        t = MetricsTracker()
        assert t.get_technique("T9999.999") is None
