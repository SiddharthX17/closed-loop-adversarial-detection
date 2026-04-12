"""
metrics/tracker.py

Tracks detection coverage, precision, recall, and FP rate
per technique per iteration. Consumes DetectionResult objects
from result_parser and ValidationResult objects from validation_pipeline.

Writes a timestamped JSON report to corpus/attack/stats/ on request.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TechniqueMetrics:
    technique_id:   str
    iteration:      int
    covered:        bool            # at least one passing rule exists
    rules_evaluated: int            # total rules run against this technique
    rules_fired:    int             # rules that matched at least one event
    total_events:   int             # emulated attack events for technique
    # attack events caught by any rule - is summed across all rules, so the same event matched by 3 rules contributes 3 to the count. This inflates recall.
    matched_events: int
    missed_events:  int             # attack events not caught by any rule
    # fired events that were attack / total fired - currently a rule-level proxy, not true event-level precision.
    precision:      Optional[float]
    # attack events caught / total attack events
    recall:         Optional[float]
    # from noise gate (None if not yet validated)
    fp_rate:        Optional[float]
    fp_count:       Optional[int] = None
    total_benign:   Optional[int] = None
    # gate that blocked a candidate rule
    validation_gate_failed: Optional[str] = None


@dataclass
class IterationReport:
    iteration:          int
    timestamp:          str
    techniques:         list[TechniqueMetrics] = field(default_factory=list)

    # Aggregate across all techniques this iteration
    total_techniques:   int = 0
    covered_techniques: int = 0
    coverage_rate:      float = 0.0
    mean_recall:        float = 0.0
    mean_fp_rate:       float = 0.0


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class MetricsTracker:
    """
    Accumulates per-technique metrics across iterations.
    Call record_detection() after each technique's detection run.
    Call record_validation() after the defender agent validates a candidate rule.
    Call finalise_iteration() to compute aggregates and optionally write to disk.
    """

    def __init__(self) -> None:
        # iteration → technique_id → TechniqueMetrics
        self._data: dict[int, dict[str, TechniqueMetrics]] = {}
        self._current_iteration: int = 1

    # ------------------------------------------------------------------
    # Iteration control
    # ------------------------------------------------------------------

    def set_iteration(self, iteration: int) -> None:
        self._current_iteration = iteration
        if iteration not in self._data:
            self._data[iteration] = {}

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_detection(
        self,
        technique_id: str,
        *,
        rules_evaluated: int,
        rules_fired: int,
        total_events: int,
        matched_events: int,
        iteration: Optional[int] = None,
    ) -> TechniqueMetrics:
        """
        Record detection layer results for a technique.
        Computes precision and recall from raw counts.

        precision = matched_events / (matched_events + phantom_fires)
        Here we approximate: rules that fired / rules evaluated as a
        rule-level precision proxy until we have per-event fired tallies.

        recall = matched_events / total_events
        """
        it = iteration if iteration is not None else self._current_iteration
        if it not in self._data:
            self._data[it] = {}

        missed = total_events - matched_events
        recall = matched_events / total_events if total_events > 0 else None
        # Rule-level precision: proportion of evaluated rules that fired
        precision = rules_fired / rules_evaluated if rules_evaluated > 0 else None

        metrics = TechniqueMetrics(
            technique_id=technique_id,
            iteration=it,
            covered=rules_fired > 0,
            rules_evaluated=rules_evaluated,
            rules_fired=rules_fired,
            total_events=total_events,
            matched_events=matched_events,
            missed_events=missed,
            precision=precision,
            recall=recall,
            fp_rate=None,
        )
        self._data[it][technique_id] = metrics

        debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")
        if debug:
            print(
                f"[tracker] it={it} {technique_id}: "
                f"covered={metrics.covered} recall={recall} precision={precision}"
            )

        return metrics

    def record_validation(
        self,
        technique_id: str,
        *,
        fp_rate: Optional[float],
        fp_count: Optional[int] = None,
        total_benign: Optional[int] = None,
        gate_failed: Optional[str] = None,
        iteration: Optional[int] = None,
    ) -> None:
        """
        Attach noise gate / validation pipeline results to an existing
        TechniqueMetrics entry. Call after validate() returns.
        """
        it = iteration if iteration is not None else self._current_iteration
        if it not in self._data or technique_id not in self._data[it]:
            return  # no detection record to attach to — silently skip

        m = self._data[it][technique_id]
        m.fp_rate = fp_rate
        m.fp_count = fp_count
        m.total_benign = total_benign
        m.validation_gate_failed = gate_failed

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def finalise_iteration(
        self,
        iteration: Optional[int] = None,
        output_dir: Optional[Path] = None,
    ) -> IterationReport:
        """
        Compute iteration-level aggregates and optionally write JSON report.

        Args:
            iteration:  Iteration to finalise. Defaults to current.
            output_dir: If provided, writes report to
                        output_dir/metrics_it{N}_{timestamp}.json
                        Pass None to suppress file writes (test isolation).

        Returns:
            IterationReport
        """
        it = iteration if iteration is not None else self._current_iteration
        technique_list = list((self._data.get(it) or {}).values())

        total = len(technique_list)
        covered = sum(1 for m in technique_list if m.covered)
        coverage_rate = covered / total if total > 0 else 0.0

        recalls = [m.recall for m in technique_list if m.recall is not None]
        mean_recall = sum(recalls) / len(recalls) if recalls else 0.0

        total_fp = sum(
            m.fp_count for m in technique_list if m.fp_count is not None)
        total_benign = sum(
            m.total_benign for m in technique_list if m.total_benign is not None)
        mean_fp = total_fp / total_benign if total_benign > 0 else 0.0

        report = IterationReport(
            iteration=it,
            timestamp=datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            techniques=technique_list,
            total_techniques=total,
            covered_techniques=covered,
            coverage_rate=coverage_rate,
            mean_recall=mean_recall,
            mean_fp_rate=mean_fp,
        )

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
            out_path = output_dir / f"metrics_it{it}_{ts}.json"
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(_report_to_dict(report), fh, indent=2)

            debug = os.environ.get(
                "PIPELINE_DEBUG", "").lower() in ("1", "true")
            if debug:
                print(f"[tracker] wrote metrics report → {out_path}")

        return report

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_technique(
        self, technique_id: str, iteration: Optional[int] = None
    ) -> Optional[TechniqueMetrics]:
        it = iteration if iteration is not None else self._current_iteration
        return (self._data.get(it) or {}).get(technique_id)

    def get_covered_techniques(self, iteration: Optional[int] = None) -> list[str]:
        it = iteration if iteration is not None else self._current_iteration
        return [
            tid for tid, m in (self._data.get(it) or {}).items() if m.covered
        ]

    def get_uncovered_techniques(self, iteration: Optional[int] = None) -> list[str]:
        it = iteration if iteration is not None else self._current_iteration
        return [
            tid for tid, m in (self._data.get(it) or {}).items() if not m.covered
        ]

    def coverage_increased(self, from_iteration: int, to_iteration: int) -> bool:
        """
        Returns True if covered technique count increased between iterations.
        Used by orchestrator to evaluate run success criterion.
        """
        prev = len(self.get_covered_techniques(from_iteration))
        curr = len(self.get_covered_techniques(to_iteration))
        return curr > prev


# ---------------------------------------------------------------------------
# Serialisation helper
# ---------------------------------------------------------------------------

def _report_to_dict(report: IterationReport) -> dict:
    d = asdict(report)
    # Round floats for readability
    for tech in d.get("techniques", []):
        for key in ("precision", "recall", "fp_rate"):
            if tech.get(key) is not None:
                tech[key] = round(tech[key], 4)
    d["coverage_rate"] = round(d["coverage_rate"], 4)
    d["mean_recall"] = round(d["mean_recall"], 4)
    d["mean_fp_rate"] = round(d["mean_fp_rate"], 4)
    return d
