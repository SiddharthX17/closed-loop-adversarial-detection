"""
attack_gate.py — Attack gate for candidate Sigma rule validation
================================================================
Path: closed-loop-adversarial-detection/pipeline/validation/attack_gate.py

One line: Runs the candidate rule against emulated attack logs and asserts
it fires — if the rule can't detect the attack it was written for, it never
reaches the noise gate.

Design notes
------------
- Delegates evaluation entirely to DetectionEngine.run_single_rule
- Engine owns the events; run_single_rule uses self.events by default
- empty_input checked explicitly before engine construction
- min_match_ratio only enforced when > 0.0, made explicit via use_ratio flag
- Division guard removed — total > 0 guaranteed by empty_input check
- Unmatched events computed by content comparison (JSON hash), not object
  identity — matched_events from engine are new dict objects reconstructed
  from sqlite3 rows, so id() comparison always fails
- Feedback includes ALL unmatched events (capped at UNMATCHED_FEEDBACK_CAP)
  so the defender agent has concrete patterns to improve against, not just
  a scalar metric
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pipeline.detection.engine import DetectionEngine, RuleMatchResult

logger = logging.getLogger(__name__)

_DEBUG = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")

# Max unmatched events to include in feedback string —
# enough for the defender agent to identify patterns without blowing token budget
UNMATCHED_FEEDBACK_CAP = 5


# ---------------------------------------------------------------------------
# Content-based event hashing (same approach as result_parser._event_hash)
# ---------------------------------------------------------------------------

def _event_hash(event: dict) -> str:
    """Stable content hash for deduplication/comparison. Not crypto."""
    serialised = json.dumps(event, sort_keys=True, default=str)
    return hashlib.md5(serialised.encode()).hexdigest()  # noqa: S324


def _find_unmatched(
    attack_sample: list[dict],
    matched_events: list[dict],
) -> list[dict]:
    """
    Return events from attack_sample whose content does not appear in
    matched_events.

    Uses content hash comparison — matched_events are new dict objects
    reconstructed from sqlite3 rows.
    """
    matched_hashes = {_event_hash(e) for e in matched_events}
    return [e for e in attack_sample if _event_hash(e) not in matched_hashes]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """
    passed           : True if rule met both count and ratio thresholds
    match_count      : events the rule fired on
    total_events     : total events in the attack sample
    match_ratio      : match_count / total_events
    matched_events   : events that triggered a match
    unmatched_events : events that did NOT match (content-compared)
    skipped          : True if evaluation could not run
    skip_reason      : empty_input / parse_error / conversion_error /
                       execution_error / no_query_generated
    rule_result      : raw RuleMatchResult for traceability
    """
    passed: bool
    match_count: int = 0
    total_events: int = 0
    match_ratio: float = 0.0
    matched_events: list[dict] = field(default_factory=list)
    unmatched_events: list[dict] = field(default_factory=list)
    skipped: bool = False
    skip_reason: Optional[str] = None
    rule_result: Optional[RuleMatchResult] = None

    def feedback(self) -> str:
        """
        Feedback for defender agent retry prompt.

        Includes all unmatched events (up to UNMATCHED_FEEDBACK_CAP) so the
        agent has concrete patterns to target, not just a scalar metric.
        """
        if self.skipped:
            return f"Attack gate could not evaluate rule: {self.skip_reason}"

        if self.passed:
            return (
                f"Attack gate passed — rule fired on {self.match_count} "
                f"of {self.total_events} attack events "
                f"({self.match_ratio:.0%} match rate)."
            )

        # Build unmatched event summary for agent context
        unmatched_summary = _format_unmatched(self.unmatched_events)

        if self.match_count == 0:
            return (
                f"Attack gate failed — rule did not fire on any of the "
                f"{self.total_events} attack events. "
                f"Broaden the detection conditions "
                f"the following unmatched patterns:\n{unmatched_summary}"
            )

        # Partial match
        return (
            f"Attack gate failed — rule fired on {self.match_count} of "
            f"{self.total_events} attack events ({self.match_ratio:.0%}), "
            f"below the required threshold. "
            f"Broaden the detection conditions "
            f"without removing existing conditions:\n{unmatched_summary}"
        )


def _format_unmatched(unmatched_events: list[dict]) -> str:
    """
    Format unmatched events as a compact list for the defender agent prompt.
    Capped at UNMATCHED_FEEDBACK_CAP. Shows key fields only to stay token-efficient.
    """
    if not unmatched_events:
        return "  (no unmatched event details available)"

    key_fields = ("Image", "CommandLine", "ParentImage", "TargetObject",
                  "DestinationIp", "DestinationHostname", "EventID")
    cap = UNMATCHED_FEEDBACK_CAP
    shown = unmatched_events[:cap]
    lines = []
    for i, event in enumerate(shown, 1):
        parts = {k: event[k] for k in key_fields if event.get(k)}
        lines.append(f"  [{i}] {parts}")
    if len(unmatched_events) > cap:
        lines.append(
            f"  ... and {len(unmatched_events) - cap} more unmatched events")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core gate function
# ---------------------------------------------------------------------------

def run(
    rule_yaml: str,
    attack_sample: list[dict],
    *,
    min_match_count: int = 1,
    min_match_ratio: float = 0.0,
) -> GateResult:
    """
    Evaluate a candidate Sigma rule against an attack log sample.

    Parameters
    ----------
    rule_yaml       : candidate Sigma rule YAML string
    attack_sample   : emulated attack events for the target technique
    min_match_count : minimum events rule must fire on. Default 1.
    min_match_ratio : minimum matched/total ratio (0.0 = disabled).
    """
    # --- Empty input checks ----------------------------------------------
    if not attack_sample:
        logger.warning("Attack gate called with empty attack sample")
        return GateResult(
            passed=False,
            skipped=True,
            skip_reason="empty_input: attack sample is empty",
        )

    if not rule_yaml or not rule_yaml.strip():
        logger.warning("Attack gate called with empty rule YAML")
        return GateResult(
            passed=False,
            skipped=True,
            skip_reason="empty_input: rule YAML is empty",
        )

    total = len(attack_sample)

    # --- Evaluate --------------------------------------------------------
    engine = DetectionEngine(rules_dir=Path("."), events=attack_sample)
    rule_result = engine.run_single_rule(rule_yaml)

    if _DEBUG:
        logger.debug(
            "Attack gate engine result: fired=%s skipped=%s matches=%d skip_reason=%s",
            rule_result.fired, rule_result.skipped,
            len(rule_result.matched_events), rule_result.skip_reason,
        )

    # --- Engine-level failure --------------------------------------------
    if rule_result.skipped:
        logger.warning("Attack gate skipped — engine error: %s",
                       rule_result.skip_reason)
        return GateResult(
            passed=False,
            total_events=total,
            skipped=True,
            skip_reason=rule_result.skip_reason,
            rule_result=rule_result,
        )

    # --- Unmatched events (content-based, not identity-based) ------------
    match_count = len(rule_result.matched_events)
    unmatched = _find_unmatched(attack_sample, rule_result.matched_events)
    match_ratio = match_count / total  # total > 0 guaranteed above

    # --- Threshold evaluation --------------------------------------------
    count_ok = match_count >= min_match_count
    use_ratio = min_match_ratio > 0.0
    ratio_ok = (match_ratio >= min_match_ratio) if use_ratio else True
    passed = count_ok and ratio_ok

    if passed:
        logger.info(
            "Attack gate PASS — %d/%d events matched (%.0f%%)",
            match_count, total, match_ratio * 100,
        )
    else:
        logger.info(
            "Attack gate FAIL — %d/%d events matched (%.0f%%) | "
            "required count>=%d%s",
            match_count, total, match_ratio * 100, min_match_count,
            f" ratio>={min_match_ratio:.0%}" if use_ratio else "",
        )

    return GateResult(
        passed=passed,
        match_count=match_count,
        total_events=total,
        match_ratio=match_ratio,
        matched_events=rule_result.matched_events,
        unmatched_events=unmatched,
        skipped=False,
        rule_result=rule_result,
    )
