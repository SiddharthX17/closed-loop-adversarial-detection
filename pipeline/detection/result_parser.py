"""
result_parser.py — Detection result structuring
================================================
Path: closed-loop-adversarial-detection/pipeline/detection/result_parser.py

Responsibilities
----------------
- Accept a list of RuleMatchResult objects from DetectionEngine.run()
- Extract technique ID from each rule's filename (Option B convention:
  T1059.001-description.yml → T1059.001)
- Group results by technique ID
- Produce one DetectionResult per technique summarising coverage,
  matched events, missed events, and per-rule breakdown
- Flag rules that skipped (execution/parse/conversion errors) separately
  from rules that ran cleanly but produced no match

This is the contract the defender agent reads in Phase 3 to understand
where gaps are and what evidence exists for each missed technique.

Technique ID extraction
-----------------------
Rule filenames must follow the convention:
    {technique_id}-{description}.yml
    e.g. T1059.001-encoded-powershell.yml
         T1547.001-registry-run-keys.yml

Subtechnique IDs (T1059.001) and base technique IDs (T1059) both supported.
Rules whose filenames don't match this pattern are grouped under
technique_id="UNKNOWN" and logged as a warning.

Design notes
------------
- DetectionResult.covered = True if at least one rule fired cleanly
- A technique with only skipped rules is NOT considered covered —
  skipped rules tell us nothing about actual detection capability
- matched_events across all fired rules are deduplicated by event content
  to avoid the defender agent seeing the same event multiple times
- per_rule_breakdown preserves the full RuleMatchResult for traceability
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from engine import RuleMatchResult

logger = logging.getLogger(__name__)

# Matches T1059, T1059.001, T1059.001.002 at the start of a filename
_TECHNIQUE_ID_PATTERN = re.compile(r"^(T\d{4}(?:\.\d{3}){0,2})", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RuleBreakdown:
    """
    Per-rule summary within a DetectionResult.
    Preserves enough detail for the defender agent to understand
    what each rule did and why it succeeded or failed.
    """
    rule_id: str
    rule_title: str
    rule_path: str
    fired: bool
    skipped: bool
    skip_reason: Optional[str]
    match_count: int
    sql_query: Optional[str]


@dataclass
class DetectionResult:
    """
    Per-technique detection summary.

    covered         : True if at least one rule fired cleanly on attack events
    technique_id    : ATT&CK technique ID extracted from rule filename
    fired_rules     : rules that produced at least one match
    missed_rules    : rules that ran cleanly but matched nothing
    skipped_rules   : rules that could not be parsed, converted, or executed
    matched_events  : deduplicated union of events matched by any fired rule
    total_rules     : total rules evaluated for this technique
    gap             : True if technique has rules but none fired — primary
                      signal for defender agent to generate a candidate rule
    """
    technique_id: str
    covered: bool
    fired_rules: list[RuleBreakdown] = field(default_factory=list)
    missed_rules: list[RuleBreakdown] = field(default_factory=list)
    skipped_rules: list[RuleBreakdown] = field(default_factory=list)
    matched_events: list[dict] = field(default_factory=list)
    total_rules: int = 0

    @property
    def gap(self) -> bool:
        """
        True when the technique has evaluable rules but none fired.
        Skipped-only techniques are also gaps — we can't claim coverage
        if rules never executed.
        """
        has_evaluable = bool(self.fired_rules or self.missed_rules)
        return has_evaluable and not self.covered

    @property
    def skip_only(self) -> bool:
        """True when every rule for this technique was skipped."""
        return bool(self.skipped_rules) and not self.fired_rules and not self.missed_rules

    def summary(self) -> str:
        status = "COVERED" if self.covered else (
            "GAP" if self.gap else "SKIP-ONLY")
        return (
            f"[{self.technique_id}] {status} | "
            f"rules={self.total_rules} fired={len(self.fired_rules)} "
            f"missed={len(self.missed_rules)} skipped={len(self.skipped_rules)} "
            f"matched_events={len(self.matched_events)}"
        )


# ---------------------------------------------------------------------------
# Technique ID extraction
# ---------------------------------------------------------------------------

def extract_technique_id(rule_path: str) -> str:
    """
    Extract ATT&CK technique ID from a rule filename.

    Expects filenames like:
        T1059.001-encoded-powershell.yml  →  T1059.001
        T1547.001-registry-run-keys.yml   →  T1547.001
        T1059-command-scripting.yml       →  T1059

    Returns "UNKNOWN" if no technique ID pattern found.
    """
    filename = Path(rule_path).stem  # strip directory + extension
    match = _TECHNIQUE_ID_PATTERN.match(filename)
    if match:
        return match.group(1).upper()
    logger.warning(
        "Could not extract technique ID from rule filename '%s' — "
        "expected format: T1234.001-description.yml. Grouped as UNKNOWN.",
        Path(rule_path).name,
    )
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Event deduplication
# ---------------------------------------------------------------------------

def _event_hash(event: dict) -> str:
    """
    Stable hash of an event dict for deduplication.
    Uses sorted key serialisation so field order doesn't affect identity.
    """
    serialised = json.dumps(event, sort_keys=True, default=str)
    return hashlib.md5(serialised.encode()).hexdigest()  # noqa: S324 — not crypto


def _deduplicate_events(event_lists: list[list[dict]]) -> list[dict]:
    """
    Merge multiple event lists, removing duplicates by content hash.
    Order is preserved — first occurrence wins.
    """
    seen: set[str] = set()
    result: list[dict] = []
    for events in event_lists:
        for event in events:
            h = _event_hash(event)
            if h not in seen:
                seen.add(h)
                result.append(event)
    return result


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def parse_results(rule_results: list[RuleMatchResult]) -> list[DetectionResult]:
    """
    Convert a flat list of RuleMatchResult objects into per-technique
    DetectionResult objects.

    Parameters
    ----------
    rule_results : output of DetectionEngine.run()

    Returns
    -------
    list[DetectionResult] sorted by technique_id, one entry per technique.
    Techniques are determined by filename convention — see module docstring.
    """
    if not rule_results:
        logger.warning("parse_results called with empty result list")
        return []

    # Group RuleMatchResults by technique ID
    grouped: dict[str, list[RuleMatchResult]] = {}
    for r in rule_results:
        tid = extract_technique_id(r.rule_path)
        grouped.setdefault(tid, []).append(r)

    detection_results: list[DetectionResult] = []

    for technique_id, results in sorted(grouped.items()):
        fired: list[RuleBreakdown] = []
        missed: list[RuleBreakdown] = []
        skipped: list[RuleBreakdown] = []

        for r in results:
            breakdown = RuleBreakdown(
                rule_id=r.rule_id,
                rule_title=r.rule_title,
                rule_path=r.rule_path,
                fired=r.fired,
                skipped=r.skipped,
                skip_reason=r.skip_reason,
                match_count=len(r.matched_events),
                sql_query=r.sql_query,
            )
            if r.skipped:
                skipped.append(breakdown)
            elif r.fired:
                fired.append(breakdown)
            else:
                missed.append(breakdown)

        # Deduplicate matched events across all fired rules for this technique
        matched_events = _deduplicate_events(
            [r.matched_events for r in results if r.fired])
        covered = bool(fired)

        dr = DetectionResult(
            technique_id=technique_id,
            covered=covered,
            fired_rules=fired,
            missed_rules=missed,
            skipped_rules=skipped,
            matched_events=matched_events,
            total_rules=len(results),
        )
        detection_results.append(dr)
        logger.info(dr.summary())

    gaps = [r for r in detection_results if r.gap]
    covered_count = sum(1 for r in detection_results if r.covered)
    logger.info(
        "Parse complete — %d techniques | %d covered | %d gaps | %d skip-only",
        len(detection_results),
        covered_count,
        len(gaps),
        sum(1 for r in detection_results if r.skip_only),
    )

    return detection_results


def get_gaps(detection_results: list[DetectionResult]) -> list[DetectionResult]:
    """
    Filter to only techniques with a coverage gap.
    Convenience function for the defender agent call site.
    """
    return [r for r in detection_results if r.gap]


def get_covered(detection_results: list[DetectionResult]) -> list[DetectionResult]:
    """Filter to only covered techniques."""
    return [r for r in detection_results if r.covered]
