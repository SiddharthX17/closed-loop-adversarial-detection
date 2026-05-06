"""
pipeline/embedding/gap_scorer.py

Wires the EmbeddingScorer into gap detection output.

score_gaps() takes the detection results from result_parser and, for every
technique with a gap, scores the missed events for technique proximity.

This is evaluation-only enrichment — output is passed to the orchestrator
for context. It never gates any detection or validation decision.

Typical call site (orchestrator, post-detection):
    from pipeline.embedding.gap_scorer import score_gaps, GapScoringResult
    scored = score_gaps(detection_results, scorer)
    # scored[technique_id].top_matches → technique proximity for defender agent
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from pipeline.emulator.log_builder import LogEvent
from pipeline.embedding.scorer import EmbeddingScorer, EventScoringResult

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class GapScoringResult:
    """
    Embedding scorer output for a single gap technique.

    technique_id:       ATT&CK technique ID with the gap
    event_scores:       one EventScoringResult per missed event
    top_technique:      highest-scoring technique ID across all events,
                        or None if nothing cleared the threshold
    top_score:          cosine similarity of top match, None if no match
    num_events_scored:  total events passed to scorer
    num_events_matched: events where at least one technique cleared threshold
    """
    technique_id: str
    event_scores: list[EventScoringResult] = field(default_factory=list)
    top_technique: str | None = None
    top_score: Optional[float] = None
    num_events_scored: int = 0
    num_events_matched: int = 0  # events where at least one technique cleared threshold


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def score_gaps(
    detection_results: dict,        # dict[technique_id, DetectionResult]
    scorer: EmbeddingScorer,
    # dict[technique_id, list[LogEvent]] from emulator
    log_stream: dict,
) -> dict[str, GapScoringResult]:
    """
    Score attack events for all gap techniques in detection_results.

    Uses log_stream (raw emulated attack events) as the event source —
    NOT detection_result.matched_events, which is always empty on gap results.

    Only scores techniques where DetectionResult.gap is True.
    Techniques with no curated rules return an empty GapScoringResult
    instead of being skipped — orchestrator can distinguish all three states:
    covered / gap-with-rules / gap-no-rules.

    Args:
        detection_results: dict[technique_id, DetectionResult] from result_parser
        scorer:            EmbeddingScorer instance (loaded once by orchestrator)
        log_stream:        dict[technique_id, list[LogEvent]] from run_emulator()

    Returns:
        dict[technique_id, GapScoringResult] — one entry per gap technique.
    """
    gap_results: dict[str, GapScoringResult] = {}

    for technique_id, detection_result in detection_results.items():
        is_gap = getattr(detection_result, "gap", False)
        matched = len(getattr(detection_result, "matched_events", []))
        total_rules = getattr(detection_result, "total_rules", 0)
        # Also score partial coverage — covered but not all events matched
        is_partial = (
            getattr(detection_result, "covered", False)
            and matched < len(log_stream.get(technique_id, []))
            and total_rules > 0
        )
        if not is_gap and not is_partial:
            continue

        total_rules = getattr(detection_result, "total_rules", 0)
        if total_rules == 0:
            # No rules curated — return empty entry so orchestrator can distinguish
            gap_results[technique_id] = GapScoringResult(
                technique_id=technique_id)
            if DEBUG:
                print(
                    f"[gap_scorer] {technique_id}: gap with no curated rules — "
                    f"returning empty entry"
                )
            continue

        # Use raw attack events from emulator — not matched_events (always empty on gaps)
        raw_events = log_stream.get(technique_id, [])
        event_dicts = [
            e.model_dump(exclude_none=True)
            for e in raw_events
        ]

        if DEBUG:
            print(
                f"[gap_scorer] {technique_id}: scoring "
                f"{len(event_dicts)} attack events"
            )

        if not event_dicts:
            gap_results[technique_id] = GapScoringResult(
                technique_id=technique_id)
            if DEBUG:
                print(
                    f"[gap_scorer] {technique_id}: gap with no emulated events to score")
            continue

        event_scores = scorer.score_missed_events(event_dicts)

        top_technique = None
        top_score = None
        num_matched = 0

        for es in event_scores:
            if es.top_matches:
                num_matched += 1
                best = es.top_matches[0]
                if top_score is None or best.score > top_score:
                    top_score = best.score
                    top_technique = best.technique_id

        gap_results[technique_id] = GapScoringResult(
            technique_id=technique_id,
            event_scores=event_scores,
            top_technique=top_technique,
            top_score=top_score,
            num_events_scored=len(event_dicts),
            num_events_matched=num_matched,
        )

        if DEBUG:
            score_str = f"{top_score:.4f}" if top_score is not None else "none"
            print(
                f"[gap_scorer] {technique_id}: top match = {top_technique} ({score_str}), "
                f"embedding similarity computed on {num_matched}/{len(event_dicts)} events"
            )

    if DEBUG:
        print(
            f"[gap_scorer] Scored {len(gap_results)} gap techniques "
            f"(skipped {len(detection_results) - len(gap_results)} covered)"
        )

    return gap_results
