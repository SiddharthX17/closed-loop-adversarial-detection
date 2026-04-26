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

from pipeline.embedding.scorer import EmbeddingScorer, EventScoringResult

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class GapScoringResult:
    """
    Embedding scorer output for a single gap technique.

    technique_id:    ATT&CK technique ID with the gap
    event_scores:    one EventScoringResult per missed event
                     (top_matches empty if event scored below threshold)
    top_technique:   the highest-scoring technique ID across all missed events,
                     or None if nothing cleared the threshold
    top_score:       cosine similarity of the top match, or 0.0
    """
    technique_id: str
    event_scores: list[EventScoringResult] = field(default_factory=list)
    top_technique: str | None = None
    top_score: float = 0.0


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def score_gaps(
    detection_results: dict,   # dict[technique_id, DetectionResult]
    scorer: EmbeddingScorer,
) -> dict[str, GapScoringResult]:
    """
    Score missed events for all gap techniques in detection_results.

    Only processes techniques where DetectionResult.gap is True —
    covered techniques have nothing to score.

    Args:
        detection_results: dict[technique_id, DetectionResult] from result_parser
        scorer:            EmbeddingScorer instance (loaded once by orchestrator)

    Returns:
        dict[technique_id, GapScoringResult] — one entry per gap technique.
        Techniques with no missed events get an entry with empty event_scores.
    """
    gap_results: dict[str, GapScoringResult] = {}

    for technique_id, detection_result in detection_results.items():
        # Only score techniques with a genuine gap
        if not getattr(detection_result, "gap", False):
            continue

        missed_events = getattr(detection_result, "matched_events", [])
        # matched_events on a gap result should be empty — but defensively
        # also check total_rules so we don't score skip-only techniques
        total_rules = getattr(detection_result, "total_rules", 0)
        if total_rules == 0:
            if DEBUG:
                print(
                    f"[gap_scorer] {technique_id}: skipping — "
                    f"no rules evaluated (no rules curated for this technique)"
                )
            continue

        if DEBUG:
            print(
                f"[gap_scorer] {technique_id}: scoring "
                f"{len(missed_events)} missed events"
            )

        if not missed_events:
            # Gap exists but no missed events available — can still create entry
            gap_results[technique_id] = GapScoringResult(
                technique_id=technique_id)
            if DEBUG:
                print(
                    f"[gap_scorer] {technique_id}: gap with no missed events to score")
            continue

        # Batch score all missed events
        event_scores = scorer.score_missed_events(missed_events)

        # Find the single best technique match across all events
        top_technique = None
        top_score = 0.0
        for es in event_scores:
            if es.top_matches:
                best = es.top_matches[0]  # already sorted descending
                if best.score > top_score:
                    top_score = best.score
                    top_technique = best.technique_id

        gap_results[technique_id] = GapScoringResult(
            technique_id=technique_id,
            event_scores=event_scores,
            top_technique=top_technique,
            top_score=top_score,
        )

        if DEBUG:
            print(
                f"[gap_scorer] {technique_id}: top match = "
                f"{top_technique} ({top_score:.4f})"
            )

    if DEBUG:
        print(
            f"[gap_scorer] Scored {len(gap_results)} gap techniques "
            f"(skipped {len(detection_results) - len(gap_results)} covered/no-rules)"
        )

    return gap_results
