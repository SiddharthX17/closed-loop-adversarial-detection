"""
pipeline/embedding/scorer.py

Evaluation-only cosine similarity scorer.
Scores missed log events against pre-computed technique embeddings.

IMPORTANT: This never gates any detection decision.
Detection logic is deterministic (pySigma). This surfaces technique proximity
on events that slipped through rules — signal for the defender agent.

Performance notes:
- Matrix is pre-normalised at __init__ — never recomputed per event
- score_missed_events() batch-encodes all events in one model call
- Similarity = pure dot product (vectors are unit-normalised)
"""

import os
import numpy as np
from pathlib import Path
from dataclasses import dataclass
from sentence_transformers import SentenceTransformer

from pipeline.embedding.embedder import load_embeddings, EMBEDDINGS_PATH, MODEL_NAME

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

DEFAULT_THRESHOLD = 0.30   # minimum similarity to surface a match
# maximum matches to return per event (if above threshold)
DEFAULT_TOP_N = 3


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class TechniqueScore:
    technique_id: str
    score: float        # dot product of unit vectors = cosine similarity, 0.0–1.0


@dataclass
class EventScoringResult:
    """
    Scoring result for a single missed event.
    top_matches: techniques that passed the threshold, sorted descending by score.
                 Empty list means no technique cleared the threshold — event is
                 genuinely ambiguous or too sparse to score meaningfully.
    """
    event_summary: str
    top_matches: list[TechniqueScore]


# ---------------------------------------------------------------------------
# Event → text
# ---------------------------------------------------------------------------

def _event_to_text(event: dict) -> str:
    """
    Convert a Sysmon event dict to structured text for embedding.

    Structured prefixes (process:, cmd:, parent:, registry:, net:) give the
    embedding model explicit field-type context rather than a flat token dump.
    Falls back to EventID + event_type so sparse events always produce something.
    """
    parts = []

    # Process creation
    if event.get("Image"):
        parts.append(f"process: {event['Image']}")
    if event.get("CommandLine"):
        parts.append(f"cmd: {event['CommandLine']}")
    if event.get("ParentImage"):
        parts.append(f"parent: {event['ParentImage']}")
    if event.get("ParentCommandLine"):
        parts.append(f"parent_cmd: {event['ParentCommandLine']}")
    if event.get("OriginalFileName"):
        parts.append(f"original: {event['OriginalFileName']}")
    if event.get("IntegrityLevel"):
        parts.append(f"integrity: {event['IntegrityLevel']}")

    # Registry
    if event.get("TargetObject"):
        parts.append(f"registry: {event['TargetObject']}")
    if event.get("Details"):
        parts.append(f"value: {event['Details']}")

    # Network
    if event.get("DestinationIp"):
        parts.append(f"net_dst: {event['DestinationIp']}")
    if event.get("DestinationHostname"):
        parts.append(f"net_dst: {event['DestinationHostname']}")
    if event.get("DestinationPort"):
        parts.append(f"port: {event['DestinationPort']}")
    if event.get("Protocol"):
        parts.append(f"proto: {event['Protocol']}")

    # Fallback
    if not parts:
        eid = event.get("EventID", "unknown")
        etype = event.get("event_type", "unknown")
        parts.append(f"EventID {eid} {etype}")

    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class EmbeddingScorer:
    """
    Scores missed log events against pre-computed technique embeddings.

    Instantiate once per run. Matrix is pre-normalised at init — all per-event
    scoring is a pure dot product with no recomputation of the matrix.
    """

    def __init__(
        self,
        embeddings_path: Path = EMBEDDINGS_PATH,
        model_name: str = MODEL_NAME,
        threshold: float = DEFAULT_THRESHOLD,
    ):
        self._threshold = threshold
        self.model = SentenceTransformer(model_name)

        embeddings = load_embeddings(embeddings_path)
        self._technique_ids = list(embeddings.keys())

        # Stack and pre-normalise once — shape: (N_techniques, 384)
        # Embeddings from build_embeddings() are already unit vectors,
        # but we normalise again here defensively in case they were built
        # with an older version that didn't set normalize_embeddings=True.
        matrix = np.stack([embeddings[tid] for tid in self._technique_ids])
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        self._matrix = matrix / \
            np.where(norms == 0, 1.0, norms)  # shape: (N, 384)

        if DEBUG:
            print(
                f"[scorer] Loaded {len(self._technique_ids)} techniques, "
                f"matrix {self._matrix.shape}, threshold={self._threshold}"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_event(
        self,
        event: dict,
        top_n: int = DEFAULT_TOP_N,
        threshold: float | None = None,
    ) -> EventScoringResult:
        """
        Score a single missed event.

        Args:
            event:     Sysmon event dict
            top_n:     max matches to return (only those above threshold)
            threshold: override instance threshold for this call

        Returns:
            EventScoringResult — top_matches is empty if nothing clears threshold
        """
        results = self.score_missed_events(
            [event], top_n=top_n, threshold=threshold)
        return results[0]

    def score_missed_events(
        self,
        events: list[dict],
        top_n: int = DEFAULT_TOP_N,
        threshold: float | None = None,
    ) -> list[EventScoringResult]:
        """
        Score a batch of missed events in a single model.encode() call.

        Args:
            events:    list of Sysmon event dicts
            top_n:     max matches per event (only those above threshold)
            threshold: override instance threshold for this call

        Returns:
            list of EventScoringResult, one per input event.
            top_matches is empty for events where nothing clears the threshold.
        """
        if not events:
            return []

        cutoff = threshold if threshold is not None else self._threshold
        top_n = min(top_n, len(self._technique_ids))

        texts = [_event_to_text(e) for e in events]

        if DEBUG:
            print(f"[scorer] Batch encoding {len(texts)} events")

        # Single model call for all events — normalize so dot product = cosine sim
        event_matrix = self.model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
        )  # shape: (N_events, 384)

        # Similarities: (N_events, N_techniques) — pure dot product
        similarities = event_matrix @ self._matrix.T

        results = []
        for i, text in enumerate(texts):
            scores = similarities[i]  # shape: (N_techniques,)

            # Sort descending, apply threshold, cap at top_n
            sorted_indices = np.argsort(scores)[::-1]
            top_matches = []
            for idx in sorted_indices:
                if len(top_matches) >= top_n:
                    break
                sim = float(scores[idx])
                if sim < cutoff:
                    break   # sorted descending — nothing below this will pass
                top_matches.append(
                    TechniqueScore(
                        technique_id=self._technique_ids[idx],
                        score=sim,
                    )
                )

            if DEBUG:
                if top_matches:
                    print(f"[scorer] {text[:60]}...")
                    for m in top_matches:
                        print(f"  {m.technique_id}: {m.score:.4f}")
                else:
                    print(
                        f"[scorer] {text[:60]}... — "
                        f"no matches above threshold {cutoff:.2f} "
                        f"(best: {float(scores[sorted_indices[0]]):.4f})"
                    )

            results.append(EventScoringResult(
                event_summary=text, top_matches=top_matches))

        return results
