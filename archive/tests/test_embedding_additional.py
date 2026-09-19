"""
tests/test_embedding_additional.py

Additional tests for embedder and scorer covering:
- Embedder: semantic sanity (related techniques cluster closer than unrelated)
- Scorer: threshold behaviour, batch vs single consistency, semantic sanity
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock
from pathlib import Path

from pipeline.embedding.embedder import (
    build_embeddings,
    load_embeddings,
    _build_description,
)
from pipeline.embedding.scorer import (
    EmbeddingScorer,
    EventScoringResult,
    TechniqueScore,
    _event_to_text,
    DEFAULT_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_embeddings(tmp_path):
    """
    Build a small real embedding set using 3 techniques with mock metadata.
    Two PowerShell/execution techniques + one persistence technique.
    Returns the path to the saved .npz file.
    """
    from types import SimpleNamespace

    def _make_meta(tid, name, tactic, sources=None):
        return SimpleNamespace(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            data_sources=sources or [],
        )

    metadata_map = {
        "T1059.001": _make_meta("T1059.001", "PowerShell", "execution",
                                ["Process", "Command"]),
        "T1059.003": _make_meta("T1059.003", "Windows Command Shell", "execution",
                                ["Process", "Command"]),
        "T1547.001": _make_meta("T1547.001", "Registry Run Keys / Startup Folder",
                                "persistence", ["Registry", "File"]),
    }

    mock_stix = MagicMock()
    mock_stix.lookup.side_effect = lambda tid: metadata_map.get(tid)

    output_path = tmp_path / "embeddings.npz"

    with patch("pipeline.embedding.embedder.get_loader", return_value=mock_stix):
        result = build_embeddings(
            technique_ids=list(metadata_map.keys()),
            output_path=output_path,
        )

    return output_path, result


# ---------------------------------------------------------------------------
# Embedder — semantic sanity
# ---------------------------------------------------------------------------

class TestEmbedderSemanticSanity:
    """
    The embedding should position related techniques closer than unrelated ones.
    T1059.001 (PowerShell/execution) should be more similar to
    T1059.003 (cmd/execution) than to T1547.001 (registry persistence).
    """

    def test_related_techniques_closer_than_unrelated(self, tmp_embeddings):
        _, embeddings = tmp_embeddings

        vec_ps = embeddings["T1059.001"]
        vec_cmd = embeddings["T1059.003"]
        vec_reg = embeddings["T1547.001"]

        # Dot product = cosine similarity (vectors are unit-normalised)
        sim_ps_cmd = float(np.dot(vec_ps, vec_cmd))
        sim_ps_reg = float(np.dot(vec_ps, vec_reg))

        assert sim_ps_cmd > sim_ps_reg, (
            f"Expected T1059.001 closer to T1059.003 ({sim_ps_cmd:.4f}) "
            f"than to T1547.001 ({sim_ps_reg:.4f})"
        )

    def test_vectors_are_unit_normalised(self, tmp_embeddings):
        """All stored embeddings should have norm ≈ 1.0 after build."""
        _, embeddings = tmp_embeddings
        for tid, vec in embeddings.items():
            norm = float(np.linalg.norm(vec))
            assert abs(norm - 1.0) < 1e-5, (
                f"{tid}: expected unit vector, got norm={norm:.6f}"
            )

    def test_roundtrip_preserves_norms(self, tmp_embeddings):
        """Save → load should preserve unit norms."""
        output_path, original = tmp_embeddings
        loaded = load_embeddings(output_path)
        for tid in original:
            norm = float(np.linalg.norm(loaded[tid]))
            assert abs(norm - 1.0) < 1e-5, (
                f"{tid}: norm after load={norm:.6f}"
            )


# ---------------------------------------------------------------------------
# Scorer — threshold behaviour
# ---------------------------------------------------------------------------

class TestScorerThreshold:

    def test_returns_empty_when_nothing_clears_threshold(self, tmp_embeddings):
        """With threshold=1.0 (impossible), no matches should be returned."""
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=1.0)

        event = {"Image": "C:\\Windows\\explorer.exe",
                 "CommandLine": "explorer.exe"}
        result = scorer.score_event(event)

        assert result.top_matches == [], (
            "threshold=1.0 should produce no matches"
        )

    def test_returns_matches_above_threshold(self, tmp_embeddings):
        """With threshold=0.0, all techniques should be returned (up to top_n)."""
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc JABj",
        }
        result = scorer.score_event(event, top_n=3)

        # 3 techniques in fixture, all above 0.0
        assert len(result.top_matches) == 3

    def test_threshold_override_per_call(self, tmp_embeddings):
        """threshold= kwarg on score_event should override instance threshold."""
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.99)

        event = {"Image": "powershell.exe", "CommandLine": "-enc JABj"}

        # Instance threshold would return nothing
        result_default = scorer.score_event(event)
        # Per-call override returns something
        result_override = scorer.score_event(event, threshold=0.0)

        assert result_default.top_matches == []
        assert len(result_override.top_matches) > 0

    def test_partial_matches_when_some_below_threshold(self, tmp_embeddings):
        """
        If 2 of 3 techniques pass threshold, return 2 not 3.
        Construct by scoring a very technique-specific event and using a mid threshold.
        """
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc JABj",
        }
        # Get actual scores to find a threshold between rank 1 and rank 3
        result_all = scorer.score_event(event, top_n=3, threshold=0.0)
        scores = [m.score for m in result_all.top_matches]

        if len(scores) >= 2:
            # Set threshold just above the lowest score
            cutoff = scores[-1] + 0.001
            result_partial = scorer.score_event(
                event, top_n=3, threshold=cutoff)
            assert len(result_partial.top_matches) < len(
                result_all.top_matches)


# ---------------------------------------------------------------------------
# Scorer — batch vs single consistency
# ---------------------------------------------------------------------------

class TestScorerBatchConsistency:

    def test_batch_matches_single_scores(self, tmp_embeddings):
        """
        score_missed_events([e1, e2]) must return same scores as
        score_event(e1) + score_event(e2) individually.
        Verifies batch encoding doesn't shift individual vectors.
        """
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        events = [
            {"Image": "powershell.exe", "CommandLine": "-enc JABj"},
            {"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"},
        ]

        batch_results = scorer.score_missed_events(
            events, top_n=3, threshold=0.0)
        single_results = [scorer.score_event(
            e, top_n=3, threshold=0.0) for e in events]

        for i, (batch, single) in enumerate(zip(batch_results, single_results)):
            assert len(batch.top_matches) == len(single.top_matches), (
                f"Event {i}: batch returned {len(batch.top_matches)} matches, "
                f"single returned {len(single.top_matches)}"
            )
            for b_match, s_match in zip(batch.top_matches, single.top_matches):
                assert b_match.technique_id == s_match.technique_id, (
                    f"Event {i}: technique order differs — "
                    f"batch={b_match.technique_id}, single={s_match.technique_id}"
                )
                assert abs(b_match.score - s_match.score) < 1e-5, (
                    f"Event {i} {b_match.technique_id}: "
                    f"batch score {b_match.score:.6f} != single score {s_match.score:.6f}"
                )

    def test_batch_returns_one_result_per_event(self, tmp_embeddings):
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        events = [
            {"Image": "powershell.exe"},
            {"TargetObject": "HKCU\\Run\\malware"},
            {"DestinationIp": "10.0.0.1"},
        ]
        results = scorer.score_missed_events(events)
        assert len(results) == 3

    def test_batch_empty_input(self, tmp_embeddings):
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path)
        assert scorer.score_missed_events([]) == []


# ---------------------------------------------------------------------------
# Scorer — semantic sanity
# ---------------------------------------------------------------------------

class TestScorerSemanticSanity:

    def test_powershell_event_scores_higher_on_execution_than_persistence(
        self, tmp_embeddings
    ):
        """
        A PowerShell process creation event should score higher against
        execution techniques (T1059.001, T1059.003) than persistence (T1547.001).
        """
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc JABjAG0AZA==",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        }

        result = scorer.score_event(event, top_n=3, threshold=0.0)
        score_map = {m.technique_id: m.score for m in result.top_matches}

        # At least one execution technique should score higher than persistence
        exec_scores = [
            score_map.get("T1059.001", 0.0),
            score_map.get("T1059.003", 0.0),
        ]
        persist_score = score_map.get("T1547.001", 0.0)

        assert max(exec_scores) > persist_score, (
            f"Expected execution techniques to outscore persistence. "
            f"exec={exec_scores}, persistence={persist_score}"
        )

    def test_registry_event_scores_higher_on_persistence(self, tmp_embeddings):
        """
        A registry run key event should score higher against T1547.001
        than against PowerShell execution techniques.
        """
        output_path, _ = tmp_embeddings
        scorer = EmbeddingScorer(embeddings_path=output_path, threshold=0.0)

        event = {
            "TargetObject": (
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\"
                "Run\\malicious_payload"
            ),
            "Details": "C:\\Users\\user\\AppData\\Roaming\\malware.exe",
        }

        result = scorer.score_event(event, top_n=3, threshold=0.0)
        score_map = {m.technique_id: m.score for m in result.top_matches}

        persist_score = score_map.get("T1547.001", 0.0)
        exec_scores = [
            score_map.get("T1059.001", 0.0),
            score_map.get("T1059.003", 0.0),
        ]

        assert persist_score > max(exec_scores), (
            f"Expected T1547.001 to outscore execution techniques. "
            f"persistence={persist_score}, exec={exec_scores}"
        )
