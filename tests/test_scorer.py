import numpy as np
import pytest

from pipeline.embedding.scorer import (
    _event_to_text,
    EmbeddingScorer,
)


# -----------------------------
# Event → text conversion
# -----------------------------

def test_event_to_text_basic():
    event = {
        "Image": "powershell.exe",
        "CommandLine": "powershell -enc abc",
        "ParentImage": "cmd.exe"
    }

    text = _event_to_text(event)

    assert "powershell.exe" in text
    assert "enc" in text
    assert "cmd.exe" in text


def test_event_to_text_sparse():
    event = {}

    text = _event_to_text(event)

    assert "EventID" in text or len(text) > 0


# -----------------------------
# Scorer behavior (mocked)
# -----------------------------

@pytest.fixture
def dummy_scorer(monkeypatch):
    from pipeline.embedding import scorer

    # Mock embeddings
    fake_embeddings = {
        "T1": np.ones(384),
        "T2": np.ones(384) * 0.5,
        "T3": np.ones(384) * 0.2,
    }

    monkeypatch.setattr(scorer, "load_embeddings",
                        lambda path: fake_embeddings)

    class DummyModel:
        def encode(self, texts, **kwargs):
            return np.ones((len(texts), 384))

    monkeypatch.setattr(scorer, "SentenceTransformer",
                        lambda name: DummyModel())

    return EmbeddingScorer()


# -----------------------------
# Score structure tests
# -----------------------------

def test_score_event_returns_sorted(dummy_scorer):
    event = {"Image": "powershell.exe"}

    result = dummy_scorer.score_event(event, top_n=3)

    scores = [m.score for m in result.top_matches]

    assert scores == sorted(scores, reverse=True)


def test_score_event_top_n_limit(dummy_scorer):
    event = {"Image": "cmd.exe"}

    result = dummy_scorer.score_event(event, top_n=1)

    assert len(result.top_matches) <= 1


def test_score_event_output_shape(dummy_scorer):
    event = {"Image": "powershell.exe"}

    result = dummy_scorer.score_event(event)

    assert isinstance(result.event_summary, str)
    assert len(result.top_matches) > 0

    for match in result.top_matches:
        assert isinstance(match.technique_id, str)
        assert isinstance(match.score, float)


def test_score_sparse_event_no_crash(dummy_scorer):
    event = {}

    result = dummy_scorer.score_event(event)

    assert result is not None
