import numpy as np
import tempfile
from pathlib import Path
import yaml

from pipeline.embedding.embedder import (
    _build_description,
    load_embeddings,
    build_embeddings,
)
from pipeline.data.stix_loader import MITREMetadata


# -----------------------------
# Description builder tests
# -----------------------------

def test_build_description_with_metadata():
    meta = MITREMetadata(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        tactics=["execution"],
        data_sources=["Process: Process Creation"],
        permissions_required=["User"]
    )

    desc = _build_description("T1059", meta)

    assert "T1059" in desc
    assert "Command and Scripting Interpreter" in desc
    assert "execution" in desc
    assert "Process Creation" in desc


def test_build_description_without_metadata():
    desc = _build_description("T9999", None)

    assert "T9999" in desc  # fallback still includes ID
    assert isinstance(desc, str)
    assert len(desc) > 0


# -----------------------------
# Technique ID loading logic
# -----------------------------

def test_load_technique_ids_formats(tmp_path, monkeypatch):
    fake_yaml = {
        "techniques": [
            "T1001",
            {"id": "T1002"},
            {"id": "T1003"},
        ]
    }

    path = tmp_path / "techniques.yaml"
    with open(path, "w") as f:
        yaml.dump(fake_yaml, f)

    from pipeline.embedding import embedder
    monkeypatch.setattr(embedder, "TECHNIQUES_PATH", path)

    ids = embedder._load_technique_ids()

    assert set(ids) == {"T1001", "T1002", "T1003"}


# -----------------------------
# Embedding persistence tests
# -----------------------------

def test_embeddings_save_and_load(tmp_path):
    # Create fake embeddings
    ids = ["T1", "T2"]
    vectors = np.array([[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]])

    path = tmp_path / "embeddings.npz"

    np.savez(path, ids=np.array(ids), embeddings=vectors)

    loaded = load_embeddings(path)

    assert len(loaded) == 2
    assert "T1" in loaded
    assert loaded["T1"].shape == (3,)


# -----------------------------
# Integration sanity test
# -----------------------------

def test_build_embeddings_basic(monkeypatch, tmp_path):
    # Avoid real STIX + heavy compute by mocking
    from pipeline.embedding import embedder

    monkeypatch.setattr(embedder, "_load_technique_ids", lambda: ["T1059"])

    class DummyMeta:
        technique_id = "T1059"
        technique_name = "PowerShell"
        tactic = "execution"
        data_sources = ["Process Creation"]

    class DummyLoader:
        def lookup(self, tid):
            return DummyMeta()

    monkeypatch.setattr(embedder, "get_loader", lambda: DummyLoader())

    class DummyModel:
        def encode(self, texts, show_progress_bar=False):
            return np.ones((len(texts), 384))

    monkeypatch.setattr(embedder, "SentenceTransformer",
                        lambda name: DummyModel())

    out_path = tmp_path / "test_embeddings.npz"

    result = embedder.build_embeddings(output_path=out_path)

    assert "T1059" in result
    assert result["T1059"].shape == (384,)
