"""
pipeline/embedding/embedder.py

Pre-embeds ATT&CK technique descriptions for all target techniques.
Vectors are L2-normalized at encode time — similarity becomes a pure dot product.
Saves to disk as .npz — load once, reuse across runs.

Usage:
    python -m pipeline.embedding.embedder
    (or import and call build_embeddings() directly)
"""

import os
import yaml
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

from pipeline.data.stix_loader import get_loader

EMBEDDINGS_PATH = Path("data/embeddings/technique_embeddings.npz")
TECHNIQUES_PATH = Path("config/techniques.yaml")
MODEL_NAME = "all-MiniLM-L6-v2"

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


# ---------------------------------------------------------------------------
# Technique ID loading
# ---------------------------------------------------------------------------

def _load_technique_ids() -> list[str]:
    with open(TECHNIQUES_PATH) as f:
        config = yaml.safe_load(f)
    techniques = config.get("techniques", [])
    ids = []
    for entry in techniques:
        if isinstance(entry, str):
            ids.append(entry)
        elif isinstance(entry, dict):
            ids.append(entry["id"])
    return ids


# ---------------------------------------------------------------------------
# Description builder
# ---------------------------------------------------------------------------

def _build_description(technique_id: str, metadata) -> str:
    """
    Build a text description for embedding from MITRE metadata.

    Signal priority (most → least):
      1. Technique name            — core behavioural label
      2. Tactic                    — execution context
      3. Data sources              — what telemetry it touches
      4. STIX description          — behavioural prose (if available, capped at 200 chars)
      5. Technique ID              — always present, weakest signal

    Sub-technique fallback: if T1059.001 has no metadata, caller should retry
    with T1059 — that's handled in build_embeddings(), not here.

    Missing metadata: falls back to ID only. Scores for this technique will be
    unreliable — the model encodes the label, not the behaviour. Log a warning.
    """
    if not metadata:
        if DEBUG:
            print(
                f"[embedder] WARNING: no STIX metadata for {technique_id} — "
                f"embedding ID only, similarity scores will be unreliable"
            )
        return technique_id

    parts = [technique_id]

    if metadata.technique_name:
        parts.append(metadata.technique_name)

    if metadata.tactic:
        parts.append(f"tactic: {metadata.tactic}")

    if metadata.data_sources:
        sources = metadata.data_sources
        if isinstance(sources, list) and sources:
            parts.append("data sources: " + ", ".join(sources[:5]))
        elif isinstance(sources, str) and sources:
            parts.append(f"data sources: {sources}")

    # STIX description — conditional: MITREMetadata may or may not have this field
    if hasattr(metadata, "description") and metadata.description:
        desc = str(metadata.description).strip()
        if desc:
            parts.append(desc[:200])

    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Build + save
# ---------------------------------------------------------------------------

def build_embeddings(
    technique_ids: list[str] | None = None,
    output_path: Path = EMBEDDINGS_PATH,
    model_name: str = MODEL_NAME,
) -> dict[str, np.ndarray]:
    """
    Embed all target technique descriptions and save normalised vectors to disk.

    Vectors are L2-normalised at encode time (normalize_embeddings=True).
    This means similarity at score time = pure dot product, no division needed.

    Sub-technique fallback: if T1059.001 has no STIX metadata, retries with
    parent T1059. Logs when fallback is used.

    Args:
        technique_ids: ATT&CK IDs to embed. Reads techniques.yaml if None.
        output_path:   destination .npz file.
        model_name:    sentence-transformers model to use.

    Returns:
        dict mapping technique_id -> normalised embedding vector (shape: (384,))
    """
    if technique_ids is None:
        technique_ids = _load_technique_ids()

    if not technique_ids:
        raise ValueError(
            "No technique IDs found — check config/techniques.yaml")

    stix = get_loader()
    model = SentenceTransformer(model_name)

    descriptions: list[str] = []
    ids_ordered: list[str] = []

    for tid in technique_ids:
        metadata = stix.lookup(tid)

        # Sub-technique fallback: T1059.001 → T1059
        if not metadata and "." in tid:
            parent_id = tid.split(".")[0]
            metadata = stix.lookup(parent_id)
            if metadata and DEBUG:
                print(
                    f"[embedder] {tid}: no direct metadata — "
                    f"using parent {parent_id} description"
                )

        desc = _build_description(tid, metadata)
        descriptions.append(desc)
        ids_ordered.append(tid)

        if DEBUG:
            print(f"[embedder] {tid}: {desc[:120]}")

    if DEBUG:
        print(
            f"[embedder] Embedding {len(descriptions)} techniques with {model_name}")

    # normalize_embeddings=True: L2-normalises each vector to unit length
    # After this, cosine_similarity(a, b) == dot(a, b)
    embeddings = model.encode(
        descriptions,
        normalize_embeddings=True,
        show_progress_bar=DEBUG,
    )  # shape: (N, 384), all unit vectors

    output_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(
        output_path,
        ids=np.array(ids_ordered),
        embeddings=embeddings,
    )

    if DEBUG:
        print(
            f"[embedder] Saved {len(ids_ordered)} normalised embeddings to {output_path}")

    return dict(zip(ids_ordered, embeddings))


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_embeddings(
    path: Path = EMBEDDINGS_PATH,
) -> dict[str, np.ndarray]:
    """
    Load pre-computed normalised embeddings from disk.

    Returns:
        dict mapping technique_id -> normalised embedding vector
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Embeddings file not found at {path}. "
            "Run: python -m pipeline.embedding.embedder"
        )

    data = np.load(path, allow_pickle=False)
    ids = data["ids"].tolist()
    embeddings = data["embeddings"]

    if DEBUG:
        print(f"[embedder] Loaded {len(ids)} embeddings from {path}")

    return dict(zip(ids, embeddings))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = build_embeddings()
    print(f"\nBuilt embeddings for {len(result)} techniques:")
    for tid, vec in result.items():
        norm = float(np.linalg.norm(vec))
        print(f"  {tid} — shape {vec.shape}, norm {norm:.6f} (should be ~1.0)")
