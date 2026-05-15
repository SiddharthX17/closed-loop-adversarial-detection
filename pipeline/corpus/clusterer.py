"""
pipeline/corpus/clusterer.py

Embeds RuleFeatures and groups them into RuleCluster objects.

Primary mechanism: cosine similarity grouping.
HDBSCAN is available but unreliable with small batches (≤15 rules) due to
curse of dimensionality in 384-dimensional space. Use HDBSCAN only when
batch size justifies it (flag: use_hdbscan, default False).

Cosine similarity threshold (default 0.82) is a starting point, not a
validated number. Cluster purity metrics emitted per run to validate it.

Purity metrics are transient — logged per run, not persisted.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics import silhouette_score
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize

from pipeline.corpus.parser import RuleFeatures

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")

# Cosine similarity threshold for grouping.
# Tune based on purity metrics after 2-3 iterations.
# Higher = tighter clusters (more LLM calls), lower = looser (fewer calls).
COSINE_THRESHOLD: float = float(os.getenv("CORPUS_CLUSTER_THRESHOLD", "0.82"))

# Prevent giant Sigma keyword soups from silently truncating inside MiniLM.
# This is approximate (word-level, not tokenizer-level) but good enough.
MAX_EMBEDDING_WORDS = int(os.getenv("CORPUS_MAX_EMBED_WORDS", "220"))

_MODEL_NAME = "all-MiniLM-L6-v2"
_model: Optional[SentenceTransformer] = None

# Simple in-memory embedding cache.
# Avoids re-embedding identical rules repeatedly during iterative runs.
_embedding_cache: dict[str, np.ndarray] = {}


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(_MODEL_NAME)
    return _model


# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------

@dataclass
class RuleCluster:
    """
    A group of semantically similar rules, pre-LLM.

    Provenance fields are required for debugging cluster quality.
    confidence reflects how tightly the cluster holds together —
    mean intra-cluster cosine similarity.
    """
    cluster_id: str                          # stable hash-derived cluster ID
    member_rule_ids: list[str]               # rule_id from RuleFeatures
    member_rules: list[RuleFeatures]         # full features, all members
    cluster_size: int
    confidence: Optional[float]              # None for singleton clusters

    # inferred from conditions: process/network/registry
    archetype_tags: list[str]

    target_eids: list[int]                   # union of all member EIDs

    # all member embedding texts (not just centroid)
    representative_embedding_texts: list[str]


# ---------------------------------------------------------------------------
# Purity metrics (transient, per run)
# ---------------------------------------------------------------------------

@dataclass
class ClusterPurityReport:
    """
    Transient per-run cluster quality metrics.
    Not persisted. Logged via PIPELINE_DEBUG.
    Used to validate threshold and embedding quality after 2-3 iterations.
    """
    n_rules: int
    n_clusters: int
    n_singletons: int
    noise_ratio: float                       # only meaningful if HDBSCAN used
    mean_intra_cluster_similarity: float    # excludes singleton clusters
    min_intra_cluster_similarity: float     # excludes singleton clusters
    silhouette: Optional[float]             # None if <2 non-singleton clusters
    threshold_used: float
    method_used: str                        # "cosine" or "hdbscan"
    timestamp: float


# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------


def _truncate_embedding_text(text: str) -> str:
    """
    Prevent oversized Sigma rules from silently truncating inside MiniLM.

    Uses approximate word count rather than tokenizer-aware truncation.
    Good enough for clustering and much simpler operationally.
    """
    words = text.split()
    if len(words) <= MAX_EMBEDDING_WORDS:
        return text

    truncated = " ".join(words[:MAX_EMBEDDING_WORDS])

    if _DEBUG:
        print(
            f"[corpus/clusterer] Truncated embedding text "
            f"from {len(words)} → {MAX_EMBEDDING_WORDS} words"
        )

    return truncated


# ---------------------------------------------------------------------------
# Purity metrics
# ---------------------------------------------------------------------------


def _compute_purity(
    clusters: list[RuleCluster],
    embeddings: np.ndarray,
    rule_features: list[RuleFeatures],
    method: str,
    noise_count: int,
    threshold_used: float,
) -> ClusterPurityReport:
    """Compute transient purity metrics for the current clustering result."""

    measured_confidences = [
        c.confidence
        for c in clusters
        if c.confidence is not None
    ]

    mean_intra = (
        float(np.mean(measured_confidences))
        if measured_confidences else 0.0
    )

    min_intra = (
        float(np.min(measured_confidences))
        if measured_confidences else 0.0
    )

    n_singletons = sum(1 for c in clusters if c.cluster_size == 1)

    # Silhouette requires ≥2 clusters with ≥2 members
    sil: Optional[float] = None

    non_singleton = [c for c in clusters if c.cluster_size > 1]

    if len(non_singleton) >= 2 and len(rule_features) >= 4:
        labels = np.full(len(rule_features), -1, dtype=int)

        # Avoid repeated O(n) scans during label assignment.
        rule_index = {
            r.rule_id: idx
            for idx, r in enumerate(rule_features)
        }

        for idx, cluster in enumerate(non_singleton):
            for rf in cluster.member_rules:
                rule_idx = rule_index.get(rf.rule_id)
                if rule_idx is not None:
                    labels[rule_idx] = idx

        valid_mask = labels >= 0

        if valid_mask.sum() >= 4:
            try:
                sil = float(silhouette_score(
                    embeddings[valid_mask],
                    labels[valid_mask],
                    metric="cosine",
                ))
            except Exception:
                sil = None

    report = ClusterPurityReport(
        n_rules=len(rule_features),
        n_clusters=len(clusters),
        n_singletons=n_singletons,
        noise_ratio=noise_count / max(len(rule_features), 1),
        mean_intra_cluster_similarity=mean_intra,
        min_intra_cluster_similarity=min_intra,
        silhouette=sil,
        threshold_used=threshold_used,
        method_used=method,
        timestamp=time.time(),
    )

    if _DEBUG:
        print("[corpus/clusterer] --- Cluster Purity Report ---")
        print(
            f"  Rules: {report.n_rules}, "
            f"Clusters: {report.n_clusters}, "
            f"Singletons: {report.n_singletons}"
        )
        print(
            f"  Method: {report.method_used}, "
            f"Threshold: {report.threshold_used}"
        )
        print(
            f"  Intra-cluster sim — mean: "
            f"{report.mean_intra_cluster_similarity:.3f}, "
            f"min: {report.min_intra_cluster_similarity:.3f}"
        )

        if report.silhouette is not None:
            print(f"  Silhouette score: {report.silhouette:.3f}")
        else:
            print("  Silhouette: n/a (too few multi-member clusters)")

        print(f"  Noise ratio: {report.noise_ratio:.2f}")
        print("[corpus/clusterer] ---------------------------")

    return report


# ---------------------------------------------------------------------------
# Archetype inference from conditions
# ---------------------------------------------------------------------------


def _contains_token(values: list[str], pattern: str) -> bool:
    """
    Regex word-boundary matching for archetype inference.

    Prevents noisy matches like:
      - 'unencoded' triggering 'encoded'
      - random path substrings triggering tags
    """
    regex = re.compile(pattern, re.IGNORECASE)
    return any(regex.search(v) for v in values)


def _infer_archetype_tags(rules: list[RuleFeatures]) -> list[str]:
    """
    Infer broad behavioral archetype tags from the union of all member conditions.
    These are passed to the LLM to guide script generation.
    """
    tags: set[str] = set()
    all_conditions = [c for r in rules for c in r.conditions]

    # EID-based
    all_eids = {e for r in rules for e in r.target_eids}

    if 1 in all_eids:
        tags.add("process")

    if 3 in all_eids:
        tags.add("network")

    if 12 in all_eids or 13 in all_eids:
        tags.add("registry")

    # Field-based patterns
    field_names = {c.field_name.lower() for c in all_conditions}
    values = [c.value.lower() for c in all_conditions]

    if "commandline" in field_names:
        tags.add("commandline")

    if any(f in field_names for f in ("parentimage", "parentcommandline")):
        tags.add("parent_process")

    if "targetobject" in field_names:
        tags.add("registry")

    if any(
        f in field_names
        for f in (
            "destinationip",
            "destinationhostname",
            "destinationport",
        )
    ):
        tags.add("network")

    # Value-based behavioral hints.
    # Regex patterns intentionally use boundaries where practical to reduce
    # accidental substring pollution.
    value_patterns = {
        r"\bpowershell(?:\.exe)?\b": "powershell",
        r"\bcmd\.exe\b": "cmd",
        r"\bschtasks(?:\.exe)?\b": "scheduled_task",
        r"\breg\.exe\b": "registry",
        r"\b(winword|outlook|excel)(?:\.exe)?\b": "office",
        r"\bmshta(?:\.exe)?\b": "mshta",
        r"\b(wscript|cscript)(?:\.exe)?\b": "script_host",
        r"\bcertutil(?:\.exe)?\b": "certutil",
        r"\bregsvr32(?:\.exe)?\b": "regsvr32",
        r"\brundll32(?:\.exe)?\b": "rundll32",
        r"\bmsiexec(?:\.exe)?\b": "installer",
        r"\bexplorer(?:\.exe)?\b": "explorer",
        r"\b(base64|encoded|encodedcommand)\b": "encoding",
        r"\bdownloadstring\b": "download",
        r"\binvoke-expression\b": "invocation",
        r"\s-enc(?:\s|$)": "encoding",
        r"\s-nop(?:\s|$)": "noprofile",
        r"\bbypass\b": "bypass",
    }

    for pattern, tag in value_patterns.items():
        if _contains_token(values, pattern):
            tags.add(tag)

    return sorted(tags)


# ---------------------------------------------------------------------------
# Cosine similarity grouping (primary mechanism)
# ---------------------------------------------------------------------------


def _cosine_group(
    rule_features: list[RuleFeatures],
    embeddings: np.ndarray,
    threshold: float,
) -> tuple[list[RuleCluster], int]:
    """
    Greedy cosine similarity grouping.

    Rules are sorted by centrality (mean similarity to all others) before
    assignment so cluster seeds are the most representative rules, not
    whichever arrived first in the batch. Removes order-dependence.

    AND-linkage: a rule joins a group only if similar to ALL existing members.
    Prevents chained merging of distant rules.

    Returns (clusters, noise_count). noise_count always 0 — every rule assigned.

    Known limitation: greedy AND-linkage does not guarantee globally optimal
    cliques. Union-find or HAC would be more correct but adds complexity not
    justified at current batch sizes (5-15 rules).
    """

    # Embeddings already normalised upstream.
    sim_matrix = cosine_similarity(embeddings)

    # Sort by centrality — most central rule (highest mean similarity to all
    # others) becomes the seed. Stable across runs for same input.
    centrality = sim_matrix.mean(axis=1)

    # original indices, high-centrality first
    order = list(np.argsort(-centrality))

    groups: list[list[int]] = []
    assigned: set[int] = set()

    for i in order:
        if i in assigned:
            continue

        group = [i]
        assigned.add(i)

        for j in order:
            if j in assigned:
                continue

            # AND-linkage: must be similar to ALL current group members.
            if all(sim_matrix[j][k] >= threshold for k in group):
                group.append(j)
                assigned.add(j)

        groups.append(group)

    clusters = _build_clusters(rule_features, groups, sim_matrix)
    return clusters, 0


def _stable_cluster_id(member_rule_ids: list[str]) -> str:
    """
    Generate stable cluster identifiers from member rule IDs.

    Prevents cluster renumbering churn when thresholds or rule order change.
    """
    joined = "|".join(sorted(member_rule_ids))
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:10]
    return f"cluster_{digest}"


def _build_clusters(
    rule_features: list[RuleFeatures],
    groups: list[list[int]],
    sim_matrix: np.ndarray,
) -> list[RuleCluster]:
    """Convert index groups into RuleCluster objects with provenance."""

    clusters = []

    for group_indices in groups:
        member_rules = [rule_features[i] for i in group_indices]
        size = len(member_rules)

        # Intra-cluster confidence: mean pairwise cosine similarity.
        # Singleton confidence is undefined rather than artificially perfect.
        if size == 1:
            confidence = None
        else:
            pairs = [
                sim_matrix[group_indices[a]][group_indices[b]]
                for a in range(size)
                for b in range(a + 1, size)
            ]
            confidence = float(np.mean(pairs))

        member_rule_ids = [r.rule_id for r in member_rules]

        # Cluster ID: stable hash-based identifier.
        if size == 1:
            cluster_id = f"singleton_{member_rule_ids[0]}"
        else:
            cluster_id = _stable_cluster_id(member_rule_ids)

        all_eids = sorted({e for r in member_rules for e in r.target_eids})
        archetype_tags = _infer_archetype_tags(member_rules)

        clusters.append(RuleCluster(
            cluster_id=cluster_id,
            member_rule_ids=member_rule_ids,
            member_rules=member_rules,
            cluster_size=size,
            confidence=confidence,
            archetype_tags=archetype_tags,
            target_eids=all_eids,
            representative_embedding_texts=[
                r.embedding_text
                for r in member_rules
            ],
        ))

    return clusters


# ---------------------------------------------------------------------------
# HDBSCAN (optional, large batches only)
# ---------------------------------------------------------------------------


def _hdbscan_group(
    rule_features: list[RuleFeatures],
    embeddings: np.ndarray,
    min_cluster_size: int = 2,
) -> tuple[list[RuleCluster], int]:
    """
    HDBSCAN-based clustering on L2-normalised embeddings.

    Only reliable for batches of 20+ rules. With 5-15 rules,
    expect high noise ratio (most rules labeled -1 / singleton).

    Noise points (label -1) are treated as singletons.
    Returns (clusters, noise_count).
    """

    try:
        import hdbscan
    except ImportError:
        raise RuntimeError(
            "hdbscan not installed. Run: pip install hdbscan"
        )

    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        metric="euclidean",
        cluster_selection_epsilon=0.0,
    )

    labels = clusterer.fit_predict(embeddings)

    # Build index groups
    label_to_indices: dict[int, list[int]] = {}
    noise_indices = []

    for idx, label in enumerate(labels):
        if label == -1:
            noise_indices.append(idx)
        else:
            label_to_indices.setdefault(label, []).append(idx)

    # Noise points become singletons
    for idx in noise_indices:
        label_to_indices[-(idx + 1000)] = [idx]

    groups = list(label_to_indices.values())

    # Embeddings already normalised upstream.
    sim_matrix = cosine_similarity(embeddings)

    clusters = _build_clusters(rule_features, groups, sim_matrix)
    return clusters, len(noise_indices)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def cluster_rules(
    rule_features: list[RuleFeatures],
    use_hdbscan: bool = False,
    threshold: float = COSINE_THRESHOLD,
    min_cluster_size: int = 2,
) -> tuple[list[RuleCluster], ClusterPurityReport]:
    """
    Embed and cluster a batch of RuleFeatures.

    Args:
        rule_features:    Parsed rules from parser.parse_rules()
        use_hdbscan:      Use HDBSCAN instead of cosine grouping.
                          Only set True for batches of 20+ rules.
        threshold:        Cosine similarity threshold for grouping.
                          Ignored when use_hdbscan=True.
        min_cluster_size: Minimum cluster size for HDBSCAN.
                          Ignored when use_hdbscan=False.

    Returns:
        (clusters, purity_report)
        purity_report is transient — log it, don't persist it.
    """

    if not rule_features:
        return [], ClusterPurityReport(
            n_rules=0,
            n_clusters=0,
            n_singletons=0,
            noise_ratio=0.0,
            mean_intra_cluster_similarity=0.0,
            min_intra_cluster_similarity=0.0,
            silhouette=None,
            threshold_used=threshold,
            method_used="none",
            timestamp=time.time(),
        )

    if _DEBUG:
        print(
            f"[corpus/clusterer] Embedding {len(rule_features)} rules "
            f"via {_MODEL_NAME}"
        )

    model = _get_model()

    processed_texts = [
        _truncate_embedding_text(rf.embedding_text)
        for rf in rule_features
    ]

    embeddings_list = []

    for text in processed_texts:
        cache_key = hashlib.sha256(text.encode("utf-8")).hexdigest()

        if cache_key not in _embedding_cache:
            vector = model.encode(text, show_progress_bar=False)
            _embedding_cache[cache_key] = np.array(
                vector,
                dtype=np.float32,
            )

        embeddings_list.append(_embedding_cache[cache_key])

    # Explicit L2 normalisation.
    # Makes cosine and euclidean distance behaviour consistent.
    embeddings = normalize(
        np.array(embeddings_list, dtype=np.float32),
        norm="l2",
    )

    if use_hdbscan and len(rule_features) >= 20:
        if _DEBUG:
            print("[corpus/clusterer] Using HDBSCAN")

        clusters, noise_count = _hdbscan_group(
            rule_features,
            embeddings,
            min_cluster_size,
        )

        method = "hdbscan"

    else:
        if use_hdbscan and _DEBUG:
            print(
                f"[corpus/clusterer] HDBSCAN requested but batch size "
                f"({len(rule_features)}) < 20 — "
                f"falling back to cosine grouping"
            )

        clusters, noise_count = _cosine_group(
            rule_features,
            embeddings,
            threshold,
        )

        method = "cosine"

    purity = _compute_purity(
        clusters,
        embeddings,
        rule_features,
        method,
        noise_count,
        threshold,
    )

    return clusters, purity
