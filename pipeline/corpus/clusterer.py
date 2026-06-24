"""
pipeline/corpus/clusterer.py

Embeds RuleFeatures and groups them into RuleCluster objects.

Embedding-based similarity grouping (sentence-transformers + cosine/HDBSCAN)
was retired. At this project's scope — a handful of deliberately distinct
ATT&CK techniques — generated rules essentially never embed similarly
enough to cluster regardless of model quality, so every run produced all
singletons anyway. Removed the torch/sentence-transformers dependency
(the actual multi-GB cost) rather than keep paying for it.

Every rule is now wrapped in its own singleton RuleCluster. Output shape
is unchanged — learner.py and yaml_generator.py need no changes.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Optional

from pipeline.corpus.parser import RuleFeatures

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")


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
    # always None — no multi-member clusters possible
    silhouette: Optional[float]
    threshold_used: float
    method_used: str                        # "singleton" or "none"
    timestamp: float


# ---------------------------------------------------------------------------
# Purity metrics
# ---------------------------------------------------------------------------


def _compute_purity(n_rules: int, n_clusters: int) -> ClusterPurityReport:
    """
    Purity report for singleton-only clustering.

    Every value that depended on embeddings (similarity, silhouette,
    noise ratio) is structurally empty — there's nothing to measure when
    every cluster has exactly one member. Kept as a real ClusterPurityReport
    object, same shape as before retirement, so callers reading
    LearnerResult.purity_report don't need to change.
    """
    report = ClusterPurityReport(
        n_rules=n_rules,
        n_clusters=n_clusters,
        n_singletons=n_clusters,
        noise_ratio=0.0,
        mean_intra_cluster_similarity=0.0,
        min_intra_cluster_similarity=0.0,
        silhouette=None,
        threshold_used=0.0,
        method_used="singleton",
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
            f"  Method: {report.method_used} "
            f"(sentence-transformers retired — every rule is its own cluster)"
        )
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
# Singleton clustering — replaces cosine/HDBSCAN grouping
# ---------------------------------------------------------------------------


def _build_singleton_clusters(rule_features: list[RuleFeatures]) -> list[RuleCluster]:
    """
    Wrap every rule in its own singleton RuleCluster — no embedding or
    similarity computation. Mirrors exactly what _build_clusters used to
    produce for a singleton group, just without needing a sim_matrix at all.
    """
    clusters = []
    for rf in rule_features:
        clusters.append(RuleCluster(
            cluster_id=f"singleton_{rf.rule_id}",
            member_rule_ids=[rf.rule_id],
            member_rules=[rf],
            cluster_size=1,
            confidence=None,  # undefined for a singleton, same as before retirement
            archetype_tags=_infer_archetype_tags([rf]),
            target_eids=sorted(set(rf.target_eids)),
            representative_embedding_texts=[rf.embedding_text],
        ))
    return clusters


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def cluster_rules(
    rule_features: list[RuleFeatures],
    use_hdbscan: bool = False,
    threshold: float = 0.0,
    min_cluster_size: int = 2,
) -> tuple[list[RuleCluster], ClusterPurityReport]:
    """
    Wrap every rule in its own singleton cluster.

    Embedding-based grouping was retired — see module docstring. Signature
    is unchanged from before retirement so existing callers (learner.py)
    need no changes; use_hdbscan/threshold/min_cluster_size are accepted
    for interface compatibility and silently ignored.

    Returns:
        (clusters, purity_report) — same shape as before retirement.
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
            threshold_used=0.0,
            method_used="none",
            timestamp=time.time(),
        )

    clusters = _build_singleton_clusters(rule_features)
    purity = _compute_purity(len(rule_features), len(clusters))

    return clusters, purity
