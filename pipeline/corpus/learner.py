"""
pipeline/corpus/learner.py

Thin orchestrator for the corpus stress-test learner.
Coordinates: parser → clusterer → yaml_generator → pusher.

Called by pipeline/orchestrator.py after the validation pipeline,
before PR creation. Async relative to the main pipeline — does not
block on GH Actions completion.

Public interface:
    run(rule_yamls, iteration_id, anthropic_client) -> LearnerResult
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import anthropic

from pipeline.corpus.clusterer import ClusterPurityReport, cluster_rules
from pipeline.corpus.parser import parse_rules
from pipeline.corpus.pusher import (
    PushResult,
    build_prior_context_map,
    load_outcomes,
    push_and_trigger,
)
from pipeline.corpus.yaml_generator import (
    ClusterIntent,
    generate_intents,
    generate_ps_script,
)

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Result contract
# ---------------------------------------------------------------------------

@dataclass
class LearnerResult:
    """
    Summary of a corpus learner run.
    Returned to orchestrator for logging — not persisted.
    """
    iteration_id: str
    rules_parsed: int
    rules_dropped: int              # failed to parse
    n_clusters: int
    n_singletons: int
    n_feasible: int
    n_infeasible: int
    n_variants_generated: int
    workflow_path: Optional[str]
    workflow_url: Optional[str]
    push_succeeded: bool
    dispatch_triggered: bool
    purity_report: Optional[ClusterPurityReport]
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run(
    rule_yamls: list[str],
    iteration_id: str,
    anthropic_client: anthropic.Anthropic,
    *,
    use_hdbscan: bool = False,
) -> LearnerResult:
    """
    Run the corpus stress-test learner for the current iteration.

    Args:
        rule_yamls:        Validated candidate rule YAML strings from this iteration.
        iteration_id:      Current pipeline iteration identifier (e.g. "iter_003").
        anthropic_client:  Shared Anthropic client from orchestrator.
        use_hdbscan:       Use HDBSCAN clustering. Only set True for 20+ rules.

    Returns:
        LearnerResult — for orchestrator logging. Does not block on GH Actions.
    """
    errors: list[str] = []

    if _DEBUG:
        print(f"[corpus/learner] Starting — iteration {iteration_id}, "
              f"{len(rule_yamls)} candidate rules")

    # --- 1. Parse ---
    all_features = parse_rules(rule_yamls)
    dropped = len(rule_yamls) - len(all_features)
    if dropped > 0 and _DEBUG:
        print(f"[corpus/learner] {dropped} rules failed to parse — dropped")

    if not all_features:
        if _DEBUG:
            print("[corpus/learner] No parseable rules — aborting")
        return LearnerResult(
            iteration_id=iteration_id,
            rules_parsed=0,
            rules_dropped=dropped,
            n_clusters=0,
            n_singletons=0,
            n_feasible=0,
            n_infeasible=0,
            n_variants_generated=0,
            workflow_path=None,
            workflow_url=None,
            push_succeeded=False,
            dispatch_triggered=False,
            purity_report=purity,
            errors=["No parseable rules in batch"],
        )

    # --- 2. Cluster ---
    clusters, purity = cluster_rules(all_features, use_hdbscan=use_hdbscan)
    n_singletons = sum(1 for c in clusters if c.cluster_size == 1)

    if _DEBUG:
        print(f"[corpus/learner] {len(clusters)} clusters "
              f"({n_singletons} singletons)")

    # --- 3. Load prior context ---
    prior_outcomes = load_outcomes()
    prior_context_map = build_prior_context_map(prior_outcomes)
    if _DEBUG and prior_context_map:
        print(f"[corpus/learner] Loaded prior context from "
              f"{len([o for o in prior_outcomes if o.useful_corpus])} useful past outcomes")

    # --- 4. LLM calls → ClusterIntents ---
    intents: list[ClusterIntent] = generate_intents(
        clusters,
        anthropic_client,
        prior_context_map,
    )

    n_feasible = sum(1 for i in intents if i.feasible and i.llm_call_succeeded)
    n_infeasible = sum(1 for i in intents if not (
        i.feasible and i.llm_call_succeeded))
    n_infeasible = len(intents) - n_feasible
    n_variants = sum(len(i.variants) for i in intents if i.feasible)

    for intent in intents:
        if not intent.llm_call_succeeded and intent.llm_error:
            errors.append(f"{intent.cluster_id}: {intent.llm_error}")

    if n_feasible == 0:
        if _DEBUG:
            print("[corpus/learner] No feasible clusters — no workflow generated")
        return LearnerResult(
            iteration_id=iteration_id,
            rules_parsed=len(all_features),
            rules_dropped=dropped,
            n_clusters=len(clusters),
            n_singletons=n_singletons,
            n_feasible=0,
            n_infeasible=n_infeasible,
            n_variants_generated=0,
            workflow_path=None,
            workflow_url=None,
            push_succeeded=False,
            dispatch_triggered=False,
            purity_report=purity,
            errors=errors,
        )

    # --- 5. Assemble workflow YAML ---
    ps_script = generate_ps_script(intents, iteration_id)

    if _DEBUG:
        print(f"[corpus/learner] Workflow assembled — "
              f"{n_variants} variants across {n_feasible} clusters")

    # --- 6. Push + trigger ---
    push_result: PushResult = push_and_trigger(
        workflow_yaml=ps_script,
        iteration_id=iteration_id,
        intents=intents,
    )

    if not push_result.success and _DEBUG:
        print(f"[corpus/learner] Push failed: {push_result.error}")
        errors.append(f"push: {push_result.error}")

    return LearnerResult(
        iteration_id=iteration_id,
        rules_parsed=len(all_features),
        rules_dropped=dropped,
        n_clusters=len(clusters),
        n_singletons=n_singletons,
        n_feasible=n_feasible,
        n_infeasible=n_infeasible,
        n_variants_generated=n_variants,
        workflow_path=push_result.workflow_path,
        workflow_url=push_result.workflow_url,
        push_succeeded=push_result.success,
        dispatch_triggered=push_result.dispatch_triggered,
        purity_report=purity,
        errors=errors,
    )
