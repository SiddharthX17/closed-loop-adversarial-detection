"""
pipeline/corpus/pusher.py

Commits generated workflow YAML to the repo and triggers it via
workflow_dispatch. Also manages corpus_outcomes.json for soft LLM
context feedback across iterations.

Outcome tracking is intentionally lightweight:
  - Did the script run? (inferred from workflow conclusion)
  - Did it produce logs? (inferred from corpus file changes)
  - Did it hit any rules? (recorded by orchestrator post-detection)
  - Useful corpus? (composite of above)

These feed into future LLM prompts as soft context, not hard reinforcement.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from github import Github, GithubException

from pipeline.corpus.yaml_generator import ClusterIntent

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")

_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
# e.g. "username/closed-loop-adversarial-detection"
_GITHUB_REPO = os.getenv("GITHUB_REPO", "")

_OUTCOMES_PATH = Path("corpus") / "corpus_outcomes.json"
_WORKFLOW_DIR = ".github/workflows"


# ---------------------------------------------------------------------------
# Outcome tracking data contract
# ---------------------------------------------------------------------------

@dataclass
class WorkflowOutcome:
    """
    Outcome record for a single generated workflow run.
    Written after GH Actions completes (async — not in same iteration).
    """
    iteration_id: str
    workflow_path: str
    cluster_ids: list[str]
    archetype_tags: list[str]           # union of all cluster tags
    behavioral_intents: list[str]       # one per cluster
    committed_at: float                 # unix timestamp
    # Fields below are populated by orchestrator in a subsequent iteration
    workflow_ran: Optional[bool] = None
    logs_produced: Optional[bool] = None
    # rule_ids that fired on generated logs
    rules_hit: Optional[list[str]] = None
    # True if logs_produced and any rules_hit
    useful_corpus: Optional[bool] = None


@dataclass
class PushResult:
    """Result of a push + dispatch attempt."""
    success: bool
    workflow_path: str
    workflow_url: Optional[str]
    dispatch_triggered: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Outcome store
# ---------------------------------------------------------------------------

def load_outcomes() -> list[WorkflowOutcome]:
    """Load all recorded outcomes from corpus_outcomes.json."""
    if not _OUTCOMES_PATH.exists():
        return []
    try:
        with open(_OUTCOMES_PATH, encoding="utf-8") as f:
            raw = json.load(f)
        return [WorkflowOutcome(**item) for item in raw]
    except Exception as e:
        if _DEBUG:
            print(f"[corpus/pusher] Failed to load outcomes: {e}")
        return []


def save_outcomes(outcomes: list[WorkflowOutcome]) -> None:
    """Persist outcomes to corpus_outcomes.json."""
    _OUTCOMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_OUTCOMES_PATH, "w", encoding="utf-8") as f:
        json.dump([asdict(o) for o in outcomes], f, indent=2)


def record_outcome(outcome: WorkflowOutcome) -> None:
    """Append a new outcome record, replacing any existing entry for same iteration."""
    outcomes = load_outcomes()
    outcomes = [o for o in outcomes if o.iteration_id != outcome.iteration_id]
    outcomes.append(outcome)
    save_outcomes(outcomes)


def save_outcomes(outcomes: list[WorkflowOutcome]) -> None:
    _OUTCOMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = _OUTCOMES_PATH.with_suffix(".tmp")

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump([asdict(o) for o in outcomes], f, indent=2)

        os.replace(tmp_path, _OUTCOMES_PATH)

    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def update_outcome(
    iteration_id: str,
    *,
    workflow_ran: Optional[bool] = None,
    logs_produced: Optional[bool] = None,
    rules_hit: Optional[list[str]] = None,
) -> None:
    """
    Update an existing outcome record with post-run results.
    Called by orchestrator in the subsequent iteration after logs are available.
    """
    outcomes = load_outcomes()
    for o in outcomes:
        if o.iteration_id == iteration_id:
            if workflow_ran is not None:
                o.workflow_ran = workflow_ran
            if logs_produced is not None:
                o.logs_produced = logs_produced
            if rules_hit is not None:
                o.rules_hit = rules_hit
                if o.logs_produced is not None:
                    o.useful_corpus = bool(
                        o.logs_produced and len(o.rules_hit) > 0)
            break
    save_outcomes(outcomes)


def build_prior_context_map(outcomes: list[WorkflowOutcome]) -> dict[str, str]:
    """
    Build tag → prior effective activity description map for LLM context.
    Only includes outcomes marked as useful_corpus=True.

    Returns dict keyed by comma-joined archetype tags, value is a
    human-readable description of what worked.
    """
    context_map: dict[str, str] = {}
    useful = [o for o in outcomes if o.useful_corpus is True]

    for outcome in useful:
        tag_key = ",".join(sorted(outcome.archetype_tags))
        descriptions = "\n".join(
            f"- {intent}" for intent in outcome.behavioral_intents
        )
        entry = (
            f"Iteration {outcome.iteration_id}: the following activity types "
            f"successfully generated corpus logs that hit rules:\n{descriptions}"
        )
        if tag_key in context_map:
            context_map[tag_key] += f"\n{entry}"
        else:
            context_map[tag_key] = entry

    return context_map


# ---------------------------------------------------------------------------
# GitHub push + dispatch
# ---------------------------------------------------------------------------

def push_and_trigger(
    workflow_yaml: str,
    iteration_id: str,
    intents: list[ClusterIntent],
) -> PushResult:
    """
    Commit the generated workflow YAML to the repo and trigger it.

    Args:
        workflow_yaml:  Complete GH Actions workflow YAML string.
        iteration_id:   Current pipeline iteration identifier.
        intents:        ClusterIntents — used to build the outcome record.

    Returns:
        PushResult with success flag and workflow URL.
    """
    if not _GITHUB_TOKEN:
        return PushResult(
            success=False,
            workflow_path="",
            workflow_url=None,
            dispatch_triggered=False,
            error="GITHUB_TOKEN not set",
        )
    if not _GITHUB_REPO:
        return PushResult(
            success=False,
            workflow_path="",
            workflow_url=None,
            dispatch_triggered=False,
            error="GITHUB_REPO not set",
        )

    workflow_filename = f"corpus_targeted_{iteration_id}.yml"
    workflow_path = f"{_WORKFLOW_DIR}/{workflow_filename}"

    try:
        gh = Github(_GITHUB_TOKEN)
        repo = gh.get_repo(_GITHUB_REPO)

        # Commit the workflow file
        commit_message = (
            f"feat: corpus stress-test workflow — iteration {iteration_id} [corpus-gen]"
        )

        try:
            # File may already exist from a previous (failed) attempt
            existing = repo.get_contents(workflow_path, ref="main")
            repo.update_file(
                path=workflow_path,
                message=commit_message,
                content=workflow_yaml,
                sha=existing.sha,
                branch="main",
            )
            if _DEBUG:
                print(
                    f"[corpus/pusher] Updated existing workflow: {workflow_path}")
        except GithubException as e:
            if e.status == 404:
                repo.create_file(
                    path=workflow_path,
                    message=commit_message,
                    content=workflow_yaml,
                    branch="main",
                )
                if _DEBUG:
                    print(
                        f"[corpus/pusher] Created new workflow: {workflow_path}")
            else:
                raise

        # Trigger via workflow_dispatch
        dispatch_triggered = False
        workflow_url = (
            f"https://github.com/{_GITHUB_REPO}/actions/workflows/{workflow_filename}"
        )

        # Brief pause to allow GitHub to register the new/updated file
        time.sleep(3)

        try:
            workflow_obj = repo.get_workflow(workflow_filename)
            if workflow_obj is None:
                raise RuntimeError(
                    f"Workflow not found after commit: {workflow_filename}")
            dispatch_triggered = False
            try:
                workflow_obj.create_dispatch(ref="main")
                dispatch_triggered = True
            except GithubException as e:
                if _DEBUG:
                    print(f"[corpus/pusher] Dispatch failed: {e}")
            if _DEBUG:
                print(
                    f"[corpus/pusher] Workflow dispatch triggered: {workflow_url}")
        except GithubException as e:
            if _DEBUG:
                print(
                    f"[corpus/pusher] Dispatch failed (workflow may still run): {e}")
            # Not fatal — workflow may auto-trigger on push in some configurations

        # Record outcome stub (results populated by orchestrator in next iteration)
        all_tags = sorted({
            tag
            for intent in intents
            for tag in intent.archetype_tags
        })
        outcome = WorkflowOutcome(
            iteration_id=iteration_id,
            workflow_path=workflow_path,
            cluster_ids=[i.cluster_id for i in intents],
            archetype_tags=all_tags,
            behavioral_intents=[
                i.behavioral_intent or ""
                for i in intents
            ],
            committed_at=time.time(),
        )
        record_outcome(outcome)

        return PushResult(
            success=True,
            workflow_path=workflow_path,
            workflow_url=workflow_url,
            dispatch_triggered=dispatch_triggered,
        )

    except Exception as e:
        if _DEBUG:
            print(f"[corpus/pusher] Push failed: {e}")
        return PushResult(
            success=False,
            workflow_path=workflow_path,
            workflow_url=None,
            dispatch_triggered=False,
            error=str(e),
        )
