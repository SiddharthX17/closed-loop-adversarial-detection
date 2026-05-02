"""
pipeline/github/pr_creator.py

Creates GitHub PRs for validated Sigma rules.

Per PR:
  - Branch: rule/{technique_id} — stable, never slug-dependent
  - Reuses existing branch when present (history preserved)
  - Commits rule YAML to rules/{technique_id}-{slug}.yml
  - PR body: validation summary + evidence events + validation feedback + labels
  - Skips entirely when content and body are unchanged
  - Returns PRResult(pr_url, pr_number, branch_name, rule_filename)

Requires in .env:
  GITHUB_TOKEN — personal access token with repo scope
  GITHUB_REPO  — "owner/repo-name"
"""

import os
import re
import time
import textwrap
import json
import yaml as pyyaml

from dataclasses import dataclass
from pathlib import Path

from github import Github, GithubException
from dotenv import load_dotenv

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

RULES_DIR = "rules/generated"
MAX_EVIDENCE_EVENTS = 5
MAX_FIELD_LENGTH = 300
_RETRY_STATUSES = {403, 429}  # rate limit only — never retry 404/422


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PRResult:
    pr_url: str
    pr_number: int
    branch_name: str
    rule_filename: str


# ---------------------------------------------------------------------------
# Retry — rate limit only
# ---------------------------------------------------------------------------

def _retry(func, retries: int = 3, base_delay: float = 2.0):
    """
    Retry a GitHub API call on rate limit (403/429) only.
    All other GithubExceptions propagate immediately.
    """
    for attempt in range(retries):
        try:
            return func()
        except GithubException as e:
            if e.status not in _RETRY_STATUSES or attempt == retries - 1:
                raise
            wait = base_delay * (attempt + 1)
            if DEBUG:
                print(
                    f"[pr_creator] Rate limited (HTTP {e.status}) — retrying in {wait}s")
            time.sleep(wait)


# ---------------------------------------------------------------------------
# YAML + naming helpers
# ---------------------------------------------------------------------------

def _extract_title(rule_yaml: str) -> str:
    """Parse rule title via yaml.safe_load — handles all valid YAML formats."""
    try:
        parsed = pyyaml.safe_load(rule_yaml)
        return (parsed or {}).get("title", "") or ""
    except Exception:
        return ""


def _slugify(text: str, max_len: int = 120) -> str:
    """
    URL/filename-safe slug, truncated to max_len.
    Avoids Windows 255-char filename limit when combined with technique ID.
    """
    slug = text.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug[:max_len].rstrip("-")


def _rule_filename(technique_id: str, rule_yaml: str) -> str:
    """
    Filename: {technique_id}-{slug}.yml
    Slug derived from rule title — falls back to technique ID slug.
    Multiple distinct rules per technique are intentional (different slugs).
    """
    title = _extract_title(rule_yaml)
    slug = _slugify(title) if title else _slugify(technique_id)
    return f"{technique_id}-{slug}.yml"


def _branch_name(technique_id: str) -> str:
    """
    Branch anchored to technique_id only — stable across title/slug changes.
    One branch per technique: rule/T1059.001
    """
    return f"rule/{technique_id}"


# ---------------------------------------------------------------------------
# PR body helpers
# ---------------------------------------------------------------------------

def _truncate(value) -> str:
    value = str(value)
    if len(value) > MAX_FIELD_LENGTH:
        return value[:MAX_FIELD_LENGTH] + "..."
    return value


def _format_evidence(missed_events: list[dict]) -> str:
    if not missed_events:
        return "_No missed events available._"

    lines = []
    for i, event in enumerate(missed_events[:MAX_EVIDENCE_EVENTS], 1):
        populated = {
            k: _truncate(v)
            for k, v in event.items()
            if v is not None and v != "" and k not in ("Channel",)
        }
        lines.append(f"**Event {i}:**")
        lines.append("```json")
        lines.append(json.dumps(populated, indent=2))
        lines.append("```")

    if len(missed_events) > MAX_EVIDENCE_EVENTS:
        lines.append(
            f"_...and {len(missed_events) - MAX_EVIDENCE_EVENTS} more events not shown._"
        )
    return "\n".join(lines)


def _format_fired_rules(fired_rules: list) -> str:
    if not fired_rules:
        return "_No rules fired (first iteration or no prior run)._"
    lines = []
    for rb in fired_rules:
        condition = _truncate(rb.sql_query or "unavailable")
        lines.append(f"- **{rb.rule_title}**")
        lines.append(f"  ```sql\n  {condition}\n  ```")
    return "\n".join(lines)


def _build_pr_body(
    technique_id: str,
    technique_name: str,
    missed_events: list[dict],
    validation_feedback: str,
    fired_rules: list,
    fp_rate: float | None,
) -> str:
    fp_str = f"{fp_rate:.1%}" if fp_rate is not None else "N/A"
    feedback_block = validation_feedback or "_No additional feedback provided._"

    return textwrap.dedent(f"""\
        ## Detection Gap Closure — {technique_id}

        **Technique:** {technique_id} — {technique_name}
        **Generated by:** Defender Agent (automated)
        **Status:** All validation gates passed ✅

        ---

        ### Validation Summary

        | Gate | Result |
        |------|--------|
        | Schema Linter | ✅ Passed |
        | Attack Gate | ✅ Fired on attack sample |
        | Noise Gate | ✅ FP rate: {fp_str} |

        ---

        ### Evidence — Missed Events

        These events were not caught by existing rules and triggered this rule generation:

        {_format_evidence(missed_events)}

        ---

        ### Prior Rules That Fired (Existing Coverage)

        {_format_fired_rules(fired_rules)}

        ---

        ### Validation Feedback

        {feedback_block}

        ---

        ### Reviewer Notes

        - Rule was generated by the defender agent and validated automatically
        - Verify detection logic is specific enough for your environment
        - Check FP rate against your own benign corpus before merging
        - This PR was opened automatically — human review required before merge
    """)


# ---------------------------------------------------------------------------
# Label helper
# ---------------------------------------------------------------------------

def _ensure_labels_exist(repo, labels: list[str]) -> None:
    """
    Create labels that don't already exist in the repo.
    Handles race condition — 422 on create means already exists, safe to ignore.
    """
    existing = {label.name for label in repo.get_labels()}
    label_colors = {
        "automated": "0075ca",
        "detection-rule": "e4e669",
    }
    for label in labels:
        if label not in existing:
            try:
                color = label_colors.get(label, "ededed")
                repo.create_label(name=label, color=color)
                if DEBUG:
                    print(f"[pr_creator] Created label: {label}")
            except GithubException as e:
                if e.status != 422:
                    if DEBUG:
                        print(
                            f"[pr_creator] Could not create label '{label}': {e}")


# ---------------------------------------------------------------------------
# Main creator
# ---------------------------------------------------------------------------

class PRCreator:

    def __init__(self):
        token = os.getenv("GITHUB_TOKEN")
        repo_name = os.getenv("GITHUB_REPO")

        if not token:
            raise EnvironmentError(
                "GITHUB_TOKEN not set — add to .env (needs repo scope)"
            )
        if not repo_name:
            raise EnvironmentError(
                "GITHUB_REPO not set — add to .env (format: owner/repo-name)"
            )

        self._gh = Github(token)
        self._repo = self._gh.get_repo(repo_name)

        if DEBUG:
            print(f"[pr_creator] Connected to repo: {repo_name}")

    def create_pr(
        self,
        technique_id: str,
        technique_name: str,
        rule_yaml: str,
        missed_events: list[dict],
        validation_result,
        fired_rules: list | None = None,
    ) -> PRResult:
        """
        Create or update a GitHub PR for a validated Sigma rule.

        Args:
            technique_id:      ATT&CK technique ID
            technique_name:    Human-readable name
            rule_yaml:         Validated Sigma YAML string
            missed_events:     Events not caught — attached as evidence
            validation_result: ValidationResult from validation_pipeline
            fired_rules:       RuleBreakdown list from prior DetectionResult (optional)

        Returns:
            PRResult with pr_url, pr_number, branch_name, rule_filename
        """
        filename = _rule_filename(technique_id, rule_yaml)
        branch = _branch_name(technique_id)
        rule_path = f"{RULES_DIR}/{filename}"

        default_branch = self._repo.default_branch
        head_sha = self._repo.get_branch(default_branch).commit.sha

        # Build PR body upfront — needed for early exit check
        fp_rate = getattr(validation_result, "fp_rate", None)
        feedback = getattr(validation_result, "feedback", "") or ""
        pr_body = _build_pr_body(
            technique_id=technique_id,
            technique_name=technique_name,
            missed_events=missed_events,
            validation_feedback=feedback,
            fired_rules=fired_rules or [],
            fp_rate=fp_rate,
        )

        # ── Early exit: check existing PR + content before any branch ops ──
        open_prs = self._repo.get_pulls(
            state="open",
            head=f"{self._repo.owner.login}:{branch}",
        )
        existing_pr = next(iter(open_prs), None)

        content_unchanged = False
        body_unchanged = False

        if existing_pr:
            try:
                existing_file = self._repo.get_contents(rule_path, ref=branch)
                existing_content = existing_file.decoded_content.decode()
                content_unchanged = existing_content.strip() == rule_yaml.strip()
                body_unchanged = (
                    existing_pr.body or "").strip() == pr_body.strip()

                if content_unchanged and body_unchanged:
                    if DEBUG:
                        print(
                            f"[pr_creator] No changes detected for "
                            f"#{existing_pr.number} — skipping entirely"
                        )
                    return PRResult(
                        pr_url=existing_pr.html_url,
                        pr_number=existing_pr.number,
                        branch_name=branch,
                        rule_filename=filename,
                    )
            except GithubException as e:
                if e.status != 404:
                    raise
                # File doesn't exist on branch yet — proceed normally

        # Body changed but content unchanged — update PR only, skip branch/file ops
        if content_unchanged and not body_unchanged and existing_pr:
            existing_pr.edit(
                title=f"[Auto] {technique_id}: {technique_name} detection rule",
                body=pr_body,
            )
            if DEBUG:
                print(
                    f"[pr_creator] Body-only update for "
                    f"#{existing_pr.number} — skipping branch/file ops"
                )
            labels = ["automated", "detection-rule", technique_id]
            try:
                _ensure_labels_exist(self._repo, labels)
                existing_pr.add_to_labels(*labels)
            except Exception as e:
                if DEBUG:
                    print(f"[pr_creator] Failed to add labels: {e}")
            return PRResult(
                pr_url=existing_pr.html_url,
                pr_number=existing_pr.number,
                branch_name=branch,
                rule_filename=filename,
            )

        # ── Branch lifecycle: create branch if absent, otherwise reuse existing branch────────────
        # Preserves commit history and PR continuity.
        # This moves the branch tip to current HEAD without losing commit history.
        # Each run's commit is added on top — PR diff remains meaningful.
        try:
            _retry(lambda: self._repo.create_git_ref(
                ref=f"refs/heads/{branch}",
                sha=head_sha,
            ))
            if DEBUG:
                print(f"[pr_creator] Created branch '{branch}'")
        except GithubException as e:
            if e.status == 422:
                if DEBUG:
                    print(
                        f"[pr_creator] Branch '{branch}' already exists — reusing")
            else:
                raise

        # ── Commit rule to branch ─────────────────────────────────────────
        if content_unchanged:
            if DEBUG:
                print(f"[pr_creator] Content unchanged — skipping commit")
        else:
            try:
                existing_file = self._repo.get_contents(rule_path, ref=branch)
                _retry(lambda: self._repo.update_file(
                    path=rule_path,
                    message=f"feat: {technique_id} detection rule — automated",
                    content=rule_yaml,
                    sha=existing_file.sha,
                    branch=branch,
                ))
                if DEBUG:
                    print(f"[pr_creator] Updated {rule_path}")
            except GithubException as e:
                if e.status == 404:
                    _retry(lambda: self._repo.create_file(
                        path=rule_path,
                        message=f"feat: {technique_id} detection rule — automated",
                        content=rule_yaml,
                        branch=branch,
                    ))
                    if DEBUG:
                        print(f"[pr_creator] Created {rule_path}")
                else:
                    raise

        # ── PR: create or update ──────────────────────────────────────────
        if existing_pr:
            if not body_unchanged:
                existing_pr.edit(
                    title=f"[Auto] {technique_id}: {technique_name} detection rule",
                    body=pr_body,
                )
                if DEBUG:
                    print(
                        f"[pr_creator] Updated PR #{existing_pr.number} title+body")
            pr = existing_pr
        else:
            pr = _retry(lambda: self._repo.create_pull(
                title=f"[Auto] {technique_id}: {technique_name} detection rule",
                body=pr_body,
                head=branch,
                base=default_branch,
            ))
            if DEBUG:
                print(f"[pr_creator] Opened PR #{pr.number}: {pr.html_url}")

        # ── Labels ────────────────────────────────────────────────────────
        labels = ["automated", "detection-rule", technique_id]
        try:
            _ensure_labels_exist(self._repo, labels)
            pr.add_to_labels(*labels)
        except Exception as e:
            if DEBUG:
                print(f"[pr_creator] Failed to add labels: {e}")

        return PRResult(
            pr_url=pr.html_url,
            pr_number=pr.number,
            branch_name=branch,
            rule_filename=filename,
        )
