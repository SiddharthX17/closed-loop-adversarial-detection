"""
pipeline/github/rules_sync.py

Syncs the local rules/ directory tree from GitHub before each pipeline
run, so DetectionEngine never evaluates against a stale local checkout.
Closes the gap where pr_creator.py writes generated rules exclusively
via the GitHub API (no local git operations) — once a PR merges, this
is what actually brings that content back to disk.

Read-only against GitHub — never writes, only reads via the Contents
API and writes to the local filesystem. Same auth pattern as
pr_creator.py (GITHUB_TOKEN / GITHUB_REPO from .env).

Failure mode: logs and returns 0. A sync failure should never abort a
pipeline run — better to detect against a (possibly stale) local
snapshot than not run at all.
"""

import os
from pathlib import Path

from github import Github, GithubException
from dotenv import load_dotenv

load_dotenv()


def sync_rules_from_github(
    rules_dir: Path,
    repo_name: str | None = None,
    token: str | None = None,
    remote_path: str = "rules",
    ref: str = "main",
) -> int:
    """
    Mirror {remote_path}/ from GitHub (recursively) into rules_dir.

    Returns the number of files written. Returns 0 and logs on any
    failure — never raises, so a sync hiccup never blocks a pipeline run.
    """
    token = token or os.getenv("GITHUB_TOKEN")
    repo_name = repo_name or os.getenv("GITHUB_REPO")

    if not token or not repo_name:
        print("[rules_sync] GITHUB_TOKEN or GITHUB_REPO not set — skipping sync")
        return 0

    try:
        gh = Github(token)
        repo = gh.get_repo(repo_name)
        return _sync_dir(repo, remote_path, rules_dir, ref)
    except GithubException as e:
        print(f"[rules_sync] Sync failed (HTTP {e.status}) — "
              f"continuing with local rules as-is")
        return 0
    except Exception as e:
        print(
            f"[rules_sync] Sync failed: {e} — continuing with local rules as-is")
        return 0


def _sync_dir(repo, remote_path: str, local_dir: Path, ref: str) -> int:
    """
    Recursively mirror a remote directory into local_dir.

    Directory-listing entries from the Contents API don't carry file
    content inline — only a single-file fetch does — so each file needs
    its own get_contents() call to retrieve decoded_content.
    """
    count = 0
    contents = repo.get_contents(remote_path, ref=ref)
    if not isinstance(contents, list):
        contents = [contents]

    local_dir.mkdir(parents=True, exist_ok=True)

    for item in contents:
        local_path = local_dir / item.name
        if item.type == "dir":
            count += _sync_dir(repo, item.path, local_path, ref)
        else:
            file_content = repo.get_contents(item.path, ref=ref)
            local_path.write_bytes(file_content.decoded_content)
            count += 1

    return count
