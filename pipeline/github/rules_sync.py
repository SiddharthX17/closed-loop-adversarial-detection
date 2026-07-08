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

Skips files whose content already matches what's on disk, compared via
git blob SHA — the directory listing already includes .sha for every
entry at zero extra cost, so an unchanged file costs nothing: no extra
API call, no rewrite, no touched mtime. Only files that actually
differ (or don't exist locally yet) trigger the per-file content fetch
and write.

Failure mode: logs and returns 0. A sync failure should never abort a
pipeline run — better to detect against a (possibly stale) local
snapshot than not run at all.
"""

import hashlib
import os
from pathlib import Path

from github import Github, GithubException
from dotenv import load_dotenv

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


def _git_blob_sha(content: bytes) -> str:
    """
    Git's own blob hashing scheme — sha1("blob {len}\\0{content}").
    Lets a local file be compared directly against GitHub's reported
    .sha without any extra API call.

    Normalises CRLF -> LF before hashing. Rule files are written by
    pr_creator.py via the GitHub API directly (plain Python strings,
    LF only) — but a local checkout on Windows with core.autocrlf
    enabled converts them to CRLF on disk during any git operation
    (clone, checkout, merge). Without normalising, every such file
    permanently mismatches the remote sha and gets rewritten on every
    run regardless of whether its content actually changed.
    """
    normalised = content.replace(b"\r\n", b"\n")
    header = f"blob {len(normalised)}\0".encode()
    return hashlib.sha1(header + normalised).hexdigest()  # noqa: S324 — not crypto, just content identity


def sync_rules_from_github(
    rules_dir: Path,
    repo_name: str | None = None,
    token: str | None = None,
    remote_path: str = "rules",
    ref: str = "main",
) -> int:
    """
    Mirror {remote_path}/ from GitHub (recursively) into rules_dir.

    Returns the number of files actually written (changed or new).
    Returns 0 and logs on any failure — never raises, so a sync hiccup
    never blocks a pipeline run.
    """
    token = token or os.getenv("GITHUB_TOKEN")
    repo_name = repo_name or os.getenv("GITHUB_REPO")

    if not token or not repo_name:
        print("[rules_sync] GITHUB_TOKEN or GITHUB_REPO not set — skipping sync")
        return 0

    try:
        gh = Github(token)
        repo = gh.get_repo(repo_name)
        written, skipped = _sync_dir(repo, remote_path, rules_dir, ref)
        if DEBUG:
            print(
                f"[rules_sync] {written} file(s) updated, "
                f"{skipped} already current"
            )
        return written
    except GithubException as e:
        print(f"[rules_sync] Sync failed (HTTP {e.status}) — "
              f"continuing with local rules as-is")
        return 0
    except Exception as e:
        print(
            f"[rules_sync] Sync failed: {e} — continuing with local rules as-is")
        return 0


def _sync_dir(repo, remote_path: str, local_dir: Path, ref: str) -> tuple[int, int]:
    """
    Recursively mirror a remote directory into local_dir.

    Directory-listing entries already carry .sha at no extra cost, so
    that's checked against the local file's git blob sha first. Only a
    real mismatch (or a file that doesn't exist locally yet) triggers
    the per-file content fetch — directory listings don't carry content
    inline, only a single-file fetch does.

    Returns (written, skipped).
    """
    written = 0
    skipped = 0
    contents = repo.get_contents(remote_path, ref=ref)
    if not isinstance(contents, list):
        contents = [contents]

    local_dir.mkdir(parents=True, exist_ok=True)

    for item in contents:
        local_path = local_dir / item.name
        if item.type == "dir":
            w, s = _sync_dir(repo, item.path, local_path, ref)
            written += w
            skipped += s
            continue

        if local_path.exists():
            if _git_blob_sha(local_path.read_bytes()) == item.sha:
                skipped += 1
                continue

        file_content = repo.get_contents(item.path, ref=ref)
        local_path.write_bytes(file_content.decoded_content)
        written += 1

    return written, skipped
