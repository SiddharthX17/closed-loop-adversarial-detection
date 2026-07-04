"""
scripts/trigger_pipeline_run.py

Helper for .github/workflows/pipeline.yml — kept as a real Python script
rather than inline bash/jq in the workflow YAML, per project convention
(nested scripting inside GH Actions YAML has been a recurring source of
errors on this project).

Subcommands, called once each as separate workflow steps:
    trigger     POST /run, write run_id to $GITHUB_OUTPUT
    poll        Poll /results/{run_id} until completed/failed/timeout,
                write status + result_json to $GITHUB_OUTPUT
    summarize   Read result_json, print a markdown summary to stdout
                (workflow redirects this into $GITHUB_STEP_SUMMARY)

Auth: trigger sends X-Pipeline-Run-Secret (the higher-stakes secret,
scoped to the cost-incurring action). poll sends X-Pipeline-Viewer-Secret
(the lower-stakes read-only secret) — matches the two-tier app.py design.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

POLL_INTERVAL_SECONDS = 15
# Workflow-level timeout-minutes is the hard backstop; this is a soft
# internal cap so the script doesn't poll indefinitely if that ever
# changes without this being updated to match.
MAX_POLL_SECONDS = 55 * 60


def _write_output(key: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print(f"[trigger_pipeline_run] (no GITHUB_OUTPUT set) {key}={value}")
        return
    with open(output_path, "a") as f:
        f.write(f"{key}={value}\n")


def _request(method: str, url: str, headers: dict, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # Surface the actual response body in the error — a bare HTTPError
        # str() loses the detail message app.py put in the response.
        body_text = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body_text}") from e


def cmd_trigger() -> None:
    service_url = os.environ["SERVICE_URL"].rstrip("/")
    run_secret = os.environ["RUN_SECRET"]
    technique_ids_raw = os.environ.get("TECHNIQUE_IDS", "").strip()
    max_iterations = int(os.environ.get("MAX_ITERATIONS", "1") or "1")

    payload: dict = {"max_iterations": max_iterations}
    if technique_ids_raw:
        payload["technique_ids"] = [t.strip()
                                    for t in technique_ids_raw.split(",") if t.strip()]

    result = _request(
        "POST",
        f"{service_url}/run",
        headers={"X-Pipeline-Run-Secret": run_secret,
                 "Content-Type": "application/json"},
        body=payload,
    )
    run_id = result["run_id"]
    print(f"[trigger_pipeline_run] Triggered run_id={run_id}")
    _write_output("run_id", run_id)


def cmd_poll() -> None:
    service_url = os.environ["SERVICE_URL"].rstrip("/")
    viewer_secret = os.environ["VIEWER_SECRET"]
    run_id = os.environ["RUN_ID"]

    deadline = time.time() + MAX_POLL_SECONDS
    result = None

    while time.time() < deadline:
        result = _request(
            "GET",
            f"{service_url}/results/{run_id}",
            headers={"X-Pipeline-Viewer-Secret": viewer_secret},
        )
        status = result.get("status")
        print(f"[trigger_pipeline_run] run_id={run_id} status={status}")
        if status in ("completed", "failed"):
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    else:
        result = result or {}
        result["status"] = "timeout"

    _write_output("status", result.get("status", "unknown"))
    _write_output("result_json", json.dumps(result))


def cmd_summarize() -> None:
    raw = os.environ.get("SUMMARY_JSON", "{}")
    result = json.loads(raw) if raw else {}

    lines = ["## Scheduled Pipeline Run\n"]
    lines.append(f"- **Status:** {result.get('status', 'unknown')}")
    lines.append(f"- **Run ID:** {result.get('run_id', 'unknown')}")
    lines.append(f"- **Started:** {result.get('started_at', 'unknown')}")
    lines.append(f"- **Completed:** {result.get('completed_at', 'unknown')}")

    if result.get("status") == "failed":
        lines.append(
            f"\n**Error:** {result.get('error', '(no error message)')}")
    elif result.get("status") == "timeout":
        lines.append(
            f"\n**Timed out waiting for completion** (limit: {MAX_POLL_SECONDS // 60} min)")
    elif result.get("status") == "completed":
        inner = result.get("result", {})
        summary = inner.get("run_summary", {})

        lines.append(
            f"\n**Techniques run:** {summary.get('techniques_run', '?')}")
        lines.append(f"**Gaps found:** {summary.get('gaps_found', '?')}")
        lines.append(
            f"**Rules generated:** {summary.get('rules_generated', '?')}")
        lines.append(
            f"**Rules validated:** {summary.get('rules_validated', '?')}")

        coverage = inner.get("coverage", {})
        if coverage:
            lines.append("\n| Technique | Coverage |")
            lines.append("|---|---|")
            icons = {"full": "✅", "partial": "⚠️",
                     "missed": "❌", "no_rules": "⬜"}
            for tid, status in sorted(coverage.items()):
                lines.append(f"| {tid} | {icons.get(status, '?')} {status} |")

        pr_urls = inner.get("pr_urls", [])
        if pr_urls:
            lines.append(f"\n**PRs opened ({len(pr_urls)}):**")
            for url in pr_urls:
                lines.append(f"  - {url}")
        else:
            lines.append("\n**PRs opened:** 0")

    print("\n".join(lines))


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("trigger", "poll", "summarize"):
        print(
            "Usage: trigger_pipeline_run.py {trigger|poll|summarize}", file=sys.stderr)
        sys.exit(2)

    command = sys.argv[1]
    if command == "trigger":
        cmd_trigger()
    elif command == "poll":
        cmd_poll()
    elif command == "summarize":
        cmd_summarize()


if __name__ == "__main__":
    main()
