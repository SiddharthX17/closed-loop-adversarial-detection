"""
pipeline/api/app.py
FastAPI service for the closed-loop adversarial detection pipeline.

Endpoints:
    POST /run               — trigger a pipeline run (non-blocking, returns run_id)
    GET  /results/{run_id}  — poll run status / fetch completed results
    GET  /health            — service status + last run summary
"""

from pipeline.orchestrator import Orchestrator
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ADD right after that line:

# ---------------------------------------------------------------------------
# Auth — two separate shared secrets, different trust tiers.
# PIPELINE_RUN_SECRET gates the cost-incurring action (/run) specifically.
# PIPELINE_VIEWER_SECRET gates read-only endpoints (/health, /results) —
# lower stakes, safe to share more loosely.
# ---------------------------------------------------------------------------


def require_run_secret(x_pipeline_run_secret: str = Header(default="")) -> None:
    expected = os.getenv("PIPELINE_RUN_SECRET", "")

    print(
        f"[AUTH] expected_len={len(expected)} "
        f"received_len={len(x_pipeline_run_secret)} "
        f"match={expected == x_pipeline_run_secret}"
    )

    if not expected or x_pipeline_run_secret != expected:
        raise HTTPException(
            status_code=401, detail="Invalid or missing run secret")


def require_viewer_secret(x_pipeline_viewer_secret: str = Header(default="")) -> None:
    expected = os.getenv("PIPELINE_VIEWER_SECRET", "")
    if not expected or x_pipeline_viewer_secret != expected:
        raise HTTPException(
            status_code=401, detail="Invalid or missing viewer secret")


# NOTE: Orchestrator constructor signature must match after the orchestrator refactor.
# Expected: Orchestrator(technique_ids: list[str] | None, max_iterations: int)

app = FastAPI(
    title="Closed-Loop Adversarial Detection Pipeline",
    description=(
        "Simulates attacker behaviour, generates Sysmon log events, "
        "evaluates Sigma rules, identifies detection gaps, and generates "
        "validated candidate rules via LLM — no human in the loop until PR review."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

# In-memory run store: run_id -> run record dict
# Survives the request lifecycle but not a container restart.
# Completed runs are also persisted to RUN_HISTORY_PATH.
_runs: dict[str, dict] = {}
_runs_lock = Lock()

# One pipeline run at a time — Cloud Run single-instance, and the pipeline
# is CPU/API-bound enough that parallelism buys nothing.
_executor = ThreadPoolExecutor(max_workers=1)

RUN_HISTORY_PATH = Path("data/run_history.json")
RULES_DIR = Path("rules")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class RunRequest(BaseModel):
    # None = use config/techniques.yaml
    technique_ids: Optional[list[str]] = None
    max_iterations: int = Field(default=1, ge=1, le=3)


class RunResponse(BaseModel):
    run_id: str
    status: str
    started_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_run_history() -> dict:
    if RUN_HISTORY_PATH.exists():
        try:
            return json.loads(RUN_HISTORY_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_run_to_history(run_id: str, record: dict) -> None:
    RUN_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    history = _load_run_history()
    history[run_id] = record
    RUN_HISTORY_PATH.write_text(json.dumps(history, indent=2, default=str))


def _execute_pipeline(
    run_id: str,
    technique_ids: Optional[list[str]],
    max_iterations: int,
) -> None:
    """
    Runs in a ThreadPoolExecutor worker. Mutates _runs[run_id] on completion
    and persists to run_history.json.

    NOTE: If Orchestrator raises on construction (bad technique IDs, missing
    config), the run is marked failed immediately — no silent hang.
    """
    try:
        # VERIFY: constructor args must match orchestrator.py after refactor
        orchestrator = Orchestrator(
            technique_ids=technique_ids,
            max_iterations=max_iterations,
        )
        result = orchestrator.run()

        record_update = {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }

    except Exception as exc:  # noqa: BLE001
        record_update = {
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }

    with _runs_lock:
        _runs[run_id].update(record_update)

    _save_run_to_history(run_id, _runs[run_id])


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/run", response_model=RunResponse, status_code=202)
def trigger_run(request: RunRequest, _: None = Depends(require_run_secret)):
    """
    Trigger a full pipeline execution.

    Returns immediately with a run_id. Poll /results/{run_id} for status.
    Rejects if a run is already in progress (409).
    """
    with _runs_lock:
        active = [r for r in _runs.values() if r["status"] == "running"]
        if active:
            raise HTTPException(
                status_code=409,
                detail=f"Pipeline already running. run_id: {active[0]['run_id']}",
            )

    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    with _runs_lock:
        _runs[run_id] = {
            "run_id": run_id,
            "status": "running",
            "started_at": started_at,
            "technique_ids": request.technique_ids,
            "max_iterations": request.max_iterations,
        }

    _executor.submit(_execute_pipeline, run_id,
                     request.technique_ids, request.max_iterations)

    return RunResponse(run_id=run_id, status="running", started_at=started_at)


@app.get("/results/{run_id}")
def get_results(run_id: str, _: None = Depends(require_viewer_secret)):
    """
    Returns the full result record for a run.

    Status values: "running" | "completed" | "failed"
    Checks in-memory store first, then falls back to persisted history
    (covers the case where the container restarted after a completed run).
    """
    with _runs_lock:
        if run_id in _runs:
            return JSONResponse(content=_runs[run_id])

    history = _load_run_history()
    if run_id in history:
        return JSONResponse(content=history[run_id])

    raise HTTPException(status_code=404, detail=f"run_id {run_id!r} not found")


@app.get("/health")
def health(_: None = Depends(require_viewer_secret)):
    """
    Service status, active run, generated rule count.
    """
    # Count from local rules/ dir — reflects state post-rules_sync.
    # Before first run: shows baked-in image count.
    # After any run: current synced count from GitHub main.
    rules_count = len(list(RULES_DIR.rglob("*.yml")))

    with _runs_lock:
        active_run_id = next(
            (r["run_id"] for r in _runs.values() if r["status"] == "running"),
            None,
        )

    return {
        "status": "ok",
        "active_run": active_run_id,
        "rules_count": rules_count,
    }
