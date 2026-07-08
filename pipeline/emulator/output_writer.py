"""
pipeline/emulator/output_writer.py

Writes emulator output to disk after a run_emulator() call.

Outputs:
  corpus/attack/{technique_id}.jsonl        — one LogEvent per line per technique
  corpus/attack/stats/run_{ts}_stats.json   — EmulatorStats for the run

Each JSONL record is the full LogEvent dict with technique_id injected
as an extra field for traceability (the filename already encodes it,
but having it inline makes the detection layer's life easier).

Overwrites existing technique JSONL files on each run — no append.
Stats files are timestamped so every run is preserved.
"""

import json
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

from pipeline.emulator.log_builder import LogEvent


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run_timestamp() -> str:
    """Filesystem-safe UTC timestamp: 20250101_143000"""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ─── Writers ──────────────────────────────────────────────────────────────────

def write_log_stream(
    log_stream: dict[str, list[LogEvent]],
    output_dir: Path,
) -> dict[str, Path]:
    """
    Write one JSONL file per technique to output_dir.

    - Skips techniques with zero events (no empty files written)
    - Overwrites existing file for the same technique_id
    - Each line: full LogEvent fields + injected technique_id

    Returns:
        dict[technique_id, Path] of files actually written.
        Techniques with no events are absent from this dict.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    for technique_id, events in log_stream.items():
        if not events:
            continue

        out_path = output_dir / f"{technique_id}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for event in events:
                record = event.model_dump(exclude_none=True)
                record["technique_id"] = technique_id
                f.write(json.dumps(record) + "\n")

        written[technique_id] = out_path
        print(
            f"[output_writer] {technique_id}: {len(events)} event(s) → {out_path}")

    return written


def write_stats(
    stats,              # EmulatorStats dataclass — no import to avoid circular dep
    stats_dir: Path,
) -> Path:
    """
    Write run stats to a timestamped JSON file in stats_dir.
    Every run produces a new file — nothing is overwritten.

    Returns:
        Path to the stats file written.
    """
    stats_dir.mkdir(parents=True, exist_ok=True)

    out_path = stats_dir / f"run_{_run_timestamp()}_stats.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(stats), f, indent=2)

    print(f"[output_writer] Stats → {out_path}")
    return out_path
