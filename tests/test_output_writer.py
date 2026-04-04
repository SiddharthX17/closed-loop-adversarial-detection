"""
test_output_writer.py

Tests for Phase 1.14 output layer.

What we test (and why):
- write_log_stream:
    * skips empty techniques → avoids useless files + cleaner Phase 2
    * overwrites correctly → deterministic runs (no stale data)
    * technique_id injected → required for traceability in detection layer
- write_stats:
    * file created → pipeline completeness
    * timestamped filename → no overwrites across runs
    * contents match EmulatorStats → correctness
- run_emulator(output_dir=None):
    * ensures NO disk writes happen when disabled
    * ensures return values are unchanged (no side effects)

These are contract tests — not testing Python I/O, only your logic.
"""

import json
import os
import re
from pathlib import Path
from dataclasses import dataclass

import pytest

from pipeline.emulator.output_writer import write_log_stream, write_stats


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DummyStats:
    total_events: int = 5
    dropped_events: int = 2


class DummyLogEvent:
    """Minimal stand-in for Pydantic LogEvent"""

    def __init__(self, data: dict):
        self._data = data

    def model_dump(self):
        return self._data


def make_event(i=1):
    return DummyLogEvent({
        "EventID": 1,
        "Image": f"powershell_{i}.exe",
        "CommandLine": "powershell.exe -enc AAA",
    })


# ─────────────────────────────────────────────────────────────────────────────
# write_log_stream tests
# ─────────────────────────────────────────────────────────────────────────────

def test_write_log_stream_skips_empty(tmp_path):
    log_stream = {
        "T1000": [],
        "T2000": [make_event()],
    }

    written = write_log_stream(log_stream, tmp_path)

    assert "T1000" not in written, "Empty technique should not create a file"
    assert "T2000" in written, "Non-empty technique should be written"

    assert (tmp_path / "T1000.jsonl").exists() is False
    assert (tmp_path / "T2000.jsonl").exists() is True


def test_write_log_stream_injects_technique_id(tmp_path):
    log_stream = {"T1059.001": [make_event()]}

    write_log_stream(log_stream, tmp_path)

    file_path = tmp_path / "T1059.001.jsonl"
    line = file_path.read_text().strip()
    record = json.loads(line)

    assert record["technique_id"] == "T1059.001"


def test_write_log_stream_overwrites_existing_file(tmp_path):
    log_stream = {"T1000": [make_event(1)]}
    write_log_stream(log_stream, tmp_path)

    # overwrite with different data
    log_stream = {"T1000": [make_event(2)]}
    write_log_stream(log_stream, tmp_path)

    file_path = tmp_path / "T1000.jsonl"
    lines = file_path.read_text().strip().splitlines()

    assert len(lines) == 1, "File should be overwritten, not appended"
    record = json.loads(lines[0])
    assert "powershell_2.exe" in record["Image"]


def test_write_log_stream_multiple_events(tmp_path):
    log_stream = {"T1000": [make_event(1), make_event(2)]}

    write_log_stream(log_stream, tmp_path)

    file_path = tmp_path / "T1000.jsonl"
    lines = file_path.read_text().strip().splitlines()

    assert len(lines) == 2, "Each event should be one line"


# ─────────────────────────────────────────────────────────────────────────────
# write_stats tests
# ─────────────────────────────────────────────────────────────────────────────

def test_write_stats_creates_file(tmp_path):
    stats = DummyStats()

    out_path = write_stats(stats, tmp_path)

    assert out_path.exists(), "Stats file should be created"


def test_write_stats_filename_contains_timestamp(tmp_path):
    stats = DummyStats()

    out_path = write_stats(stats, tmp_path)

    # matches run_YYYYMMDD_HHMMSS_stats.json
    pattern = r"run_\d{8}_\d{6}_stats\.json"
    assert re.search(
        pattern, out_path.name), f"Filename not timestamped: {out_path.name}"


def test_write_stats_content_matches(tmp_path):
    stats = DummyStats(total_events=10, dropped_events=3)

    out_path = write_stats(stats, tmp_path)

    data = json.loads(out_path.read_text())

    assert data["total_events"] == 10
    assert data["dropped_events"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# run_emulator(output_dir=None) behavior
# ─────────────────────────────────────────────────────────────────────────────

def test_run_emulator_no_output_dir_no_writes(monkeypatch):
    """
    run_emulator(output_dir=None) should NOT call write_log_stream or write_stats
    """

    from pipeline.emulator import emulator

    called = {
        "log_stream": False,
        "stats": False,
    }

    def fake_write_log_stream(*args, **kwargs):
        called["log_stream"] = True

    def fake_write_stats(*args, **kwargs):
        called["stats"] = True

    monkeypatch.setattr(emulator, "write_log_stream", fake_write_log_stream)
    monkeypatch.setattr(emulator, "write_stats", fake_write_stats)

    # Minimal mocks to let run_emulator execute safely
    monkeypatch.setattr(
        emulator,
        "_load_technique_ids",
        lambda *a, **k: []
    )

    monkeypatch.setattr(
        emulator,
        "_select_tests",
        lambda *a, **k: []
    )

    emulator.run_emulator(output_dir=None)

    assert not called["log_stream"], "write_log_stream should NOT be called"
    assert not called["stats"], "write_stats should NOT be called"


def test_run_emulator_output_dir_triggers_writes(monkeypatch, tmp_path):
    """
    run_emulator(output_dir=...) should call write_log_stream and write_stats
    """

    from pipeline.emulator import emulator

    called = {
        "log_stream": False,
        "stats": False,
    }

    def fake_write_log_stream(*args, **kwargs):
        called["log_stream"] = True

    def fake_write_stats(*args, **kwargs):
        called["stats"] = True

    monkeypatch.setattr(emulator, "write_log_stream", fake_write_log_stream)
    monkeypatch.setattr(emulator, "write_stats", fake_write_stats)

    # Minimal mocks
    monkeypatch.setattr(
        emulator,
        "_load_technique_ids",
        lambda *a, **k: []
    )

    monkeypatch.setattr(
        emulator,
        "_select_tests",
        lambda *a, **k: []
    )

    emulator.run_emulator(output_dir=tmp_path)

    assert called["log_stream"], "write_log_stream should be called"
    assert called["stats"], "write_stats should be called"
