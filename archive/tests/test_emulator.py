"""
tests/test_emulator.py

Purpose:
--------
Unit tests for emulator orchestration layer (Phase 1.13).

Scope:
------
- Tests ONLY control flow and orchestration logic
- All external dependencies are mocked:
    - STIX lookup
    - Atomic loader
    - Cleaner
    - LLM interpreter
    - Log builder

Why this matters:
-----------------
This file ensures:
1. Pipeline never crashes on bad inputs
2. Skips happen correctly (clean_test=None, unresolved vars, etc.)
3. Stats are accurate (critical for gap analysis later)
4. Output structure is stable and predictable

NOTE:
-----
These are NOT integration tests.
No real YAML, STIX, or LLM calls are used.

Run:
----
pytest tests/test_emulator.py -v
"""

import pytest


class DummyTest:
    def __init__(self, name="test"):
        self.test_name = name


class DummyCleaned:
    def __init__(self, name="cleaned", unresolved=False):
        self.test_name = name
        self.has_unresolved_vars = unresolved
        self.formatted_input = "powershell.exe -enc SQBFAFgA"


# =============================================================================
# BASIC END-TO-END FLOW (MOCKED)
# =============================================================================

def test_run_emulator_basic_flow(monkeypatch):
    """Full happy path: 1 technique → 2 cleaned tests → 2 events"""

    from pipeline.emulator.emulator import run_emulator

    def mock_lookup(tid):
        return object()

    def mock_select(*args, **kwargs):
        return [DummyCleaned("c1"), DummyCleaned("c2")]

    def mock_interpret(cleaned, evasion_hints=None):
        return {
            "EventID": 1,
            "event_type": "process_creation",
            "fields": {
                "Image": "cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
            },
            "confidence": "high",
        }

    def mock_build(*args, **kwargs):
        from pipeline.emulator.log_builder import LogEvent
        return LogEvent(
            timestamp="now",
            host="x",
            user="y",
            EventID=1,
            event_type="process_creation",
            Image="cmd.exe",
            CommandLine="cmd.exe /c whoami",
        )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.lookup_technique", mock_lookup)
    monkeypatch.setattr(
        "pipeline.emulator.emulator._select_tests", mock_select)
    monkeypatch.setattr(
        "pipeline.emulator.emulator.interpret_procedure", mock_interpret)
    monkeypatch.setattr(
        "pipeline.emulator.emulator.build_log_event", mock_build)

    log_stream, stats = run_emulator(["T1059.001"])

    assert "T1059.001" in log_stream
    assert len(log_stream["T1059.001"]) == 2
    assert stats.events_generated == 2
    assert stats.techniques_with_events == 1


# =============================================================================
# FAILURE / SKIP PATHS
# =============================================================================

def test_emulate_technique_missing_metadata(monkeypatch):
    """Technique not found in STIX → should skip cleanly"""

    from pipeline.emulator.emulator import _emulate_technique, EmulatorStats

    monkeypatch.setattr(
        "pipeline.emulator.emulator.lookup_technique", lambda x: None)

    stats = EmulatorStats()
    events = _emulate_technique("T9999", None, stats)

    assert events == []


def test_no_atomic_tests(monkeypatch):
    """Atomic loader returns nothing → no tests selected"""

    from pipeline.emulator.emulator import _select_tests, EmulatorStats

    monkeypatch.setattr(
        "pipeline.emulator.emulator.load_tests_for_technique",
        lambda x: [],
    )

    stats = EmulatorStats()
    result = _select_tests("T1059.001", object(), stats)

    assert result == []


def test_clean_test_none_skipped(monkeypatch):
    """clean_test returns None → skipped + stat increment"""

    from pipeline.emulator.emulator import _select_tests, EmulatorStats

    class Dummy:
        test_name = "bad test"

    monkeypatch.setattr(
        "pipeline.emulator.emulator.load_tests_for_technique",
        lambda x: [Dummy()],
    )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.clean_test",
        lambda t, m: None,
    )

    stats = EmulatorStats()
    result = _select_tests("T1059.001", object(), stats)

    assert result == []
    assert stats.tests_skipped_no_clean == 1


def test_unresolved_vars_skipped(monkeypatch):
    """cleaned.has_unresolved_vars == True → skipped"""

    from pipeline.emulator.emulator import _select_tests, EmulatorStats

    class Cleaned:
        has_unresolved_vars = True
        test_name = "bad vars"

    monkeypatch.setattr(
        "pipeline.emulator.emulator.load_tests_for_technique",
        lambda x: [DummyTest()],
    )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.clean_test",
        lambda t, m: Cleaned(),
    )

    stats = EmulatorStats()
    result = _select_tests("T1059.001", object(), stats)

    assert result == []
    assert stats.tests_skipped_unresolved == 1


def test_build_log_event_none_dropped(monkeypatch):
    """LLM output invalid → build_log_event returns None → dropped"""

    from pipeline.emulator.emulator import _emulate_technique, EmulatorStats

    monkeypatch.setattr(
        "pipeline.emulator.emulator.lookup_technique", lambda x: object())
    monkeypatch.setattr(
        "pipeline.emulator.emulator._select_tests",
        lambda *args: [DummyCleaned()],
    )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.interpret_procedure",
        lambda *args, **kwargs: {},
    )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.build_log_event",
        lambda *args, **kwargs: None,
    )

    stats = EmulatorStats()
    events = _emulate_technique("T1059.001", None, stats)

    assert events == []


# =============================================================================
# LIMITING / CONTROL LOGIC
# =============================================================================

def test_max_tests_limit(monkeypatch):
    """Ensure _MAX_TESTS_PER_TECHNIQUE cap is enforced"""

    from pipeline.emulator.emulator import _select_tests, EmulatorStats, _MAX_TESTS_PER_TECHNIQUE

    class Cleaned:
        has_unresolved_vars = False
        test_name = "ok"

    monkeypatch.setattr(
        "pipeline.emulator.emulator.load_tests_for_technique",
        lambda x: [DummyTest()] * 10,
    )

    monkeypatch.setattr(
        "pipeline.emulator.emulator.clean_test",
        lambda t, m: Cleaned(),
    )

    stats = EmulatorStats()
    result = _select_tests("T1059.001", object(), stats)

    assert len(result) == _MAX_TESTS_PER_TECHNIQUE


# =============================================================================
# OUTPUT CONTRACT
# =============================================================================

def test_all_techniques_present_in_output(monkeypatch):
    """Every technique must exist in output dict (even if empty)"""

    from pipeline.emulator.emulator import run_emulator

    monkeypatch.setattr(
        "pipeline.emulator.emulator._emulate_technique",
        lambda *args: [],
    )

    log_stream, _ = run_emulator(["T1", "T2"])

    assert "T1" in log_stream
    assert "T2" in log_stream
    assert log_stream["T1"] == []
    assert log_stream["T2"] == []


# =============================================================================
# STATS INTEGRITY
# =============================================================================

def test_stats_consistency(monkeypatch):
    """Stats must reflect actual generated events"""

    from pipeline.emulator.emulator import run_emulator

    monkeypatch.setattr(
        "pipeline.emulator.emulator._emulate_technique",
        lambda *args: [1, 2, 3],
    )

    log_stream, stats = run_emulator(["T1"])

    assert stats.events_generated == 3
    assert stats.per_technique["T1"] == 3
    assert stats.techniques_with_events == 1

# =============================================================================
# TECHNIQUE IDs LOADS
# =============================================================================


def test_load_technique_ids_valid(tmp_path):
    from pipeline.emulator.emulator import _load_technique_ids

    config = tmp_path / "techniques.yaml"
    config.write_text("""
techniques:
  - T1059.001
  - T1547.001
""")

    ids = _load_technique_ids(config)

    assert ids == ["T1059.001", "T1547.001"]


def test_load_technique_ids_missing_file(tmp_path):
    from pipeline.emulator.emulator import _load_technique_ids

    missing = tmp_path / "nope.yaml"

    with pytest.raises(FileNotFoundError):
        _load_technique_ids(missing)


def test_load_technique_ids_empty_list(tmp_path):
    from pipeline.emulator.emulator import _load_technique_ids

    config = tmp_path / "techniques.yaml"
    config.write_text("techniques: []")

    with pytest.raises(ValueError):
        _load_technique_ids(config)
