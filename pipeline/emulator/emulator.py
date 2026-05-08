"""
pipeline/emulator/emulator.py

Orchestrates the full emulation chain for a list of ATT&CK techniques:
  stix_loader → atomic_loader → atomic_cleaner
  → interpret_procedure → build_log_event
  → LogStream: dict[technique_id, list[LogEvent]]

Usage:
  from pipeline.emulator.emulator import run_emulator

  # reads config/techniques.yaml
  log_stream, stats = run_emulator()

  # explicit list (useful for tests and one-off runs)
  log_stream, stats = run_emulator(technique_ids=["T1059.001", "T1547.001"])

Environment:
  PIPELINE_DEBUG=1   enable per-test debug output
"""

import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path

from pipeline.data.stix_loader import lookup_technique
from pipeline.data.atomic_loader import load_tests_for_technique_with_fallback
from pipeline.data.atomic_cleaner import clean_test
from pipeline.emulator.procedure_interpreter import interpret_procedure, build_log_event
from pipeline.emulator.log_builder import LogEvent
from pipeline.emulator.output_writer import write_log_stream, write_stats

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")
_CONFIG_PATH = Path("config/techniques.yaml")
_MAX_TESTS_PER_TECHNIQUE = 4       # absolute cap (no selected guid)
_MAX_TESTS_WITH_SELECTION = 2      # selected test + 1 diverse test per iteration


def _dbg(msg: str) -> None:
    if _DEBUG:
        print(f"[emulator] {msg}")


# ─── Run stats ────────────────────────────────────────────────────────────────

@dataclass
class EmulatorStats:
    """
    Counters collected during a single run_emulator() call.
    Drops are tracked at each gate so you can see where events are lost.
    """
    techniques_attempted: int = 0
    techniques_with_events: int = 0
    tests_attempted: int = 0
    tests_skipped_no_clean: int = 0       # clean_test returned None
    tests_with_unresolved_vars: int = 0     # has_unresolved_vars == True
    events_generated: int = 0
    # technique_id → event count
    per_technique: dict = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            "\n── Emulator Run Stats ──────────────────────────────",
            f"  Techniques attempted         : {self.techniques_attempted}",
            f"  Techniques with ≥1 event     : {self.techniques_with_events}",
            f"  Tests attempted              : {self.tests_attempted}",
            f"  Tests skipped (no clean)     : {self.tests_skipped_no_clean}",
            f"  Tests skipped (unresolved)   : {self.tests_with_unresolved_vars}",
            f"  Events generated             : {self.events_generated}",
            "  Per-technique breakdown:",
        ]
        for tid, count in self.per_technique.items():
            marker = "✓" if count > 0 else "✗"
            lines.append(f"    {marker} {tid}: {count} event(s)")
        lines.append("────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─── Config ───────────────────────────────────────────────────────────────────

def _load_technique_ids(config_path: Path = _CONFIG_PATH) -> list[str]:
    """
    Load technique IDs from config/techniques.yaml.

    Expected format:
      techniques:
        - T1059.001
        - T1547.001
        - T1112

    Raises FileNotFoundError if the file is missing.
    Raises ValueError if the file exists but contains no technique IDs.
    """
    if not config_path.exists():
        raise FileNotFoundError(
            f"techniques.yaml not found at '{config_path}'. "
            "Create it or pass technique_ids explicitly to run_emulator()."
        )
    with open(config_path) as f:
        data = yaml.safe_load(f)

    ids = data.get("techniques", [])
    if not ids:
        raise ValueError(
            f"No technique IDs found under 'techniques:' key in {config_path}")

    return [str(t) for t in ids]


# ─── Test selection ───────────────────────────────────────────────────────────

def _select_tests(
    technique_id: str,
    metadata,
    stats: EmulatorStats,
    selected_guid: str | None = None,
) -> list:
    """
    Load all Atomic tests for a technique, clean each one, and return up to
    _MAX_TESTS_PER_TECHNIQUE that are ready for LLM interpretation.

    Skips:
      - Tests where clean_test returns None (no commands survive cleaning)

    atomic_loader already pre-filters for: Windows platform, non-manual executor,
    non-empty command. No need to re-check those here.

    If selected_guid is provided (attacker agent made a selection):
      - Selected test is always first
      - One additional diverse test included for breadth
      - Cap: _MAX_TESTS_WITH_SELECTION
    Otherwise:
      - Cap: _MAX_TESTS_PER_TECHNIQUE
    """
    raw_tests = load_tests_for_technique_with_fallback(technique_id)
    if not raw_tests:
        _dbg(f"{technique_id}: no atomic tests returned by loader")
        return []

    cap = _MAX_TESTS_WITH_SELECTION if selected_guid else _MAX_TESTS_PER_TECHNIQUE
    cleaned_all = []

    for test in raw_tests:
        stats.tests_attempted += 1
        cleaned = clean_test(test, metadata)

        if cleaned is None:
            _dbg(
                f"{technique_id} / '{test.test_name}': clean_test returned None — skipping")
            stats.tests_skipped_no_clean += 1
            continue

        if cleaned.has_unresolved_vars:
            _dbg(
                f"{technique_id} / '{test.test_name}': unresolved vars remain — "
                f"passing to LLM for interpretation")
            stats.tests_with_unresolved_vars += 1
            continue

        cleaned_all.append((test.test_guid, cleaned))

    if not cleaned_all:
        return []

    selected = []
    selected_guids_seen = set()

    # If attacker selected a specific test, put it first
    if selected_guid:
        for guid, cleaned in cleaned_all:
            if guid == selected_guid:
                selected.append(cleaned)
                selected_guids_seen.add(guid)
                _dbg(
                    f"{technique_id} / '{cleaned.test_name}': "
                    f"selected (attacker choice, 1/{cap})")
                break

    # Fill remaining slots with diverse tests (skip already selected)
    for guid, cleaned in cleaned_all:
        if len(selected) >= cap:
            break
        if guid in selected_guids_seen:
            continue
        selected.append(cleaned)
        selected_guids_seen.add(guid)
        _dbg(
            f"{technique_id} / '{cleaned.test_name}': "
            f"selected ({len(selected)}/{cap})")

    return selected

# ─── Per-technique emulation ──────────────────────────────────────────────────


def _emulate_technique(
    technique_id: str,
    evasion_hints: dict | None,
    stats: EmulatorStats,
    selected_test_guids: dict[str, str] | None = None,
) -> list[LogEvent]:
    """
    Run the full emulation chain for a single technique.
    Returns a (possibly empty) list of LogEvents — never raises.
    """
    metadata = lookup_technique(technique_id)
    if metadata is None:
        print(
            f"[emulator] {technique_id}: not found in STIX bundle — skipping")
        return []

    selected_guid = selected_test_guids.get(
        technique_id) if selected_test_guids else None
    cleaned_tests = _select_tests(
        technique_id, metadata, stats, selected_guid=selected_guid)
    if not cleaned_tests:
        _dbg(f"{technique_id}: no valid tests after selection — 0 events")
        return []

    # evasion_hints is keyed by technique_id — None until attacker agent wired in Phase 3
    hints = evasion_hints.get(technique_id) if evasion_hints else None

    events = []

    for i, cleaned in enumerate(cleaned_tests):
        _dbg(f"{technique_id} / '{cleaned.test_name}': calling interpret_procedure")

        test_hints = hints if i == 0 else None
        interpretation = interpret_procedure(cleaned, evasion_hints=test_hints)

        log_event = build_log_event(
            interpretation=interpretation,
            procedure_text=cleaned.formatted_input,
            evasion_hints=hints,
        )

        if log_event is not None:
            events.append(log_event)
            _dbg(
                f"{technique_id} / '{cleaned.test_name}': "
                f"LogEvent generated (EID {log_event.EventID}, {log_event.event_type})"
            )
        else:
            _dbg(
                f"{technique_id} / '{cleaned.test_name}': build_log_event returned None — dropped")

    return events


# ─── Public interface ─────────────────────────────────────────────────────────

def run_emulator(
    technique_ids: list[str] | None = None,
    evasion_hints: dict[str, dict] | None = None,
    selected_test_guids: dict[str, str] | None = None,
    # pass None to suppress file output
    output_dir: Path | None = Path("corpus/attack"),
) -> tuple[dict[str, list[LogEvent]], EmulatorStats]:
    """
    Run emulation across all target techniques.

    Args:
        technique_ids:      Explicit list of ATT&CK technique IDs.
                            If None, reads from config/techniques.yaml.
        evasion_hints:      Per-technique evasion context from AttackerAgent.
                            Keyed by technique_id — Sysmon field name → mutated value.
                            Pass None to run base procedures without mutation.
        selected_test_guids: dict[technique_id, test_guid] from extract_emulator_inputs().
                             Attacker-selected test sorted first, cap reduced to 2 per technique.
                             Pass None to run all tests up to _MAX_TESTS_PER_TECHNIQUE.
        output_dir:         Root directory for JSONL output and stats.
                            Writes to:
                                {output_dir}/{technique_id}.jsonl
                                {output_dir}/stats/run_{ts}_stats.json
                            Pass None to skip all file output (useful in tests).

    Returns:
        log_stream:  dict[technique_id, list[LogEvent]]
                     Every technique has an entry, even if its list is empty.
        stats:       EmulatorStats with full run summary.
    """
    if technique_ids is None:
        technique_ids = _load_technique_ids()

    stats = EmulatorStats()
    log_stream: dict[str, list[LogEvent]] = {}

    for technique_id in technique_ids:
        stats.techniques_attempted += 1
        print(f"[emulator] Processing {technique_id}...")

        events = _emulate_technique(
            technique_id, evasion_hints, stats, selected_test_guids=selected_test_guids)

        log_stream[technique_id] = events
        stats.per_technique[technique_id] = len(events)
        stats.events_generated += len(events)

        if events:
            stats.techniques_with_events += 1

        print(f"[emulator] {technique_id}: {len(events)} event(s)")

    print(stats.summary())

    # ─── write output if output_dir provided ───────────────────────
    if output_dir is not None:
        output_dir = Path(output_dir)
        write_log_stream(log_stream, output_dir)
        write_stats(stats, output_dir / "stats")

    return log_stream, stats
