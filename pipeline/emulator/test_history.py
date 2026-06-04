"""
pipeline/emulator/test_history.py

Persistent cross-run test selection history.

Tracks which Atomic tests have been selected across pipeline runs so the
weighted sampler can deprioritise previously seen tests and heavily penalise
tests that already produced a validated rule. Over time this ensures the
full eligible test pool is exercised and a rule is attempted for every test.

Storage: data/test_selection_history.json
Schema:
  {
    "T1059.001": {
      "<guid>": {"runs_seen": 2, "rule_generated": false},
      ...
    }
  }

Environment:
  CLEAR_TEST_HISTORY=1   wipe history file on next load (takes effect
                         at the start of the following pipeline run)
"""

import json
import os
from pathlib import Path

_HISTORY_PATH = Path("data/test_selection_history.json")

# Cross-run penalty multipliers applied in _select_candidates.
# These combine with the within-run _SEEN_PENALTY via min() — whichever
# is more aggressive wins; penalties do not stack.
PENALTY_CROSS_RUN = 0.35   # seen in a previous run, no rule yet
PENALTY_RULE_GENERATED = 0.15   # test already produced a validated rule


def load() -> dict:
    """
    Load history from disk. Returns empty dict if file does not exist.
    If CLEAR_TEST_HISTORY=1 is set, deletes the file first so this run
    starts with a clean slate.
    """
    if os.getenv("CLEAR_TEST_HISTORY", "").lower() in ("1", "true"):
        if _HISTORY_PATH.exists():
            _HISTORY_PATH.unlink()
            print("[test_history] CLEAR_TEST_HISTORY set — history wiped")
        return {}

    if not _HISTORY_PATH.exists():
        return {}

    try:
        with open(_HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[test_history] Failed to load history ({e}) — starting fresh")
        return {}


def save(history: dict) -> None:
    """
    Persist history to disk. Creates data/ directory if needed.
    Silent on failure — a write error should never crash the pipeline.
    """
    try:
        _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except OSError as e:
        print(f"[test_history] Failed to save history: {e}")


def record_selections(
    history: dict,
    technique_id: str,
    guids: list[str],
) -> None:
    """
    Increment runs_seen for every guid selected in this run.
    Call once per technique at the end of run_emulator(), before save().
    Mutates history in place.
    """
    tech = history.setdefault(technique_id, {})
    for guid in guids:
        if guid not in tech:
            tech[guid] = {"runs_seen": 0, "rule_generated": False}
        tech[guid]["runs_seen"] += 1


def mark_rule_generated(
    history: dict,
    technique_id: str,
    guid: str,
) -> None:
    """
    Mark a test as having produced a validated rule.
    Call from the orchestrator after a successful PR is opened.
    Saves immediately so the flag is not lost if the run exits early.
    Mutates history in place.
    """
    tech = history.setdefault(technique_id, {})
    if guid not in tech:
        tech[guid] = {"runs_seen": 0, "rule_generated": False}
    tech[guid]["rule_generated"] = True
    save(history)
    print(f"[test_history] {technique_id} / {guid}: marked rule_generated")


def get_penalty(history: dict, technique_id: str, guid: str) -> float:
    """
    Return the cross-run penalty multiplier for a test.
      1.0  — never seen
      0.35 — seen in a previous run, no rule yet
      0.15 — test already produced a validated rule
    """
    entry = history.get(technique_id, {}).get(guid)
    if entry is None:
        return 1.0
    if entry.get("rule_generated"):
        return PENALTY_RULE_GENERATED
    if entry.get("runs_seen", 0) > 0:
        return PENALTY_CROSS_RUN
    return 1.0
