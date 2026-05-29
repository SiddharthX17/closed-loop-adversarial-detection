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
import random
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

# In-memory seen-test tracking.
# technique_id → set of test GUIDs selected in prior iterations this run.
# Persists across run_emulator() calls within the same process (i.e. across
# iterations in the orchestrator loop). Reset between top-level pipeline runs
# by calling reset_seen_tests().

_prior_attempts: dict[str, set[str]] = {}


def reset_seen_tests() -> None:
    """
    Clear seen-test history. Call once at the start of each top-level
    pipeline run so separate invocations do not bleed into each other.
    """
    _prior_attempts.clear()


_MAX_CANDIDATES = 3       # tests selected per technique per iteration
_SEEN_PENALTY = 0.4     # weight multiplier for previously selected tests


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


# ── Scoring buckets ────────────────────────────────────────────────────────────
# Each bucket is a frozenset of lowercase keywords. A bucket fires (boolean)
# when ANY keyword is present in the lowercased combined command text.
# Buckets are independent — no intra-bucket stacking.

# HIGH (+0.5 each) — adds a distinct Sysmon field a Sigma rule can key on
_BUCKET_LOLBIN: frozenset[str] = frozenset({
    # LOLBINs
    "certutil", "mshta", "rundll32", "regsvr32", "wmic", "cscript",
    "wscript", "msiexec", "bitsadmin", "odbcconf", "installutil",
    "regasm", "regsvcs", "forfiles", "esentutl", "extrac32", "makecab",
    "mavinject", "ntdsutil", "cmstp", "diskshadow", "dnscmd", "rdrleakdiag",
    "sqldumper", "sqlps", "xwizard", "pcalua", "msdeploy", "findstr",
    "replace", "csc.exe", "vbc",
    # Dual-use / Sysinternals
    "procdump", "psexec", "accesschk",
    # Known offensive tooling and modules
    "mimikatz", "bloodhound", "sharphound", "rubeus", "nanodump",
    "pypykatz", "cobaltstrike", "meterpreter", "empire",
    "powerup", "powerview", "nishang",
})

_BUCKET_OBFUSCATION: frozenset[str] = frozenset({
    "-enc", "-encoded", "-encodedcommand",
    "frombase64string", "tobase64string", "[convert]::",
    "base64", "[char]", "iex(", "invoke-expression",
    "-bxor", "[reflection.assembly]::load", "assembly.load",
})

# MEDIUM (+0.25 each) — enriches the primary signal with additional field dimensions
_BUCKET_NETWORK: frozenset[str] = frozenset({
    "http://", "https://", "ftp://",
    "invoke-webrequest", "iwr", "net.webclient", "[system.net.webclient]",
    "downloadstring", "downloadfile", "invoke-restmethod",
    "start-bitstransfer",
})

_BUCKET_REGISTRY: frozenset[str] = frozenset({
    "hklm:", "hkcu:", "hklm\\", "hkcu\\",
    "reg add", "reg query", "reg delete",
    "new-itemproperty", "set-itemproperty", "get-itemproperty",
    "[microsoft.win32.registry]", "registry::hk",
})

_BUCKET_SPAWN: frozenset[str] = frozenset({
    "cmd /c", "cmd.exe /c", "start-process",
    "invoke-wmimethod", "invoke-cimmethod", "win32_process",
    "new-object -comobject", "createobject",
    "shell.run", "shellexecute", "& $",
})

_BUCKET_POSTEX: frozenset[str] = frozenset({
    # Mimikatz modules
    "sekurlsa::", "lsadump::", "privilege::", "token::",
    # Dump indicators
    "/fullmemdmp", "out-minidump", "dumpcreds",
    # Credential / AD
    "ntds.dit", "dpapi", "masterkeys", "kerberoast", "asreproast",
    # VSS / backup destruction
    "vssadmin delete", "shadowcopy",
    # Certutil abuse flags (not the binary — already in lolbin)
    "-decode", "-urlcache",
    # Process dump
    "minidump",
})

# MINOR (+0.10) — contextual enrichment, low standalone rule specificity
_BUCKET_SUSPPATH: frozenset[str] = frozenset({
    "\\temp\\", "$env:temp", "%temp%",
    "\\appdata\\", "\\programdata\\", "\\users\\public\\",
    "\\windows\\temp\\",
})

# Bucket registry: (keywords, weight, label)
_SCORE_BUCKETS: tuple[tuple[frozenset, float, str], ...] = (
    (_BUCKET_LOLBIN,      0.50, "lolbin"),
    (_BUCKET_OBFUSCATION, 0.50, "obfusc"),
    (_BUCKET_NETWORK,     0.25, "network"),
    (_BUCKET_REGISTRY,    0.25, "registry"),
    (_BUCKET_SPAWN,       0.25, "spawn"),
    (_BUCKET_POSTEX,      0.25, "postex"),
    (_BUCKET_SUSPPATH,    0.10, "susppath"),
)


def _score_complexity(cleaned) -> tuple[float, list[str]]:
    """
    Score a cleaned test's detection value using independent signal buckets.
    Returns (score, fired_labels) so callers can display which buckets fired.

    Threshold: score < 1.0 → drop (base of 1.0 requires at least one command;
    kept as safety net — pre-filtering means this rarely fires).

    Scoring:
      +1.0   base  (test has runnable commands — always present post pre-filter)
      +0.50  per HIGH bucket that fires   (lolbin, obfuscation)
      +0.25  per MEDIUM bucket that fires (network, registry, spawn, postex)
      +0.10  per MINOR bucket that fires  (susppath)

    Each bucket is boolean — fires once regardless of keyword count.
    Max score: 1.0 + 0.5 + 0.5 + 0.25×4 + 0.10 = 3.10
    """
    if not cleaned.commands:
        return 0.0, []

    text = " ".join(cleaned.commands).lower()
    score = 1.0
    fired: list[str] = []

    for keywords, weight, label in _SCORE_BUCKETS:
        if any(kw in text for kw in keywords):
            score += weight
            fired.append(label)

    return score, fired


def _select_candidates(
    cleaned_all: list[tuple[str, object]],
    technique_id: str,
    selected_guid: str | None = None,
) -> list:
    """
    Weighted random sampling without replacement.

    Priority = base_score × seen_penalty × uniform(0.35, 1.0)

    If selected_guid is provided (attacker's choice), that test is guaranteed
    to appear first in the result regardless of its sampled priority. The
    remaining slots are filled by the weighted draw as normal.

    Floor of 0.35 prevents a high-value test from being completely wiped out
    by an unlucky draw while still allowing a seen high-scorer to lose to a
    fresh lower-scorer. All tests scoring >= 1.0 are eligible.

    Seen-test penalty (_SEEN_PENALTY) is multiplicative: depresses weight of
    previously selected tests without permanently excluding them.

    Updates _prior_attempts[technique_id] with the selected GUIDs.
    """
    seen = _prior_attempts.get(technique_id, set())
    pinned: tuple | None = None          # (guid, cleaned) for selected_guid
    candidates: list[tuple[float, str, list[str], object]] = []

    for guid, cleaned in cleaned_all:
        score, fired = _score_complexity(cleaned)
        if score < 1.0:
            _dbg(f"  {cleaned.test_name}: score={score:.2f} < 1.0 — dropped")
            continue

        if selected_guid and guid == selected_guid:
            pinned = (guid, cleaned)
            _dbg(f"  {cleaned.test_name}: pinned (attacker selection)")
            continue                     # exclude from random draw

        weight = score * (_SEEN_PENALTY if guid in seen else 1.0)
        priority = weight * random.uniform(0.35, 1.0)
        candidates.append((priority, guid, fired, cleaned))
        _dbg(
            f"  {cleaned.test_name}: base={score:.2f} "
            f"{'(seen) ' if guid in seen else ''}"
            f"buckets={fired} weight={weight:.2f} priority={priority:.3f}"
        )

    candidates.sort(reverse=True)
    fill_slots = _MAX_CANDIDATES - (1 if pinned else 0)
    top = candidates[:fill_slots]

    seen_set = _prior_attempts.setdefault(technique_id, set())

    result: list = []
    if pinned:
        seen_set.add(pinned[0])
        result.append(pinned[1])

    for _, guid, _, cleaned in top:
        seen_set.add(guid)
        result.append(cleaned)

    return result if result else []


def _select_tests(
    technique_id: str,
    metadata,
    stats: EmulatorStats,
    selected_guid: str | None = None,   # kept for API compatibility
) -> list:
    """
    Load, clean, and select tests via weighted random sampling.

    selected_guid is accepted for API compatibility but no longer forces
    priority — rotation is handled by _select_candidates.

    Skips tests where clean_test returns None or has_unresolved_vars.
    All remaining tests scoring >= 1.0 enter the weighted draw.
    Up to _MAX_CANDIDATES are returned.
    """
    raw_tests = load_tests_for_technique_with_fallback(technique_id)
    if not raw_tests:
        _dbg(f"{technique_id}: no atomic tests returned by loader")
        return []

    cleaned_all: list[tuple[str, object]] = []

    for test in raw_tests:
        stats.tests_attempted += 1
        cleaned = clean_test(test, metadata)

        if cleaned is None:
            _dbg(
                f"{technique_id} / '{test.test_name}': clean_test returned None — skipping")
            stats.tests_skipped_no_clean += 1
            continue

        if cleaned.has_unresolved_vars:
            _dbg(f"{technique_id} / '{test.test_name}': unresolved vars — skipping")
            stats.tests_with_unresolved_vars += 1
            continue

        cleaned_all.append((test.test_guid, cleaned))

    if not cleaned_all:
        return []

    selected = _select_candidates(
        cleaned_all, technique_id, selected_guid=selected_guid)

    for i, cleaned in enumerate(selected):
        _dbg(
            f"{technique_id} / '{cleaned.test_name}': selected ({i + 1}/{len(selected)})")

    return selected

# ─── Per-technique emulation ──────────────────────────────────────────────────


def _emulate_technique(
    technique_id: str,
    evasion_hints: dict | None,
    stats: EmulatorStats,
    selected_test_guids: dict[str, str] | None = None,
    evasion_hints_v2: dict | None = None,
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

    hints = evasion_hints.get(technique_id) if evasion_hints else None
    hints_v2 = evasion_hints_v2.get(technique_id) if evasion_hints_v2 else None

    events = []

    # Always: attacker picks one test (pinned first by _select_candidates),
    # generate base + mutated variant from it. 1 test × 2 events per iteration.
    tests_to_emit = cleaned_tests[:1]
    hint_sets = [hints, hints_v2] if hints_v2 is not None else [hints]

    for cleaned in tests_to_emit:
        for variant_idx, variant_hints in enumerate(hint_sets):
            _dbg(
                f"{technique_id} / '{cleaned.test_name}': "
                f"calling interpret_procedure (variant {variant_idx + 1})"
            )

            interpretation = interpret_procedure(
                cleaned, evasion_hints=variant_hints)

            log_event = build_log_event(
                interpretation=interpretation,
                procedure_text=cleaned.formatted_input,
                evasion_hints=variant_hints,
            )

            if log_event is not None:
                events.append(log_event)
                _dbg(
                    f"{technique_id} / '{cleaned.test_name}': "
                    f"LogEvent generated (EID {log_event.EventID}, {log_event.event_type})"
                )
            else:
                _dbg(
                    f"{technique_id} / '{cleaned.test_name}': "
                    f"build_log_event returned None — dropped"
                )

    return events


# ─── Public interface ─────────────────────────────────────────────────────────

def run_emulator(
    technique_ids: list[str] | None = None,
    evasion_hints: dict[str, dict] | None = None,
    evasion_hints_v2: dict[str, dict] | None = None,
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
            technique_id, evasion_hints, stats, selected_test_guids=selected_test_guids, evasion_hints_v2=evasion_hints_v2)

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
