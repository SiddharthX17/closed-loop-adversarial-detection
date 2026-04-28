"""
noise_gate.py

Runs a candidate Sigma rule against the benign corpus and asserts
FP rate stays below threshold (default 1%).

Corpus loading:
  - Determines relevant subdirs from EventIDs present in attack_sample
  - Loads all .jsonl files from those subdirs
  - Supplements with benign_generator synthetic events (same seed per run)

Returns NoiseGateResult with fp_rate, fp_count, total_events, and a
capped sample of FP events for defender agent retry context.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pipeline.detection.engine import DetectionEngine
from pipeline.emulator.benign_generator import generate_benign_events
from pipeline.emulator.log_builder import LogEvent

# ---------------------------------------------------------------------------
# EventID → corpus subdir mapping
# ---------------------------------------------------------------------------

_EID_TO_SUBDIR: dict[int, str] = {
    1:  "process",
    12: "registry",
    13: "registry",
    3:  "network",
}

_CANONICAL_FIELDS = {
    "timestamp": "timestamp",
    "host": "host",
    "user": "user",
    "eventid": "EventID",
    "event_type": "event_type",
    "image": "Image",
    "commandline": "CommandLine",
    "parentimage": "ParentImage",
    "parentcommandline": "ParentCommandLine",
    "processid": "ProcessId",
    "parentprocessid": "ParentProcessId",
    "targetobject": "TargetObject",
    "details": "Details",
    "sourceip": "SourceIp",
    "destinationip": "DestinationIp",
    "destinationhostname": "DestinationHostname",
    "destinationport": "DestinationPort",
    "originalfilename": "OriginalFileName",
    "currentdirectory": "CurrentDirectory",
    "integritylevel": "IntegrityLevel",
    "protocol": "Protocol",
    "initiated": "Initiated",
}


_DEFAULT_FP_THRESHOLD = 0.01
_FP_SAMPLE_CAP = 5       # max FP events surfaced to defender agent
_BENIGN_GEN_COUNT = 200  # synthetic events per type, supplements corpus


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class NoiseGateResult:
    passed:        bool
    fp_rate:       float
    fp_count:      int
    total_events:  int
    fp_events:     list[dict] = field(default_factory=list)  # capped sample
    error:         Optional[str] = None
    # populated on failure, fed to defender
    feedback:      Optional[str] = None


# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------

def _subdirs_for_attack_sample(attack_sample: list[LogEvent]) -> set[str]:
    """
    Derive which corpus subdirs to load based on EventIDs in attack_sample.
    Falls back to all three subdirs if attack_sample is empty or has unknown EIDs.
    """
    subdirs: set[str] = set()
    for event in attack_sample:
        subdir = _EID_TO_SUBDIR.get(event.EventID)
        if subdir:
            subdirs.add(subdir)

    if not subdirs:
        # Defensive fallback — load everything
        subdirs = {"process", "network", "registry"}

    return subdirs


def _load_jsonl_corpus(corpus_root: Path, subdirs: set[str]) -> list[dict]:
    """
    Load all .jsonl files from corpus_root/{subdir}/ for each subdir.
    Returns list of raw event dicts (not LogEvent — engine expects dicts).
    Skips malformed lines silently.
    """
    events: list[dict] = []

    for subdir in subdirs:
        subdir_path = corpus_root / subdir
        if not subdir_path.exists():
            continue

        for jsonl_file in sorted(subdir_path.glob("*.jsonl")):
            with open(jsonl_file, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        events.append(json.loads(raw))
                    except json.JSONDecodeError:
                        continue

    return events


def _log_events_to_dicts(events: list[LogEvent]) -> list[dict]:
    return [e.model_dump(exclude_none=True) for e in events]


def _normalise_event_keys(event: dict) -> dict:
    """
    Resolve case-insensitive duplicate keys while preserving canonical schema names.
    First canonical value wins.
    """
    result = {}

    for k, v in event.items():
        if k is None:
            continue

        raw = str(k)
        canonical = _CANONICAL_FIELDS.get(raw.lower(), raw)

        if canonical not in result:
            result[canonical] = v

    return result


def _normalise_event_list(events: list[dict]) -> list[dict]:
    return [_normalise_event_keys(e) for e in events]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    rule_yaml: str,
    attack_sample: list[LogEvent],
    corpus_root: Path,
    fp_threshold: float = _DEFAULT_FP_THRESHOLD,
    benign_gen_seed: int = 42,
    supplement_with_generated: bool = True,
) -> NoiseGateResult:
    """
    Run candidate Sigma rule against the benign corpus.

    Args:
        rule_yaml:                 Sigma rule YAML string (candidate rule).
        attack_sample:             Emulated attack events for the technique.
                                   Used only to determine which corpus subdirs to load.
        corpus_root:               Path to corpus/benign/ directory.
        fp_threshold:              Max acceptable FP rate (default 0.01 = 1%).
        benign_gen_seed:           Seed for synthetic benign event generation.
        supplement_with_generated: If True, adds benign_generator events to corpus.
                                   Set False in tests that want corpus-only evaluation.

    Returns:
        NoiseGateResult
    """
    debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")

    # 1. Determine which corpus subdirs to load
    subdirs = _subdirs_for_attack_sample(attack_sample)

    if debug:
        print(f"[noise_gate] attack_sample EventIDs: "
              f"{sorted({e.EventID for e in attack_sample})}")
        print(f"[noise_gate] loading corpus subdirs: {subdirs}")

    # 2. Load corpus from disk
    corpus_events = _load_jsonl_corpus(corpus_root, subdirs)

    if debug:
        print(
            f"[noise_gate] loaded {len(corpus_events)} events from disk corpus")

    # 3. Supplement with synthetic benign events
    if supplement_with_generated:
        generated = generate_benign_events(
            count_per_type=_BENIGN_GEN_COUNT,
            seed=benign_gen_seed,
            output_dir=None,
        )
        # Filter generated events to same subdirs as corpus
        relevant_eids = {
            eid for eid, sub in _EID_TO_SUBDIR.items() if sub in subdirs
        }
        filtered_generated = [
            e for e in generated if e.EventID in relevant_eids]
        corpus_events.extend(_log_events_to_dicts(filtered_generated))

        if debug:
            print(f"[noise_gate] added {len(filtered_generated)} synthetic events "
                  f"(total: {len(corpus_events)})")

    corpus_events = _normalise_event_list(corpus_events)

    if debug:
        print(f"[noise_gate] normalised {len(corpus_events)} corpus events")

    if not corpus_events:
        return NoiseGateResult(
            passed=False,
            fp_rate=0.0,
            fp_count=0,
            total_events=0,
            error="Benign corpus is empty — cannot evaluate noise gate",
            feedback="Benign corpus is empty. Cannot assess FP rate.",
        )

    # 4. Run rule against benign corpus
    try:
        engine = DetectionEngine(rules_dir=Path("rules"), events=corpus_events)
        result = engine.run_single_rule(rule_yaml)
        if result.skipped:
            return NoiseGateResult(
                passed=False,
                fp_rate=0.0,
                fp_count=0,
                total_events=len(corpus_events),
                error=f"Rule skipped during noise gate execution: {result.skip_reason}",
                feedback=f"Rule could not be executed against benign corpus: {result.skip_reason}",
            )
    except Exception as exc:
        return NoiseGateResult(
            passed=False,
            fp_rate=0.0,
            fp_count=0,
            total_events=len(corpus_events),
            error=f"Engine error during noise gate: {exc}",
            feedback=f"Rule failed to execute against benign corpus: {exc}",
        )

    # 5. Calculate FP rate
    total = len(corpus_events)
    fp_count = len(result.matched_events)
    fp_rate = fp_count / total if total > 0 else 0.0

    # 6. Sample of FP events for defender context (capped)
    fp_sample = result.matched_events[:_FP_SAMPLE_CAP] if result.fired else []

    if debug:
        print(f"[noise_gate] total={total} fp_count={fp_count} "
              f"fp_rate={fp_rate:.1%} threshold={fp_threshold:.1%}")

    passed = fp_rate < fp_threshold

    feedback: Optional[str] = None
    if not passed:
        feedback = (
            f"Rule fired on {fp_count}/{total} benign events "
            f"(FP rate {fp_rate:.1%}, threshold {fp_threshold:.1%}). "
            f"Sample FP events: {json.dumps(fp_sample[:2], indent=2)}"
        )

    return NoiseGateResult(
        passed=passed,
        fp_rate=fp_rate,
        fp_count=fp_count,
        total_events=total,
        fp_events=fp_sample,
        feedback=feedback,
    )
