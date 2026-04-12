"""
pipeline/attacker/agent.py

Attacker agent — pre-filters Atomic Red Team candidates per technique,
calls Haiku to select + mutate, returns a CampaignPlan.

CampaignPlan feeds directly into run_emulator() via evasion_hints.
"""

from pipeline.attacker.prompts import (
    AtomicCandidate,
    build_coldstart_prompt,
    build_mutation_prompt,
)
from pipeline.data.stix_loader import get_loader
from pipeline.data.atomic_cleaner import clean_test
from pipeline.data.atomic_loader import load_tests_for_technique
import os
import json
import yaml
import anthropic
from dotenv import load_dotenv

from dataclasses import dataclass, field
from pathlib import Path

load_dotenv()


DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

TECHNIQUES_PATH = Path("config/techniques.yaml")
MODEL = "claude-haiku-4-5-20251001"
MAX_CANDIDATES = 3

# Executor preference order for diversity selection
EXECUTOR_PRIORITY = ["powershell",
                     "command_prompt", "cmd", "sh", "bash", "python"]


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

@dataclass
class TechniqueTask:
    """
    One technique's worth of attacker output.
    formatted_input is the cleaned Atomic procedure text for the selected test.
    evasion_hints plugs directly into run_emulator() as the evasion_hints param.
    """
    technique_id: str
    selected_test_name: str
    selected_test_guid: str
    formatted_input: str        # CleanedAtomicTest.formatted_input for selected test
    evasion_hints: dict = field(default_factory=dict)


# CampaignPlan: keyed by technique_id — formalised further at 3.08 wiring
CampaignPlan = dict[str, TechniqueTask]


# ---------------------------------------------------------------------------
# Pre-filter helpers
# ---------------------------------------------------------------------------

def _has_concrete_observables(formatted_input: str) -> bool:
    """
    Rough heuristic — formatted_input must reference something extractable.
    Mirrors the confidence check in procedure_interpreter.
    """
    text = formatted_input.lower()
    indicators = [
        ".exe", ".ps1", ".bat", ".cmd",
        "hkcu", "hklm",
        "http://", "https://",
        "reg ", "powershell", "cmd.exe",
        "step 1:",  # means commands were parsed — at least one command exists
    ]
    return any(ind in text for ind in indicators)


def _normalise_executor(executor_image: str) -> str:
    # executor_image is e.g. "powershell.exe", "cmd.exe" — strip to bare name
    name = (executor_image or "").lower().strip()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _select_diverse_candidates(
    pairs: list[tuple],  # list of (AtomicTest, CleanedAtomicTest)
    max_n: int = MAX_CANDIDATES,
) -> list[tuple]:
    """
    Pick up to max_n candidates, prioritising executor diversity.
    Avoids passing 3x powershell when cmd/registry alternatives exist.
    """
    if len(pairs) <= max_n:
        return pairs

    seen_executors: set[str] = set()
    selected = []

    by_executor: dict[str, list[tuple]] = {}
    for pair in pairs:
        ex = _normalise_executor(pair[1].executor_image)
        by_executor.setdefault(ex, []).append(pair)

    for ex in EXECUTOR_PRIORITY:
        if ex in by_executor and ex not in seen_executors:
            selected.append(by_executor[ex][0])
            seen_executors.add(ex)
            if len(selected) >= max_n:
                return selected

    # Fill remaining slots
    for pair in pairs:
        if pair not in selected:
            selected.append(pair)
            if len(selected) >= max_n:
                break

    return selected


def _build_candidates(
    pairs: list[tuple],  # list of (AtomicTest, CleanedAtomicTest)
) -> tuple[list[AtomicCandidate], dict]:
    """
    Build AtomicCandidate list + guid->CleanedAtomicTest lookup dict.
    guid comes from AtomicTest.test_guid — CleanedAtomicTest doesn't carry it.
    """
    candidates = []
    lookup = {}  # guid -> CleanedAtomicTest

    for raw_test, cleaned in pairs:
        guid = raw_test.test_guid or cleaned.test_name  # test_name as fallback
        candidate = AtomicCandidate(
            name=cleaned.test_name,
            guid=guid,
            executor=_normalise_executor(cleaned.executor_image),
            procedure_text=cleaned.formatted_input,
        )
        candidates.append(candidate)
        lookup[guid] = cleaned

    return candidates, lookup


# ---------------------------------------------------------------------------
# LLM call + parse
# ---------------------------------------------------------------------------

def _call_llm(prompt: str, client: anthropic.Anthropic) -> dict | None:
    """
    Call Haiku at temp=0, parse JSON response.
    Returns parsed dict or None on failure.
    """
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=512,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()

        # Strip accidental markdown fences if present
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            )

        return json.loads(raw)

    except (json.JSONDecodeError, IndexError, anthropic.APIError) as e:
        if DEBUG:
            print(f"[attacker] LLM call failed: {e}")
        return None


def _parse_llm_output(
    raw: dict,
    candidates: list[AtomicCandidate],
    lookup: dict,       # guid -> CleanedAtomicTest
    technique_id: str,
) -> TechniqueTask | None:
    """
    Validate LLM output and build TechniqueTask.
    Falls back to first candidate if LLM returns unknown guid/name.
    """
    if not raw:
        return None

    selected_guid = raw.get("selected_test_guid")
    selected_name = raw.get("selected_test_name")
    evasion_hints = raw.get("evasion_hints", {})

    # Validate evasion_hints — must be flat dict of strings
    if not isinstance(evasion_hints, dict):
        evasion_hints = {}
    evasion_hints = {
        k: v for k, v in evasion_hints.items()
        if isinstance(k, str) and isinstance(v, str)
    }

    # Resolve selected test — guid first, fallback to name match
    selected_cleaned = lookup.get(selected_guid)
    if not selected_cleaned:
        selected_cleaned = next(
            (lookup[g]
             for g in lookup if lookup[g].test_name == selected_name),
            None,
        )
        if selected_cleaned:
            selected_guid = next(
                g for g in lookup if lookup[g].test_name == selected_name
            )

    if not selected_cleaned:
        if DEBUG:
            print(
                f"[attacker] {technique_id}: LLM returned unknown test "
                f"(guid={selected_guid}, name={selected_name}) — using first candidate"
            )
        if not candidates:
            return None
        first = candidates[0]
        selected_cleaned = lookup.get(first.guid)
        selected_guid = first.guid
        selected_name = first.name

    return TechniqueTask(
        technique_id=technique_id,
        selected_test_name=selected_cleaned.test_name,
        selected_test_guid=selected_guid,
        formatted_input=selected_cleaned.formatted_input,
        evasion_hints=evasion_hints,
    )


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class AttackerAgent:

    def __init__(self):
        self._client = anthropic.Anthropic()
        self._stix = get_loader()

    def _load_technique_ids(self) -> list[str]:
        with open(TECHNIQUES_PATH) as f:
            config = yaml.safe_load(f)
        techniques = config.get("techniques", [])
        return [
            t if isinstance(t, str) else t["id"]
            for t in techniques
        ]

    def _prepare_candidates(
        self,
        technique_id: str,
    ) -> tuple[list[AtomicCandidate], dict]:
        """
        Load, clean, filter, and diversify Atomic tests for a technique.
        Returns (candidates, guid_lookup). Empty on failure.
        """
        metadata = self._stix.lookup(technique_id)
        if not metadata:
            if DEBUG:
                print(
                    f"[attacker] {technique_id}: no STIX metadata — skipping")
            return [], {}

        raw_tests = load_tests_for_technique(technique_id)
        if not raw_tests:
            return [], {}

        pairs = []
        for raw_test in raw_tests:
            cleaned = clean_test(raw_test, metadata)
            if cleaned is None:
                continue
            if cleaned.has_unresolved_vars:
                if DEBUG:
                    print(
                        f"[attacker] {technique_id}: skipping '{cleaned.test_name}' — unresolved vars")
                continue
            if not _has_concrete_observables(cleaned.formatted_input):
                if DEBUG:
                    print(
                        f"[attacker] {technique_id}: skipping '{cleaned.test_name}' — no concrete observables")
                continue
            pairs.append((raw_test, cleaned))

        if not pairs:
            if DEBUG:
                print(
                    f"[attacker] {technique_id}: no usable candidates after filtering")
            return [], {}

        diverse_pairs = _select_diverse_candidates(pairs)
        return _build_candidates(diverse_pairs)

    def _get_caught_fields(
        self,
        technique_id: str,
        previous_results: dict | None,
    ) -> dict[str, list[str]]:
        """
        Extract Sysmon field values that fired rules in the previous run.
        Returns {} on first iteration or if technique had no matches.
        """
        if not previous_results:
            return {}

        result = previous_results.get(technique_id)
        if not result:
            return {}

        caught: dict[str, list[str]] = {}
        matched_events = getattr(result, "matched_events", [])
        sysmon_fields = [
            "Image", "CommandLine", "ParentImage", "ParentCommandLine",
            "TargetObject", "DestinationIp", "DestinationHostname", "OriginalFileName",
        ]
        for event in matched_events:
            for f in sysmon_fields:
                val = event.get(f)
                if val:
                    caught.setdefault(f, [])
                    if val not in caught[f]:
                        caught[f].append(val)

        return caught

    def run(
        self,
        technique_ids: list[str] | None = None,
        previous_results: dict | None = None,
    ) -> CampaignPlan:
        """
        Generate a CampaignPlan for the given techniques.

        Args:
            technique_ids:    list of ATT&CK IDs. Reads techniques.yaml if None.
            previous_results: dict[technique_id, DetectionResult] from prior run.
                              None on first iteration (cold start).

        Returns:
            CampaignPlan — dict[technique_id, TechniqueTask]
        """
        if technique_ids is None:
            technique_ids = self._load_technique_ids()

        plan: CampaignPlan = {}

        for tid in technique_ids:
            if DEBUG:
                print(f"[attacker] Processing {tid}")

            candidates, lookup = self._prepare_candidates(tid)
            if not candidates:
                continue

            metadata = self._stix.lookup(tid)
            technique_name = metadata.technique_name if metadata else tid
            tactic = metadata.tactic if metadata else "unknown"

            caught_fields = self._get_caught_fields(tid, previous_results)

            if caught_fields:
                prompt = build_mutation_prompt(
                    technique_id=tid,
                    technique_name=technique_name,
                    tactic=tactic,
                    candidates=candidates,
                    caught_fields=caught_fields,
                )
            else:
                prompt = build_coldstart_prompt(
                    technique_id=tid,
                    technique_name=technique_name,
                    tactic=tactic,
                    candidates=candidates,
                )

            if DEBUG:
                print(
                    f"[attacker] {tid}: calling LLM "
                    f"({len(candidates)} candidates, "
                    f"{'mutation' if caught_fields else 'coldstart'})"
                )

            raw = _call_llm(prompt, self._client)
            task = _parse_llm_output(raw, candidates, lookup, tid)

            if task:
                plan[tid] = task
                if DEBUG:
                    print(
                        f"[attacker] {tid}: selected '{task.selected_test_name}', "
                        f"evasion_hints={list(task.evasion_hints.keys())}"
                    )
            else:
                if DEBUG:
                    print(
                        f"[attacker] {tid}: failed to parse LLM output — skipping")

        return plan
