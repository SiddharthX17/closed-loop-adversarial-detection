"""
pipeline/attacker/agent.py

Attacker agent — pre-filters Atomic Red Team candidates per technique,
calls Haiku to select + mutate, returns a CampaignPlan.

Selection logic:
  - Primary filter: len(cleaned.commands) > 0 (cleaner extracted real commands)
  - Unresolved vars: NOT skipped — LLM substitutes realistic values
  - Primary ranking: complexity score (command count + interesting binary refs)
  - Tiebreaker: executor diversity (prefer powershell + cmd over 3x powershell)
  - Cap: MAX_CANDIDATES (1) passed to LLM

Mutation context (iteration 2+):
  - caught_fields: Sysmon field values that fired rules last run
  - caught_rules: rule titles + SQL conditions that matched
  - prior_attempts: (test_guid, hints_hash) pairs tried this run — deduplication

CampaignPlan feeds into run_emulator() via evasion_hints.
"""

import os
import json
import yaml
import hashlib
import anthropic
import random

from dataclasses import dataclass, field
from dotenv import load_dotenv
from pathlib import Path

from pipeline.data.atomic_loader import load_tests_for_technique_with_fallback
from pipeline.data.atomic_cleaner import clean_test
from pipeline.data.stix_loader import get_loader
from pipeline.attacker.prompts import (
    AtomicCandidate,
    build_coldstart_prompt,
    build_mutation_prompt,
)

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

TECHNIQUES_PATH = Path("config/techniques.yaml")
MODEL = "claude-haiku-4-5-20251001"
TEMPERATURE = 0.2
MAX_CANDIDATES = 1

# ---------------------------------------------------------------------------
# Executor list — used as diversity tiebreaker only, not primary filter.
# LOLBins and script hosts included — these are the most detection-relevant
# execution chains and should be preferred when complexity scores are equal.
# ---------------------------------------------------------------------------
EXECUTOR_PRIORITY = [
    # Script-based execution
    "powershell",
    "command_prompt",
    "cmd",
    # LOLBins — indirect execution, commonly abused
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "msiexec",
    "certutil",
    "bitsadmin",
    "installutil",
    "regasm",
    "regsvcs",
    "odbcconf",
    # Script hosts
    "wscript",
    "cscript",
    # Other shells
    "pwsh",
    "bash",
    "sh",
    "python",
]

# Binaries that indicate interesting/detection-relevant behaviour.
# Presence in cleaned.commands increases complexity score.
INTERESTING_BINARIES = {
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "certutil.exe",
    "bitsadmin.exe", "odbcconf.exe", "regasm.exe", "regsvcs.exe",
    "installutil.exe", "pwsh.exe", "powershell.exe", "cmd.exe",
    "schtasks.exe", "at.exe", "sc.exe", "reg.exe", "regedit.exe",
    "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "dsquery.exe",
}

SYSMON_FIELDS = [
    "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "TargetObject", "DestinationIp", "DestinationHostname", "OriginalFileName",
]


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------

@dataclass
class TechniqueTask:
    """
    One technique's worth of attacker output.
    evasion_hints: plugs directly into run_emulator() as evasion_hints param.
    mutation_applied: False if mutation context was present but hints came back empty.
    Test selection is handled by the emulator
    """
    technique_id: str
    evasion_hints: dict = field(default_factory=dict)
    evasion_hints_v2: dict | None = None
    mutation_applied: bool = True


# CampaignPlan: keyed by technique_id — formalised at 3.08 wiring
CampaignPlan = dict[str, TechniqueTask]


def extract_emulator_inputs(
    plan: CampaignPlan,
) -> tuple[list[str], dict[str, dict], dict[str, str], dict[str, dict]]:
    """
    Extract run_emulator() inputs from a CampaignPlan.

    Returns:
        technique_ids:       ordered list of technique IDs
        evasion_hints:       dict[technique_id, dict] of Sysmon field overrides
        evasion_hints_v2:    dict[technique_id, dict] of second variant overrides
    """
    technique_ids = list(plan.keys())
    evasion_hints = {
        tid: (task.evasion_hints if task.mutation_applied else {})
        for tid, task in plan.items()
    }
    evasion_hints_v2 = {
        tid: task.evasion_hints_v2
        for tid, task in plan.items()
        if task.evasion_hints_v2
    }
    return technique_ids, evasion_hints, evasion_hints_v2


# ---------------------------------------------------------------------------
# Candidate filtering and ranking
# ---------------------------------------------------------------------------

def _has_concrete_observables(cleaned) -> bool:
    """
    True if the cleaner extracted at least one executable command.
    Empty commands list means nothing concrete was parsed — skip.
    """
    return len(cleaned.commands) > 0


def _score_complexity(cleaned) -> int:
    """
    Complexity score for candidate ranking.
    Higher = more detection-relevant, more interesting for mutation.

    Scoring:
      +1 per command step (multi-stage > single-line)
      +2 per interesting binary referenced in commands
      +1 if has_unresolved_vars (real-world tool dependency = more interesting)
    """
    score = len(cleaned.commands)

    all_commands = " ".join(cleaned.commands).lower()
    for binary in INTERESTING_BINARIES:
        if binary in all_commands:
            score += 2

    if cleaned.has_unresolved_vars:
        score += 1  # interesting tests tend to have env-specific vars

    return score


def _normalise_executor(executor_image: str) -> str:
    name = (executor_image or "").lower().strip()
    # Extract bare filename — handles full paths like C:\Windows\System32\mshta.exe
    # stem strips extension, works on both paths and bare names
    name = Path(name).stem
    return name


def _select_candidates(
    pairs: list[tuple],
    max_n: int = MAX_CANDIDATES,
) -> list[tuple]:
    """
    Select up to max_n candidates.

    Primary: complexity score descending.
    Tiebreaker: executor diversity (greedy — pick highest complexity,
                then next highest with a different executor, etc.)
    """
    if len(pairs) <= max_n:
        return pairs

    # Sort by complexity descending
    scored = sorted(pairs, key=lambda p: _score_complexity(p[1]), reverse=True)

    selected = []
    seen_executors: set[str] = set()

    # First pass: one per executor type, highest complexity first
    for pair in scored:
        ex = _normalise_executor(pair[1].executor_image)
        if ex not in seen_executors:
            selected.append(pair)
            seen_executors.add(ex)
            if len(selected) >= max_n:
                return selected

    # Second pass: fill remaining slots by complexity regardless of executor
    for pair in scored:
        if pair not in selected:
            selected.append(pair)
            if len(selected) >= max_n:
                break

    return selected


def _build_candidates(
    pairs: list[tuple],
) -> tuple[list[AtomicCandidate], dict]:
    """
    Build AtomicCandidate list + guid->CleanedAtomicTest lookup.
    guid from AtomicTest.test_guid — not on CleanedAtomicTest.
    """
    candidates = []
    lookup = {}  # guid -> CleanedAtomicTest

    for raw_test, cleaned in pairs:
        guid = raw_test.test_guid or cleaned.test_name
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
# Prior attempt tracking
# ---------------------------------------------------------------------------

def _hints_hash(evasion_hints: dict) -> str:
    return hashlib.md5(
        json.dumps(evasion_hints, sort_keys=True).encode()
    ).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Detection context extraction
# ---------------------------------------------------------------------------

def _extract_detection_block(rule_path: str) -> str:
    """
    Extract just the detection: block from a Sigma rule YAML.
    More readable for LLM reasoning about evasion than SQL.
    Falls back to empty string if file unreadable.
    """
    try:
        import yaml as pyyaml
        text = Path(rule_path).read_text(encoding="utf-8")
        parsed = pyyaml.safe_load(text)
        if parsed and "detection" in parsed:
            # Re-serialise just the detection block — compact and clean
            return pyyaml.dump(
                {"detection": parsed["detection"]},
                default_flow_style=False,
            ).strip()
    except Exception:
        pass
    return "unavailable"


def _get_detection_context(
    technique_id: str,
    previous_results: dict | None,
) -> tuple[dict[str, list[str]], list[dict]]:
    """
    Extract mutation context from the previous run's DetectionResult.

    Returns:
        caught_fields: {sysmon_field: [values that triggered rules]}
        caught_rules:  [{"title": str, "condition": str}] for each fired rule
    """
    if not previous_results:
        return {}, []

    result = previous_results.get(technique_id)
    if not result:
        return {}, []

    # Field values from matched events
    caught_fields: dict[str, list[str]] = {}
    for event in getattr(result, "matched_events", []):
        for f in SYSMON_FIELDS:
            val = event.get(f)
            if val:
                caught_fields.setdefault(f, [])
                if val not in caught_fields[f]:
                    caught_fields[f].append(val)

    # Rules that fired — title + SQL condition for LLM to reason about what to evade
    caught_rules = []
    for rb in getattr(result, "fired_rules", []):
        # Load detection block from rule file — more readable than SQL for LLM
        detection_yaml = _extract_detection_block(rb.rule_path)
        caught_rules.append({
            "title": rb.rule_title,
            "detection_yaml": detection_yaml,
        })

    return caught_fields, caught_rules


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def _build_full_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    candidates: list[AtomicCandidate],
    caught_fields: dict,
    caught_rules: list[dict],
    prior_attempts: list[dict],
    has_unresolved_vars: bool,
) -> str:
    """
    Assemble the full prompt for the LLM.
    Base prompt from prompts.py, additional mutation context appended here.
    prompts.py content is not modified — extra context injected by agent.
    """
    if caught_fields:
        prompt = build_mutation_prompt(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            candidates=candidates,
            caught_fields=caught_fields,
        )
    else:
        prompt = build_coldstart_prompt(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            candidates=candidates,
        )

    # Inject caught rules — LLM should understand what condition matched
    # so it can reason about what to evade, not just which field values
    if caught_rules:
        prompt += "\n\nRules that fired last run (understand what each detects, then evade it):\n"
        for i, rule in enumerate(caught_rules, 1):
            prompt += f"\n  Rule {i}: {rule['title']}\n"
            prompt += f"  Detection block:\n"
            for line in rule['detection_yaml'].splitlines():
                prompt += f"    {line}\n"

    # Inject prior attempts — prevent repeating the same hints combination
    if prior_attempts:
        prompt += "\n\nPrior hint combinations attempted this run (do not repeat):\n"
        for attempt in prior_attempts:
            prompt += f"  - hints_hash: {attempt['hints_hash']}\n"

    # Unresolved vars note — instruct LLM to substitute realistic values
    if has_unresolved_vars:
        prompt += (
            "\n\nNote: the selected test may contain unresolved variables "
            "(e.g. #{tool_path}, #{domain}). "
            "Substitute realistic Windows values in your evasion_hints — "
            "do not leave placeholders in field values."
        )

    return prompt


# ---------------------------------------------------------------------------
# LLM call + parse
# ---------------------------------------------------------------------------

def _call_llm(prompt: str, client: anthropic.Anthropic) -> dict | None:
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=2048,
            temperature=TEMPERATURE,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()

        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            ).strip()

        return json.loads(raw)

    except (json.JSONDecodeError, IndexError, anthropic.APIError) as e:
        if DEBUG:
            print(f"[attacker] LLM call failed: {e}")
        return None


def _parse_llm_output(
    raw: dict,
    technique_id: str,
) -> TechniqueTask | None:
    if not raw:
        return None

    evasion_hints = raw.get(
        "evasion_hints") or raw.get("evasion_hints", {})
    evasion_hints_v2 = raw.get("evasion_hints_v2")

    if not isinstance(evasion_hints, dict):
        evasion_hints = {}
    evasion_hints = {
        k: v for k, v in evasion_hints.items()
        if isinstance(k, str) and isinstance(v, str)
    }
    if not isinstance(evasion_hints_v2, dict):
        evasion_hints_v2 = None
    if evasion_hints_v2:
        evasion_hints_v2 = {
            k: v for k, v in evasion_hints_v2.items()
            if isinstance(k, str) and isinstance(v, str)
        }

    return TechniqueTask(
        technique_id=technique_id,
        evasion_hints=evasion_hints,
        evasion_hints_v2=evasion_hints_v2,
        mutation_applied=True,
    )


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class AttackerAgent:

    def __init__(self):
        self._client = anthropic.Anthropic()
        self._stix = get_loader()
        # Prior attempts tracked per technique within a run.
        # Keyed by technique_id. Each entry: {test_guid, hints_hash}.
        # Resets on each run() call — does not persist across pipeline iterations.
        self._prior_attempts: dict[str, list[dict]] = {}

    def _load_technique_ids(self) -> list[str]:
        with open(TECHNIQUES_PATH) as f:
            config = yaml.safe_load(f)
        techniques = config.get("techniques", [])
        return [t if isinstance(t, str) else t["id"] for t in techniques]

    def _prepare_candidates(
        self,
        technique_id: str,
        caught_fields:  dict[str, list[str]],
        previous_results: dict | None = None,
    ) -> tuple[list[AtomicCandidate], dict]:
        """
        Load, clean, filter, rank, and cap Atomic tests for a technique.
        Unresolved vars are NOT skipped — passed through for LLM substitution.
        Returns (candidates, guid_lookup). Empty on failure.
        """
        metadata = self._stix.lookup(technique_id)
        if not metadata:
            if DEBUG:
                print(
                    f"[attacker] {technique_id}: no STIX metadata — skipping")
            return [], {}

        raw_tests = load_tests_for_technique_with_fallback(technique_id)
        if not raw_tests:
            return [], {}

        pairs = []
        for raw_test in raw_tests:
            cleaned = clean_test(raw_test, metadata)
            if cleaned is None:
                continue
            if not _has_concrete_observables(cleaned):
                if DEBUG:
                    print(
                        f"[attacker] {technique_id}: "
                        f"skipping '{cleaned.test_name}' — no commands extracted"
                    )
                continue
            # Note: has_unresolved_vars is NOT a filter — LLM substitutes values
            pairs.append((raw_test, cleaned))

        if not pairs:
            if DEBUG:
                print(
                    f"[attacker] {technique_id}: no usable candidates after filtering")
            return [], {}

        # Shuffle so the LLM sees varied execution contexts across runs.
        # Test selection is owned by the emulator — no guidance needed here.
        random.shuffle(pairs)
        selected_pairs = _select_candidates(pairs)
        return _build_candidates(selected_pairs)

    def _is_duplicate_attempt(
        self,
        technique_id: str,
        evasion_hints: dict,
    ) -> bool:
        prior = self._prior_attempts.get(technique_id, [])
        h = _hints_hash(evasion_hints)
        return any(p["hints_hash"] == h for p in prior)

    def _record_attempt(
        self,
        technique_id: str,
        evasion_hints: dict,
    ) -> None:
        self._prior_attempts.setdefault(technique_id, []).append({
            "hints_hash": _hints_hash(evasion_hints),
        })

    def run(
        self,
        technique_ids: list[str] | None = None,
        previous_results: dict | None = None,
    ) -> CampaignPlan:
        """
        Generate a CampaignPlan for the given techniques.

        Args:
            technique_ids:    ATT&CK IDs. Reads techniques.yaml if None.
            previous_results: dict[technique_id, DetectionResult] from prior run.
                              None on first iteration (cold start).

        Returns:
            CampaignPlan — dict[technique_id, TechniqueTask]
        """
        if technique_ids is None:
            technique_ids = self._load_technique_ids()

        # Reset prior attempts for this run
        self._prior_attempts = {}

        plan: CampaignPlan = {}

        for tid in technique_ids:
            if DEBUG:
                print(f"[attacker] Processing {tid}")

            caught_fields: dict[str, list[str]] = {}
            caught_rules: list[dict] = []
            if previous_results:
                caught_fields, caught_rules = _get_detection_context(
                    tid, previous_results)

            candidates, lookup = self._prepare_candidates(
                tid,
                caught_fields=caught_fields,
                previous_results=previous_results,
            )
            if not candidates:
                continue

            metadata = self._stix.lookup(tid)
            technique_name = metadata.technique_name if metadata else tid
            tactic = metadata.tactic if metadata else "unknown"

            # Check if any selected candidate has unresolved vars
            has_unresolved = any(
                lookup[c.guid].has_unresolved_vars
                for c in candidates
                if c.guid in lookup
            )

            prior_for_technique = self._prior_attempts.get(tid, [])

            prompt = _build_full_prompt(
                technique_id=tid,
                technique_name=technique_name,
                tactic=tactic,
                candidates=candidates,
                caught_fields=caught_fields,
                caught_rules=caught_rules,
                prior_attempts=prior_for_technique,
                has_unresolved_vars=has_unresolved,
            )

            if DEBUG:
                print(
                    f"[attacker] {tid}: calling LLM "
                    f"({len(candidates)} candidates, "
                    f"{'mutation' if caught_fields else 'coldstart'}, "
                    f"temp={TEMPERATURE})"
                )

            raw = _call_llm(prompt, self._client)
            task = _parse_llm_output(raw, tid)

            if not task:
                if DEBUG:
                    print(
                        f"[attacker] {tid}: failed to parse LLM output — skipping")
                continue

            # Mutation context present but LLM returned no hints — flag it
            if caught_fields and not task.evasion_hints:
                if DEBUG:
                    print(
                        f"[attacker] {tid}: mutation context present but "
                        f"LLM returned empty evasion_hints — no mutation applied"
                    )
                task.mutation_applied = False

            # Duplicate attempt check
            if self._is_duplicate_attempt(tid, task.evasion_hints):
                if DEBUG:
                    print(
                        f"[attacker] {tid}: duplicate hints detected — using as-is")

            self._record_attempt(tid, task.evasion_hints)

            plan[tid] = task

            if DEBUG:
                print(
                    f"[attacker] {tid}: hints generated, "
                    f"evasion_hints={list(task.evasion_hints.keys())}, "
                    f"evasion_hints_v2={list(task.evasion_hints_v2.keys()) if task.evasion_hints_v2 else None}, "
                    f"mutation_applied={task.mutation_applied}")

        return plan
