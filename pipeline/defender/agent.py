"""
pipeline/defender/agent.py

Defender agent — receives a GapContext, generates candidate Sigma YAML,
validates through the full validation pipeline, retries on failure (max 2).

Returns (rule_yaml, ValidationResult) or (None, last_result) on exhaustion.
"""

import json
import os
import uuid
import anthropic

from dataclasses import dataclass, field
from datetime import date
from dotenv import load_dotenv
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from pipeline.defender.prompts import (
    build_defender_user_message,
    DEFENDER_SYSTEM_PROMPT,
    DEFENDER_OUTPUT_SCHEMA,
)
from pipeline.validation.validation_pipeline import validate, ValidationResult
from pipeline.emulator.log_builder import LogEvent
from pipeline.validation.rule_normalizer import normalize_rule_yaml

if TYPE_CHECKING:
    from pipeline.detection_planner.planner import DetectionStrategy

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

MODEL = "claude-sonnet-5"
MAX_RETRIES = 2
MAX_RETRIES_GATE_FAILURE = 3
RULES_DIR = Path("rules")


# ---------------------------------------------------------------------------
# GapContext
# ---------------------------------------------------------------------------

@dataclass
class GapContext:
    """
    Everything the defender agent needs to generate a candidate rule.

    attack_sample:       Full attack LogEvents for this technique — passed to
                         validation pipeline (attack_gate + noise_gate).
                         Must be list[LogEvent] — validate() requires this type.
    missed_events:       Subset of attack_sample not caught by existing rules.
                         Passed to the prompt as evidence for rule generation.
                         Dicts (serialised LogEvents) — prompt doesn't need typed objects.
    existing_rule_paths: Paths to existing Sigma rules for this technique.
                         Agent reads + passes to prompt for context.
    corpus_root:         Root of benign corpus — passed to noise_gate.
    detection_strategy:  Optional pre-analysis from DetectionPlanner. When present,
                         drives generalised rule generation anchored to invariants
                         rather than the specific emulated procedure. None triggers
                         standard (unenriched) prompt path.
    """
    technique_id: str
    technique_name: str
    tactic: str
    missed_events: list[dict]           # for prompt — serialised
    existing_rule_paths: list[Path]
    attack_sample: list[LogEvent]       # for validation — typed
    corpus_root: Path
    detection_strategy: Optional["DetectionStrategy"] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_existing_rules(rule_paths: list[Path]) -> list[str]:
    """Read existing rule YAML strings from disk."""
    rules = []
    for path in rule_paths:
        try:
            rules.append(path.read_text(encoding="utf-8"))
        except Exception as e:
            if DEBUG:
                print(f"[defender] Could not read rule {path}: {e}")
    return rules


def find_existing_rule_paths(
    technique_id: str,
    rules_dir: Path = RULES_DIR,
) -> list[Path]:
    """
    Find existing Sigma rules for a technique by filename pattern.
    Convention: rules/T1059.001-description.yml
    """
    if not rules_dir.exists():
        return []
    # Match both T1059.001-* and T1059-* (parent technique)
    patterns = [
        f"{technique_id}-*.yml",
        f"{technique_id}-*.yaml",
    ]
    found = []
    for pattern in patterns:
        found.extend(rules_dir.glob(pattern))
    return sorted(set(found))

# ---------------------------------------------------------------------------
# Rule assembly — merges model-authored fields with code-injected constants
# ---------------------------------------------------------------------------


AUTHOR = "SiddharthX17"  # single constant — change here if needed


def _quote_yaml_string(value: str) -> str:
    """Double-quote and escape a string for safe inline YAML (title, tags, author)."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _mitre_reference(technique_id: str) -> str:
    """Deterministic MITRE ATT&CK technique URL — no LLM involvement, no hallucination risk."""
    path = technique_id.replace(".", "/")
    return f"https://attack.mitre.org/techniques/{path}/"


def assemble_rule_yaml(parsed: dict, technique_id: str) -> str:
    """
    Merge LLM-authored fields (parsed JSON matching DEFENDER_OUTPUT_SCHEMA) with
    code-injected constants (id, date, status, author, references) into a
    complete Sigma YAML document. Field order matches SigmaHQ convention.

    The 'detection' block is spliced in as raw text, untouched — it still runs
    through normalize_rule_yaml() afterward exactly as before.
    """
    rule_id = str(uuid.uuid4())
    today = date.today().isoformat()

    lines = [
        f"title: {_quote_yaml_string(parsed['title'])}",
        f"id: {rule_id}",
        "status: experimental",
        "references:",
        f"    - {_mitre_reference(technique_id)}",
        f"author: {_quote_yaml_string(AUTHOR)}",
        f"date: {today}",
        "tags:",
    ]
    for tag in parsed.get("tags", []):
        lines.append(f"    - {tag}")

    lines += [
        "logsource:",
        f"    category: {parsed['logsource']['category']}",
        f"    product: {parsed['logsource']['product']}",
        "detection:",
    ]
    for det_line in parsed["detection"].splitlines():
        lines.append(f"    {det_line}" if det_line.strip() else "")

    fp_list = parsed.get("falsepositives") or []
    if fp_list:
        lines.append("falsepositives:")
        for fp in fp_list:
            lines.append(f"    - {_quote_yaml_string(fp)}")
    else:
        lines.append("falsepositives: []")

    lines.append(f"level: {parsed['level']}")

    return "\n".join(lines) + "\n"


def _call_llm(system_prompt: str, user_message: str, client: anthropic.Anthropic) -> dict | None:
    """
    Call Sonnet with cached system prompt and schema-constrained JSON output.
    Returns the parsed dict (matching DEFENDER_OUTPUT_SCHEMA), or None on failure.
    """
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=[
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_message}],
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": DEFENDER_OUTPUT_SCHEMA,
                }
            },
            thinking={"type": "disabled"},
        )

        if DEBUG:
            usage = response.usage
            if getattr(usage, "cache_creation_input_tokens", 0):
                print(
                    f"[defender] Cache WRITE: {usage.cache_creation_input_tokens} tokens")
            if getattr(usage, "cache_read_input_tokens", 0):
                print(
                    f"[defender] Cache HIT: {usage.cache_read_input_tokens} tokens")

        text_block = next(
            (b for b in response.content if b.type == "text"), None
        )
        if text_block is None:
            if DEBUG:
                print(
                    f"[defender] No text block in response "
                    f"(stop_reason={response.stop_reason})"
                )
            return None

        return json.loads(text_block.text.strip())

    except anthropic.APIError as e:
        if DEBUG:
            print(f"[defender] LLM call failed: {e}")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        if DEBUG:
            print(f"[defender] Response parsing failed: {e}")
        return None


def _build_retry_feedback(
    validation_result: ValidationResult,
    previous_rule: str,
) -> dict:
    """
    Build retry_feedback dict from a failed ValidationResult.
    Extracts the most actionable signal for the next attempt.
    """
    gate_failed = "unknown"
    error = "unknown"
    feedback = ""

    if not validation_result.lint_passed:
        gate_failed = "schema_linter"
        error = validation_result.feedback or "Lint failed"
        feedback = validation_result.feedback or ""
    elif not validation_result.attack_passed:
        gate_failed = "attack_gate"
        error = "Rule did not fire on attack log sample"
        feedback = validation_result.feedback or ""
    else:
        gate_failed = "noise_gate"
        fp_info = ""
        if validation_result.fp_rate is not None:
            fp_info = f" (FP rate: {validation_result.fp_rate:.1%})"
        error = f"FP rate too high{fp_info}"
        feedback = validation_result.feedback or ""

    return {
        "gate_failed": gate_failed,
        "error": error,
        "feedback": feedback,
        "previous_rule": previous_rule,
    }


# ---------------------------------------------------------------------------
# Main agent
# ---------------------------------------------------------------------------

class DefenderAgent:

    def __init__(self, corpus_root: Path | None = None):
        self._client = anthropic.Anthropic()
        self._default_corpus_root = corpus_root or Path("corpus/benign")

    def run(
        self,
        gap_context: GapContext,
    ) -> tuple[str | None, ValidationResult | None]:
        """
        Generate and validate a Sigma rule for the given gap.

        Attempts rule generation → validation up to MAX_RETRIES + 1 times.
        On each failure, passes gate feedback back to the LLM.

        Args:
            gap_context: GapContext describing what was missed and what exists.

        Returns:
            (rule_yaml, ValidationResult) — rule_yaml is None if all attempts fail.
            ValidationResult is the last result regardless of pass/fail.
        """
        technique_id = gap_context.technique_id
        existing_rules = _load_existing_rules(gap_context.existing_rule_paths)
        corpus_root = gap_context.corpus_root or self._default_corpus_root

        retry_feedback: dict | None = None
        last_result: ValidationResult | None = None
        last_rule: str | None = None

        # Determine retry cap based on which gate fails.
        # Lint failures = prompt quality issue — more retries won't help.
        # Noise/attack gate failures = rule logic issue — one extra retry is worthwhile.
        max_attempts = MAX_RETRIES + 1
        attempt = 1

        while attempt <= max_attempts:
            if DEBUG:
                print(
                    f"[defender] {technique_id}: attempt {attempt}/{max_attempts}"
                )

            user_message = build_defender_user_message(
                technique_id=technique_id,
                technique_name=gap_context.technique_name,
                tactic=gap_context.tactic,
                missed_events=gap_context.missed_events,
                existing_rules=existing_rules,
                retry_feedback=retry_feedback,
                detection_strategy=gap_context.detection_strategy,
            )

            parsed = _call_llm(DEFENDER_SYSTEM_PROMPT,
                               user_message, self._client)

            if not parsed:
                if DEBUG:
                    print(
                        f"[defender] {technique_id}: "
                        f"LLM returned nothing on attempt {attempt}"
                    )
                break

            rule_yaml = assemble_rule_yaml(parsed, technique_id)
            rule_yaml = normalize_rule_yaml(rule_yaml)
            last_rule = rule_yaml

            if DEBUG:
                print(f"[defender] {technique_id}: validating candidate rule")

            result = validate(
                rule_yaml=rule_yaml,
                attack_sample=gap_context.attack_sample,
                corpus_root=corpus_root,
            )
            last_result = result

            if result.passed:
                if DEBUG:
                    print(
                        f"[defender] {technique_id}: "
                        f"validation passed on attempt {attempt}"
                    )
                return rule_yaml, result

            gate = (
                "schema_linter" if not result.lint_passed
                else "attack_gate" if not result.attack_passed
                else "noise_gate"
            )

            print(
                f"[defender] {technique_id}: attempt {attempt}/{max_attempts} "
                f"failed — gate={gate} — "
                f"{str(result.feedback or 'none')[:120]}"
            )

            retry_feedback = _build_retry_feedback(result, rule_yaml)

            # Allow one extra retry for logical rule failures.
            if gate in ("attack_gate", "noise_gate"):
                max_attempts = max(
                    max_attempts,
                    MAX_RETRIES_GATE_FAILURE + 1
                )

            if attempt == max_attempts:
                print(
                    f"[defender] EXHAUSTED: {technique_id} — "
                    f"gate={gate}, "
                    f"feedback={result.feedback or 'none'}\n"
                    f"Final rule attempt:\n{rule_yaml}"
                )
                break

            attempt += 1

        return None, last_result
