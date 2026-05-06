"""
pipeline/defender/agent.py

Defender agent — receives a GapContext, generates candidate Sigma YAML,
validates through the full validation pipeline, retries on failure (max 2).

Returns (rule_yaml, ValidationResult) or (None, last_result) on exhaustion.
"""

import os
import anthropic

from dataclasses import dataclass, field
from dotenv import load_dotenv
from pathlib import Path

from pipeline.defender.prompts import build_defender_prompt
from pipeline.validation.validation_pipeline import validate, ValidationResult
from pipeline.emulator.log_builder import LogEvent

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

MODEL = "claude-haiku-4-5-20251001"
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
    """
    technique_id: str
    technique_name: str
    tactic: str
    missed_events: list[dict]           # for prompt — serialised
    existing_rule_paths: list[Path]
    attack_sample: list[LogEvent]       # for validation — typed
    corpus_root: Path


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


def _call_llm(prompt: str, client: anthropic.Anthropic) -> str | None:
    """
    Call Haiku, return raw text response (Sigma YAML).
    Returns None on API failure.
    """
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()

        # Strip markdown fences — LLM sometimes wraps YAML in ```yaml
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            ).strip()

        return raw

    except (IndexError, anthropic.APIError) as e:
        if DEBUG:
            print(f"[defender] LLM call failed: {e}")
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
        max_attempts = MAX_RETRIES + 1  # default: 3 total attempts

        for attempt in range(1, max_attempts + 1):
            if DEBUG:
                print(
                    f"[defender] {technique_id}: attempt {attempt}/{max_attempts}"
                )

            prompt = build_defender_prompt(
                technique_id=technique_id,
                technique_name=gap_context.technique_name,
                tactic=gap_context.tactic,
                missed_events=gap_context.missed_events,
                existing_rules=existing_rules,
                retry_feedback=retry_feedback,
            )

            rule_yaml = _call_llm(prompt, self._client)

            if not rule_yaml:
                if DEBUG:
                    print(
                        f"[defender] {technique_id}: "
                        f"LLM returned nothing on attempt {attempt}"
                    )
                break

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

            if attempt < max_attempts:
                retry_feedback = _build_retry_feedback(result, rule_yaml)

                # Bump cap if gate (not lint) is failing — one extra attempt worth it
                if gate in ("noise_gate", "attack_gate"):
                    max_attempts = min(
                        max_attempts,
                        MAX_RETRIES_GATE_FAILURE + 1
                    )
            else:
                print(
                    f"[defender] EXHAUSTED: {technique_id} — "
                    f"gate={gate}, "
                    f"feedback={result.feedback or 'none'}\\n"
                    f"Final rule attempt:\\n{rule_yaml}"
                )

        return None, last_result
