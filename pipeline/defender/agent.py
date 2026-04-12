"""
pipeline/defender/agent.py

Defender agent — receives a GapContext, generates candidate Sigma YAML,
validates through the full validation pipeline, retries on failure (max 2).

Returns (rule_yaml, ValidationResult) or (None, last_result) on exhaustion.
"""

import os
import json
import anthropic

from dataclasses import dataclass, field
from dotenv import load_dotenv
from pathlib import Path

from pipeline.defender.prompts import build_defender_prompt
from pipeline.validation.validation_pipeline import ValidationPipeline

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

MODEL = "claude-haiku-4-5-20251001"
MAX_RETRIES = 2
RULES_DIR = Path("rules")


# ---------------------------------------------------------------------------
# GapContext
# ---------------------------------------------------------------------------

@dataclass
class GapContext:
    """
    Everything the defender agent needs to generate a candidate rule.

    missed_events:       Log events that existing rules did not catch (up to 5).
                         Dicts with Sysmon field names as keys.
    existing_rule_paths: Paths to existing Sigma rules for this technique.
                         Agent reads them and decides whether to improve or write new.
    attack_sample:       Full attack log sample for this technique — passed to
                         attack_gate for validation. Superset of missed_events.
    corpus_root:         Root of benign corpus — passed to noise_gate.
    """
    technique_id: str
    technique_name: str
    tactic: str
    missed_events: list[dict]
    existing_rule_paths: list[Path]
    attack_sample: list[dict]
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


def find_existing_rule_paths(technique_id: str, rules_dir: Path = RULES_DIR) -> list[Path]:
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
    Call Haiku, return raw text response.
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

        # Strip markdown fences if present — LLM sometimes wraps YAML in ```yaml
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
    validation_result,
    previous_rule: str,
) -> dict:
    """
    Build the retry_feedback dict from a failed ValidationResult.
    Extracts the most useful signal for the next attempt.
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
    elif not validation_result.noise_passed:
        gate_failed = "noise_gate"
        error = f"FP rate too high — rule fired on benign corpus"
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
        self._pipeline = ValidationPipeline()
        self._default_corpus_root = corpus_root or Path("corpus/benign")

    def run(
        self,
        gap_context: GapContext,
    ) -> tuple[str | None, object]:
        """
        Generate and validate a Sigma rule for the given gap.

        Attempts rule generation → validation up to MAX_RETRIES + 1 times.
        On each failure, passes the gate feedback back to the LLM.

        Args:
            gap_context: GapContext describing what was missed and what exists.

        Returns:
            (rule_yaml, ValidationResult) — rule_yaml is None if all attempts fail.
        """
        technique_id = gap_context.technique_id
        existing_rules = _load_existing_rules(gap_context.existing_rule_paths)
        corpus_root = gap_context.corpus_root or self._default_corpus_root

        retry_feedback: dict | None = None
        last_result = None
        last_rule = None

        for attempt in range(1, MAX_RETRIES + 2):  # attempts: 1, 2, 3
            if DEBUG:
                print(
                    f"[defender] {technique_id}: attempt {attempt}/{MAX_RETRIES + 1}"
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
                        f"[defender] {technique_id}: LLM returned nothing on attempt {attempt}")
                # No point retrying an API failure with the same prompt
                break

            last_rule = rule_yaml

            if DEBUG:
                print(f"[defender] {technique_id}: validating candidate rule")

            result = self._pipeline.run(
                rule_yaml=rule_yaml,
                attack_sample=gap_context.attack_sample,
                corpus_root=corpus_root,
            )
            last_result = result

            if result.passed:
                if DEBUG:
                    print(
                        f"[defender] {technique_id}: validation passed on attempt {attempt}")
                return rule_yaml, result

            if DEBUG:
                print(
                    f"[defender] {technique_id}: attempt {attempt} failed — "
                    f"gate={('schema_linter' if not result.lint_passed else 'attack_gate' if not result.attack_passed else 'noise_gate')}, "
                    f"feedback={result.feedback[:120] if result.feedback else 'none'}"
                )

            if attempt <= MAX_RETRIES:
                retry_feedback = _build_retry_feedback(result, rule_yaml)
            else:
                # Exhausted retries — log and give up
                gate = (
                    "schema_linter" if not result.lint_passed
                    else "attack_gate" if not result.attack_passed
                    else "noise_gate"
                )
                print(
                    f"[defender] EXHAUSTED: {technique_id} — "
                    f"gate={gate}, "
                    f"feedback={result.feedback or 'none'}\n"
                    f"Final rule attempt:\n{rule_yaml}"
                )

        return None, last_result
