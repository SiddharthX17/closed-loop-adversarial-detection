"""
validation_pipeline.py

Sequential validation pipeline: schema_linter → attack_gate → noise_gate.
All three gates must pass. Failure at any gate returns immediately with
structured feedback for the defender agent retry loop.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pipeline.validation import schema_linter, attack_gate, noise_gate
from pipeline.emulator.log_builder import LogEvent


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    passed:       bool
    # "schema_linter" | "attack_gate" | "noise_gate"
    gate_failed:  Optional[str] = None
    # fed directly to defender agent retry prompt
    feedback:     Optional[str] = None
    error:        Optional[str] = None   # engine/execution error if any

    # Per-gate detail (populated regardless of pass/fail for diagnostics)
    lint_passed:  Optional[bool] = None
    attack_passed: Optional[bool] = None
    noise_passed: Optional[bool] = None

    # Noise gate metrics (useful for metrics/tracker.py)
    fp_rate:      Optional[float] = None
    fp_count:     Optional[int] = None
    total_benign: Optional[int] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(
    rule_yaml: str,
    attack_sample: list[LogEvent],
    corpus_root: Path,
    *,
    min_match_count: int = 1,
    min_match_ratio: float = 1.0,
    fp_threshold: float = 0.01,
    benign_gen_seed: int = 42,
    supplement_with_generated: bool = True,
) -> ValidationResult:
    """
    Run a candidate Sigma rule through all three validation gates in sequence.

    Args:
        rule_yaml:                 Sigma rule YAML string.
        attack_sample:             Emulated attack LogEvents for the technique.
        corpus_root:               Path to corpus/benign/ directory.
        min_match_count:           Minimum events attack_gate must match.
        min_match_ratio:           Minimum ratio of attack events matched.
        fp_threshold:              Max FP rate for noise_gate (default 0.01).
        benign_gen_seed:           Seed passed to benign_generator supplement.
        supplement_with_generated: Whether noise_gate supplements with synthetic events.

    Returns:
        ValidationResult — passed=True only if all three gates pass.
    """
    debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")

    # attack_gate expects list[dict]; noise_gate expects list[LogEvent]
    attack_sample_dicts = [e.model_dump(
        exclude_none=True) for e in attack_sample]

    # ------------------------------------------------------------------
    # Gate 1 — Schema linter
    # ------------------------------------------------------------------
    if debug:
        print("[validation_pipeline] Gate 1: schema_linter")

    lint_result = schema_linter.validate(rule_yaml)

    if not lint_result.passed:
        if debug:
            print(
                f"[validation_pipeline] schema_linter FAILED: {lint_result.feedback()}")
        return ValidationResult(
            passed=False,
            gate_failed="schema_linter",
            feedback=lint_result.feedback(),
            lint_passed=False,
            attack_passed=None,
            noise_passed=None,
        )

    # ------------------------------------------------------------------
    # Gate 2 — Attack gate
    # ------------------------------------------------------------------
    if debug:
        print("[validation_pipeline] Gate 2: attack_gate")

    attack_result = attack_gate.run(
        rule_yaml,
        attack_sample_dicts,
        min_match_count=min_match_count,
        min_match_ratio=min_match_ratio,
    )
    if attack_result.skipped:
        if debug:
            print(
                f"[validation_pipeline] attack_gate SKIPPED: {attack_result.feedback()}")
        return ValidationResult(
            passed=False,
            gate_failed="attack_gate",
            feedback=attack_result.feedback(),
            lint_passed=True,
            attack_passed=False,
            noise_passed=None,
        )

    if not attack_result.passed:
        if debug:
            print(
                f"[validation_pipeline] attack_gate FAILED: {attack_result.feedback()}")
        return ValidationResult(
            passed=False,
            gate_failed="attack_gate",
            feedback=attack_result.feedback(),
            lint_passed=True,
            attack_passed=False,
            noise_passed=None,
        )

    # ------------------------------------------------------------------
    # Gate 3 — Noise gate
    # ------------------------------------------------------------------
    if debug:
        print("[validation_pipeline] Gate 3: noise_gate")

    noise_result = noise_gate.run(
        rule_yaml,
        attack_sample,
        corpus_root,
        fp_threshold=fp_threshold,
        benign_gen_seed=benign_gen_seed,
        supplement_with_generated=supplement_with_generated,
    )

    if not noise_result.passed:
        if debug:
            print(
                f"[validation_pipeline] noise_gate FAILED: {noise_result.feedback()}")
        return ValidationResult(
            passed=False,
            gate_failed="noise_gate",
            feedback=noise_result.feedback(),
            error=noise_result.error,
            lint_passed=True,
            attack_passed=True,
            noise_passed=False,
            fp_rate=noise_result.fp_rate,
            fp_count=noise_result.fp_count,
            total_benign=noise_result.total_events,
        )

    if debug:
        print("[validation_pipeline] All gates passed.")

    return ValidationResult(
        passed=True,
        lint_passed=True,
        attack_passed=True,
        noise_passed=True,
        fp_rate=noise_result.fp_rate,
        fp_count=noise_result.fp_count,
        total_benign=noise_result.total_events,
    )
