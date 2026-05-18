"""
pipeline/defender/prompts.py

Prompt templates for the defender agent.

Two execution paths:
  - Enriched:  DetectionStrategy present — planner has already done technique-level
               analysis. Prompt is anchored to invariants and FP categories.
               Rule-writing is guided by generalisation principles, not just events.
  - Fallback:  DetectionStrategy absent — standard path using missed events and
               existing rules. Effective but not invariant-anchored.

Both paths handle first attempt and retries through the same template.
retry_feedback is None on first call, populated on subsequent attempts.

Detection engineering principles applied:
  1. Write to the behaviour, not the artifact.
     A rule that fires on 'powershell.exe' breaks when the attacker renames it.
     A rule that fires on 'script interpreter loading encoded content from a
     user-writable path' survives tooling substitution.

  2. The missed events are a spark, not a blueprint.
     One observed procedure confirms the technique is present. It does not define
     the full detection surface. A rule scoped to a single procedure variant will
     miss the next iteration.

  3. Specificity is a dial, not a binary.
     Too broad: fires on legitimate enterprise activity. Too narrow: misses variants.
     The right position is the most specific condition that still captures the
     technique family across realistic procedure variation.

  4. FP exclusions are first-class conditions.
     Knowing what legitimate activity looks like is as important as knowing what
     malicious activity looks like. Explicit exclusions reduce noise gate failures
     and make the rule defensible in a real environment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, TYPE_CHECKING
import uuid

if TYPE_CHECKING:
    from pipeline.detection_planner.planner import DetectionStrategy


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _format_missed_events(missed_events: list[dict]) -> str:
    if not missed_events:
        return "  (none available)"
    lines = []
    for i, event in enumerate(missed_events[:5], 1):
        populated = {k: v for k,
                     v in event.items() if v is not None and v != ""}
        lines.append(f"  [{i}] {populated}")
    return "\n".join(lines)


def _format_existing_rules(existing_rules: list[str]) -> str:
    if not existing_rules:
        return "  (no existing rules for this technique)"
    parts = []
    for i, rule_yaml in enumerate(existing_rules, 1):
        parts.append(f"--- Rule {i} ---\n{rule_yaml.strip()}")
    return "\n\n".join(parts)


def _format_retry_feedback(retry_feedback: dict | None) -> str:
    if not retry_feedback:
        return ""
    lines = [
        "\n─── PREVIOUS ATTEMPT FAILED ────────────────────────────",
        f"Gate:     {retry_feedback.get('gate_failed', 'unknown')}",
        f"Error:    {retry_feedback.get('error', 'unknown')}",
    ]
    if retry_feedback.get("feedback"):
        lines.append(f"Specific feedback: {retry_feedback['feedback']}")
    if retry_feedback.get("previous_rule"):
        lines.append(
            f"\nPrevious rule (do not repeat this):\n"
            f"{retry_feedback['previous_rule'].strip()}"
        )
    lines.append(
        "\nFix the issues identified above. "
        "Do not repeat the same flawed logic. Reuse fields only where justified.\n"
        "Fix the failed gate while preserving aspects that likely passed."
    )
    return "\n".join(lines)


def _format_strategy_block(strategy: "DetectionStrategy") -> str:
    """Format DetectionStrategy into the enriched prompt section."""
    behaviors = "\n".join(
        f"  - {b}" for b in strategy.key_behaviors) or "  (none)"
    fields = ", ".join(strategy.relevant_fields) or "(none specified)"
    invariants = "\n".join(
        f"  - {inv}" for inv in strategy.detection_invariants) or "  (none)"
    fp_cats = "\n".join(
        f"  - {cat}" for cat in strategy.false_positive_profile) or "  (none)"

    return (
        "─── DETECTION STRATEGY (pre-analysis) ──────────────────\n"
        "A senior detection engineer has analysed this gap. Use this strategy\n"
        "to write a rule that captures the technique, not just this procedure.\n\n"

        "What the attacker is accomplishing:\n"
        f"{behaviors}\n\n"

        f"Highest-signal Sysmon fields for this technique: {fields}\n\n"

        "Detection invariants — conditions that hold across tooling variation.\n"
        "Anchor your rule logic to these. They are the non-negotiable core:\n"
        f"{invariants}\n\n"

        "False positive categories to explicitly exclude in rule conditions.\n"
        "Legitimate enterprise activity in these categories produces similar\n"
        "observables — your conditions must discriminate against them:\n"
        f"{fp_cats}\n\n"

        "Generalisation guidance:\n"
        f"  {strategy.generalization_notes.strip()}\n"
    )


# ---------------------------------------------------------------------------
# Main prompt builder
# ---------------------------------------------------------------------------

def build_defender_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    missed_events: list[dict],
    existing_rules: list[str],
    retry_feedback: dict | None = None,
    detection_strategy: Optional["DetectionStrategy"] = None,
) -> str:
    """
    Build a defender agent prompt.

    When detection_strategy is present, the prompt is structured around the
    pre-analysis: invariant-anchored, FP-aware, generalised beyond the specific
    emulated procedure.

    When detection_strategy is None, the prompt falls back to the standard
    evidence-driven path: missed events + existing rules as primary context.

    Args:
        technique_id:       ATT&CK technique ID e.g. T1059.001
        technique_name:     Human-readable name
        tactic:             ATT&CK tactic
        missed_events:      Log events not caught by existing rules (up to 5)
        existing_rules:     Existing Sigma YAML strings for this technique
        retry_feedback:     None on first attempt. On retry: gate_failed, error,
                            feedback, previous_rule
        detection_strategy: Optional DetectionStrategy from DetectionPlanner.
                            Controls which prompt path is used.

    Returns:
        Prompt string ready to send to the LLM.
    """
    generated_id = str(uuid.uuid4())
    is_retry = retry_feedback is not None
    is_enriched = detection_strategy is not None

    # ── Header ────────────────────────────────────────────────────────────
    prompt = (
        "You are a detection engineer writing a Sigma rule for Windows Sysmon telemetry.\n\n"
        f"Technique: {technique_id} — {technique_name}\n"
        f"Tactic:    {tactic}\n\n"
    )

    # ── Detection strategy (enriched path) ────────────────────────────────
    if is_enriched:
        prompt += _format_strategy_block(detection_strategy) + "\n"

    # ── Attack evidence ───────────────────────────────────────────────────
    if is_enriched:
        prompt += (
            "─── ATTACK EVIDENCE ─────────────────────────────────────\n"
            "These events confirm the technique is present. They represent one\n"
            "specific procedure instance — treat them as a spark, not a blueprint.\n"
            "Write to the invariants above, not to the field values below:\n\n"
        )
    else:
        prompt += (
            "─── ATTACK EVIDENCE ─────────────────────────────────────\n"
            "The following events were not caught by existing rules.\n"
            "Write a Sigma rule that detects them:\n\n"
        )

    prompt += f"{_format_missed_events(missed_events)}\n\n"

    # ── Existing rules ────────────────────────────────────────────────────
    prompt += (
        "─── EXISTING RULES (reference only) ────────────────────\n"
        "Understand what is already covered (use them as context, not ground truth) \n"
        "before deciding whether to write a new rule or improve an existing one:\n\n"
        f"{_format_existing_rules(existing_rules)}\n\n"
    )

    # ── Decision guidance ─────────────────────────────────────────────────
    prompt += (
        "─── DECISION GUIDANCE ───────────────────────────────────\n"
        "Write a NEW rule if the evidence represents a fundamentally different\n"
        "execution pattern (different event type, different execution chain).\n\n"
        "IMPROVE an existing rule if the evidence is a variant of what it already\n"
        "targets and tightening or broadening conditions would close the gap.\n\n"
    )

    # ── Retry feedback (if applicable) ────────────────────────────────────
    if is_retry:
        prompt += _format_retry_feedback(retry_feedback) + "\n\n"

    # ── Requirements ──────────────────────────────────────────────────────
    prompt += (
        "─── REQUIREMENTS ────────────────────────────────────────\n\n"

        "Rule ID:\n"
        f"  Use exactly this UUID4: {generated_id}\n"
        "  Do not change it.\n\n"

        "Field selection:\n"
        "  Use only valid Sysmon field names:\n"
        "    Image, CommandLine, ParentImage, ParentCommandLine, TargetObject,\n"
        "    Details, DestinationIp, DestinationHostname, DestinationPort,\n"
        "    SourceIp, OriginalFileName, CurrentDirectory, Protocol, Initiated,\n"
        "    ProcessId, ParentProcessId\n\n"
    )

    if is_enriched:
        prompt += (
            "Detection logic:\n"
            "  Prefer conditions anchored to the detection invariants in the strategy above —\n"
            "  they survive binary renaming, flag reordering, and procedure substitution.\n"
            "  Exception: if the tool or binary is the core of the attack, or is a prerequisite\n"
            "  for the technique to work at all, tool-specific conditions are preferred and\n"
            "  should be combined with invariant-level conditions where possible.\n"
            "  Use AND logic to combine high-signal conditions — avoid single-field rules.\n"
            "  FP filtering: use the false positive categories in the strategy as a starting\n"
            "  point for exclusion conditions (NOT / filter logic). Lower priority than\n"
            "  detection coverage — filters must not introduce false negatives.\n\n"
        )
    else:
        prompt += (
            "Detection logic:\n"
            "  The rule must match the missed events above — not just the technique in general.\n"
            "  Keep logic specific enough to avoid routine enterprise activity\n"
            "  (legitimate PowerShell, scheduled tasks, software updates).\n"
            "  If using CommandLine matching, require multiple AND conditions.\n"
            "  Prefer specific high-signal fields over broad keyword matching.\n"
            "  Good: Image|endswith: '\\\\rundll32.exe' AND CommandLine|contains: 'comsvcs'\n"
            "  Bad: CommandLine|contains: 'malware' (too vague)\n\n"
        )

    prompt += (
        "Logsource:\n"
        "  Set logsource correctly for Sysmon:\n"
        "    logsource:\n"
        "      category: process_creation  # or registry_set, network_connection, etc.\n"
        "      product: windows\n\n"

        "Modifiers:\n"
        "  Use Sigma modifiers correctly: contains, startswith, endswith, re (regex), all (all conditions must match).\n"
        "  Do not hardcode full URLs, file hashes, or exact string payloads unless\n"
        "  they are definitively unique to malicious activity.\n\n"

        "Metadata:\n"
        "  - Descriptive title\n"
        f"  - tags: attack.{technique_id.lower()}\n"
        "  - status: experimental\n"
        f"  - Rule filename convention (for your title): {technique_id}-<short-description>\n\n"
        "Output the Sigma YAML rule only. No explanation, no markdown fences, no preamble."
    )

    return prompt
