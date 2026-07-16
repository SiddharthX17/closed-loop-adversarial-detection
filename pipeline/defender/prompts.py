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

if TYPE_CHECKING:
    from pipeline.detection_planner.planner import DetectionStrategy


# ---------------------------------------------------------------------------
# Structured output schema — enforced via output_config.format
# ---------------------------------------------------------------------------

DEFENDER_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "title": {"type": "string", "minLength": 1},
        "level": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "tags": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "logsource": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "category": {"type": "string"},
                "product": {"type": "string"},
            },
            "required": ["category", "product"],
        },
        "detection": {"type": "string", "minLength": 1},
        "falsepositives": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["title", "level", "tags", "logsource", "detection", "falsepositives"],
}


# ---------------------------------------------------------------------------
# Static system prompt — cached on first call, reused across all attempts
# ---------------------------------------------------------------------------

DEFENDER_SYSTEM_PROMPT = (
    "You are a detection engineer writing a Sigma rule for Windows Sysmon telemetry.\n\n"
    "Field selection:\n"
    "  Use only valid Sysmon field names:\n"
    "    Image, CommandLine, ParentImage, ParentCommandLine, TargetObject,\n"
    "    Details, DestinationIp, DestinationHostname, DestinationPort,\n"
    "    SourceIp, OriginalFileName, CurrentDirectory, Protocol, Initiated,\n"
    "    ProcessId, ParentProcessId\n\n"

    "Identity and exemption fields:\n"
    "  No field here is unspoofable identity — Image, OriginalFileName, and file\n"
    "  paths are all attacker-modifiable. When writing an identity or exemption\n"
    "  condition, prefer a field describing an inherent property of the entity\n"
    "  itself (its own Image path) over a field describing its relationship to\n"
    "  something else (ParentImage, CurrentDirectory) — relational fields are set\n"
    "  by the caller and are attacker-influenceable regardless of whether the\n"
    "  entity itself is genuine. Never use CurrentDirectory for security-relevant\n"
    "  scoping.\n\n"

    "Exemption/filter honesty:\n"
    "  Name and scope a filter for what it literally matches, not what it is\n"
    "  intended to represent — 'Image|startswith: C:\\Program Files\\' exempts\n"
    "  everything in Program Files, not just the vendor you meant. Use specific\n"
    "  vendor/tool paths or binary names when the intent is narrower than a\n"
    "  directory root.\n"
    "  Before filtering, judge whether the overlap with legitimate activity is\n"
    "  undifferentiated baseline behaviour (safe to exclude broadly) or a\n"
    "  mechanism also used by attackers for the same objective (installers,\n"
    "  LOLBins, admin tooling) — in the latter case, key the filter on what\n"
    "  specifically differs between legitimate and malicious use, not on the\n"
    "  mechanism's mere presence. Where no reliable differentiator exists, say\n"
    "  so rather than filtering anyway.\n\n"

    "Logsource:\n"
    "  logsource.category: process_creation, registry_set, network_connection,\n"
    "  or whichever matches the event type actually being targeted.\n"
    "  logsource.product: windows\n\n"

    "Multiple event types:\n"
    "  If the attack evidence contains events with different EventIDs (e.g. EID 1 and\n"
    "  EID 3, or EID 1 and EID 13), write a SINGLE rule targeting whichever event type\n"
    "  provides the strongest, most specific detection signal for this technique.\n"
    "  One rule = one logsource category. Do not attempt to cover multiple event types\n"
    "  in one rule — it is not possible in Sigma.\n\n"

    "Single-event scope:\n"
    "  Rules in this system evaluate one event at a time — there is no cross-event\n"
    "  correlation. Before combining two field values with AND, confirm both could\n"
    "  plausibly appear together in a single event from the same process invocation.\n"
    "  If two artifacts originate from separate, sequential commands, use OR instead\n"
    "  of faking co-occurrence that will rarely or never actually match.\n\n"

    "Registry paths:\n"
    "  Registry keys appear in two equivalent forms in Windows telemetry:\n"
    "  'HKCU' (shorthand) and 'HKEY_CURRENT_USER' (full form). Both may appear\n"
    "  in the same event stream for the same key. Use contains with a path fragment\n"
    "  that appears in both forms — never startswith with one specific prefix.\n"
    "  Correct:   TargetObject|contains: '\\SOFTWARE\\MyKey'\n"
    "  Wrong:     TargetObject|startswith: 'HKEY_CURRENT_USER\\SOFTWARE\\MyKey'\n"
    "  Backslashes in single-quoted YAML strings are literal — no escaping needed.\n"
    "  Correct:   TargetObject|contains: '\\SOFTWARE\\'\n"
    "  Wrong:     TargetObject|contains: '\\\\SOFTWARE\\\\'\n\n"

    "Encoded content matching:\n"
    "  Use a minimum of 16 non-padding characters when matching base64 in Details\n"
    "  or CommandLine — not 20 or higher. Short payloads (16-24 chars) are common.\n"
    "  Correct:   Details|re: '^[A-Za-z0-9+/]{16,}={0,2}$'\n"
    "  Wrong:     Details|re: '^[A-Za-z0-9+/]{20,}={0,2}$'\n\n"

    "Modifiers:\n"
    "  Valid: contains, startswith, endswith, re, all, base64, windash, exists.\n"
    "  Invalid (will fail schema linter): notcontains, not_contains, excludes.\n"
    "  For negative matching, use a filter selection and 'not' in the condition.\n"
    "  Do not hardcode full URLs, file hashes, or exact payloads unless definitively\n"
    "  unique to malicious activity.\n\n"

    "Output format:\n"
    "  The 'detection' field in your response is the YAML text for the Sigma\n"
    "  detection block's contents only — selections and condition, e.g.\n"
    "  'selection:\\n  Image|endswith: ...\\ncondition: selection'. Do not include\n"
    "  the 'detection:' key itself, and do not include title, logsource, or other\n"
    "  top-level rule fields in this string — those are separate response fields.\n"
)

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
    """Format DetectionStrategy (new schema) into the enriched prompt section."""

    # ── Evidence quality ──────────────────────────────────────────────────
    eq = strategy.evidence_quality
    unique_count = eq.get("unique_event_count", "?")
    diversity_note = eq.get("diversity_note", "")
    degenerate = isinstance(unique_count, int) and unique_count <= 1

    quality_lines = f"  {unique_count} distinct event(s). {diversity_note}"
    if degenerate:
        quality_lines += (
            "\n  DEGENERATE EVIDENCE: Do not anchor rule conditions on specific\n"
            "  field values from the events. They represent a single data point.\n"
            "  Rely on the detection opportunities and observable invariants below."
        )

    # ── Evidence assessment split by classification ───────────────────────
    assessment = strategy.evidence_assessment or []

    def _fmt_entries(entries: list[dict]) -> str:
        if not entries:
            return "    (none)"
        lines = []
        for e in entries:
            field = e.get("field", "?")
            use = e.get("detection_use") or e.get("rationale", "")
            lines.append(f"    {field}: {use}")
        return "\n".join(lines)

    invariant_entries = [e for e in assessment if e.get(
        "classification") == "invariant"]
    instance_entries = [e for e in assessment if e.get(
        "classification") == "instance"]
    artifact_entries = [e for e in assessment if e.get(
        "classification") == "artifact"]

    # ── Detection opportunities ───────────────────────────────────────────
    opp_blocks = []
    for i, opp in enumerate(strategy.detection_opportunities, 1):
        ctype = opp.get("coverage_type", "?").upper()
        desc = opp.get("description", "")
        etype = opp.get("event_type", "?")
        anchors = ", ".join(opp.get("anchor_fields") or [])
        obs_inv = opp.get("observable_invariant", "")
        viability = opp.get("viability", "?")
        precision = opp.get("precision_estimate", "?")
        reason = opp.get("selection_reason", "")
        fp_risk = opp.get("fp_risk", "")

        block = (
            f"  [{i}] {ctype} — {desc}\n"
            f"      Event type:    {etype}\n"
            f"      Anchor fields: {anchors}\n"
        )
        if obs_inv:
            block += f"      Invariant:     {obs_inv}\n"
        block += f"      Viability: {viability}  |  Precision: {precision}\n"
        if reason:
            block += f"      Selected:      {reason}\n"
        if fp_risk:
            block += f"      FP risk:       {fp_risk}\n"
        opp_blocks.append(block)

    # ── False positive profile ────────────────────────────────────────────
    fp_blocks = []
    for fp in (strategy.false_positive_profile or []):
        cat = fp.get("category", "?")
        manifests = ", ".join(fp.get("manifests_via") or []) or "?"
        filter_appr = fp.get("filter_approach", "")
        applies_to = fp.get("applies_to", "all")

        entry = f"  - {cat}"
        if applies_to != "all":
            entry += f" (applies to: {applies_to} coverage)"
        entry += f"\n    Manifests via: {manifests}"
        if filter_appr:
            entry += f"\n    Filter approach: {filter_appr}"
        fp_blocks.append(entry)

    fp_section = "\n".join(fp_blocks) if fp_blocks else "  (none identified)"

    return (
        "─── DETECTION STRATEGY ─────────────────────────────────\n"
        "Pre-analysis by a senior detection engineer. Use this to write a rule\n"
        "that captures the technique, not just the specific emulated procedure.\n\n"

        "Technique objective:\n"
        f"  {strategy.technique_objective}\n\n"

        "Evidence quality:\n"
        f"{quality_lines}\n\n"

        "Evidence assessment — how to treat each field:\n"
        "  ANCHOR on these (invariants — stable regardless of tooling):\n"
        f"{_fmt_entries(invariant_entries)}\n\n"
        "  GENERALISE these (instances — detect the class, not the specific value):\n"
        f"{_fmt_entries(instance_entries)}\n\n"
        "  IGNORE these (test artifacts — never match):\n"
        f"{_fmt_entries(artifact_entries)}\n\n"

        "Detection opportunities (implement the highest-viability option):\n"
        f"{''.join(opp_blocks)}\n"

        "False positive profile:\n"
        f"{fp_section}\n\n"

        "Rule design guidance:\n"
        f"  {strategy.rule_design_guidance.strip()}\n"
    )


# ---------------------------------------------------------------------------
# Main prompt builder
# ---------------------------------------------------------------------------

def build_defender_user_message(
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
    is_retry = retry_feedback is not None
    is_enriched = detection_strategy is not None

    # ── Header ────────────────────────────────────────────────────────────
    prompt = (
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
            "specific procedure instance. Use the evidence assessment above to\n"
            "decide what to anchor on, generalise, or ignore — not raw field values.\n"
            "The rule must match every event shown below, not just one — multiple\n"
            "events typically represent a base procedure and an evasion variant,\n"
            "and the rule must generalise across all of them:\n\n"
        )
    else:
        prompt += (
            "─── ATTACK EVIDENCE ─────────────────────────────────────\n"
            "The following events were not caught by existing rules.\n"
            "The rule must match every event shown below, not just one — multiple\n"
            "events typically represent a base procedure and an evasion variant,\n"
            "and the rule must generalise across all of them:\n\n"
        )

    prompt += f"{_format_missed_events(missed_events)}\n\n"

    # ── Existing rules ────────────────────────────────────────────────────
    prompt += (
        "─── EXISTING RULES (reference only) ────────────────────\n"
        "Shown to help you avoid duplicating coverage — not as a quality\n"
        "template. Apply the same standards to your rule regardless of whether\n"
        "these already meet them; do not imitate a filter, field choice, or\n"
        "condition structure merely because it already exists:\n\n"
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
    prompt += "─── REQUIREMENTS ────────────────────────────────────────\n\n"

    if is_enriched:
        prompt += (
            "Detection logic:\n"
            "  Implement the highest-viability detection opportunity in the strategy.\n"
            "  The rule design guidance specifies required conditions, supporting\n"
            "  conditions, negative conditions, and FP filters — follow it.\n\n"
            "  Use the evidence assessment to guide field handling:\n"
            "    INVARIANT fields: anchor rule conditions here\n"
            "    INSTANCE fields: detect the named class, not the literal value\n"
            "    ARTIFACT fields: do not match these — they are test-specific\n\n"
            "  If evidence is degenerate (flagged above), rely on the observable\n"
            "  invariant from the detection opportunity, not on specific event values.\n\n"
            "  FP filtering: use the filter approach from each FP profile entry.\n"
            "  Each entry specifies which fields to filter on and how.\n"
            "  Critical: verify each filter condition does NOT match any field value\n"
            "  visible in the attack evidence. A filter matching attacker-controlled\n"
            "  strings (task names, command lines, paths) excludes the detection.\n"
            "  Use specific binary names or known-good path prefixes only — generic\n"
            "  keywords that could appear in attacker-chosen strings will cause\n"
            "  false negatives.\n"
            "  Use AND logic to combine conditions — avoid single-field rules.\n\n"
        )
    else:
        prompt += (
            "Detection logic:\n"
            "  The rule must match the missed events above — not just the technique in general.\n"
            "  Keep logic specific enough to avoid routine enterprise activity\n"
            "  (legitimate PowerShell, scheduled tasks, software updates).\n"
            "  If using CommandLine matching, combine conditions only when they would\n"
            "  co-occur in the same event (see single-event scope above).\n"
            "  Prefer specific high-signal fields over broad keyword matching.\n"
            "  Good: Image|endswith: '\\\\rundll32.exe' AND CommandLine|contains: 'comsvcs'\n"
            "  Bad: CommandLine|contains: 'malware' (too vague)\n\n"
        )

    prompt += (
        "Metadata:\n"
        "  Title: concise and descriptive — also the basis for the rule's filename\n"
        f"  ({technique_id}-<short-description>), so keep it tight.\n\n"
        "  Tags: include at minimum the tactic tag and the technique tag —\n"
        f"  e.g. 'attack.{tactic.lower().replace(' ', '-')}' and\n"
        f"  'attack.{technique_id.lower()}'.\n\n"
        "  Level: your genuine severity judgment — not a default value.\n\n"
        "  False positives: genuine legitimate-activity sources only. An empty\n"
        "  list is correct when none meaningfully apply — do not pad it.\n\n"

        "Your response is constrained to a JSON schema enforced by the API — you\n"
        "do not need to format YAML yourself. Focus on the quality of the detection\n"
        "logic and metadata judgment; structure is guaranteed."
    )

    return prompt
