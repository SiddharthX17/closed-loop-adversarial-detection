"""
pipeline/detection_planner/prompts.py

Prompt template for the detection planner stage.

The planner emulates a detection engineer triaging a new coverage gap.
It works through a structured reasoning framework — attack analysis,
evidence classification, detection opportunity mapping, FP profiling —
and produces a DetectionStrategy that the defender agent consumes directly.

System prompt is static (cached on Sonnet at ≥1024 tokens).
User message is dynamic per call (technique metadata + evidence).
"""


def _format_missed_events(missed_events: list[dict]) -> str:
    if not missed_events:
        return "  (no events available)"
    lines = []
    for i, event in enumerate(missed_events[:5], 1):
        populated = {k: v for k,
                     v in event.items() if v is not None and v != ""}
        lines.append(f"  [{i}] {populated}")
    return "\n".join(lines)


def _format_data_sources(data_sources: list[str]) -> str:
    if not data_sources:
        return "  (not specified)"
    return "\n".join(f"  - {ds}" for ds in data_sources[:8])


PLANNER_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "technique_objective": {"type": "string"},
        "evidence_quality": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "unique_event_count": {"type": "integer"},
                "diversity_note": {"type": "string"},
            },
            "required": ["unique_event_count", "diversity_note"],
        },
        "evidence_assessment": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "field": {"type": "string"},
                    "value_summary": {"type": "string"},
                    "classification": {"type": "string", "enum": ["artifact", "instance", "invariant"]},
                    "rationale": {"type": "string"},
                    "detection_use": {"type": "string"},
                },
                "required": ["field", "value_summary", "classification", "rationale", "detection_use"],
            },
        },
        "detection_opportunities": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "description": {"type": "string"},
                    "event_type": {"type": "string", "enum": ["process_creation", "registry", "network"]},
                    "anchor_fields": {"type": "array", "items": {"type": "string"}},
                    "coverage_type": {"type": "string", "enum": ["specific", "adjacent", "family"]},
                    "observable_invariant": {"type": "string"},
                    "coverage_gain": {"type": "string", "enum": ["high", "medium", "low"]},
                    "precision_estimate": {"type": "string", "enum": ["high", "medium", "low"]},
                    "viability": {"type": "string", "enum": ["high", "medium", "low"]},
                    "selection_reason": {"type": "string"},
                    "fp_risk": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "level": {"type": "string", "enum": ["high", "medium", "low"]},
                            "reason": {"type": "string"},
                        },
                        "required": ["level", "reason"],
                    },
                },
                "required": [
                    "description", "event_type", "anchor_fields", "coverage_type",
                    "observable_invariant", "coverage_gain", "precision_estimate",
                    "viability", "selection_reason", "fp_risk",
                ],
            },
        },
        "false_positive_profile": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "category": {"type": "string"},
                    "manifests_via": {"type": "array", "items": {"type": "string"}},
                    "filter_approach": {"type": "string"},
                    "applies_to": {"type": "string", "enum": ["all", "specific", "adjacent", "family"]},
                },
                "required": ["category", "manifests_via", "filter_approach", "applies_to"],
            },
        },
        "rule_design_guidance": {"type": "string"},
    },
    "required": [
        "technique_objective", "evidence_quality", "evidence_assessment",
        "detection_opportunities", "false_positive_profile", "rule_design_guidance",
    ],
}


PLANNER_SYSTEM_PROMPT = (
    "You are a senior detection engineer triaging a missed attack detection.\n"
    "Your output is consumed directly by an automated Sigma rule writer.\n"
    "Every field you produce becomes a direct input to rule construction.\n"
    "Analysis quality here determines rule quality downstream.\n\n"
    "Work through the six phases below in order. Produce no output until all\n"
    "phases are complete. The JSON you return is the result of this reasoning —\n"
    "not a summary of what the technique does.\n\n"

    "══ PHASE 1 — TECHNIQUE OBJECTIVE ══════════════════════════════════════════\n"
    "Establish what the attacker is mechanically accomplishing.\n"
    "Derive this from technique knowledge first. The evidence is one instance.\n"
    "Answer: what capability is being exercised and what does it enable?\n"
    "Format: verb-led, mechanism-focused, one sentence.\n"
    "  Weak:   'attacker runs encoded PowerShell'\n"
    "  Strong: 'execute arbitrary code via a trusted interpreter using payload\n"
    "           encoding to evade command-line based inspection'\n\n"

    "══ ADJACENT BEHAVIOR ANALYSIS ══════════════════════════════════════════════\n"
    "Think beyond the observed procedure before assessing the evidence.\n\n"
    "Identify:\n\n"
    "  Likely predecessor activity\n"
    "    What commonly occurs immediately before this behavior in an attack chain?\n\n"
    "  Likely follow-on activity\n"
    "    What attacker actions commonly occur after this technique succeeds?\n\n"
    "  Interchangeable tooling\n"
    "    What alternative tools or procedures achieve the same attacker objective?\n\n"
    "  Shared attacker objective\n"
    "    What broader goal does this behavior support, independent of the tool used?\n\n"
    "Use this analysis to discover detection opportunities that remain valid when the\n"
    "observed tool, payload, command-line, or infrastructure changes.\n\n"
    "Do not generate detections from this section directly.\n"
    "Use it to inform opportunity selection in Phase 4.\n\n"
    "══ PHASE 2 — EVIDENCE QUALITY ══════════════════════════════════════════════\n"
    "Before analysing any field values, assess the evidence itself.\n"
    "Count distinct events after deduplication by content.\n"
    "Two events with identical field values is one data point, not two.\n"
    "If unique_event_count == 1, all subsequent phases must weight technique\n"
    "knowledge over observable values — the evidence cannot support specific\n"
    "or adjacent-level detection without overfitting to a single test instance.\n"
    "State this clearly in diversity_note.\n\n"

    "══ PHASE 3 — EVIDENCE ASSESSMENT ══════════════════════════════════════════\n"
    "Classify each field that has detection potential. Skip pure context fields,\n"
    "e.g. generic hostnames, process IDs, timestamps, SYSTEM user, standard ports.\n\n"
    "  ARTIFACT  — Test-specific. A rule matching this is a test-detector, not a\n"
    "              technique-detector. Never anchor rule conditions on artifacts.\n"
    "    Signs:  test framework identifiers in paths (ATOMIC-, T1XXX in strings),\n"
    "            loopback/localhost addresses, hardcoded test tool names,\n"
    "            sequential test identifiers, values only meaningful in a harness.\n"
    "    detection_use: 'ignore'\n\n"
    "  INSTANCE  — One concrete example of a detectable class.\n"
    "              The value is not the signal — the class it belongs to is.\n"
    "    Signs:  a specific paste site (class: paste site hostnames), a specific\n"
    "            encoded string (class: base64-encoded payload in this field),\n"
    "            a specific suspicious path (class: user-writable non-system paths).\n"
    "    Requirement: name the class explicitly. That named class is what the rule\n"
    "    will detect. Leaving it unnamed passes the work to the rule writer.\n"
    "    detection_use: 'detect class: <explicit class name>'\n\n"
    "  INVARIANT — Structurally required by the technique regardless of tooling.\n"
    "              This is the anchor. Rules built here survive binary renames,\n"
    "              flag reordering, and procedure substitution.\n"
    "    Signs:  Initiated:true for any attacker-initiated outbound connection,\n"
    "            a registry hive that is structurally required for the persistence\n"
    "            mechanism, a binary whose use defines the technique (certutil for\n"
    "            T1140 — the tool IS the technique, it cannot be substituted).\n"
    "    detection_use: 'anchor condition: <describe what to match>'\n\n"
    "  Important: a tool is an INVARIANT only when its use fundamentally defines\n"
    "  the technique itself. Common attacker tools — PowerShell, rundll32, mshta,\n"
    "  cmd, wscript, renamed binaries — are normally implementations, not invariants.\n"
    "  Prefer behavioral requirements over tool identity whenever possible.\n\n"
    "  Evasion cost (apply only when a field is a well-established, common\n"
    "  evasion vector — e.g. binary renaming changes Image while OriginalFileName\n"
    "  persists as PE metadata, PPID spoofing undermines ParentImage — and the\n"
    "  technique realistically permits that evasion; do not force this reasoning\n"
    "  onto every field or turn a simple, sufficient single condition into\n"
    "  unnecessary complexity): rank preference as behavioral/structural\n"
    "  invariant > PE metadata (OriginalFileName) > filename/path (Image,\n"
    "  ParentImage).\n\n"

    "══ PHASE 4 — DETECTION OPPORTUNITIES ══════════════════════════════════════\n"
    "Before selecting coverage types, evaluate potential detection opportunities.\n\n"
    "For each opportunity identify:\n\n"
    "  Detection target\n"
    "    What attacker behavior would this opportunity detect?\n\n"
    "  Observable invariant\n"
    "    What observable survives tooling changes, binary renaming, and procedure\n"
    "    variation? What must remain true for the technique to work at all?\n\n"
    "  Coverage gain\n"
    "    Does this detect only the observed procedure, a procedure family,\n"
    "    or multiple implementations of the same attacker objective?\n"
    "    Values: high | medium | low\n\n"
    "  Precision estimate\n"
    "    How precisely does this opportunity distinguish attacker activity from\n"
    "    legitimate enterprise behaviour?\n"
    "    Values: high | medium | low\n\n"
    "  Viability\n"
    "    Can the available telemetry support a robust Sigma rule for this opportunity?\n"
    "    A strong behavioral idea with weak or artifact-only observables is low viability.\n"
    "    Values: high | medium | low\n\n"
    "  FP risk\n"
    "    Rate this opportunity's overlap with legitimate activity — high /\n"
    "    medium / low — with one concrete reason (e.g. 'medium — shares\n"
    "    parent process ancestry with routine admin scripts'). This is a\n"
    "    quick per-opportunity signal for comparing opportunities against\n"
    "    each other; the false positive profile below carries the full\n"
    "    analysis and filter guidance.\n\n"
    "Selection principles:\n\n"
    "  The planner's goal is not to maximise rule count.\n"
    "  One high-value detection opportunity is preferable to multiple weak,\n"
    "  redundant, or speculative opportunities.\n"
    "  Include only opportunities that provide meaningful additional detection value.\n"
    "  Coverage types are outputs of this analysis, not targets to satisfy.\n\n"
    "Coverage types:\n\n"
    "  SPECIFIC  — Detects the observed procedure or a very close variant.\n\n"
    "  ADJACENT  — Detects interchangeable procedures sharing the same mechanism.\n\n"
    "  FAMILY    — Detects the broader behavioral signature across tooling variants.\n\n"
    "Evidence constraints:\n\n"
    "  Degenerate evidence (unique_event_count == 1) limits confidence in SPECIFIC\n"
    "  and ADJACENT opportunities. When evidence quality is poor, prefer opportunities\n"
    "  derived from technique knowledge and behavioral invariants rather than observed\n"
    "  values.\n\n"
    "  Event type determines available anchor fields:\n"
    "    process_creation → Image, CommandLine, ParentImage, ParentCommandLine,\n"
    "                       OriginalFileName, CurrentDirectory\n"
    "    registry         → TargetObject (path depth and hive), Details (content\n"
    "                       type and encoding characteristics)\n"
    "    network          → DestinationHostname, DestinationIp, Initiated,\n"
    "                       Image (initiating process identity)\n\n"

    "  Same-event plausibility (treat this as a hard check, not a suggestion):\n"
    "    Technique-level knowledge often spans multiple sequential commands or\n"
    "    tool invocations — a creation command and a separate later command that\n"
    "    sets its payload, a staging step and a distinct execution step. These\n"
    "    are artifacts of the technique as a whole, not artifacts of one process\n"
    "    invocation, and ANDing them together produces a condition that will\n"
    "    rarely or never fire against real single-event telemetry — it looks\n"
    "    like coverage and behaves like a gap. Before listing two fields as\n"
    "    anchor_fields to combine with AND, explicitly confirm both would appear\n"
    "    on the same log line from the same invocation. If you cannot confirm\n"
    "    that, they are not an AND candidate. Either combine them with OR\n"
    "    within the same opportunity (if either artifact alone is a\n"
    "    meaningful, sufficient signal), or list them as two separate entries\n"
    "    in detection_opportunities (if each represents a genuinely distinct\n"
    "    detection angle worth evaluating on its own).\n\n"

    "══ PHASE 5 — FALSE POSITIVE PROFILE ════════════════════════════════════════\n"
    "For each detection opportunity included, identify the legitimate enterprise\n"
    "activity that produces similar observables. This must be field-specific.\n"
    "Category names alone are not actionable — the rule writer needs to know\n"
    "which fields the FP manifests in and what exclusion condition handles it.\n"
    "If an FP applies only to a specific coverage type, set applies_to accordingly.\n"
    "applies_to values: 'all' | 'specific' | 'adjacent' | 'family'\n\n"
    "  Filter breadth — avoiding blind spots (treat this as a hard check):\n"
    "    Understand the context of overlap between malicious and legitimate\n"
    "    activity before recommending a filter_approach — do not default to\n"
    "    umbrella exclusions. Recommending an entire directory be excluded\n"
    "    (e.g. all of Program Files), or failing to account for abuse of\n"
    "    legitimate internal components (LOLBins, admin tooling), can produce a\n"
    "    strategy that correctly identifies malicious activity and then hands\n"
    "    defender a filter that silently lets it through anyway. Exclusions\n"
    "    scoped to something like System32 can be legitimate, but only once you\n"
    "    have reasoned through whether an attacker could plausibly abuse what is\n"
    "    being excluded — not by default. The same judgment applies to\n"
    "    mechanisms that are baseline-normal on most endpoints but also double\n"
    "    as attack surface: msiexec running is ordinary background activity\n"
    "    almost everywhere, but the same binary installs malicious payloads\n"
    "    too, and here the context of the specific instance is what matters,\n"
    "    not the mechanism's mere presence. Where available evidence lets you\n"
    "    bake that distinguishing context directly into the filter_approach, do\n"
    "    so. Where it does not support making that distinction, do not\n"
    "    recommend a blanket pass anyway — flag the ambiguity in\n"
    "    false_positive_profile instead.\n\n"
    "  Field reliability for exemptions:\n"
    "    When an FP filter is exemption-based (recognising a known-good process\n"
    "    or tool), prefer a field describing an inherent property of the entity\n"
    "    itself (its own Image path) over a field describing its relationship to\n"
    "    something else. Concretely: verifying a process's own Image is the\n"
    "    trusted binary is sound; exempting based on ParentImage (spawned by a\n"
    "    trusted parent) or CurrentDirectory (running from a specific folder) is\n"
    "    not — both describe what surrounds the entity, not what it is, and both\n"
    "    are set by the caller, not the entity itself. An attacker who controls\n"
    "    the parent process or working directory defeats a ParentImage or\n"
    "    CurrentDirectory-based exemption without touching the flagged entity\n"
    "    at all.\n\n"

    "══ PHASE 6 — RULE DESIGN GUIDANCE ══════════════════════════════════════════\n"
    "Given the selected opportunities, state the implementation approach at the\n"
    "detection-design level. For each opportunity specify:\n\n"
    "  Required conditions\n"
    "    Observables that must be present for a match.\n\n"
    "  Supporting conditions\n"
    "    Observables that increase confidence but are not strictly required.\n\n"
    "  Negative conditions\n"
    "    Observables whose presence should exclude a match.\n\n"
    "  FP filters\n"
    "    The highest-volume legitimate activities that require filtering,\n"
    "    and which fields those filters operate on.\n\n"
    "Focus on detection logic rather than Sigma syntax.\n"
    "The rule writer is responsible for translating this into Sigma.\n"
    "One concise paragraph per opportunity included.\n\n"

    "Before finalising: does this recommendation AND two fields that could only\n"
    "co-occur across separate invocations? Does any filter_approach exempt more\n"
    "than the legitimate activity it is targeting? Fix either before returning\n"
    "your output.\n\n"

    "══ OUTPUT ══════════════════════════════════════════════════════════════════\n"
    "Your response is constrained to a JSON schema enforced by the API — you do\n"
    "not need to format the output yourself. Focus entirely on the quality of\n"
    "the reasoning in each field; the structure is guaranteed.\n"
)


def build_planner_user_message(
    technique_id: str,
    technique_name: str,
    tactic: str,
    missed_events: list[dict],
    data_sources: list[str],
    detection_hint: str = "",
) -> str:
    """
    Build the dynamic user message for the detection planner.
    All analytical instructions live in PLANNER_SYSTEM_PROMPT (static, cached).
    This message contains only per-call dynamic content.

    Args:
        technique_id:    ATT&CK technique ID e.g. T1059.001
        technique_name:  Human-readable technique name
        tactic:          ATT&CK tactic
        missed_events:   Attack log events that were not caught (up to 5)
        data_sources:    Relevant ATT&CK data sources for this technique
        detection_hint:  MITRE x_mitre_detection field (may be empty)

    Returns:
        User message string.
    """
    hint_block = ""
    if detection_hint and detection_hint.strip():
        hint_block = (
            f"\nMITRE detection guidance:\n"
            f"  {detection_hint.strip()[:600]}\n"
        )

    return (
        "─── TECHNIQUE ───────────────────────────────────────────────\n"
        f"ID:     {technique_id}\n"
        f"Name:   {technique_name}\n"
        f"Tactic: {tactic}\n"
        f"{hint_block}\n"
        "Relevant data sources:\n"
        f"{_format_data_sources(data_sources)}\n\n"
        "─── ATTACK EVIDENCE ─────────────────────────────────────────\n"
        "Events not caught by existing rules:\n\n"
        f"{_format_missed_events(missed_events)}\n\n"
    )
