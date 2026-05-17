"""
pipeline/detection_planner/prompts.py

Prompt template for the detection planner stage.

The planner is is doing pre-analysis before the defender receives the gap.
Its job is to generalise from a specific attack evidence sample to a 
durable, technique-level detection strategy.

Framing: senior detection engineer performing initial triage on a new coverage gap.
The attack events are one observed instance. The strategy must survive tooling changes.
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


def build_planner_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    missed_events: list[dict],
    data_sources: list[str],
    detection_hint: str = "",
) -> str:
    """
    Build the detection planner prompt.

    Args:
        technique_id:    ATT&CK technique ID e.g. T1059.001
        technique_name:  Human-readable technique name
        tactic:          ATT&CK tactic
        missed_events:   Attack log events that were not caught (up to 5)
        data_sources:    Relevant ATT&CK data sources for this technique
        detection_hint:  MITRE x_mitre_detection field (may be empty)

    Returns:
        Prompt string ready to send to the LLM.
    """

    hint_block = ""
    if detection_hint and detection_hint.strip():
        hint_block = (
            f"\nMITRE detection guidance for this technique:\n"
            f"  {detection_hint.strip()[:600]}\n"
        )

    prompt = (
        "You are a senior detection engineer performing pre-analysis on a coverage gap.\n\n"

        "Your task is NOT to write a Sigma rule. Your task is to produce a structured\n"
        "detection strategy that a rule-writing engineer will use as their starting point.\n\n"

        "Core principle: the attack evidence below is one observed procedure instance.\n"
        "It is a spark — not a blueprint. Your strategy must generalise beyond this\n"
        "specific sample to the underlying technique objective and stable observables.\n\n"

        "─── TECHNIQUE ───────────────────────────────────────────────\n"
        f"ID:     {technique_id}\n"
        f"Name:   {technique_name}\n"
        f"Tactic: {tactic}\n"
        f"{hint_block}\n"
        "Relevant data sources:\n"
        f"{_format_data_sources(data_sources)}\n\n"

        "─── ATTACK EVIDENCE (one procedure instance) ────────────────\n"
        "These events were not caught by existing rules. Analyse what the attacker\n"
        "is accomplishing — do not write detection logic anchored to these specific\n"
        "field values. \n\n"
        f"{_format_missed_events(missed_events)}\n\n"

        "─── YOUR ANALYSIS TASK ──────────────────────────────────────\n"
        "Produce a JSON object with exactly these five fields:\n\n"

        "  key_behaviors      : list[str]\n"
        "    What the attacker is accomplishing at the technique level.\n"
        "    Focus on behavioral intent rather than tooling artifacts.\n"
        "    Frame as attacker objectives, not specific commands.\n"
        "    Example: 'executing arbitrary code via a trusted interpreter'\n\n"

        "  relevant_fields    : list[str]\n"
        "    Sysmon field names that carry the strongest detection signal for this\n"
        "    technique. Choose from: Image, CommandLine, ParentImage,\n"
        "    ParentCommandLine, TargetObject, Details, DestinationIp,\n"
        "    DestinationHostname, DestinationPort, OriginalFileName,\n"
        "    CurrentDirectory, Protocol.\n"
        "    Rank by signal stability — prefer fields that survive tooling changes.\n\n"

        "  detection_invariants : list[str]\n"
        "    Conditions that remain true regardless of which tool, binary name,\n"
        "    or command variant the attacker uses. These are the non-negotiable\n"
        "    anchors for any rule targeting this technique.\n"
        "    Example: 'a script interpreter loading from a user-writable path'\n"
        "    Avoid: 'CommandLine contains powershell.exe' (too artifact-specific)\n"
        "    Do not anchor invariants to exact filenames, hardcoded paths, hashes, single encoded strings\n\n"

        "  false_positive_profile : list[str]\n"
        "    Broad categories of legitimate enterprise activity that produce\n"
        "    observables similar to this technique.\n"
        "    Write category labels, not specific examples or product names.\n"
        "    Example: 'administrative scripting', 'software deployment tooling',\n"
        "             'scheduled maintenance tasks'\n"
        "    A rule-writer will use these categories to add exclusion conditions.\n\n"

        "  generalization_notes : str\n"
        "    One concise paragraph. How should a rule-writer broaden beyond this\n"
        "    specific procedure instance? What parent-level pattern captures the\n"
        "    technique family? What modifiers or condition combinations are likely\n"
        "    to improve coverage without inflating FP rate?\n\n"

        "─── OUTPUT FORMAT ───────────────────────────────────────────\n"
        "Return ONLY a valid JSON object. No explanation, no markdown, no preamble.\n\n"
        "{\n"
        '  "key_behaviors": ["...", "..."],\n'
        '  "relevant_fields": ["Image", "CommandLine"],\n'
        '  "detection_invariants": ["...", "..."],\n'
        '  "false_positive_profile": ["category one", "category two"],\n'
        '  "generalization_notes": "..."\n'
        "}"
    )

    return prompt
