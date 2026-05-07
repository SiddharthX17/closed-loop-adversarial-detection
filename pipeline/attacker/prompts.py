"""
pipeline/attacker/prompts.py

Prompt templates for the attacker agent.
Two variants: cold start (iteration 1) and mutation (iteration 2+).
"""

import json
from dataclasses import dataclass


@dataclass
class AtomicCandidate:
    """
    Structured candidate passed to the attacker agent prompt.
    Built from CleanedAtomicTest — only what the LLM needs.
    """
    name: str
    guid: str
    executor: str       # powershell | cmd | command_prompt | sh etc.
    procedure_text: str


def _format_candidates(candidates: list[AtomicCandidate]) -> str:
    lines = []
    for i, c in enumerate(candidates, 1):
        lines.append(
            f"Candidate {i}:\n"
            f"  name: {c.name}\n"
            f"  guid: {c.guid}\n"
            f"  executor: {c.executor}\n"
            f"  procedure:\n    {c.procedure_text.strip()}"
        )
    return "\n\n".join(lines)


def _base_instructions(technique_id: str, technique_name: str, tactic: str) -> str:
    return (
        f"You are an adversarial simulation assistant helping stress-test detection rules.\n\n"
        f"Technique: {technique_id} — {technique_name}\n"
        f"Tactic: {tactic}\n\n"
        "Your job:\n"
        "1. Select the best candidate test from the list below.\n"
        "2. Generate a realistic variation of that test that might evade naive detection rules.\n"
        "   Treat the Atomic test as a seed — a starting point, not gospel.\n"
        "   The goal is to vary execution in ways that stress pattern-matching rules.\n\n"
        "Mutation rules (follow strictly):\n"
        "- All mutations must remain executable and realistic on a Windows endpoint.\n"
        "- Do not invent flags, binaries, command arguments, or syntax that does not exist.\n"
        "- Prefer BEHAVIOURAL mutations over syntactic ones.\n"
        "  Syntactic (bad): changing -enc to -EncodedCommand — same bytes, trivially caught.\n"
        "  Behavioural (good): changing execution chain from powershell.exe→cmd.exe "
        "to mshta.exe→powershell.exe — different parent, different binary context.\n"
        "  Behavioural (good): using a LOLBin (rundll32, mshta, wscript) as the executor "
        "instead of the canonical binary.\n"
        "- Avoid repeating the same execution strategy you have used before unless "
        "no alternatives exist within the technique scope.\n"
        "- Stay within the technique's behavioural envelope — do not drift into a "
        "different ATT&CK technique.\n\n"
        "- If evasion hint values contain runtime variables (e.g. $lsass_pid, $url, "
        "$pid), substitute them with realistic concrete values "
        "(e.g. use a numeric PID like 632, a real URL. "
        "Do not propagate variable names into hint values.\n"
        "ParentImage must be realistic for the execution method.\n"
        "Masqueraded binaries/paths should use plausible user-writable or staging paths "
        "(Temp, Downloads, AppData etc.) not protected paths unless explicitly stated in tests.\n"
        "If the technique is process creation (EID 1), do NOT include network fields "
        "(DestinationIp, DestinationHostname, DestinationPort) in evasion_hints.\n\n"
    )


def _output_schema() -> str:
    return (
        "Respond with a single JSON object only. No preamble, no explanation, "
        "no markdown fences.\n\n"
        "JSON encoding rules (strict):\n"
        "- All string values must be valid JSON.\n"
        "- Escape backslashes as \\\\\\\\ (four backslashes in source = \\\\ in JSON).\n"
        "- Do not use PowerShell escape characters (backtick, unescaped single quotes) "
        "inside JSON string values.\n"
        "- If a command line contains quotes, escape them as \\\\\".\n\n"
        "- Do not include literal newlines, tabs, or control characters "
        "- inside JSON string values. Replace newlines with a space.\n"
        "Schema:\n"
        "{\n"
        '  "technique_id": "<technique ID>",\n'
        '  "selected_test_name": "<name field from chosen candidate>",\n'
        '  "selected_test_guid": "<guid field from chosen candidate>",\n'
        '  "evasion_hints": {\n'
        '    "<SysmonFieldName>": "<mutated value>"\n'
        "    // include only fields you are actually mutating\n"
        "    // use Sysmon field names: Image, CommandLine, ParentImage,\n"
        "    // ParentCommandLine, TargetObject, DestinationIp,\n"
        "    // DestinationHostname, OriginalFileName\n"
        "  }\n"
        "}"
    )


def build_coldstart_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    candidates: list[AtomicCandidate],
) -> str:
    """
    Iteration 1 prompt — no prior detection context.
    LLM picks the best candidate and proposes initial evasion variation.
    """
    prompt = _base_instructions(technique_id, technique_name, tactic)
    prompt += "This is iteration 1. No prior detection data available.\n"
    prompt += "Choose the candidate with the most detection-relevant execution chain.\n\n"
    prompt += "Candidates:\n\n"
    prompt += _format_candidates(candidates)
    prompt += "\n\n"
    prompt += _output_schema()
    return prompt


def build_mutation_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    candidates: list[AtomicCandidate],
    caught_fields: dict[str, list[str]],
) -> str:
    """
    Iteration 2+ prompt — includes field values that were caught by pySigma
    in the previous run so the LLM mutates specifically away from those.

    Args:
        caught_fields: dict mapping Sysmon field name to list of values that fired
                       rules in the previous iteration.
                       e.g. {"Image": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
                              "CommandLine": ["-enc JABj..."]}
    """
    prompt = _base_instructions(technique_id, technique_name, tactic)

    prompt += (
        "This is a subsequent iteration. The following field values triggered "
        "detection rules in the previous run. Your evasion hints must produce "
        "events that do NOT match these conditions:\n\n"
    )
    prompt += json.dumps(caught_fields, indent=2)
    prompt += "\n\n"
    prompt += (
        "Do not reuse any of the above field values verbatim. "
        "Change the execution approach, not just the string representation.\n\n"
    )
    prompt += "Candidates:\n\n"
    prompt += _format_candidates(candidates)
    prompt += "\n\n"
    prompt += _output_schema()
    return prompt
