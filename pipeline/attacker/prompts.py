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
        f"You are an adversarial simulation assistant helping test detection coverage.\n\n"
        f"Technique: {technique_id} — {technique_name}\n"
        f"Tactic: {tactic}\n\n"
        "Your job:\n"
        "1. Select the best candidate test from the list below.\n"
        "2. Propose evasion hints — light mutations on specific Sysmon field values "
        "that would stress naïve detection rules without leaving the technique's "
        "behavioural envelope.\n\n"
        "Mutation rules (follow strictly):\n"
        "- All mutations must remain executable and realistic on a Windows endpoint.\n"
        "- Do not invent flags, binaries, or command arguments that do not exist.\n"
        "- Prefer behavioural mutations (different parent process, different LOLBin, "
        "different execution chain) over purely syntactic ones "
        "(e.g. changing -enc to -EncodedCommand achieves nothing meaningful).\n"
        "- Avoid repeating the same execution strategy you have used before unless "
        "no alternatives exist within the technique scope.\n"
        "- Stay within the technique's behavioural envelope — do not drift into a "
        "different technique.\n\n"
    )


def _output_schema() -> str:
    return (
        "Respond with a single JSON object only. No preamble, no explanation, "
        "no markdown fences.\n\n"
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
    LLM picks the best candidate and proposes initial evasion hints.
    """
    prompt = _base_instructions(technique_id, technique_name, tactic)
    prompt += "This is iteration 1. No prior detection data available.\n\n"
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

    prompt += "This is a subsequent iteration. The following field values were caught "
    prompt += "by detection rules in the previous run — do not reuse them:\n\n"
    prompt += json.dumps(caught_fields, indent=2)
    prompt += "\n\n"
    prompt += (
        "Select a candidate and propose evasion hints that specifically avoid "
        "the caught field values above while remaining realistic and executable.\n\n"
    )
    prompt += "Candidates:\n\n"
    prompt += _format_candidates(candidates)
    prompt += "\n\n"
    prompt += _output_schema()
    return prompt
