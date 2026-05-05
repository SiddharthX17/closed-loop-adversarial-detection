"""
pipeline/defender/prompts.py

Prompt templates for the defender agent.
Single template handles both first attempt and retries — retry_feedback
is None on first call, populated with gate failure details on subsequent calls.
"""

from pathlib import Path
import uuid


def _format_missed_events(missed_events: list[dict]) -> str:
    if not missed_events:
        return "  (none available)"
    lines = []
    for i, event in enumerate(missed_events[:5], 1):
        # Only include populated fields to keep prompt tight
        populated = {k: v for k,
                     v in event.items() if v is not None and v != ""}
        lines.append(f"  Event {i}: {populated}")
    return "\n".join(lines)


def _format_existing_rules(existing_rules: list[str]) -> str:
    if not existing_rules:
        return "  (no existing rules for this technique)"
    parts = []
    for i, rule_yaml in enumerate(existing_rules, 1):
        parts.append(f"--- Existing Rule {i} ---\n{rule_yaml.strip()}")
    return "\n\n".join(parts)


def _format_retry_feedback(retry_feedback: dict | None) -> str:
    if not retry_feedback:
        return ""

    lines = [
        "\n--- PREVIOUS ATTEMPT FAILED ---",
        f"Gate that failed: {retry_feedback.get('gate_failed', 'unknown')}",
        f"Error: {retry_feedback.get('error', 'unknown')}",
    ]

    if retry_feedback.get("feedback"):
        lines.append(f"Specific feedback: {retry_feedback['feedback']}")

    if retry_feedback.get("previous_rule"):
        lines.append(
            f"\nYour previous rule attempt (do not repeat this):\n"
            f"{retry_feedback['previous_rule'].strip()}"
        )

    lines.append(
        "\nFix the issues identified above. "
        "Do not repeat the same flawed logic. Reuse fields only where justified.\n"
        "Fix the failed gate while preserving aspects that likely passed."
    )

    return "\n".join(lines)


def build_defender_prompt(
    technique_id: str,
    technique_name: str,
    tactic: str,
    missed_events: list[dict],
    existing_rules: list[str],
    retry_feedback: dict | None = None,
) -> str:
    """
    Build a defender agent prompt.

    Args:
        technique_id:    ATT&CK technique ID e.g. T1059.001
        technique_name:  Human-readable name
        tactic:          ATT&CK tactic
        missed_events:   Log events that were not caught by existing rules (up to 5)
        existing_rules:  List of existing Sigma rule YAML strings for this technique
        retry_feedback:  None on first attempt. On retry, dict with keys:
                           gate_failed, error, feedback, previous_rule

    Returns:
        Prompt string ready to send to the LLM.
    """
    is_retry = retry_feedback is not None

    prompt = (
        f"You are a detection engineer writing Sigma rules for Windows Sysmon telemetry.\n\n"
        f"Technique: {technique_id} — {technique_name}\n"
        f"Tactic: {tactic}\n\n"
    )

    prompt += (
        "The following log events were NOT detected by existing rules. "
        "Write a Sigma rule that detects them:\n\n"
        "Missed events:\n"
        f"{_format_missed_events(missed_events)}\n\n"
    )

    prompt += (
        "Existing rules for this technique (for context):\n\n"
        f"{_format_existing_rules(existing_rules)}\n\n"
    )

    prompt += (
        "Decision guidance:\n"
        "- Write a NEW rule if the missed events represent a fundamentally different "
        "execution pattern from existing rules (different binary, different execution chain, "
        "different event type).\n"
        "- IMPROVE an existing rule if the missed events are a variant of what it already "
        "targets (same binary, slightly different command line or parent).\n\n"
    )

    if is_retry:
        prompt += _format_retry_feedback(retry_feedback)
        prompt += "\n\n"

    generated_id = str(uuid.uuid4())

    prompt += (
        "Requirements — follow all of these:\n\n"

        "Rule ID:\n"
        f"- Use exactly this UUID4 for the id field: {generated_id}\n"
        "  Do not change it, do not generate your own.\n\n"

        "Field selection:\n"
        "- Use only Sysmon field names that exist in a standard Sysmon schema:\n"
        "  Image, CommandLine, ParentImage, ParentCommandLine, TargetObject,\n"
        "  Details, DestinationIp, DestinationHostname, DestinationPort,\n"
        "  SourceIp, OriginalFileName, CurrentDirectory, Protocol, Initiated,\n"
        "  ProcessId, ParentProcessId\n"
        "- Prefer specific high-signal fields over broad keyword matching.\n"
        "  Good: Image|endswith: '\\\\rundll32.exe' AND CommandLine|contains: 'comsvcs'\n"
        "  Bad: CommandLine|contains: 'malware' (too vague)\n"
        "- Do NOT hardcode full URLs, file hashes, or exact string payloads unless "
        "they are definitively unique to malicious activity and not present in any "
        "benign enterprise context.\n\n"

        "Logsource:\n"
        "- Set logsource correctly for Sysmon:\n"
        "    logsource:\n"
        "      category: process_creation   "
        "# or registry_set, network_connection, registry_event etc.\n"
        "      product: windows\n\n"

        "Detection logic:\n"
        "- The rule must match the missed events above — not just the technique in general.\n"
        "- Keep detection logic specific enough to avoid firing on routine enterprise "
        "activity (legitimate PowerShell, scheduled tasks, software updates).\n"
        "- If using CommandLine matching, require multiple conditions (AND) to reduce FPs.\n"
        "- Use Sigma modifiers correctly: contains, startswith, endswith, re (regex), "
        "all (all conditions must match).\n\n"

        "Metadata:\n"
        "- Use a descriptive title.\n"
        "- Set tags with the ATT&CK technique ID.\n"
        "- Set status: experimental\n"
        f"- Rule filename convention (for your title): {technique_id}-<short-description>\n\n"

        "Output the Sigma YAML rule only. No explanation, no markdown fences, no preamble."
    )

    return prompt
