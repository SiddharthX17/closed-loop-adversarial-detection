"""
pipeline/defender/prompts.py

beta

Prompt templates for the defender agent.
Single template handles both first attempt and retries — retry_feedback
is None on first call, populated with gate failure details on subsequent calls.
"""

from pathlib import Path


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
        "Do not repeat the same field names or logic that caused the failure."
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
        "Your job is to write a Sigma rule that detects them:\n\n"
        "Missed events:\n"
        f"{_format_missed_events(missed_events)}\n\n"
    )

    prompt += (
        "Existing rules for this technique (for context — "
        "you may improve one of these or write a new rule, "
        "whichever better covers the missed events):\n\n"
        f"{_format_existing_rules(existing_rules)}\n\n"
    )

    if is_retry:
        prompt += _format_retry_feedback(retry_feedback)
        prompt += "\n\n"

    prompt += (
        "Requirements:\n"
        "- Output valid Sigma YAML only. No explanation, no markdown fences.\n"
        "- Use only Sysmon field names that exist in a standard Sysmon schema:\n"
        "  Image, CommandLine, ParentImage, ParentCommandLine, TargetObject,\n"
        "  Details, DestinationIp, DestinationHostname, DestinationPort,\n"
        "  SourceIp, OriginalFileName, CurrentDirectory, IntegrityLevel,\n"
        "  Protocol, Initiated, ProcessId, ParentProcessId\n"
        "- Set logsource correctly for Sysmon:\n"
        "    logsource:\n"
        "      category: process_creation   # or registry_set, network_connection etc.\n"
        "      product: windows\n"
        "- The rule must match the missed events above — not just the technique in general.\n"
        "- Keep detection logic specific enough to avoid firing on routine benign activity.\n"
        "- Use a descriptive title and set tags with the ATT&CK technique ID.\n"
        "- Set status: experimental\n"
        f"- Rule filename convention (for your title/id): T{technique_id}-<short-description>\n\n"
        "Output the Sigma YAML rule now:"
    )

    return prompt
