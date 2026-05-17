"""
pipeline/corpus/prompts.py

Prompt templates for the corpus stress-test learner LLM calls.

One call per cluster. Single call produces:
  - behavioral intent of the cluster's rules
  - 2-3 benign activity variants covering the pattern
  - PowerShell/CMD/binary scripts for each variant
  - feasibility flag (False if pattern requires env we can't simulate)

Structured JSON output. Safety constraints baked into system prompt.
"""

from __future__ import annotations

from pipeline.corpus.clusterer import RuleCluster

# ---------------------------------------------------------------------------
# System prompt — baked-in safety and realism constraints
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a Windows detection engineering assistant generating
benign stress-test activity scripts for a security research pipeline.

Your scripts run on GitHub Actions windows-latest runners with Sysmon installed
using the SwiftOnSecurity configuration.

CONSTRAINTS — NON-NEGOTIABLE:
- Generate ONLY legitimate, benign Windows activity. No malicious commands.
- No privilege escalation, lateral movement, persistence, or payload downloads.
- Scripts must run unattended in non-interactive CI environments.
- Do not use interactive prompts, GUI dialogs, infinite loops, or background jobs.
- No connections to non-public URLs or suspicious domains.
- All file/registry changes must be cleaned up within the same script.
- Scripts must be realistic — they must look like real user or admin activity,
  not synthetic test scaffolding.
- Use real Windows tools that would appear in normal enterprise environments.

OUTPUT FORMAT:
Return a single valid JSON object. No markdown fences. No preamble. No explanation.
All JSON must be syntactically valid and directly parseable by standard JSON parsers.
In JSON string values: escape all backslashes as \\\\ escape embedded double quotes
and represent newlines as \\n.

Long scripts with many lines are expected — do not truncate them.
"""

# ---------------------------------------------------------------------------
# User prompt template
# ---------------------------------------------------------------------------

_CLUSTER_PROMPT_TEMPLATE = """Analyse these Sigma detection rules and generate
benign stress-test activity that would realistically exercise their detection logic.

=== RULES IN THIS CLUSTER ({cluster_size} rule(s)) ===
{rules_block}

=== CLUSTER METADATA ===
Target EventIDs: {target_eids}
Inferred behavioral tags: {archetype_tags}
Cluster confidence (intra-similarity): {confidence:.2f}

=== PRIOR EFFECTIVE ACTIVITIES (if any) ===
{prior_context}

=== TASK ===
1. Determine if this cluster can be meaningfully stress-tested on a GitHub Actions
   windows-latest runner. Set "feasible": false if the pattern requires:
   - Office applications (Word, Excel, Outlook) — not installed on runners
   - Domain/AD context — not available on runners
   - Specific internal IPs or non-public network targets
   - Driver or kernel-level activity

2. If feasible, generate 2-3 DISTINCT benign activity variants that exercise the
   detection pattern from different angles.

   Each variant must use a DIFFERENT workflow archetype:
   - IT admin workflow: sysadmin performing a legitimate maintenance task
   - User-driven workflow: standard end-user performing a normal task
   - Software installer/updater workflow: installation or update process
   - Document/file operation workflow: user opening, editing, saving files

   Choose the 2-3 most realistic archetypes for this specific pattern.
   Do NOT generate all 4 if some are a poor fit.

3. For each variant, generate a complete script in the appropriate shell that:
   - Uses the shell most natural for the activity (PowerShell, CMD, or native binary)
   - Generates real Sysmon events (the target EventIDs)
   - Reads like real enterprise activity, not test scaffolding. Specifically:
     AVOID: comments like "# Simulate X activity", variable names like $testScript,
     one-liners that just Write-Host a message, placeholder paths like C:\test\thing,
     invented registry paths like HKLM:\Software\myapp-test, words like "test",
     "stress test", "stress-test" anywhere in scripts or comments
     USE: real tool invocations with realistic parameters, actual paths like
     $env:TEMP\report_Q3.csv or $env:APPDATA\CompanyName\config.ini, plausible
     operational reasons for each action
   - For registry operations: use real Windows subsystem paths, not invented ones.
     Examples: Task Scheduler tasks live under
     HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
     Run keys live under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
     Services live under HKLM:\SYSTEM\CurrentControlSet\Services\
     Use the real path the rule is monitoring, not a stand-in
   - Cleans up any files or registry keys it creates
   - Includes brief inline comments explaining the legitimate business use case
   - Scripts must complete within a few minutes on a GitHub Actions runner.
   - Avoid reboot-required, GUI-dependent, or user-interactive workflows.
   - Avoid external dependencies not normally present on windows-latest runners.

4. Identify if this cluster contains DISTINCT behavioral sub-patterns
   (e.g. two rules both mention powershell.exe but one targets encoding,
   one targets web download). If so, ensure your variants cover BOTH sub-patterns.

Return this exact JSON structure:
{{
  "feasible": true,
  "infeasible_reason": null,
  "behavioral_intent": "one sentence: what attacker behavior these rules hunt",
  "sub_patterns": ["list", "of", "distinct", "sub-patterns", "if", "any"],
  "variants": [
    {{
      "archetype": "IT admin workflow",
      "description": "what this script does and why it's realistic",
      "shell": "powershell",
      "script": "full script content as a single string with \\n for newlines",
      "expected_eids": [1],
      "covers_sub_patterns": ["sub-pattern it targets"]
    }}
  ]
}}

If not feasible:
{{
  "feasible": false,
  "infeasible_reason": "specific reason why this cannot be run on a GH Actions runner",
  "behavioral_intent": "one sentence describing what these rules hunt",
  "sub_patterns": [],
  "variants": []
}}
"""


def build_cluster_prompt(
    cluster: RuleCluster,
    prior_context: str = "",
) -> str:
    """
    Build the user prompt for a single cluster LLM call.

    Args:
        cluster:       The cluster to analyse.
        prior_context: Optional context from corpus_outcomes.json describing
                       previously effective activities for similar patterns.
                       Empty string if no prior history.
    """
    rules_block = _format_rules_block(cluster)
    eids_str = ", ".join(
        str(e) for e in cluster.target_eids) if cluster.target_eids else "unknown"
    tags_str = ", ".join(
        cluster.archetype_tags) if cluster.archetype_tags else "none inferred"
    prior_str = prior_context.strip() if prior_context.strip() else "None recorded yet."

    # Sigma rule values and prior context can contain { } characters —
    # e.g. #{var} placeholders, regex patterns, PowerShell scriptblocks.
    # Escape them before .format() or Python raises KeyError trying to
    # resolve them as named format placeholders.
    safe_rules_block = rules_block.replace("{", "{{").replace("}", "}}")
    safe_prior_str = prior_str.replace("{", "{{").replace("}", "}}")

    return _CLUSTER_PROMPT_TEMPLATE.format(
        cluster_size=cluster.cluster_size,
        rules_block=safe_rules_block,
        target_eids=eids_str,
        archetype_tags=tags_str,
        confidence=(
            cluster.confidence
            if cluster.confidence is not None
            else 0.0),
        prior_context=safe_prior_str,
    )


def _format_rules_block(cluster: RuleCluster) -> str:
    """
    Format all member rules for the LLM prompt.
    Includes structured embedding text (operator-aware) for all members.
    Does NOT include raw YAML — keeps the prompt focused on semantics.
    """
    lines = []
    for i, rule in enumerate(cluster.member_rules, 1):
        lines.append(f"Rule {i}: {rule.title}")
        lines.append(f"  ID: {rule.rule_id}")
        if rule.technique_ids:
            lines.append(f"  ATT&CK: {', '.join(rule.technique_ids)}")
        if rule.level:
            lines.append(f"  Severity: {rule.level}")
        lines.append(f"  Detection logic: {rule.embedding_text}")
        lines.append("")
    return "\n".join(lines).strip()
