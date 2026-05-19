"""
pipeline/corpus/yaml_generator.py

Drives LLM calls per cluster and assembles the GH Actions workflow YAML.

Two responsibilities:
  1. Call the LLM for each cluster → ClusterIntent (post-LLM data contract)
  2. Assemble all ClusterIntents into a complete GH Actions workflow YAML

The LLM receives all member rules (not just cluster centroid) so it can
identify behaviorally distinct sub-patterns within a cluster.
"""

from __future__ import annotations

import json
import os
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

import anthropic

from pipeline.corpus.clusterer import RuleCluster
from pipeline.corpus.prompts import SYSTEM_PROMPT, build_cluster_prompt

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")

_LLM_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 4096  # 2048 truncates multi-rule clusters with 3 variants
_MAX_VARIANTS_PER_WORKFLOW = 40


# ---------------------------------------------------------------------------
# Post-LLM data contract
# ---------------------------------------------------------------------------

@dataclass
class ScriptVariant:
    """A single benign activity variant for a cluster."""
    archetype: str          # IT admin / user-driven / software installer / document
    description: str
    shell: str              # powershell | cmd | binary
    script: str             # full script content
    expected_eids: list[int]
    covers_sub_patterns: list[str]


@dataclass
class ClusterIntent:
    """
    Post-LLM representation of a cluster.
    Extends RuleCluster with LLM-derived semantic content.
    """
    # Provenance from RuleCluster
    cluster_id: str
    member_rule_ids: list[str]
    cluster_size: int
    confidence: float
    archetype_tags: list[str]
    target_eids: list[int]

    # LLM output
    feasible: bool
    infeasible_reason: Optional[str]
    behavioral_intent: str
    sub_patterns: list[str]
    variants: list[ScriptVariant]

    # Metadata
    llm_call_succeeded: bool = True
    llm_error: Optional[str] = None


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_llm(
    cluster: RuleCluster,
    client: anthropic.Anthropic,
    prior_context: str = "",
) -> ClusterIntent:
    """
    Call the LLM for a single cluster and parse the response.
    Returns a ClusterIntent with feasible=False and llm_call_succeeded=False
    on error rather than raising — caller continues with other clusters.
    """
    prompt = build_cluster_prompt(cluster, prior_context)

    if _DEBUG:
        print(f"[corpus/yaml_generator] LLM call for cluster {cluster.cluster_id} "
              f"({cluster.cluster_size} rules)")

    try:
        response = client.messages.create(
            model=_LLM_MODEL,
            max_tokens=_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        # Extract text block defensively — don't assume content[0] is text.
        # Anthropic response shape is stable but tool_use blocks can appear.
        text_blocks = [b for b in response.content if hasattr(b, "text")]
        if not text_blocks:
            raise ValueError("No text content block in LLM response")
        raw_text = text_blocks[0].text.strip()

        # Strip markdown fences if the model adds them despite instructions
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[-1]
            raw_text = raw_text.rsplit("```", 1)[0].strip()

        start = raw_text.find("{")
        end = raw_text.rfind("}")

        if start == -1 or end == -1:
            raise ValueError("No JSON object found in LLM response")

        raw_text = raw_text[start:end + 1]
        parsed = json.loads(raw_text)

    except json.JSONDecodeError as e:
        if _DEBUG:
            print(
                f"[corpus/yaml_generator] JSON parse error for {cluster.cluster_id}: {e}")
        return _failed_intent(cluster, f"JSON parse error: {e}")
    except Exception as e:
        if _DEBUG:
            print(
                f"[corpus/yaml_generator] LLM error for {cluster.cluster_id}: {e}")
        return _failed_intent(cluster, str(e))

    feasible = bool(parsed.get("feasible", False))
    variants = []
    if feasible:
        seen_archetypes: set[str] = set()
        deduped_variants = []
        for v in parsed.get("variants", []):
            archetype = v.get("archetype", "unknown")
            if archetype not in seen_archetypes:
                seen_archetypes.add(archetype)
                deduped_variants.append(v)
        for v in deduped_variants:
            variants.append(ScriptVariant(
                archetype=v.get("archetype", "unknown"),
                description=v.get("description", ""),
                shell=v.get("shell", "powershell").lower(),
                script=v.get("script", ""),
                expected_eids=v.get("expected_eids", []),
                covers_sub_patterns=v.get("covers_sub_patterns", []),
            ))

    return ClusterIntent(
        cluster_id=cluster.cluster_id,
        member_rule_ids=cluster.member_rule_ids,
        cluster_size=cluster.cluster_size,
        confidence=cluster.confidence,
        archetype_tags=cluster.archetype_tags,
        target_eids=cluster.target_eids,
        feasible=feasible,
        infeasible_reason=parsed.get("infeasible_reason"),
        behavioral_intent=parsed.get("behavioral_intent", ""),
        sub_patterns=parsed.get("sub_patterns", []),
        variants=variants,
        llm_call_succeeded=True,
    )


def _failed_intent(cluster: RuleCluster, error: str) -> ClusterIntent:
    return ClusterIntent(
        cluster_id=cluster.cluster_id,
        member_rule_ids=cluster.member_rule_ids,
        cluster_size=cluster.cluster_size,
        confidence=cluster.confidence,
        archetype_tags=cluster.archetype_tags,
        target_eids=cluster.target_eids,
        feasible=False,
        infeasible_reason=None,
        behavioral_intent="",
        sub_patterns=[],
        variants=[],
        llm_call_succeeded=False,
        llm_error=error,
    )


# ---------------------------------------------------------------------------
# Dry-run validator
# ---------------------------------------------------------------------------

def _validate_script(script: str, shell: str) -> tuple[bool, str]:
    """
    Lightweight pre-commit script validation.
    Checks for obvious safety violations and structural issues.
    Does NOT execute the script — pure static analysis.

    Returns (passed, reason).
    """
    if not script.strip():
        return False, "empty script"

    script_lower = script.lower()

    # Safety floor — not a malware sandbox. Catches obviously wrong LLM output
    # (credential dumpers, log clearers) without attempting to enumerate all
    # obfuscation variants. Do not expand this into a security control.
    _blocklist = [
        ("invoke-mimikatz", "credential dumping"),
        ("net user /add", "user creation"),
        ("net localgroup administrators", "privilege escalation"),
        ("sekurlsa", "credential access"),
        ("downloadfile(", "payload download"),
        ("start-bitstransfer", "payload download"),
        ("iex(", "inline execution"),
        # benign uses shouldn't need this
        ("invoke-expression", "inline execution"),
        ("-windowstyle hidden", "hidden window"),
        ("reg add hklm\\sam", "SAM tampering"),
        ("cacls ", "permission tampering"),
        ("icacls ", "permission tampering"),
        ("wevtutil cl ", "log clearing"),
        ("clear-eventlog", "log clearing"),
    ]

    for pattern, reason in _blocklist:
        if pattern in script_lower:
            return False, f"blocked pattern: {reason} ('{pattern}')"

    # Structural: PowerShell scripts should not be empty or one-liners
    # claiming to be full workflows
    if shell == "powershell" and len(script.strip().splitlines()) < 2:
        return False, "powershell script suspiciously short (< 2 lines)"

    return True, "ok"


# ---------------------------------------------------------------------------
# GH Actions YAML assembly
# ---------------------------------------------------------------------------

_WORKFLOW_HEADER = """\
name: corpus-targeted-{iteration_id}
# Auto-generated by pipeline/corpus/yaml_generator.py
# Iteration: {iteration_id}
# Clusters: {n_clusters} | Feasible: {n_feasible} | Variants: {n_variants}
# Do not edit manually — regenerated each iteration.

on:
  workflow_dispatch:

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  generate-corpus:
    runs-on: windows-latest
    timeout-minutes: 30

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Sysmon
        shell: powershell
        run: |
          $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
          $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
          Invoke-WebRequest -Uri $sysmonUrl -OutFile Sysmon.zip
          Expand-Archive -Path Sysmon.zip -DestinationPath Sysmon
          Invoke-WebRequest -Uri $configUrl -OutFile sysmonconfig.xml
          .\\Sysmon\\Sysmon64.exe -accepteula -i sysmonconfig.xml
          Start-Sleep -Seconds 3
          Write-Host "Sysmon installed"
          # Record start time — export step filters to events after this point only
          $ts = (Get-Date).ToString("o")
          echo "CORPUS_START_TIME=$ts" >> $env:GITHUB_ENV
"""

_STEP_TEMPLATE = """\
      - name: "{step_name}"
        shell: {shell}
        run: |
{script_indented}

"""

_EXPORT_STEP = _EXPORT_STEP = """\
      - name: Export and commit corpus logs
        shell: powershell
        run: |
          $exportDir = "corpus\\\\benign"
          $processDir = "$exportDir\\\\process"
          $networkDir = "$exportDir\\\\network"
          $registryDir = "$exportDir\\\\registry"
          New-Item -ItemType Directory -Force -Path $processDir, $networkDir, $registryDir | Out-Null

          # Map Sysmon Properties array positions to field names per EventID.
          # Positional mapping matches SwiftOnSecurity sysmonconfig field order.
          function Export-SysmonEvent {{
              param($Event, $Eid)
              $p = $Event.Properties
              $obj = [ordered]@{{
                  Channel     = "Microsoft-Windows-Sysmon/Operational"
                  EventID     = $Eid
                  TimeCreated = $Event.TimeCreated.ToString("o")
              }}
              switch ($Eid) {{
                  1 {{
                      $obj["Image"]             = if ($p.Count -gt 4)  {{ [string]$p[4].Value  }} else {{ "" }}
                      $obj["CommandLine"]        = if ($p.Count -gt 10) {{ [string]$p[10].Value }} else {{ "" }}
                      $obj["ParentImage"]        = if ($p.Count -gt 20) {{ [string]$p[20].Value }} else {{ "" }}
                      $obj["ParentCommandLine"]  = if ($p.Count -gt 21) {{ [string]$p[21].Value }} else {{ "" }}
                      $obj["ProcessId"]          = if ($p.Count -gt 3)  {{ [string]$p[3].Value  }} else {{ "" }}
                      $obj["ParentProcessId"]    = if ($p.Count -gt 19) {{ [string]$p[19].Value }} else {{ "" }}
                      $obj["User"]               = if ($p.Count -gt 12) {{ [string]$p[12].Value }} else {{ "" }}
                      $obj["CurrentDirectory"]   = if ($p.Count -gt 11) {{ [string]$p[11].Value }} else {{ "" }}
                      $obj["IntegrityLevel"]     = if ($p.Count -gt 16) {{ [string]$p[16].Value }} else {{ "" }}
                      $obj["OriginalFileName"]   = if ($p.Count -gt 9)  {{ [string]$p[9].Value  }} else {{ "" }}
                  }}
                  3 {{
                      $obj["Image"]               = if ($p.Count -gt 4)  {{ [string]$p[4].Value  }} else {{ "" }}
                      $obj["Protocol"]            = if ($p.Count -gt 6)  {{ [string]$p[6].Value  }} else {{ "" }}
                      $obj["Initiated"]           = if ($p.Count -gt 7)  {{ [string]$p[7].Value  }} else {{ "" }}
                      $obj["SourceIp"]            = if ($p.Count -gt 9)  {{ [string]$p[9].Value  }} else {{ "" }}
                      $obj["SourcePort"]          = if ($p.Count -gt 11) {{ [string]$p[11].Value }} else {{ "" }}
                      $obj["DestinationIp"]       = if ($p.Count -gt 14) {{ [string]$p[14].Value }} else {{ "" }}
                      $obj["DestinationHostname"] = if ($p.Count -gt 15) {{ [string]$p[15].Value }} else {{ "" }}
                      $obj["DestinationPort"]     = if ($p.Count -gt 16) {{ [string]$p[16].Value }} else {{ "" }}
                  }}
                  11 {{
                      $obj["Image"]          = if ($p.Count -gt 4) {{ [string]$p[4].Value }} else {{ "" }}
                      $obj["TargetFilename"] = if ($p.Count -gt 6) {{ [string]$p[6].Value }} else {{ "" }}
                  }}
                  12 {{
                      $obj["EventType"]    = if ($p.Count -gt 1) {{ [string]$p[1].Value }} else {{ "" }}
                      $obj["Image"]        = if ($p.Count -gt 5) {{ [string]$p[5].Value }} else {{ "" }}
                      $obj["TargetObject"] = if ($p.Count -gt 6) {{ [string]$p[6].Value }} else {{ "" }}
                  }}
                  13 {{
                      $obj["EventType"]    = if ($p.Count -gt 1) {{ [string]$p[1].Value }} else {{ "" }}
                      $obj["Image"]        = if ($p.Count -gt 5) {{ [string]$p[5].Value }} else {{ "" }}
                      $obj["TargetObject"] = if ($p.Count -gt 6) {{ [string]$p[6].Value }} else {{ "" }}
                      $obj["Details"]      = if ($p.Count -gt 7) {{ [string]$p[7].Value }} else {{ "" }}
                  }}
              }}
              return $obj
          }}

          $eidMap = @{{
              1  = $processDir
              11 = $processDir
              3  = $networkDir
              12 = $registryDir
              13 = $registryDir
          }}

          foreach ($eid in $eidMap.Keys) {{
              $outFile = "$($eidMap[$eid])\\\\targeted_{iteration_id}_eid${{eid}}.jsonl"
              try {{
                  $startTime = if ($env:CORPUS_START_TIME) {{
                      [datetime]::Parse($env:CORPUS_START_TIME)
                  }} else {{
                      (Get-Date).AddMinutes(-30)
                  }}
                  Get-WinEvent -FilterHashtable @{{
                      LogName = "Microsoft-Windows-Sysmon/Operational"
                      Id      = $eid
                      StartTime = $startTime
                  }} -ErrorAction SilentlyContinue |
                  ForEach-Object {{
                      Export-SysmonEvent -Event $_ -Eid $eid | ConvertTo-Json -Compress
                  }} | Out-File -Append -Encoding utf8 $outFile
                  $n = if (Test-Path $outFile) {{ (Get-Content $outFile | Measure-Object -Line).Lines }} else {{ 0 }}
                  Write-Host "EID ${{eid}}: $n events → $outFile"
              }} catch {{
                  Write-Host "EID ${{eid}}: error — $_"
              }}
          }}

          git config user.name "corpus-bot"
          git config user.email "corpus-bot@pipeline"
          git add corpus/benign/
          $count = (git diff --cached --name-only | Measure-Object -Line).Lines
          if ($count -gt 0) {{
              git commit -m "corpus: targeted stress-test iteration {iteration_id} [skip ci]"
              try {{
                  git push
                  Write-Host "Committed $count corpus files"
              }} catch {{
                  Write-Host "git push failed: $_"
              }}
          }} else {{
              Write-Host "No new corpus files to commit"
          }}

"""

_WORKFLOW_FOOTER = """\
      - name: Uninstall Sysmon
        shell: powershell
        if: always()
        run: |
          .\\Sysmon\\Sysmon64.exe -u force 2>$null
          Write-Host "Sysmon uninstalled"
"""


def _shell_to_gha(shell: str) -> str:
    """Map shell name to GH Actions shell identifier."""
    mapping = {"powershell": "powershell",
               "cmd": "cmd", "binary": "powershell"}
    return mapping.get(shell, "powershell")


def generate_intents(
    clusters: list[RuleCluster],
    client: anthropic.Anthropic,
    prior_context_map: dict[str, str] | None = None,
) -> list[ClusterIntent]:
    """
    Call LLM for each cluster and return ClusterIntent list.

    Args:
        clusters:          From clusterer.cluster_rules()
        client:            Anthropic client instance
        prior_context_map: Optional map of cluster behavioral tags → prior
                           effective activity descriptions from outcomes.
    """
    if prior_context_map is None:
        prior_context_map = {}

    intents = []
    for cluster in clusters:
        # Match prior context by archetype tags overlap
        prior = _lookup_prior_context(cluster, prior_context_map)
        intent = _call_llm(cluster, client, prior)

        if _DEBUG:
            status = "feasible" if intent.feasible else f"infeasible: {intent.infeasible_reason}"
            variants = len(intent.variants) if intent.feasible else 0
            print(f"[corpus/yaml_generator] {cluster.cluster_id}: {status}, "
                  f"{variants} variant(s)")

        intents.append(intent)

    return intents


def generate_workflow(
    intents: list[ClusterIntent],
    iteration_id: str,
) -> str:
    """
    Assemble a complete GH Actions workflow YAML from ClusterIntents.

    Skips infeasible clusters with a comment noting the reason.
    Validates each script before inclusion — invalid scripts are skipped.
    Returns the complete YAML string.
    """
    feasible = [i for i in intents if i.feasible and i.llm_call_succeeded]
    n_variants = sum(len(i.variants) for i in feasible)

    if _DEBUG:
        skipped = [
            i for i in intents if not i.feasible or not i.llm_call_succeeded]
        print(f"[corpus/yaml_generator] Assembling workflow: "
              f"{len(feasible)} feasible clusters, {n_variants} variants, "
              f"{len(skipped)} skipped")

    parts = [
        _WORKFLOW_HEADER.format(
            iteration_id=iteration_id,
            n_clusters=len(intents),
            n_feasible=len(feasible),
            n_variants=n_variants,
        )
    ]

    included_variants = 0

    for intent in feasible:
        if included_variants >= _MAX_VARIANTS_PER_WORKFLOW:
            parts.append(
                "      # Variant limit reached — remaining clusters skipped\n")
            break
        parts.append(
            f"      # Cluster: {intent.cluster_id}\n"
            f"      # Intent: {intent.behavioral_intent}\n"
            f"      # Rules: {', '.join(intent.member_rule_ids)}\n"
        )

        for variant in intent.variants:
            if included_variants >= _MAX_VARIANTS_PER_WORKFLOW:
                parts.append(
                    "      # Variant limit reached — remaining variants skipped\n")
                break
            passed, reason = _validate_script(variant.script, variant.shell)
            if not passed:
                if _DEBUG:
                    print(f"[corpus/yaml_generator] Script validation failed for "
                          f"{intent.cluster_id}/{variant.archetype}: {reason}")
                parts.append(
                    f"      # SKIPPED variant '{variant.archetype}': {reason}\n"
                )
                continue

            safe_intent = re.sub(r"[\r\n:\"'\[\]{}]+",
                                 " ", intent.behavioral_intent)
            safe_intent = re.sub(r"\s+", " ", safe_intent).strip()

            # Truncate at word boundary to avoid mid-word cuts in step names
            _truncated = safe_intent[:50]
            if len(safe_intent) > 50:
                _last_space = _truncated.rfind(" ")
                _truncated = _truncated[:_last_space] if _last_space > 0 else _truncated
            step_name = f"{_truncated} [{variant.archetype}]".replace('"', "'")

            # Normalise line endings before embedding in YAML block scalar.
            # Strip trailing whitespace per line (GH Actions YAML is sensitive
            # to trailing spaces). Ensure terminal newline for clean block end.
            script_clean = "\n".join(
                line.rstrip() for line in variant.script.splitlines()
            )
            if not script_clean.endswith("\n"):
                script_clean += "\n"
            indented = textwrap.indent(script_clean, " " * 10)

            parts.append(_STEP_TEMPLATE.format(
                step_name=step_name,
                shell=_shell_to_gha(variant.shell),
                script_indented=indented,
            ))
            included_variants += 1

    # Skip comments for infeasible clusters
    for intent in intents:
        if not intent.feasible or not intent.llm_call_succeeded:
            reason = intent.infeasible_reason or intent.llm_error or "unknown"
            parts.append(
                f"      # SKIPPED cluster {intent.cluster_id}: {reason}\n"
            )

    parts.append(_EXPORT_STEP.format(iteration_id=iteration_id))
    parts.append(_WORKFLOW_FOOTER)

    return "".join(parts)


def _lookup_prior_context(
    cluster: RuleCluster,
    prior_context_map: dict[str, str],
) -> str:
    """
    Find prior effective activity context for a cluster by tag overlap.
    Returns empty string if no relevant prior context found.
    """
    if not prior_context_map:
        return ""
    cluster_tags = set(cluster.archetype_tags)
    matches = []
    for tag_key, description in prior_context_map.items():
        key_tags = set(tag_key.split(","))
        overlap = cluster_tags & key_tags
        if len(overlap) >= 2:  # any overlap
            matches.append(description)
    return "\n".join(matches) if matches else ""
