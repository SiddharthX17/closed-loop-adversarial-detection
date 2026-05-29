"""
pipeline/corpus/yaml_generator.py

Drives LLM calls per cluster and assembles a PowerShell .ps1 corpus
stress-test script.

Two responsibilities:
  1. Call the LLM for each cluster -> ClusterIntent
  2. Assemble all ClusterIntents into a single .ps1 script

The .ps1 is committed to corpus/scripts/ and executed by the static
corpus_runner.yml workflow. No YAML escaping -- PowerShell lives in a
real .ps1 file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import anthropic

from pipeline.corpus.clusterer import RuleCluster
from pipeline.corpus.prompts import SYSTEM_PROMPT, build_cluster_prompt

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")

_LLM_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 4096


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class ScriptVariant:
    archetype: str
    description: str
    shell: str
    script: str
    expected_eids: list[int]
    covers_sub_patterns: list[str]


@dataclass
class ClusterIntent:
    cluster_id: str
    member_rule_ids: list[str]
    cluster_size: int
    confidence: float
    archetype_tags: list[str]
    target_eids: list[int]
    feasible: bool
    infeasible_reason: Optional[str]
    behavioral_intent: str
    sub_patterns: list[str]
    variants: list[ScriptVariant]
    llm_call_succeeded: bool = True
    llm_error: Optional[str] = None


# ---------------------------------------------------------------------------
# PowerShell script templates
#
# These are raw strings (r"...") so backslashes are literal.
# All substitution uses .replace("__TOKEN__", value) -- never .format().
# This means PS @{}, ${var}, {0} etc. are never touched by Python.
# ---------------------------------------------------------------------------

_PS_HEADER = r"""# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  __ITERATION_ID__
# Clusters:   __N_CLUSTERS__  |  Feasible: __N_FEASIBLE__  |  Variants: __N_VARIANTS__
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = '__ITERATION_ID__'

"""

_VARIANT_HEADER = r"""# -- Cluster: __CLUSTER_ID__  (__CLUSTER_SIZE__ rule(s)) ---------------------
# Intent:    __INTENT__
# Rules:     __RULE_IDS__
# Archetype: __ARCHETYPE__

"""

# Export block uses PS -f operator and Join-Path to avoid any Python
# format-field ambiguity. Raw string so backslashes are literal.
_PS_EXPORT = r"""
# ===========================================================================
# Export Sysmon events to corpus/benign/
# ===========================================================================

$exportDir   = Join-Path (Get-Location) 'corpus\benign'
$processDir  = Join-Path $exportDir 'process'
$networkDir  = Join-Path $exportDir 'network'
$registryDir = Join-Path $exportDir 'registry'
New-Item -ItemType Directory -Force -Path $processDir, $networkDir, $registryDir | Out-Null

function Export-SysmonEvent {
    param($Event, $Eid)
    $p   = $Event.Properties
    $obj = [ordered]@{
        Channel     = 'Microsoft-Windows-Sysmon/Operational'
        EventID     = $Eid
        TimeCreated = $Event.TimeCreated.ToString('o')
    }
    if ($Eid -eq 1) {
        if ($p.Count -gt 4)  { $obj['Image']            = [string]$p[4].Value  }
        if ($p.Count -gt 10) { $obj['CommandLine']       = [string]$p[10].Value }
        if ($p.Count -gt 20) { $obj['ParentImage']       = [string]$p[20].Value }
        if ($p.Count -gt 21) { $obj['ParentCommandLine'] = [string]$p[21].Value }
        if ($p.Count -gt 3)  { $obj['ProcessId']         = [string]$p[3].Value  }
        if ($p.Count -gt 19) { $obj['ParentProcessId']   = [string]$p[19].Value }
        if ($p.Count -gt 12) { $obj['User']              = [string]$p[12].Value }
        if ($p.Count -gt 11) { $obj['CurrentDirectory']  = [string]$p[11].Value }
        if ($p.Count -gt 16) { $obj['IntegrityLevel']    = [string]$p[16].Value }
        if ($p.Count -gt 9)  { $obj['OriginalFileName']  = [string]$p[9].Value  }
    } elseif ($Eid -eq 3) {
        if ($p.Count -gt 4)  { $obj['Image']               = [string]$p[4].Value  }
        if ($p.Count -gt 6)  { $obj['Protocol']            = [string]$p[6].Value  }
        if ($p.Count -gt 7)  { $obj['Initiated']           = [string]$p[7].Value  }
        if ($p.Count -gt 9)  { $obj['SourceIp']            = [string]$p[9].Value  }
        if ($p.Count -gt 11) { $obj['SourcePort']          = [string]$p[11].Value }
        if ($p.Count -gt 14) { $obj['DestinationIp']       = [string]$p[14].Value }
        if ($p.Count -gt 15) { $obj['DestinationHostname'] = [string]$p[15].Value }
        if ($p.Count -gt 16) { $obj['DestinationPort']     = [string]$p[16].Value }
    } elseif ($Eid -eq 11) {
        if ($p.Count -gt 4) { $obj['Image']          = [string]$p[4].Value }
        if ($p.Count -gt 6) { $obj['TargetFilename'] = [string]$p[6].Value }
    } elseif ($Eid -eq 12) {
        if ($p.Count -gt 1) { $obj['EventType']    = [string]$p[1].Value }
        if ($p.Count -gt 5) { $obj['Image']        = [string]$p[5].Value }
        if ($p.Count -gt 6) { $obj['TargetObject'] = [string]$p[6].Value }
    } elseif ($Eid -eq 13) {
        if ($p.Count -gt 1) { $obj['EventType']    = [string]$p[1].Value }
        if ($p.Count -gt 5) { $obj['Image']        = [string]$p[5].Value }
        if ($p.Count -gt 6) { $obj['TargetObject'] = [string]$p[6].Value }
        if ($p.Count -gt 7) { $obj['Details']      = [string]$p[7].Value }
    }
    return $obj
}

$startTime = if ($env:CORPUS_START_TIME) {
    [datetime]::Parse($env:CORPUS_START_TIME)
} else {
    (Get-Date).AddMinutes(-30)
}

$eidMap = @{
    1  = $processDir
    11 = $processDir
    3  = $networkDir
    12 = $registryDir
    13 = $registryDir
}

foreach ($eid in $eidMap.Keys) {
    $outFile = Join-Path $eidMap[$eid] ('targeted_' + $iterationId + '_eid' + $eid + '.jsonl')
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = $eid
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
        ForEach-Object {
            Export-SysmonEvent -Event $_ -Eid $eid | ConvertTo-Json -Compress
        } | Out-File -Append -Encoding utf8 $outFile
        $n = if (Test-Path $outFile) { (Get-Content $outFile | Measure-Object -Line).Lines } else { 0 }
        Write-Host ('EID ' + $eid + ': ' + $n + ' events -> ' + $outFile)
    } catch {
        Write-Host ('EID ' + $eid + ': error - ' + $_.Exception.Message)
    }
}

Write-Host ('Export complete for iteration: ' + $iterationId)
"""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_script(script: str, shell: str) -> tuple[bool, str]:
    """
    Static safety floor -- not a security control.
    Catches obviously wrong LLM output without enumerating obfuscation variants.
    """
    if not script.strip():
        return False, "empty script"

    s = script.lower()

    _blocklist = [
        ("invoke-mimikatz",               "credential dumping"),
        ("net user /add",                 "user creation"),
        ("net localgroup administrators", "privilege escalation"),
        ("sekurlsa",                      "credential access"),
        ("downloadfile(",                 "payload download"),
        ("start-bitstransfer",            "payload download"),
        ("-windowstyle hidden",           "hidden window"),
        ("reg add hklm\\sam",             "SAM tampering"),
        ("wevtutil cl ",                  "log clearing"),
        ("clear-eventlog",                "log clearing"),
    ]

    for pattern, reason in _blocklist:
        if pattern in s:
            return False, f"blocked pattern: {reason} ('{pattern}')"

    if shell == "powershell" and len(script.strip().splitlines()) < 2:
        return False, "powershell script too short (< 2 lines)"

    return True, "ok"


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_llm(
    cluster: RuleCluster,
    client: anthropic.Anthropic,
    prior_context: str = "",
) -> ClusterIntent:
    prompt = build_cluster_prompt(cluster, prior_context)

    if _DEBUG:
        print(f"[corpus/yaml_generator] LLM call for {cluster.cluster_id} "
              f"({cluster.cluster_size} rules)")

    try:
        response = client.messages.create(
            model=_LLM_MODEL,
            max_tokens=_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        text_blocks = [b for b in response.content if hasattr(b, "text")]
        if not text_blocks:
            raise ValueError("No text block in LLM response")
        raw_text = text_blocks[0].text.strip()

        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("No JSON object in LLM response")
        parsed = json.loads(raw_text[start:end + 1])

    except json.JSONDecodeError as e:
        if _DEBUG:
            print(
                f"[corpus/yaml_generator] JSON error {cluster.cluster_id}: {e}")
        return _failed_intent(cluster, f"JSON parse error: {e}")
    except Exception as e:
        if _DEBUG:
            print(
                f"[corpus/yaml_generator] LLM error {cluster.cluster_id}: {e}")
        return _failed_intent(cluster, str(e))

    feasible = bool(parsed.get("feasible", False))
    variants: list[ScriptVariant] = []

    if feasible:
        seen: set[str] = set()
        for v in parsed.get("variants", []):
            arch = v.get("archetype", "unknown")
            if arch in seen:
                continue
            seen.add(arch)
            variants.append(ScriptVariant(
                archetype=arch,
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


def _lookup_prior_context(
    cluster: RuleCluster,
    prior_context_map: dict[str, str],
) -> str:
    if not prior_context_map:
        return ""
    cluster_tags = set(cluster.archetype_tags)
    matches = []
    for tag_key, desc in prior_context_map.items():
        if len(cluster_tags & set(tag_key.split(","))) >= 2:
            matches.append(desc)
    return "\n".join(matches) if matches else ""


# ---------------------------------------------------------------------------
# Public interfaces
# ---------------------------------------------------------------------------

def generate_intents(
    clusters: list[RuleCluster],
    client: anthropic.Anthropic,
    prior_context_map: dict[str, str] | None = None,
) -> list[ClusterIntent]:
    """Call LLM for each cluster, return ClusterIntent list."""
    if prior_context_map is None:
        prior_context_map = {}
    intents = []
    for cluster in clusters:
        prior = _lookup_prior_context(cluster, prior_context_map)
        intent = _call_llm(cluster, client, prior)
        if _DEBUG:
            status = "feasible" if intent.feasible else f"infeasible: {intent.infeasible_reason}"
            n = len(intent.variants) if intent.feasible else 0
            print(
                f"[corpus/yaml_generator] {cluster.cluster_id}: {status}, {n} variant(s)")
        intents.append(intent)
    return intents


def generate_ps_script(
    intents: list[ClusterIntent],
    iteration_id: str,
) -> str:
    """
    Assemble a .ps1 corpus stress-test script from ClusterIntents.

    Returns the complete PS script string.
    pusher.py writes it to corpus/scripts/targeted_{iteration_id}.ps1.
    corpus_runner.yml executes it.
    """
    feasible = [i for i in intents if i.feasible and i.llm_call_succeeded]
    n_variants = sum(len(i.variants) for i in feasible)

    if _DEBUG:
        print(f"[corpus/yaml_generator] Building PS script -- "
              f"{len(feasible)} feasible clusters, {n_variants} variants")

    parts: list[str] = []

    # Header
    parts.append(
        _PS_HEADER
        .replace("__ITERATION_ID__", iteration_id)
        .replace("__N_CLUSTERS__",   str(len(intents)))
        .replace("__N_FEASIBLE__",   str(len(feasible)))
        .replace("__N_VARIANTS__",   str(n_variants))
    )

    # Activity blocks
    for intent in feasible:
        for variant in intent.variants:
            passed, reason = _validate_script(variant.script, variant.shell)
            if not passed:
                if _DEBUG:
                    print(f"[corpus/yaml_generator] Skipping '{variant.archetype}' "
                          f"in {intent.cluster_id}: {reason}")
                parts.append(
                    f"# SKIPPED variant '{variant.archetype}': {reason}\n\n")
                continue

            parts.append(
                _VARIANT_HEADER
                .replace("__CLUSTER_ID__",   intent.cluster_id)
                .replace("__CLUSTER_SIZE__", str(intent.cluster_size))
                .replace("__INTENT__",       intent.behavioral_intent[:80])
                .replace("__RULE_IDS__",     ", ".join(intent.member_rule_ids))
                .replace("__ARCHETYPE__",    variant.archetype)
            )

            # Normalise: strip trailing whitespace per line
            script_clean = "\n".join(
                line.rstrip() for line in variant.script.splitlines()
            ).rstrip()
            parts.append(script_clean)
            parts.append("\n\n")

    # Infeasible cluster notes
    for intent in intents:
        if not intent.feasible or not intent.llm_call_succeeded:
            reason = intent.infeasible_reason or intent.llm_error or "unknown"
            parts.append(f"# SKIPPED cluster {intent.cluster_id}: {reason}\n")

    # Export block
    parts.append(_PS_EXPORT)

    return "".join(parts)
