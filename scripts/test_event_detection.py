"""
scripts/test_event_detection.py

Feed a raw event dict directly through the detection engine and see which rules fire.
Bypasses the emulator entirely — use this to test specific events from debug output.

Usage:
    1. Paste your event dict(s) into the EVENTS list below
    2. Run: python scripts/test_event_detection.py
    3. Optional flags:
         --rules-dir rules/generated    (test generated rules only)
         --show-sql                      (print the SQL each rule compiles to)
         --technique T1003.001          (filter rules by technique prefix)
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── PASTE YOUR EVENT(S) HERE ──────────────────────────────────────────────────
# Copy the fields dict from [DEBUG] Raw LLM output in the full run log.
# Add as many events as you need — one dict per list entry.
# Required fields: EventID, event_type, timestamp, host, user
# Channel is injected automatically if missing.

EVENTS = [
    {
        "event_type": "process_creation",
        "EventID": 1,
        "fields": {
            "ParentImage": "C:\\Windows\\System32\\mshta.exe",
            "ParentCommandLine": "mshta.exe vbscript:CreateObject(\"WScript.Shell\").Run(\"powershell.exe -NoProfile -Command Get-Process lsass | Select-Object -ExpandProperty Id | ForEach-Object { & 'C:\\Windows\\System32\\rdrleakdiag.exe' /p $_ /o C:\\Users\\Public\\Documents\\dump /fullmemdmp /wait 1 }\",0)(window.close)",
            "Image": "C:\\Windows\\System32\\rdrleakdiag.exe",
            "CommandLine": "rdrleakdiag.exe /p 632 /o C:\\Users\\Public\\Documents\\dump /fullmemdmp /wait 1",
            "OriginalFileName": "rdrleakdiag.exe"
        }
    }
]

# ─────────────────────────────────────────────────────────────────────────────


REQUIRED_BASE = {"EventID", "event_type"}
CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _inject_defaults(event: dict) -> dict:
    """Fill in mandatory fields the engine needs if they're absent."""
    out = dict(event)
    out.setdefault("Channel",    CHANNEL)
    out.setdefault("timestamp",  "2024-01-01T00:00:00Z")
    out.setdefault("host",       "WORKSTATION")
    out.setdefault("user",       "SYSTEM")
    return out


def _summarise(event: dict, index: int) -> str:
    eid = event.get("EventID", "?")
    etype = event.get("event_type", "?")
    lines = [f"  [{index}] EID={eid}  type={etype}"]
    for field in ("Image", "CommandLine", "ParentImage",
                  "TargetObject", "Details",
                  "DestinationHostname", "DestinationIp",
                  "Protocol", "Initiated", "OriginalFileName"):
        v = event.get(field)
        if v:
            lines.append(f"          {field} = {str(v)[:100]}")
    return "\n".join(lines)


def _extract_title(yaml_text: str) -> str:
    for line in yaml_text.splitlines():
        if line.strip().startswith("title:"):
            return line.split(":", 1)[1].strip()
    return "(untitled)"


def _get_sql(rule_yaml: str) -> str | None:
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import SqliteBackend
        from sigma.pipelines.sysmon import sysmon_pipeline
        from sigma.pipelines.windows import windows_logsource_pipeline
        pipeline = sysmon_pipeline() + windows_logsource_pipeline()
        backend = SqliteBackend(processing_pipeline=pipeline)
        stmts = backend.convert(SigmaCollection.from_yaml(rule_yaml))
        return "\n".join(stmts) if stmts else "(no SQL generated)"
    except Exception as e:
        return f"(SQL failed: {e})"


def load_rules(rules_dir: Path, technique: str | None) -> list[tuple[str, str]]:
    rules, seen = [], set()
    for ext in ("*.yml", "*.yaml"):
        for p in sorted(rules_dir.rglob(ext)):
            if str(p) in seen:
                continue
            seen.add(str(p))
            if technique and not p.name.startswith(technique):
                continue
            try:
                rules.append((str(p), p.read_text(encoding="utf-8")))
            except Exception as e:
                print(f"  [!] Cannot read {p}: {e}")
    return rules


def run(rules_dir: Path, technique: str | None, show_sql: bool):
    # Validate input
    valid_events = []
    for i, ev in enumerate(EVENTS):
        missing = REQUIRED_BASE - ev.keys()
        if missing:
            print(
                f"[!] Event[{i}] missing required fields: {missing} — skipping")
            continue
        if not ev.get("EventID"):
            print(
                f"[!] Event[{i}] is empty (placeholder not filled in) — skipping")
            continue
        valid_events.append(_inject_defaults(ev))

    if not valid_events:
        print(
            "\nNo valid events to test. Fill in the EVENTS list at the top of this script.")
        print(
            "Paste the fields dict from [DEBUG] Raw LLM output in your run log.")
        sys.exit(1)

    rules = load_rules(rules_dir, technique)
    if not rules:
        print(f"No rules found in {rules_dir}" +
              (f" matching {technique}" if technique else ""))
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  Events: {len(valid_events)}    Rules: {len(rules)}")
    if technique:
        print(f"  Technique filter: {technique}")
    print(f"{'='*70}\n")

    print("── Events under test ────────────────────────────────────────────────")
    for i, ev in enumerate(valid_events):
        print(_summarise(ev, i))
    print()

    from pipeline.detection.engine import DetectionEngine
    engine = DetectionEngine(rules_dir=rules_dir, events=[])

    print("── Results ──────────────────────────────────────────────────────────")
    any_match = False

    for rule_path, rule_yaml in rules:
        title = _extract_title(rule_yaml)
        for i, ev in enumerate(valid_events):
            try:
                result = engine.run_single_rule(rule_yaml, events=[ev])
                if result and result.matched_events:
                    any_match = True
                    print(f"\n  ╔═ MATCH {'═'*58}")
                    print(f"  ║  Rule:  {title}")
                    print(f"  ║  File:  {Path(rule_path).name}")
                    print(f"  ║  Event: {_summarise(ev, i).strip()}")
                    if show_sql:
                        sql = _get_sql(rule_yaml)
                        wrapped = sql.replace(" AND ", "\n  ║         AND ") \
                                     .replace(" OR ",  "\n  ║         OR  ")
                        print(f"  ║  SQL:\n  ║         {wrapped}")
                    print(f"  ╚{'═'*66}")
            except Exception as e:
                print(f"  [ERROR] '{title}' on event[{i}]: {str(e)[:120]}")

    if not any_match:
        print("  No rules fired on any of the provided events.")
        print()
        print("  Possible reasons:")
        print("  - Rule logsource/EventID filter excludes this event type")
        print("  - Rule field conditions don't match the event values")
        print("  - Run with --show-sql to see what the rule is actually checking")

    print()


def main():
    ap = argparse.ArgumentParser(
        description="Test a specific event against all rules")
    ap.add_argument("--rules-dir",  type=Path, default=Path("rules"),
                    help="Rules directory (default: rules/)")
    ap.add_argument("--technique",  type=str,  default=None,
                    help="Only test rules whose filename starts with this ID")
    ap.add_argument("--show-sql",   action="store_true",
                    help="Print the SQL compiled from each fired rule")
    args = ap.parse_args()
    run(args.rules_dir, args.technique, args.show_sql)


if __name__ == "__main__":
    main()
