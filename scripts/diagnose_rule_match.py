"""
scripts/diagnose_rule_match.py

Identifies which rule fired on which event for a given technique.
Shows the generated SQL per rule so EventID/logsource filtering can be
verified — catches cases where enrichment adds fields that cause
process-creation rules to fire on network events.

Usage:
    python scripts/diagnose_rule_match.py --technique T1003.001
    python scripts/diagnose_rule_match.py --technique T1003.001 --event-id 3
    python scripts/diagnose_rule_match.py --technique T1003.001 --events-file corpus/attack/T1003.001.jsonl
    python scripts/diagnose_rule_match.py --technique T1003.001 --show-sql
"""

from pipeline.detection.engine import DetectionEngine
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Event helpers ─────────────────────────────────────────────────────────────

def load_events(events_file: Path) -> list[dict]:
    events = []
    with open(events_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def summarise_event(event: dict, index: int) -> str:
    eid = event.get("EventID", "?")
    etype = event.get("event_type", "?")
    parts = [f"[{index}] EID={eid} type={etype}"]
    for field in ("Image", "ParentImage", "CommandLine",
                  "TargetObject", "DestinationHostname", "DestinationIp",
                  "Protocol", "Initiated"):
        val = event.get(field)
        if val:
            parts.append(f"  {field}={str(val)[:80]}")
    return "\n".join(parts)


# ── Rule helpers ──────────────────────────────────────────────────────────────

def load_rules(rules_dir: Path) -> list[tuple[str, str]]:
    rules = []
    seen = set()
    for rule_path in sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml")):
        if str(rule_path) in seen:
            continue
        seen.add(str(rule_path))
        try:
            rules.append(
                (str(rule_path), rule_path.read_text(encoding="utf-8")))
        except Exception as e:
            print(f"  [!] Could not read {rule_path}: {e}")
    return rules


def extract_title(yaml_text: str) -> str:
    for line in yaml_text.splitlines():
        if line.strip().startswith("title:"):
            return line.split(":", 1)[1].strip()
    return "(untitled)"


def extract_logsource(yaml_text: str) -> str:
    lines = yaml_text.splitlines()
    in_ls = False
    parts = []
    for line in lines:
        if line.strip().startswith("logsource:"):
            in_ls = True
            continue
        if in_ls:
            if line and not line.startswith(" ") and not line.startswith("\t"):
                break
            stripped = line.strip()
            if stripped:
                parts.append(stripped)
    return " | ".join(parts) if parts else "(unknown logsource)"


def get_rule_sql(rule_yaml: str) -> list[str] | None:
    """
    Generate SQL for a rule using the same pipeline as the detection engine.
    Returns list of SQL strings, or None if conversion fails.
    """
    try:
        import re as _re
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import SqliteBackend
        from sigma.pipelines.sysmon import sysmon_pipeline
        from sigma.pipelines.windows import windows_logsource_pipeline

        pipeline = sysmon_pipeline() + windows_logsource_pipeline()
        backend = SqliteBackend(processing_pipeline=pipeline)
        sigma_col = SigmaCollection.from_yaml(rule_yaml)
        return backend.convert(sigma_col)
    except Exception as e:
        return [f"<SQL generation failed: {e}>"]


# ── Main diagnosis ────────────────────────────────────────────────────────────

def run_diagnosis(
    technique_id: str,
    events_file: Path,
    rules_dir: Path,
    filter_event_id: int | None,
    show_sql: bool,
):
    print(f"\n{'='*72}")
    print(f"  Diagnostic: {technique_id}")
    print(f"  Events:     {events_file}")
    print(f"  Rules:      {rules_dir}")
    if filter_event_id:
        print(f"  Filter:     EventID={filter_event_id} only")
    print(f"{'='*72}\n")

    all_events = load_events(events_file)
    if not all_events:
        print("No events found in file.")
        return

    events = (
        [e for e in all_events if e.get("EventID") == filter_event_id]
        if filter_event_id else all_events
    )

    rules = load_rules(rules_dir)
    if not rules:
        print(f"No rules found in {rules_dir}")
        return

    print(f"Events total: {len(all_events)}, after filter: {len(events)}")
    print(f"Rules loaded: {len(rules)}\n")

    # ── Print events being tested ─────────────────────────────────────────────
    print("── Events under test ────────────────────────────────────────────────")
    for i, ev in enumerate(events):
        print(summarise_event(ev, i))
        print()

    # ── Rule × event matrix ───────────────────────────────────────────────────
    engine = DetectionEngine(rules_dir=rules_dir, events=[])

    print("── Rule × Event Matrix ──────────────────────────────────────────────")
    any_match = False

    for rule_path, rule_yaml in rules:
        title = extract_title(rule_yaml)
        logsource = extract_logsource(rule_yaml)

        # Test each event individually
        for i, event in enumerate(events):
            try:
                result = engine.run_single_rule(rule_yaml, events=[event])
                fired = result is not None and len(result.matched_events) > 0
            except Exception as e:
                print(f"  [ERROR] '{title}' on event[{i}]: {str(e)[:100]}")
                continue

            if fired:
                any_match = True
                print(
                    f"\n  ╔═ MATCH ════════════════════════════════════════════════════════")
                print(f"  ║  Rule:      {title}")
                print(f"  ║  File:      {Path(rule_path).name}")
                print(f"  ║  Logsource: {logsource}")
                print(
                    f"  ║  Event:     {summarise_event(event, i).replace(chr(10), chr(10)+'  ║           ')}")
                print(f"  ║  Matched:   {len(result.matched_events)} event(s)")

                if show_sql:
                    sql_list = get_rule_sql(rule_yaml)
                    if sql_list:
                        print(
                            f"  ║  SQL generated ({len(sql_list)} statement(s)):")
                        for j, sql in enumerate(sql_list):
                            # Wrap long SQL for readability
                            wrapped = sql.replace(" AND ", "\n  ║      AND ")
                            wrapped = wrapped.replace(
                                " OR ",  "\n  ║      OR  ")
                            print(f"  ║    [{j}] {wrapped}")

                print(f"  ╚{'═'*66}")

    if not any_match:
        print("\n  No rules fired on the filtered events.")
        print("  If you expected a match, run without --event-id filter to check")
        print("  whether the rule fires on a different event type in the sample.")

    # ── Aggregate: all rules vs full event set ────────────────────────────────
    print(
        f"\n── Aggregate: all rules vs all {len(all_events)} events (unfiltered) ──────────")
    for rule_path, rule_yaml in rules:
        title = extract_title(rule_yaml)
        try:
            result = engine.run_single_rule(rule_yaml, events=all_events)
            count = len(result.matched_events) if result else 0
            if count:
                event_ids = [e.get("EventID", "?")
                             for e in result.matched_events]
                print(
                    f"  FIRED  '{title}': {count} event(s) matched  EIDs={event_ids}")
        except Exception as e:
            print(f"  ERROR  '{title}': {str(e)[:100]}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Diagnose which rules fire on which events for a technique"
    )
    parser.add_argument(
        "--technique", required=True,
        help="Technique ID e.g. T1003.001"
    )
    parser.add_argument(
        "--events-file", type=Path,
        help="Path to JSONL events file (default: corpus/attack/{technique}.jsonl)"
    )
    parser.add_argument(
        "--rules-dir", type=Path, default=Path("rules"),
        help="Rules directory to search (default: rules/)"
    )
    parser.add_argument(
        "--event-id", type=int,
        help="Filter to only test events with this EventID (e.g. 3 for network)"
    )
    parser.add_argument(
        "--show-sql", action="store_true",
        help="Show the SQL generated by pySigma for each fired rule"
    )
    args = parser.parse_args()

    events_file = args.events_file or Path(
        f"corpus/attack/{args.technique}.jsonl")
    if not events_file.exists():
        print(f"Events file not found: {events_file}")
        available = list(Path("corpus/attack").glob("*.jsonl"))
        if available:
            print("Available files in corpus/attack/:")
            for f in sorted(available):
                print(f"  {f}")
        sys.exit(1)

    run_diagnosis(
        technique_id=args.technique,
        events_file=events_file,
        rules_dir=args.rules_dir,
        filter_event_id=args.event_id,
        show_sql=args.show_sql,
    )


if __name__ == "__main__":
    main()
