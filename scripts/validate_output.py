"""
scripts/validate_output.py

Phase 1.15 — End-to-end validation and gap analysis.

Two sections:
  1. Gap analysis    — which techniques produced events, which didn't, where
                       events were lost (skipped tests vs dropped by gates)
  2. Field coverage  — EID 1 field presence in emulated output vs benign corpus
                       (flags fields present in real logs but missing in emulated)

Run from repo root:
  python scripts/validate_output.py

Adjust the path constants below if your layout differs.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich import box

# ─── Config — edit if paths differ ────────────────────────────────────────────

ATTACK_DIR = Path("corpus/attack")
STATS_DIR = Path("corpus/attack/stats")
BENIGN_DIR = Path("corpus/benign/process_creation")

# Fields defined in schema.yaml — used for coverage comparison
SCHEMA_FIELDS = [
    "timestamp", "host", "user", "EventID", "event_type",
    "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "ProcessId", "ParentProcessId", "TargetObject", "Details",
    "SourceIp", "DestinationIp", "DestinationHostname", "DestinationPort",
    "OriginalFileName", "CurrentDirectory", "IntegrityLevel",
    "Protocol", "Initiated",
]

# Only these fields are meaningful for EID 1 comparison
EID1_FIELDS = [
    "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "ProcessId", "ParentProcessId", "OriginalFileName",
    "CurrentDirectory", "IntegrityLevel",
]

console = Console()


# ─── Loaders ──────────────────────────────────────────────────────────────────

def load_latest_stats() -> dict | None:
    """Load the most recent stats JSON from STATS_DIR."""
    if not STATS_DIR.exists():
        console.print(f"[yellow]Stats dir not found: {STATS_DIR}[/yellow]")
        return None

    stat_files = sorted(STATS_DIR.glob("run_*_stats.json"))
    if not stat_files:
        console.print(f"[yellow]No stats files found in {STATS_DIR}[/yellow]")
        return None

    latest = stat_files[-1]
    console.print(f"[dim]Loading stats: {latest.name}[/dim]")
    return json.loads(latest.read_text())


def load_emulated_events() -> list[dict]:
    """
    Load all events from corpus/attack/*.jsonl.
    Returns flat list of dicts, each with technique_id injected.
    """
    events = []
    if not ATTACK_DIR.exists():
        console.print(f"[yellow]Attack dir not found: {ATTACK_DIR}[/yellow]")
        return events

    for path in sorted(ATTACK_DIR.glob("*.jsonl")):
        count = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                    count += 1
                except json.JSONDecodeError:
                    console.print(
                        f"[yellow]  Skipped malformed line in {path.name}[/yellow]")
        console.print(f"[dim]  Loaded {count} event(s) from {path.name}[/dim]")

    return events


def load_benign_events() -> list[dict]:
    """
    Load benign corpus events from BENIGN_DIR.
    Handles two formats:
      - JSONL: one JSON object per line
      - JSON array: list of objects in a single file
    Skips files that can't be parsed and reports them.
    """
    events = []
    if not BENIGN_DIR.exists():
        console.print(
            f"[yellow]Benign dir not found: {BENIGN_DIR} — skipping field coverage[/yellow]")
        return events

    for path in sorted(BENIGN_DIR.iterdir()):
        if path.suffix not in (".json", ".jsonl"):
            continue

        raw = path.read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            continue

        loaded = []
        # Try JSON array first
        if raw.startswith("["):
            try:
                loaded = json.loads(raw)
                if not isinstance(loaded, list):
                    loaded = []
            except json.JSONDecodeError:
                pass

        # Try JSONL
        if not loaded:
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        loaded.append(obj)
                except json.JSONDecodeError:
                    pass

        if loaded:
            events.extend(loaded)
            console.print(
                f"[dim]  Loaded {len(loaded)} benign event(s) from {path.name}[/dim]")
        else:
            console.print(
                f"[yellow]  Could not parse {path.name} — check format[/yellow]")

    return events


# ─── Field presence helpers ───────────────────────────────────────────────────

def field_present(event: dict, field: str) -> bool:
    """True if field exists in event and is not None/empty string."""
    val = event.get(field)
    return val is not None and val != ""


def coverage_pct(events: list[dict], field: str) -> float:
    """Percentage of events where field is populated."""
    if not events:
        return 0.0
    return sum(1 for e in events if field_present(e, field)) / len(events) * 100


# ─── Section 1: Gap analysis ──────────────────────────────────────────────────

def print_gap_analysis(stats: dict, emulated_events: list[dict]) -> None:
    console.rule("[bold cyan]Section 1 — Gap Analysis[/bold cyan]")

    # Overall stats
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Techniques attempted",       str(
        stats.get("techniques_attempted", "?")))
    table.add_row("Techniques with ≥1 event",   str(
        stats.get("techniques_with_events", "?")))
    table.add_row("Tests attempted",            str(
        stats.get("tests_attempted", "?")))
    table.add_row("Tests skipped (no clean)",   str(
        stats.get("tests_skipped_no_clean", "?")))
    table.add_row("Tests skipped (unresolved)", str(
        stats.get("tests_skipped_unresolved", "?")))
    table.add_row("Events generated",           str(
        stats.get("events_generated", "?")))
    console.print(table)

    # Per-technique breakdown
    per_technique = stats.get("per_technique", {})
    if not per_technique:
        console.print("[yellow]No per-technique data in stats.[/yellow]")
        return

    t = Table(title="Per-Technique Results", box=box.MARKDOWN)
    t.add_column("Technique",    style="cyan")
    t.add_column("Events", justify="right")
    t.add_column("Status")
    t.add_column("Note")

    zero_techniques = []
    for tid, count in sorted(per_technique.items()):
        if count > 0:
            t.add_row(tid, str(count), "[green]✓ PASS[/green]", "")
        else:
            t.add_row(tid, "0", "[red]✗ FAIL[/red]", "no events generated")
            zero_techniques.append(tid)

    console.print(t)

    if zero_techniques:
        console.print(
            f"\n[red]Zero-event techniques ({len(zero_techniques)}):[/red] "
            + ", ".join(zero_techniques)
        )
        console.print(
            "[dim]Possible causes: no Atomic tests found, all tests skipped "
            "(unresolved vars), all LLM outputs dropped by grounding or min-field gate.[/dim]"
        )
    else:
        console.print(
            "\n[green]All techniques produced at least one event.[/green]")

    # Gate loss estimate
    total_attempted = stats.get("tests_attempted", 0)
    total_skipped = (
        stats.get("tests_skipped_no_clean", 0) +
        stats.get("tests_skipped_unresolved", 0)
    )
    total_events = stats.get("events_generated", 0)
    reached_llm = total_attempted - total_skipped
    dropped_by_gate = reached_llm - total_events if reached_llm > total_events else 0

    if reached_llm > 0:
        console.print(f"\n[dim]Gate loss estimate:[/dim]")
        console.print(f"  {total_attempted} tests attempted")
        console.print(
            f"  {total_skipped} skipped before LLM  ({total_skipped/total_attempted*100:.0f}%)")
        console.print(f"  {reached_llm} reached LLM")
        console.print(
            f"  {dropped_by_gate} dropped by grounding/min-field/confidence gates")
        console.print(f"  {total_events} events survived")


# ─── Section 2: Field coverage ────────────────────────────────────────────────

def print_field_coverage(emulated_events: list[dict], benign_events: list[dict]) -> None:
    console.rule("[bold cyan]Section 2 — EID 1 Field Coverage[/bold cyan]")

    eid1_emulated = [e for e in emulated_events if e.get("EventID") == 1]
    eid1_benign = [e for e in benign_events if str(
        e.get("EventID", "")) == "1"]

    console.print(
        f"EID 1 events — emulated: [cyan]{len(eid1_emulated)}[/cyan]  "
        f"benign: [cyan]{len(eid1_benign)}[/cyan]"
    )

    if not eid1_emulated:
        console.print(
            "[yellow]No emulated EID 1 events found — skipping comparison.[/yellow]")
        return

    t = Table(title="EID 1 Field Presence", box=box.MARKDOWN)
    t.add_column("Field",               style="cyan", no_wrap=True)
    t.add_column("Emulated",            justify="right")
    t.add_column("Benign",              justify="right")
    t.add_column("Gap?")

    for field in EID1_FIELDS:
        em_pct = coverage_pct(eid1_emulated, field)
        ben_pct = coverage_pct(eid1_benign, field) if eid1_benign else None

        em_str = f"{em_pct:.0f}%"
        ben_str = f"{ben_pct:.0f}%" if ben_pct is not None else "[dim]N/A[/dim]"

        # Gap: field present in real logs but missing in emulated
        if ben_pct is not None and ben_pct >= 50 and em_pct < 50:
            gap = "[red]⚠ MISSING IN EMULATED[/red]"
        elif ben_pct is not None and ben_pct >= 50 and em_pct >= 50:
            gap = "[green]✓[/green]"
        else:
            gap = ""

        t.add_row(field, em_str, ben_str, gap)

    console.print(t)

    if not eid1_benign:
        console.print(
            "[yellow]No benign EID 1 events loaded — "
            "gap column shows N/A. Check BENIGN_DIR path and file format.[/yellow]"
        )
    else:
        # Summary: fields in real logs missing in emulated
        gaps = [
            f for f in EID1_FIELDS
            if coverage_pct(eid1_benign, f) >= 50 and coverage_pct(eid1_emulated, f) < 50
        ]
        if gaps:
            console.print(
                f"\n[red]Fields common in real logs but sparse in emulated ({len(gaps)}):[/red] "
                + ", ".join(gaps)
            )
            console.print(
                "[dim]These are detection blind spots — Sigma rules using these fields "
                "won't fire against your emulated logs.[/dim]"
            )
        else:
            console.print(
                "\n[green]No significant field gaps detected.[/green]")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    console.print("\n[bold]Phase 1.15 — Emulator Output Validation[/bold]\n")

    # Load data
    stats = load_latest_stats()
    if not stats:
        console.print("[red]Cannot run gap analysis without stats file. "
                      "Run the emulator first.[/red]")
        sys.exit(1)

    console.print()
    emulated_events = load_emulated_events()
    console.print()
    benign_events = load_benign_events()
    console.print()

    # Section 1
    print_gap_analysis(stats, emulated_events)
    console.print()

    # Section 2
    print_field_coverage(emulated_events, benign_events)
    console.print()


if __name__ == "__main__":
    main()
