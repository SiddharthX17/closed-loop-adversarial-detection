"""
benign_generator.py

Template-based benign Windows Sysmon event generator.
Supplements the GH Actions corpus with synthetic events.
All events include Channel="Microsoft-Windows-Sysmon/Operational"
so they pass windows_logsource_pipeline() WHERE clauses.

Output: JSONL files written to corpus/benign/{process,network,registry}/
        Returns list[LogEvent] in all cases (output_dir=None = no file writes).
"""

import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from pipeline.emulator.log_builder import LogEvent

# ---------------------------------------------------------------------------
# Value pools — realistic Windows activity, no attack artifacts
# ---------------------------------------------------------------------------

_HOSTS = [
    "DESKTOP-A1B2C3D", "DESKTOP-X7Y8Z9W", "WORKSTATION-01",
    "WORKSTATION-02", "LAPTOP-ENG-04", "LAPTOP-HR-07",
]

_USERS = [
    "jsmith", "adavis", "mbrown", "lgarcia", "SYSTEM", "LOCAL SERVICE",
]

_INTEGRITY = ["Medium", "High", "System", "Low"]

_BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
]

_SYSTEM_PROCS = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\smss.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\taskhostw.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
    r"C:\Windows\System32\spoolsv.exe",
]

_OFFICE_PROCS = [
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
]

_EID1_TEMPLATES = [
    # Explorer spawning notepad
    {
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": r"notepad.exe C:\Users\{user}\Documents\notes.txt",
        "ParentImage": r"C:\Windows\explorer.exe",
        "ParentCommandLine": r"C:\Windows\explorer.exe",
        "OriginalFileName": "notepad.exe",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Users\{user}\\",
    },
    # svchost standard
    {
        "Image": r"C:\Windows\System32\svchost.exe",
        "CommandLine": r"C:\Windows\System32\svchost.exe -k netsvcs -p",
        "ParentImage": r"C:\Windows\System32\services.exe",
        "ParentCommandLine": r"C:\Windows\System32\services.exe",
        "OriginalFileName": "svchost.exe",
        "IntegrityLevel": "System",
        "CurrentDirectory": r"C:\Windows\system32\\",
    },
    # cmd spawning whoami (typical IT admin activity)
    {
        "Image": r"C:\Windows\System32\whoami.exe",
        "CommandLine": r"whoami /all",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": r'cmd.exe /c "whoami /all"',
        "OriginalFileName": "whoami.exe",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Users\{user}\\",
    },
    # powershell getting date (legitimate script)
    {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": r"powershell.exe -NonInteractive -Command Get-Date",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": r'cmd.exe /c powershell -NonInteractive -Command Get-Date',
        "OriginalFileName": "PowerShell.EXE",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Windows\System32\\",
    },
    # tasklist (monitoring tool)
    {
        "Image": r"C:\Windows\System32\tasklist.exe",
        "CommandLine": r"tasklist /fo csv /nh",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": r"cmd.exe",
        "OriginalFileName": "tasklist.exe",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Windows\System32\\",
    },
    # msiexec legitimate install
    {
        "Image": r"C:\Windows\System32\msiexec.exe",
        "CommandLine": r"C:\Windows\system32\msiexec.exe /i update.msi /qn",
        "ParentImage": r"C:\Windows\System32\services.exe",
        "ParentCommandLine": r"C:\Windows\System32\services.exe",
        "OriginalFileName": "msiexec.exe",
        "IntegrityLevel": "System",
        "CurrentDirectory": r"C:\Windows\System32\\",
    },
    # Windows Defender scan
    {
        "Image": r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        "CommandLine": r'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1',
        "ParentImage": r"C:\Windows\System32\svchost.exe",
        "ParentCommandLine": r"C:\Windows\System32\svchost.exe -k netsvcs",
        "OriginalFileName": "MpCmdRun.exe",
        "IntegrityLevel": "High",
        "CurrentDirectory": r"C:\Program Files\Windows Defender\\",
    },
    # ipconfig benign network check
    {
        "Image": r"C:\Windows\System32\ipconfig.exe",
        "CommandLine": r"ipconfig /all",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": r"cmd.exe",
        "OriginalFileName": "ipconfig.exe",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Windows\System32\\",
    },
    # chrome spawned by explorer
    {
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window',
        "ParentImage": r"C:\Windows\explorer.exe",
        "ParentCommandLine": r"C:\Windows\explorer.exe",
        "OriginalFileName": "chrome.exe",
        "IntegrityLevel": "Medium",
        "CurrentDirectory": r"C:\Program Files\Google\Chrome\Application\\",
    },
    # scheduled task host
    {
        "Image": r"C:\Windows\System32\taskeng.exe",
        "CommandLine": r"taskeng.exe {B1234567-89AB-CDEF-0123-456789ABCDEF} S-1-5-18:NT AUTHORITY\System:Service:",
        "ParentImage": r"C:\Windows\System32\svchost.exe",
        "ParentCommandLine": r"C:\Windows\System32\svchost.exe -k netsvcs",
        "OriginalFileName": "taskeng.exe",
        "IntegrityLevel": "System",
        "CurrentDirectory": r"C:\Windows\System32\\",
    },
]

_EID3_TEMPLATES = [
    # Chrome HTTPS browse
    {
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "DestinationIp": "142.250.80.46",
        "DestinationHostname": "www.google.com",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # Windows Update
    {
        "Image": r"C:\Windows\System32\svchost.exe",
        "DestinationIp": "13.107.4.52",
        "DestinationHostname": "windowsupdate.microsoft.com",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # DNS lookup (port 53)
    {
        "Image": r"C:\Windows\System32\svchost.exe",
        "DestinationIp": "8.8.8.8",
        "DestinationHostname": "",
        "DestinationPort": 53,
        "Protocol": "udp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # NTP sync
    {
        "Image": r"C:\Windows\System32\w32tm.exe",
        "DestinationIp": "17.253.52.125",
        "DestinationHostname": "time.apple.com",
        "DestinationPort": 123,
        "Protocol": "udp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # Outlook HTTPS
    {
        "Image": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "DestinationIp": "52.96.0.1",
        "DestinationHostname": "outlook.office365.com",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # Teams
    {
        "Image": r"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe",
        "DestinationIp": "52.113.194.132",
        "DestinationHostname": "teams.microsoft.com",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
    # Windows Defender cloud
    {
        "Image": r"C:\Program Files\Windows Defender\MsMpEng.exe",
        "DestinationIp": "13.89.179.12",
        "DestinationHostname": "wdcp.microsoft.com",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": "192.168.1.{octet}",
    },
]

_EID12_13_TEMPLATES = [
    # Office MRU
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Office\16.0\Word\File MRU\Item 1",
        "Details": r"C:\Users\{user}\Documents\report.docx",
    },
    # User shell folder
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop",
        "Details": r"C:\Users\{user}\Desktop",
    },
    # Run key for benign app (Teams auto-start)
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams",
        "Details": r"C:\Users\{user}\AppData\Local\Microsoft\Teams\Update.exe --processStart Teams.exe",
    },
    # EID 12 key create — temp scratch key from installer
    {
        "EventID": 12,
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\{GUID}",
        "Details": "",
    },
    # Windows Search history
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\{GUID}\AppId",
        "Details": r"C:\Windows\System32\cmd.exe",
    },
    # Printer preference
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Device",
        "Details": r"Microsoft Print to PDF,winspool,Ne00:",
    },
    # Font cache
    {
        "EventID": 12,
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontCache\{FontName}",
        "Details": "",
    },
    # Explorer recent folder
    {
        "EventID": 13,
        "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx",
        "Details": r"C:\Users\{user}\Documents\notes.docx",
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _iso_timestamp(base: datetime, jitter_seconds: int = 0) -> str:
    delta = timedelta(seconds=random.randint(0, max(jitter_seconds, 1)))
    return (base + delta).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fill(template_val: str, user: str, rng: random.Random) -> str:
    """Substitute {user} and {octet} placeholders in template strings."""
    val = template_val.replace("{user}", user)
    val = val.replace("{octet}", str(rng.randint(10, 254)))
    val = val.replace("{GUID}", str(uuid.uuid4()).upper())
    val = val.replace("{FontName}", rng.choice(
        ["Segoe UI", "Arial", "Calibri"]))
    return val


# ---------------------------------------------------------------------------
# Per-event-type generators
# ---------------------------------------------------------------------------

def _generate_eid1(
    count: int,
    base_time: datetime,
    rng: random.Random,
) -> list[LogEvent]:
    events = []
    for _ in range(count):
        tmpl = rng.choice(_EID1_TEMPLATES)
        host = rng.choice(_HOSTS)
        user = rng.choice(_USERS)
        pid = str(rng.randint(1000, 9999))
        ppid = str(rng.randint(400, 999))

        events.append(LogEvent(
            timestamp=_iso_timestamp(base_time, jitter_seconds=3600),
            host=host,
            user=user,
            EventID=1,
            event_type="process_creation",
            Channel=_SYSMON_CHANNEL,
            Image=_fill(tmpl["Image"], user, rng),
            CommandLine=_fill(tmpl["CommandLine"], user, rng),
            ParentImage=_fill(tmpl["ParentImage"], user, rng),
            ParentCommandLine=_fill(
                tmpl.get("ParentCommandLine", ""), user, rng),
            OriginalFileName=tmpl.get("OriginalFileName"),
            IntegrityLevel=tmpl.get("IntegrityLevel", rng.choice(_INTEGRITY)),
            CurrentDirectory=_fill(
                tmpl.get("CurrentDirectory", r"C:\Windows\System32\\"), user, rng),
            ProcessId=pid,
            ParentProcessId=ppid,
        ))
    return events


def _generate_eid3(
    count: int,
    base_time: datetime,
    rng: random.Random,
) -> list[LogEvent]:
    events = []
    for _ in range(count):
        tmpl = rng.choice(_EID3_TEMPLATES)
        host = rng.choice(_HOSTS)
        user = rng.choice(_USERS)

        events.append(LogEvent(
            timestamp=_iso_timestamp(base_time, jitter_seconds=3600),
            host=host,
            user=user,
            EventID=3,
            event_type="network",
            Channel=_SYSMON_CHANNEL,
            Image=_fill(tmpl["Image"], user, rng),
            DestinationIp=_fill(tmpl.get("DestinationIp", ""), user, rng),
            DestinationHostname=_fill(
                tmpl.get("DestinationHostname", ""), user, rng),
            DestinationPort=tmpl.get("DestinationPort"),
            Protocol=tmpl.get("Protocol"),
            Initiated=tmpl.get("Initiated"),
            SourceIp=_fill(tmpl.get("SourceIp", "192.168.1.10"), user, rng),
        ))
    return events


def _generate_eid12_13(
    count: int,
    base_time: datetime,
    rng: random.Random,
) -> list[LogEvent]:
    events = []
    for _ in range(count):
        tmpl = rng.choice(_EID12_13_TEMPLATES)
        host = rng.choice(_HOSTS)
        user = rng.choice(_USERS)
        eid = tmpl["EventID"]

        events.append(LogEvent(
            timestamp=_iso_timestamp(base_time, jitter_seconds=3600),
            host=host,
            user=user,
            EventID=eid,
            event_type="registry",
            Channel=_SYSMON_CHANNEL,
            TargetObject=_fill(tmpl["TargetObject"], user, rng),
            Details=_fill(tmpl.get("Details", ""), user, rng) or None,
        ))
    return events


# ---------------------------------------------------------------------------
# Channel injection for existing corpus files
# ---------------------------------------------------------------------------

def inject_channel_into_corpus(corpus_root: Path) -> dict[str, int]:
    """
    Walk corpus_root recursively. For every .jsonl file found:
      - Read each line, parse as JSON.
      - If Channel is missing or empty, inject _SYSMON_CHANNEL.
      - Rewrite the file only if at least one line was modified.

    Returns a summary dict: {filepath: lines_injected}
    Skips files where all lines already have Channel set.
    """
    summary: dict[str, int] = {}

    for jsonl_path in corpus_root.rglob("*.jsonl"):
        lines_injected = 0
        updated_lines: list[str] = []
        needs_rewrite = False

        with open(jsonl_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.rstrip("\n")
                if not raw:
                    updated_lines.append(raw)
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    updated_lines.append(raw)
                    continue

                if not obj.get("Channel"):
                    obj["Channel"] = _SYSMON_CHANNEL
                    lines_injected += 1
                    needs_rewrite = True

                updated_lines.append(json.dumps(obj))

        if needs_rewrite:
            with open(jsonl_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(updated_lines))
                if updated_lines:
                    fh.write("\n")
            summary[str(jsonl_path)] = lines_injected
        else:
            summary[str(jsonl_path)] = 0

    return summary


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_benign_events(
    count_per_type: int = 200,
    seed: Optional[int] = 42,
    output_dir: Optional[Path] = None,
) -> list[LogEvent]:
    """
    Generate synthetic benign Sysmon events.

    Args:
        count_per_type: Number of events to generate per event type
                        (EID 1, EID 3, EID 12/13 each get this count).
        seed:           RNG seed for reproducibility. Pass None for random.
        output_dir:     If provided, writes JSONL files to:
                          output_dir/process/benign_generated.jsonl
                          output_dir/network/benign_generated.jsonl
                          output_dir/registry/benign_generated.jsonl
                        If None, no files are written (test isolation).

    Returns:
        Combined list[LogEvent] across all event types.
    """
    rng = random.Random(seed)
    base_time = datetime.now(tz=timezone.utc).replace(
        hour=rng.randint(8, 17), minute=0, second=0, microsecond=0
    )

    eid1_events = _generate_eid1(count_per_type, base_time, rng)
    eid3_events = _generate_eid3(count_per_type, base_time, rng)
    eid12_13_events = _generate_eid12_13(count_per_type, base_time, rng)

    if output_dir is not None:
        _write_corpus(eid1_events, output_dir /
                      "process", "benign_generated.jsonl")
        _write_corpus(eid3_events, output_dir /
                      "network", "benign_generated.jsonl")
        _write_corpus(eid12_13_events, output_dir /
                      "registry", "benign_generated.jsonl")

    return eid1_events + eid3_events + eid12_13_events


def _write_corpus(events: list[LogEvent], subdir: Path, filename: str) -> None:
    subdir.mkdir(parents=True, exist_ok=True)
    out_path = subdir / filename
    with open(out_path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.model_dump_json(exclude_none=True) + "\n")

    debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")
    if debug:
        print(f"[benign_generator] wrote {len(events)} events → {out_path}")
