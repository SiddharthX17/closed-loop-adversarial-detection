import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from pipeline.emulator.log_builder import LogEvent


USERS = ["jsmith", "admin", "svc_backup"]
HOSTS = ["WORKSTATION-01", "WORKSTATION-02"]

BASE_PROCESSES = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
]

NETWORK_TARGETS = [
    ("142.250.80.46", "google.com", 443),
    ("151.101.1.140", "reddit.com", 443),
    ("13.107.4.50", "settings-win.data.microsoft.com", 443),
    ("40.119.6.228", "windowsupdate.microsoft.com", 80),
]

REGISTRY_PATHS = [
    "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Common\\General",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
]


def _ts(base, offset):
    return (base + timedelta(seconds=offset)).isoformat()


def _jitter(rng, base=10, spread=120):
    return base + rng.randint(0, spread)


def generate_benign_events(count=50, seed=42):
    rng = random.Random(seed)
    base_time = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)

    events = []
    current_time_offset = 0

    # Maintain active processes
    process_table = {}

    def new_pid():
        return str(rng.randint(1000, 50000))

    # Start with explorer as root process
    root_pid = new_pid()
    process_table[root_pid] = {
        "Image": "C:\\Windows\\Explorer.EXE",
        "ParentProcessId": "0",
        "CommandLine": "C:\\Windows\\Explorer.EXE"
    }

    while len(events) < count:
        current_time_offset += _jitter(rng)

        action = rng.choices(
            ["spawn", "network", "registry"],
            weights=[50, 30, 20]
        )[0]

        user = rng.choice(USERS)
        host = rng.choice(HOSTS)

        # -------------------------
        # PROCESS CREATION
        # -------------------------
        if action == "spawn":
            parent_pid = rng.choice(list(process_table.keys()))
            parent = process_table[parent_pid]

            proc_name, image = rng.choice(BASE_PROCESSES)

            pid = new_pid()

            cmd_variants = {
                "chrome.exe": [
                    f"\"{image}\" --type=renderer",
                    f"\"{image}\" --profile-directory=Default",
                ],
                "WINWORD.EXE": [
                    f"\"{image}\"",
                    f"\"{image}\" C:\\Users\\{user}\\Documents\\report.docx",
                ],
                "notepad.exe": [
                    f"{image} C:\\Users\\{user}\\Documents\\notes.txt"
                ],
            }

            cmd = rng.choice(cmd_variants.get(proc_name, [image]))

            process_table[pid] = {
                "Image": image,
                "ParentProcessId": parent_pid,
                "CommandLine": cmd
            }

            events.append(LogEvent(
                timestamp=_ts(base_time, current_time_offset),
                host=host,
                user=user,
                EventID=1,
                event_type="process_creation",
                Image=image,
                CommandLine=cmd,
                ParentImage=parent["Image"],
                ParentCommandLine=parent.get("CommandLine"),
                ParentProcessId=parent_pid,
                ProcessId=pid
            ))

        # -------------------------
        # NETWORK ACTIVITY
        # -------------------------
        elif action == "network" and process_table:
            pid = rng.choice(list(process_table.keys()))
            proc = process_table[pid]

            ip, hostn, port = rng.choice(NETWORK_TARGETS)

            events.append(LogEvent(
                timestamp=_ts(base_time, current_time_offset),
                host=host,
                user=user,
                EventID=3,
                event_type="network",
                Image=proc["Image"],
                ProcessId=pid,
                SourceIp=f"192.168.1.{rng.randint(2, 254)}",
                DestinationIp=ip,
                DestinationHostname=hostn,
                DestinationPort=port
            ))

        # -------------------------
        # REGISTRY ACTIVITY
        # -------------------------
        elif action == "registry" and process_table:
            pid = rng.choice(list(process_table.keys()))
            proc = process_table[pid]

            path = rng.choice(REGISTRY_PATHS)

            events.append(LogEvent(
                timestamp=_ts(base_time, current_time_offset),
                host=host,
                user=user,
                EventID=rng.choice([12, 13]),
                event_type="registry",
                Image=proc["Image"],
                ProcessId=pid,
                TargetObject=path,
                Details=f"C:\\Users\\{user}\\AppData\\Local"
            ))

    return events


def save_events(events, output_path):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump([e.model_dump() for e in events], f, indent=2)


def save_by_type(events, base_dir="corpus/benign"):
    by_type = {}

    for e in events:
        by_type.setdefault(e.event_type, []).append(e)

    for etype, evs in by_type.items():
        output_path = f"{base_dir}/{etype}/generated.json"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump([e.model_dump() for e in evs], f, indent=2)

        print(f"[benign_generator] Saved {len(evs)} events → {output_path}")


if __name__ == "__main__":
    events = generate_benign_events(count=500, seed=42)
    save_by_type(events)
