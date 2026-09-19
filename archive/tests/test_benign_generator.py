from pipeline.emulator.log_builder import LogEvent
from pipeline.emulator.benign_generator import (
    _SYSMON_CHANNEL,
    generate_benign_events,
    inject_channel_into_corpus,
)
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# generate_benign_events
# ---------------------------------------------------------------------------


class TestGenerateBenignEvents:
    def test_returns_list_of_log_events(self):
        events = generate_benign_events(
            count_per_type=5, seed=42, output_dir=None)
        assert isinstance(events, list)
        assert all(isinstance(e, LogEvent) for e in events)

    def test_total_count(self):
        # 3 types × count_per_type
        events = generate_benign_events(
            count_per_type=10, seed=42, output_dir=None)
        assert len(events) == 30

    def test_channel_set_on_all_events(self):
        events = generate_benign_events(
            count_per_type=20, seed=42, output_dir=None)
        for e in events:
            assert e.Channel == _SYSMON_CHANNEL, (
                f"Event EventID={e.EventID} missing Channel"
            )

    def test_all_event_types_covered(self):
        events = generate_benign_events(
            count_per_type=10, seed=42, output_dir=None)
        event_ids = {e.EventID for e in events}
        assert 1 in event_ids
        assert 3 in event_ids
        assert {12, 13} & event_ids  # at least one of 12/13

    def test_eid1_minimum_fields(self):
        events = generate_benign_events(
            count_per_type=20, seed=42, output_dir=None)
        eid1 = [e for e in events if e.EventID == 1]
        assert len(eid1) > 0
        for e in eid1:
            assert e.Image, f"EID1 event missing Image"
            assert e.CommandLine, f"EID1 event missing CommandLine"

    def test_eid3_minimum_fields(self):
        events = generate_benign_events(
            count_per_type=20, seed=42, output_dir=None)
        eid3 = [e for e in events if e.EventID == 3]
        assert len(eid3) > 0
        for e in eid3:
            has_dest = bool(e.DestinationIp) or bool(e.DestinationHostname)
            assert has_dest, f"EID3 event missing both DestinationIp and DestinationHostname"

    def test_eid12_13_minimum_fields(self):
        events = generate_benign_events(
            count_per_type=20, seed=42, output_dir=None)
        reg = [e for e in events if e.EventID in (12, 13)]
        assert len(reg) > 0
        for e in reg:
            assert e.TargetObject, f"Registry event missing TargetObject"

    def test_reproducible_with_same_seed(self):
        events_a = generate_benign_events(count_per_type=10, seed=99)
        events_b = generate_benign_events(count_per_type=10, seed=99)
        assert [e.model_dump_json() for e in events_a] == [
            e.model_dump_json() for e in events_b]

    def test_different_seeds_differ(self):
        events_a = generate_benign_events(count_per_type=10, seed=1)
        events_b = generate_benign_events(count_per_type=10, seed=2)
        # Very unlikely to be identical
        dumps_a = [e.model_dump_json() for e in events_a]
        dumps_b = [e.model_dump_json() for e in events_b]
        assert dumps_a != dumps_b

    def test_no_attack_artifacts_in_commandline(self):
        """Spot-check: none of the well-known attack strings appear in benign events."""
        attack_strings = [
            "mimikatz", "invoke-mimikatz", "-enc JAB", "sekurlsa",
            "powerdump", "meterpreter", "-nop -w hidden -c iex",
        ]
        events = generate_benign_events(
            count_per_type=50, seed=42, output_dir=None)
        for e in events:
            cmdline = (e.CommandLine or "").lower()
            for s in attack_strings:
                assert s.lower() not in cmdline, (
                    f"Attack artifact '{s}' found in benign CommandLine: {e.CommandLine}"
                )

    def test_output_dir_none_no_files_written(self, tmp_path):
        generate_benign_events(count_per_type=5, seed=42, output_dir=None)
        assert not any(tmp_path.iterdir())

    def test_output_dir_writes_jsonl(self, tmp_path):
        generate_benign_events(count_per_type=5, seed=42, output_dir=tmp_path)
        assert (tmp_path / "process" / "benign_generated.jsonl").exists()
        assert (tmp_path / "network" / "benign_generated.jsonl").exists()
        assert (tmp_path / "registry" / "benign_generated.jsonl").exists()

    def test_output_jsonl_valid_and_has_channel(self, tmp_path):
        generate_benign_events(count_per_type=5, seed=42, output_dir=tmp_path)
        for subdir in ("process", "network", "registry"):
            p = tmp_path / subdir / "benign_generated.jsonl"
            lines = [l for l in p.read_text().splitlines() if l.strip()]
            assert len(lines) == 5
            for line in lines:
                obj = json.loads(line)
                assert obj.get("Channel") == _SYSMON_CHANNEL


# ---------------------------------------------------------------------------
# inject_channel_into_corpus
# ---------------------------------------------------------------------------

class TestInjectChannelIntoCorpus:
    def test_injects_into_file_missing_channel(self, tmp_path):
        jsonl = tmp_path / "process" / "test.jsonl"
        jsonl.parent.mkdir(parents=True)
        jsonl.write_text(
            '{"EventID": 1, "Image": "notepad.exe", "CommandLine": "notepad.exe"}\n'
            '{"EventID": 1, "Image": "cmd.exe", "CommandLine": "cmd.exe"}\n'
        )
        summary = inject_channel_into_corpus(tmp_path)
        assert summary[str(jsonl)] == 2

        lines = [json.loads(l)
                 for l in jsonl.read_text().splitlines() if l.strip()]
        for obj in lines:
            assert obj["Channel"] == _SYSMON_CHANNEL

    def test_skips_file_already_has_channel(self, tmp_path):
        jsonl = tmp_path / "registry" / "test.jsonl"
        jsonl.parent.mkdir(parents=True)
        jsonl.write_text(
            f'{{"EventID": 13, "TargetObject": "HKCU\\\\key", "Channel": "{_SYSMON_CHANNEL}"}}\n'
        )
        summary = inject_channel_into_corpus(tmp_path)
        assert summary[str(jsonl)] == 0

    def test_partial_injection(self, tmp_path):
        """Some lines have Channel, some don't — only inject where missing."""
        jsonl = tmp_path / "network" / "test.jsonl"
        jsonl.parent.mkdir(parents=True)
        jsonl.write_text(
            f'{{"EventID": 3, "DestinationIp": "1.2.3.4", "Channel": "{_SYSMON_CHANNEL}"}}\n'
            '{"EventID": 3, "DestinationIp": "5.6.7.8"}\n'
        )
        summary = inject_channel_into_corpus(tmp_path)
        assert summary[str(jsonl)] == 1

        lines = [json.loads(l)
                 for l in jsonl.read_text().splitlines() if l.strip()]
        for obj in lines:
            assert obj["Channel"] == _SYSMON_CHANNEL

    def test_handles_empty_corpus_dir(self, tmp_path):
        summary = inject_channel_into_corpus(tmp_path)
        assert summary == {}

    def test_handles_malformed_json_line_gracefully(self, tmp_path):
        jsonl = tmp_path / "process" / "bad.jsonl"
        jsonl.parent.mkdir(parents=True)
        jsonl.write_text(
            '{"EventID": 1, "Image": "notepad.exe"}\n'
            'THIS IS NOT JSON\n'
            '{"EventID": 1, "Image": "cmd.exe"}\n'
        )
        # Should not raise
        summary = inject_channel_into_corpus(tmp_path)
        assert summary[str(jsonl)] == 2
