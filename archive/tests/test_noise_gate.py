"""
tests/test_noise_gate.py

Tests for pipeline/validation/noise_gate.py
Run from project root: pytest tests/test_noise_gate.py -v
"""

from pipeline.validation.noise_gate import (
    NoiseGateResult,
    _subdirs_for_attack_sample,
    run,
)
from pipeline.emulator.log_builder import LogEvent
import json
import sys
from pathlib import Path

from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _make_eid1_event(**kwargs) -> LogEvent:
    defaults = dict(
        timestamp="2024-01-01T10:00:00.000Z",
        host="WORKSTATION-01",
        user="jsmith",
        EventID=1,
        event_type="process_creation",
        Channel=SYSMON_CHANNEL,
        Image=r"C:\Windows\System32\notepad.exe",
        CommandLine="notepad.exe notes.txt",
        ParentImage=r"C:\Windows\explorer.exe",
        ParentCommandLine=r"C:\Windows\explorer.exe",
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


def _make_eid3_event(**kwargs) -> LogEvent:
    defaults = dict(
        timestamp="2024-01-01T10:00:00.000Z",
        host="WORKSTATION-01",
        user="jsmith",
        EventID=3,
        event_type="network",
        Channel=SYSMON_CHANNEL,
        Image=r"C:\Windows\System32\svchost.exe",
        DestinationIp="8.8.8.8",
        DestinationPort=443,
        Protocol="tcp",
        Initiated="true",
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


def _make_eid13_event(**kwargs) -> LogEvent:
    defaults = dict(
        timestamp="2024-01-01T10:00:00.000Z",
        host="WORKSTATION-01",
        user="jsmith",
        EventID=13,
        event_type="registry",
        Channel=SYSMON_CHANNEL,
        TargetObject=r"HKCU\Software\Microsoft\Office\16.0\Word\File MRU\Item 1",
    )
    defaults.update(kwargs)
    return LogEvent(**defaults)


# Sigma rule that fires on notepad.exe — should trip a noisy rule test
_NOTEPAD_RULE = """
title: Notepad Execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'notepad.exe'
    condition: selection
"""

# Sigma rule targeting a rare attack-specific binary unlikely in benign corpus
_RARE_BINARY_RULE = """
title: Rare Attack Binary
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'definitely_not_a_real_binary_xyz.exe'
    condition: selection
"""

# Sigma rule targeting specific registry key unlikely in benign corpus
_RARE_REGISTRY_RULE = """
title: Rare Registry Key
status: test
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: 'ATTACK_SPECIFIC_KEY_XYZ_12345'
    condition: selection
"""


def _write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


# ---------------------------------------------------------------------------
# _subdirs_for_attack_sample
# ---------------------------------------------------------------------------

class TestSubdirsForAttackSample:
    def test_eid1_maps_to_process(self):
        sample = [_make_eid1_event()]
        assert _subdirs_for_attack_sample(sample) == {"process"}

    def test_eid3_maps_to_network(self):
        sample = [_make_eid3_event()]
        assert _subdirs_for_attack_sample(sample) == {"network"}

    def test_eid12_maps_to_registry(self):
        e = _make_eid13_event(EventID=12)
        assert _subdirs_for_attack_sample([e]) == {"registry"}

    def test_eid13_maps_to_registry(self):
        sample = [_make_eid13_event()]
        assert _subdirs_for_attack_sample(sample) == {"registry"}

    def test_mixed_eids_returns_union(self):
        sample = [_make_eid1_event(), _make_eid3_event()]
        result = _subdirs_for_attack_sample(sample)
        assert result == {"process", "network"}

    def test_empty_sample_returns_all_subdirs(self):
        result = _subdirs_for_attack_sample([])
        assert result == {"process", "network", "registry"}

    def test_unknown_eid_falls_back_to_all(self):
        e = _make_eid1_event(EventID=999)
        result = _subdirs_for_attack_sample([e])
        assert result == {"process", "network", "registry"}


# ---------------------------------------------------------------------------
# run() — corpus loading
# ---------------------------------------------------------------------------

class TestNoiseGateCorpusLoading:
    def test_empty_corpus_returns_failure(self, tmp_path):
        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is False
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_loads_from_correct_subdir(self, tmp_path):
        # Write benign EID1 events to process/ subdir
        events = [_make_eid1_event().model_dump(exclude_none=True)
                  for _ in range(20)]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.total_events == 20

    def test_does_not_load_wrong_subdir(self, tmp_path):
        # Write events only to network/ — attack sample is EID1
        events = [_make_eid3_event().model_dump(exclude_none=True)
                  for _ in range(10)]
        _write_jsonl(tmp_path / "network" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        # process/ is empty — corpus is empty
        assert result.total_events == 0 or result.error is not None

    def test_loads_multiple_jsonl_files(self, tmp_path):
        for i in range(3):
            events = [_make_eid1_event().model_dump(exclude_none=True)
                      for _ in range(10)]
            _write_jsonl(tmp_path / "process" / f"corpus_{i}.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.total_events == 30

    def test_skips_malformed_jsonl_lines(self, tmp_path):
        p = tmp_path / "process" / "corpus.jsonl"
        p.parent.mkdir(parents=True)
        with open(p, "w") as fh:
            fh.write(json.dumps(_make_eid1_event().model_dump(
                exclude_none=True)) + "\n")
            fh.write("THIS IS NOT JSON\n")
            fh.write(json.dumps(_make_eid1_event().model_dump(
                exclude_none=True)) + "\n")

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.total_events == 2


# ---------------------------------------------------------------------------
# run() — FP rate logic
# ---------------------------------------------------------------------------

class TestNoiseGateFPRate:
    def test_passes_when_rule_fires_on_nothing(self, tmp_path):
        events = [_make_eid1_event().model_dump(exclude_none=True)
                  for _ in range(50)]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is True
        assert result.fp_count == 0
        assert result.fp_rate == 0.0

    def test_fails_when_fp_rate_exceeds_threshold(self, tmp_path):
        # notepad rule will fire on all notepad events
        events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(100)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is False
        assert result.fp_rate > 0.05

    def test_passes_just_below_threshold(self, tmp_path):
        # 1 notepad events out of 200 = 0.5% FP rate — below 1% threshold
        notepad_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(1)
        ]
        other_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\svchost.exe",
                CommandLine="svchost.exe -k netsvcs",
            ).model_dump(exclude_none=True)
            for _ in range(199)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl",
                     notepad_events + other_events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is True
        assert abs(result.fp_rate - 0.005) < 0.001

    def test_fails_just_above_threshold(self, tmp_path):
        # 2 notepad events out of 100 = 2% FP rate — above 1% threshold
        notepad_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(2)
        ]
        other_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\svchost.exe",
                CommandLine="svchost.exe -k netsvcs",
            ).model_dump(exclude_none=True)
            for _ in range(98)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl",
                     notepad_events + other_events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is False

    def test_custom_threshold_respected(self, tmp_path):
        # 8 notepad / 100 = 8% — fails at 5% but passes at 10%
        notepad_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(8)
        ]
        other_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\svchost.exe",
                CommandLine="svchost.exe -k netsvcs",
            ).model_dump(exclude_none=True)
            for _ in range(92)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl",
                     notepad_events + other_events)

        attack_sample = [_make_eid1_event()]

        result_strict = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            fp_threshold=0.05,
            supplement_with_generated=False,
        )
        result_lenient = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            fp_threshold=0.10,
            supplement_with_generated=False,
        )
        assert result_strict.passed is False
        assert result_lenient.passed is True

    def test_registry_rule_uses_registry_corpus(self, tmp_path):
        events = [_make_eid13_event().model_dump(exclude_none=True)
                  for _ in range(30)]
        _write_jsonl(tmp_path / "registry" / "corpus.jsonl", events)

        attack_sample = [_make_eid13_event()]
        result = run(
            rule_yaml=_RARE_REGISTRY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.total_events == 30
        assert result.passed is True


# ---------------------------------------------------------------------------
# run() — result fields
# ---------------------------------------------------------------------------

class TestNoiseGateResultFields:
    def test_fp_events_capped_at_5(self, tmp_path):
        # Rule fires on all 20 events — fp_events should be capped at 5
        events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(20)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert len(result.fp_events) <= 5

    def test_feedback_populated_on_failure(self, tmp_path):
        events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(100)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.feedback is not None
        assert "FP rate" in result.feedback or "fp" in result.feedback.lower()

    def test_feedback_none_on_pass(self, tmp_path):
        events = [_make_eid1_event().model_dump(exclude_none=True)
                  for _ in range(20)]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.passed is True
        assert result.feedback is None

    def test_result_counts_are_consistent(self, tmp_path):
        notepad_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\notepad.exe"
            ).model_dump(exclude_none=True)
            for _ in range(10)
        ]
        other_events = [
            _make_eid1_event(
                Image=r"C:\Windows\System32\svchost.exe",
                CommandLine="svchost.exe -k netsvcs",
            ).model_dump(exclude_none=True)
            for _ in range(90)
        ]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl",
                     notepad_events + other_events)

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_NOTEPAD_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        assert result.total_events == 100
        assert result.fp_count == 10
        assert abs(result.fp_rate - 0.10) < 0.001

    def test_supplement_with_generated_increases_total(self, tmp_path):
        events = [_make_eid1_event().model_dump(exclude_none=True)
                  for _ in range(20)]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        attack_sample = [_make_eid1_event()]

        result_no_gen = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )
        result_with_gen = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=True,
            benign_gen_seed=42,
        )
        assert result_with_gen.total_events > result_no_gen.total_events


class TestNoiseGateEdgeCases:
    @patch("pipeline.validation.noise_gate.DetectionEngine")
    def test_engine_skipped_returns_failure(self, MockEngine, tmp_path):
        # Write some benign events so corpus isn't empty
        events = [_make_eid1_event().model_dump(exclude_none=True)
                  for _ in range(10)]
        _write_jsonl(tmp_path / "process" / "corpus.jsonl", events)

        # Mock engine returns a skipped result
        mock_result = MagicMock()
        mock_result.skipped = True
        mock_result.skip_reason = "unsupported_modifier: base64offset"
        mock_result.fired = False
        mock_result.matched_events = []
        MockEngine.return_value.run_single_rule.return_value = mock_result

        attack_sample = [_make_eid1_event()]
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,
            supplement_with_generated=False,
        )

        assert result.passed is False
        assert result.error is not None
        assert "skipped" in result.error.lower()
        assert result.fp_rate == 0.0
        assert result.total_events == 10  # corpus was loaded before skip

    @patch("pipeline.validation.noise_gate.DetectionEngine")
    def test_generator_filtered_to_matching_eids(self, MockEngine, tmp_path):
        # attack_sample is EID1 only → should only supplement with process events
        mock_result = MagicMock()
        mock_result.skipped = False
        mock_result.fired = False
        mock_result.matched_events = []
        MockEngine.return_value.run_single_rule.return_value = mock_result

        attack_sample = [_make_eid1_event()]  # EID1 only
        result = run(
            rule_yaml=_RARE_BINARY_RULE,
            attack_sample=attack_sample,
            corpus_root=tmp_path,  # empty disk corpus
            supplement_with_generated=True,
            benign_gen_seed=42,
        )

        # benign_generator produces 200 per type (EID1 + EID3 + EID12/13)
        # only EID1 (process) should be included since attack_sample is EID1
        # generator makes 200 EID1 events → total should be 200, not 600
        assert result.total_events == 200
        assert result.passed is True
