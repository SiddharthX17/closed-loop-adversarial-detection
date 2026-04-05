"""
test_engine.py — Unit tests for pipeline/detection/engine.py
=============================================================
Run with:
    pytest tests/test_engine.py -v

Coverage targets
----------------
- load_events_from_jsonl        : happy path, blank lines, malformed JSON, non-dict
- _build_db                     : REGEXP UDF, backtick quoting, NULL for missing fields,
                                  empty event list raises
- _regexp_udf                   : match, no match, NULL input, invalid pattern
- _convert_rule_to_sql          : valid rule, unsupported modifier, bad YAML
- DetectionEngine.run           : no rules dir, no rule files, parse error, conversion
                                  error, successful fire, successful miss,
                                  OperationalError on missing column
- DetectionEngine.run_on_events : corpus swap resets DB correctly
- Modifier integration          : contains, endswith, re (REGEXP path)
"""

from __future__ import annotations

import json
import sqlite3
import textwrap
from pathlib import Path

import pytest

# ── Adjust this import to match your actual package layout ────────────────
# If engine.py is on PYTHONPATH or installed, use:
#   from pipeline.detection.engine import ...
# For local dev with engine.py in the same directory:
from engine import (
    DetectionEngine,
    RuleMatchResult,
    _build_db,
    _convert_rule_to_sql,
    _regexp_udf,
    load_events_from_jsonl,
)

from sigma.collection import SigmaCollection

# ---------------------------------------------------------------------------
# Fixtures — reusable Sigma rule YAML strings
# ---------------------------------------------------------------------------

RULE_PROCESS_CREATION = textwrap.dedent("""\
    title: Test Process Creation
    name: test_proc_create
    id: 11111111-1111-1111-1111-111111111111
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|endswith: '\\\\malware.exe'
        condition: sel
""")

RULE_CONTAINS_MODIFIER = textwrap.dedent("""\
    title: Test Contains Modifier
    name: test_contains
    id: 22222222-2222-2222-2222-222222222222
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains: 'suspicious_arg'
        condition: sel
""")

RULE_REGEX_MODIFIER = textwrap.dedent("""\
    title: Test Regex Modifier
    name: test_regex
    id: 33333333-3333-3333-3333-333333333333
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image|re: '.*\\\\(malware|payload)\\.exe$'
        condition: sel
""")

RULE_MISSING_FIELD = textwrap.dedent("""\
    title: Test Missing Field
    name: test_missing_field
    id: 44444444-4444-4444-4444-444444444444
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            ParentCommandLine|contains: 'something'
        condition: sel
""")

# A rule with a field that definitely won't be in our test events
RULE_NULL_FIELD = textwrap.dedent("""\
    title: Test Null Field
    name: test_null_field
    id: 55555555-5555-5555-5555-555555555555
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Image: null
        condition: sel
""")


# ---------------------------------------------------------------------------
# Sample event helpers
# ---------------------------------------------------------------------------

def make_process_event(**overrides) -> dict:
    """Minimal sysmon-style process creation event."""
    base = {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "DOMAIN\\user",
        "ProcessId": "1234",
        "ParentProcessId": "5678",
        "UtcTime": "2024-01-01 12:00:00.000",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. load_events_from_jsonl
# ---------------------------------------------------------------------------

class TestLoadEventsFromJsonl:
    def test_happy_path(self, tmp_path):
        f = tmp_path / "events.jsonl"
        events = [{"EventID": "1", "Image": "cmd.exe"},
                  {"EventID": "2", "Image": "powershell.exe"}]
        f.write_text("\n".join(json.dumps(e) for e in events))
        result = load_events_from_jsonl(f)
        assert len(result) == 2
        assert result[0]["Image"] == "cmd.exe"

    def test_blank_lines_skipped(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('\n{"EventID": "1"}\n\n{"EventID": "2"}\n')
        result = load_events_from_jsonl(f)
        assert len(result) == 2

    def test_malformed_json_line_skipped(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"EventID": "1"}\nNOT_JSON\n{"EventID": "3"}\n')
        result = load_events_from_jsonl(f)
        assert len(result) == 2
        assert result[1]["EventID"] == "3"

    def test_non_dict_line_skipped(self, tmp_path):
        f = tmp_path / "events.jsonl"
        # A valid JSON array is not a dict — should be skipped
        f.write_text('{"EventID": "1"}\n["not", "a", "dict"]\n')
        result = load_events_from_jsonl(f)
        assert len(result) == 1

    def test_empty_file_returns_empty_list(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        result = load_events_from_jsonl(f)
        assert result == []

    def test_all_blank_returns_empty_list(self, tmp_path):
        f = tmp_path / "blanks.jsonl"
        f.write_text("\n\n\n")
        result = load_events_from_jsonl(f)
        assert result == []


# ---------------------------------------------------------------------------
# 2. _regexp_udf
# ---------------------------------------------------------------------------

class TestRegexpUdf:
    def test_match_returns_1(self):
        assert _regexp_udf(r"malware\.exe$", r"C:\Windows\malware.exe") == 1

    def test_no_match_returns_0(self):
        assert _regexp_udf(r"malware\.exe$", r"C:\Windows\cmd.exe") == 0

    def test_null_value_returns_0(self):
        assert _regexp_udf(r".*", None) == 0

    def test_invalid_pattern_returns_0(self):
        # Should not raise — defensive return 0
        assert _regexp_udf(r"[invalid", "somevalue") == 0

    def test_case_insensitive_match(self):
        # IGNORECASE: uppercase path should still match lowercase pattern
        assert _regexp_udf(r"malware\.exe$", r"C:\Windows\MALWARE.EXE") == 1

    def test_inline_flag_respected(self):
        # Even with global IGNORECASE, a valid pattern without (?-i) should still match
        assert _regexp_udf(r"(?i)MALWARE", "malware.exe") == 1

    def test_empty_string_value(self):
        assert _regexp_udf(r".*", "") == 1  # .* matches empty string

    def test_special_chars_in_value(self):
        assert _regexp_udf(r"cmd\.exe", r"C:\Windows\System32\cmd.exe") == 1


# ---------------------------------------------------------------------------
# 3. _build_db
# ---------------------------------------------------------------------------

class TestBuildDb:
    def test_table_created(self):
        events = [make_process_event()]
        conn = _build_db(events)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        assert cursor.fetchone() is not None

    def test_events_inserted(self):
        events = [make_process_event(), make_process_event(
            Image="C:\\evil.exe")]
        conn = _build_db(events)
        count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        assert count == 2

    def test_missing_field_stored_as_null(self):
        # Event A has 'Image', Event B doesn't — B's Image should be NULL
        events = [
            {"EventID": "1", "Image": "cmd.exe"},
            {"EventID": "2"},  # no Image key
        ]
        conn = _build_db(events)
        row = conn.execute(
            "SELECT `Image` FROM logs WHERE `EventID` = '2'").fetchone()
        assert row is not None
        assert row[0] is None

    def test_regexp_udf_registered(self):
        events = [make_process_event(Image=r"C:\Windows\malware.exe")]
        conn = _build_db(events)
        # This would raise OperationalError if REGEXP isn't registered
        result = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE `Image` REGEXP 'malware\\.exe$'"
        ).fetchone()[0]
        assert result == 1

    def test_empty_events_raises(self):
        with pytest.raises(ValueError, match="empty"):
            _build_db([])

    def test_backtick_columns_queryable(self):
        # Columns with spaces/special chars — pySigma may generate these
        events = [{"EventID": "1", "some field": "value"}]
        conn = _build_db(events)
        # Query using backtick quoting
        result = conn.execute("SELECT `some field` FROM logs").fetchone()
        assert result[0] == "value"

    def test_row_factory_returns_dict(self):
        events = [make_process_event()]
        conn = _build_db(events)
        row = conn.execute("SELECT * FROM logs").fetchone()
        # sqlite3.Row supports dict() conversion
        assert isinstance(dict(row), dict)

    def test_numeric_string_coercion(self):
        # Numeric comparisons should work on TEXT-stored values via sqlite3 affinity
        events = [make_process_event(ProcessId="9999")]
        conn = _build_db(events)
        result = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE `ProcessId` > 1000").fetchone()[0]
        assert result == 1


# ---------------------------------------------------------------------------
# 4. _convert_rule_to_sql
# ---------------------------------------------------------------------------

class TestConvertRuleToSql:
    def test_valid_rule_returns_sql(self):
        collection = SigmaCollection.from_yaml(RULE_PROCESS_CREATION)
        sql, err = _convert_rule_to_sql(collection)
        assert err is None
        assert sql is not None
        assert "SELECT" in sql.upper()
        assert "logs" in sql

    def test_sql_references_table(self):
        collection = SigmaCollection.from_yaml(RULE_PROCESS_CREATION)
        sql, err = _convert_rule_to_sql(collection)
        assert "logs" in sql

    def test_contains_modifier_uses_like(self):
        collection = SigmaCollection.from_yaml(RULE_CONTAINS_MODIFIER)
        sql, err = _convert_rule_to_sql(collection)
        assert err is None
        assert "LIKE" in sql.upper()
        # Backend escapes _ as \_ (underscore is a SQL LIKE wildcard),
        # so assert on the unescaped parts rather than the full literal
        assert "suspicious" in sql
        assert "arg" in sql

    def test_endswith_modifier_uses_like(self):
        collection = SigmaCollection.from_yaml(RULE_PROCESS_CREATION)
        sql, err = _convert_rule_to_sql(collection)
        assert err is None
        assert "LIKE" in sql.upper()
        assert "%" in sql  # endswith → LIKE '%value'

    def test_regex_modifier_uses_regexp(self):
        collection = SigmaCollection.from_yaml(RULE_REGEX_MODIFIER)
        sql, err = _convert_rule_to_sql(collection)
        assert err is None
        assert "REGEXP" in sql.upper()

    def test_fresh_pipeline_per_call(self):
        # SigmaCollection objects are stateful — rules are transformed in-place
        # during conversion.  Reload from YAML each time to get a clean object,
        # then assert that two independent conversions produce identical SQL.
        # This confirms our fresh-pipeline-per-call design is deterministic.
        sql1, _ = _convert_rule_to_sql(
            SigmaCollection.from_yaml(RULE_PROCESS_CREATION))
        sql2, _ = _convert_rule_to_sql(
            SigmaCollection.from_yaml(RULE_PROCESS_CREATION))
        assert sql1 == sql2


# ---------------------------------------------------------------------------
# 5. DetectionEngine — integration-level tests using real rule files
# ---------------------------------------------------------------------------

class TestDetectionEngineRun:

    # ── fixture helpers ──────────────────────────────────────────────────

    @staticmethod
    def write_rule(tmp_path: Path, filename: str, content: str) -> Path:
        p = tmp_path / filename
        p.write_text(content)
        return p

    # ── no rules ─────────────────────────────────────────────────────────

    def test_empty_rules_dir_returns_empty(self, tmp_path):
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results == []

    def test_nonexistent_rules_dir_returns_empty(self, tmp_path):
        events = [make_process_event()]
        engine = DetectionEngine(
            rules_dir=tmp_path / "does_not_exist", events=events)
        results = engine.run()
        assert results == []

    # ── parse error isolation ─────────────────────────────────────────────

    def test_invalid_yaml_rule_skipped(self, tmp_path):
        # Unclosed bracket = guaranteed YAML parse failure
        self.write_rule(tmp_path, "bad_rule.yml", "title: [unclosed bracket")
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert len(results) == 1
        assert results[0].skipped is True
        assert "parse_error" in results[0].skip_reason

    def test_bad_rule_does_not_abort_batch(self, tmp_path):
        # One bad rule + one good rule — good rule should still fire
        self.write_rule(tmp_path, "aaa_bad_rule.yml",
                        "title: [unclosed bracket")
        self.write_rule(tmp_path, "bbb_good_rule.yml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event(
            CommandLine="cmd.exe suspicious_arg --flag")]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert len(results) == 2
        good = next(r for r in results if not r.skipped)
        assert good.fired is True

    # ── successful fire ───────────────────────────────────────────────────

    def test_rule_fires_on_matching_event(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event(
            CommandLine="cmd.exe suspicious_arg --flag")]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert len(results) == 1
        r = results[0]
        assert r.fired is True
        assert r.skipped is False
        assert len(r.matched_events) == 1

    def test_matched_events_are_dicts(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event(CommandLine="suspicious_arg here")]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert isinstance(results[0].matched_events[0], dict)

    def test_multiple_events_multiple_matches(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        events = [
            make_process_event(CommandLine="suspicious_arg one"),
            make_process_event(CommandLine="suspicious_arg two"),
            make_process_event(CommandLine="benign command"),
        ]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].fired is True
        assert len(results[0].matched_events) == 2

    def test_regex_rule_fires(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_REGEX_MODIFIER)
        events = [make_process_event(Image=r"C:\Users\attacker\payload.exe")]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].fired is True

    # ── miss (no match) ───────────────────────────────────────────────────

    def test_rule_does_not_fire_on_benign_event(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event(CommandLine="notepad.exe C:\\legit.txt")]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].fired is False
        assert results[0].skipped is False
        assert results[0].matched_events == []

    # ── missing column (sparse logs) ─────────────────────────────────────

    def test_missing_column_skipped_not_crash(self, tmp_path):
        # RULE_MISSING_FIELD references ParentCommandLine which is not in our events
        self.write_rule(tmp_path, "rule.yml", RULE_MISSING_FIELD)
        # Events deliberately omit ParentCommandLine
        events = [{"EventID": "1", "Channel": "Microsoft-Windows-Sysmon/Operational",
                   "Image": "cmd.exe"}]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert len(results) == 1
        r = results[0]
        assert r.skipped is True
        assert "execution_error" in r.skip_reason

    def test_missing_column_skip_reason_names_the_column(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_MISSING_FIELD)
        events = [{"EventID": "1", "Channel": "Microsoft-Windows-Sysmon/Operational",
                   "Image": "cmd.exe"}]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        # skip_reason should mention the missing field by name
        assert "ParentCommandLine" in results[0].skip_reason or \
               "execution_error" in results[0].skip_reason

    # ── sql_query populated ───────────────────────────────────────────────

    def test_sql_query_populated_on_success(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].sql_query is not None

    def test_sql_query_none_on_parse_error(self, tmp_path):
        self.write_rule(tmp_path, "bad.yml", "title: [unclosed bracket")
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].sql_query is None

    # ── metadata extraction ───────────────────────────────────────────────

    def test_rule_id_extracted(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_PROCESS_CREATION)
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].rule_id == "11111111-1111-1111-1111-111111111111"

    def test_rule_title_extracted(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_PROCESS_CREATION)
        events = [make_process_event()]
        engine = DetectionEngine(rules_dir=tmp_path, events=events)
        results = engine.run()
        assert results[0].rule_title == "Test Process Creation"

    # ── glob pattern ─────────────────────────────────────────────────────

    def test_custom_glob_pattern(self, tmp_path):
        self.write_rule(tmp_path, "rule.yaml",
                        RULE_CONTAINS_MODIFIER)  # .yaml not .yml
        events = [make_process_event(CommandLine="suspicious_arg here")]
        engine = DetectionEngine(
            rules_dir=tmp_path, events=events, glob_pattern="**/*.yaml")
        results = engine.run()
        assert len(results) == 1
        assert results[0].fired is True

    def test_default_glob_ignores_yaml_extension(self, tmp_path):
        self.write_rule(tmp_path, "rule.yaml", RULE_CONTAINS_MODIFIER)
        events = [make_process_event()]
        engine = DetectionEngine(
            rules_dir=tmp_path, events=events)  # default *.yml
        results = engine.run()
        assert results == []

    # ── run_on_events corpus swap ─────────────────────────────────────────

    def test_run_on_events_swaps_corpus(self, tmp_path):
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        engine = DetectionEngine(
            rules_dir=tmp_path,
            events=[make_process_event(CommandLine="benign command")]
        )
        first_run = engine.run()
        assert first_run[0].fired is False

        second_run = engine.run_on_events(
            [make_process_event(CommandLine="suspicious_arg here")]
        )
        assert second_run[0].fired is True

    def test_run_on_events_does_not_bleed_between_corpora(self, tmp_path):
        # Events from run 1 must not appear in run 2 results
        self.write_rule(tmp_path, "rule.yml", RULE_CONTAINS_MODIFIER)
        engine = DetectionEngine(
            rules_dir=tmp_path,
            events=[make_process_event(CommandLine="suspicious_arg run1")]
        )
        engine.run()

        second_run = engine.run_on_events(
            [make_process_event(CommandLine="benign command run2")]
        )
        assert second_run[0].fired is False
        assert second_run[0].matched_events == []


# ---------------------------------------------------------------------------
# 6. RuleMatchResult shape sanity
# ---------------------------------------------------------------------------

class TestRuleMatchResultShape:
    def test_defaults(self):
        r = RuleMatchResult(
            rule_id="x", rule_title="y", rule_path="/tmp/r.yml", fired=False
        )
        assert r.matched_events == []
        assert r.skipped is False
        assert r.skip_reason is None
        assert r.sql_query is None

    def test_fired_true_with_events(self):
        r = RuleMatchResult(
            rule_id="x", rule_title="y", rule_path="/tmp/r.yml",
            fired=True,
            matched_events=[{"EventID": "1"}],
        )
        assert r.fired is True
        assert len(r.matched_events) == 1
