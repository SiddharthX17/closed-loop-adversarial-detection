from __future__ import annotations
import pytest
import textwrap

from pipeline.validation.schema_linter import (
    validate,
    ERR_PARSE,
    ERR_INVALID_FIELDS,
    LintResult,
    _extract_fields_from_rule,
)

# ---------------------------------------------------------------------------
# Controlled schema (minimal, stable)
# ---------------------------------------------------------------------------

VALID_FIELDS = {
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "ProcessId",
    "TargetObject",
}

# ---------------------------------------------------------------------------
# Helper to generate VALID Sigma rules (critical fix)
# ---------------------------------------------------------------------------


def make_rule(detection_block: str) -> str:
    return textwrap.dedent(f"""
        title: Test Rule
        logsource:
          product: windows
        detection:
{textwrap.indent(textwrap.dedent(detection_block), "          ")}
    """)


BAD_YAML = "title: [unclosed bracket"


# ---------------------------------------------------------------------------
# 1. _extract_fields_from_rule
# ---------------------------------------------------------------------------

def test_extract_fields_valid():
    rule = make_rule("""
    sel:
      Image|endswith: test.exe
      CommandLine|contains: powershell
    condition: sel
    """)

    fields, err_type, err = _extract_fields_from_rule(rule)

    assert err is None
    assert "Image" in fields
    assert "CommandLine" in fields


def test_extract_fields_keyword_only():
    rule = make_rule("""
    keywords:
      - powershell
    condition: keywords
    """)

    fields, err_type, err = _extract_fields_from_rule(rule)

    assert err is None
    assert fields == set()


def test_extract_fields_parse_error():
    fields, err_type, err = _extract_fields_from_rule(BAD_YAML)

    assert fields == set()
    assert err_type == ERR_PARSE


# ---------------------------------------------------------------------------
# 2. validate — core logic
# ---------------------------------------------------------------------------

def test_valid_rule_passes():
    rule = make_rule("""
    sel:
      Image: cmd.exe
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.passed is True
    assert result.invalid_fields == []


def test_invalid_field_fails():
    rule = make_rule("""
    sel:
      CommandLines: bad
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.passed is False
    assert "CommandLines" in result.invalid_fields
    assert result.error_type == ERR_INVALID_FIELDS


def test_multiple_invalid_fields():
    rule = make_rule("""
    sel:
      CommandLines: bad
      BadField: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert len(result.invalid_fields) == 2


# ---------------------------------------------------------------------------
# 3. Case Sensitivity (fixed behavior)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field, should_pass", [
    ("commandline", True),
    ("COMMANDLINE", True),
    ("CommandLine", True),
    ("Commandline", True),
    ("CommandLines", False),
])
def test_case_sensitivity(field, should_pass):
    rule = make_rule(f"""
    sel:
      {field}: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.passed is should_pass


# ---------------------------------------------------------------------------
# 4. Suggestions
# ---------------------------------------------------------------------------

def test_suggestions_close_match():
    rule = make_rule("""
    sel:
      Imagee: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert "imagee" in result.suggestions
    assert "Image" in result.suggestions["imagee"]


def test_suggestions_none_for_random():
    rule = make_rule("""
    sel:
      xyzzy_random: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.suggestions.get("xyzzy_random") == []


def test_suggestions_cutoff():
    rule = make_rule("""
    sel:
      Cmd: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.suggestions.get("cmd") == []


# ---------------------------------------------------------------------------
# 5. has_fields behavior
# ---------------------------------------------------------------------------

def test_keyword_only_rule():
    rule = make_rule("""
    keywords:
      - powershell
    condition: keywords
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.passed is True
    assert result.has_fields is False


def test_mixed_rule():
    rule = make_rule("""
    sel:
      Image: cmd.exe
    keywords:
      - powershell
    condition: sel or keywords
    """)

    result = validate(rule, VALID_FIELDS)

    assert result.passed is True
    assert result.has_fields is True


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------

def test_parse_error():
    result = validate(BAD_YAML, VALID_FIELDS)

    assert result.passed is False
    assert result.error_type == ERR_PARSE


# ---------------------------------------------------------------------------
# 7. Edge cases
# ---------------------------------------------------------------------------

def test_numeric_value():
    rule = make_rule("""
    sel:
      ProcessId: 1
    condition: sel
    """)

    assert validate(rule, VALID_FIELDS).passed is True


def test_null_value():
    rule = make_rule("""
    sel:
      Image: null
    condition: sel
    """)

    assert validate(rule, VALID_FIELDS).passed is True


def test_modifier_all():
    rule = make_rule("""
    sel:
      CommandLine|contains|all:
        - a
        - b
    condition: sel
    """)

    assert validate(rule, VALID_FIELDS).passed is True


# ---------------------------------------------------------------------------
# 8. Feedback
# ---------------------------------------------------------------------------

def test_feedback_contains_invalid_field():
    rule = make_rule("""
    sel:
      BadField: test
    condition: sel
    """)

    result = validate(rule, VALID_FIELDS)
    fb = result.feedback()

    assert "BadField" in fb


def test_feedback_valid_fields_once():
    rule = make_rule("""
    sel:
      Bad1: test
      Bad2: test
    condition: sel
    """)

    fb = validate(rule, VALID_FIELDS).feedback()

    assert fb.count("Valid fields") <= 1


# ---------------------------------------------------------------------------
# 9. Garbage input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule", ["", "   ", "::::", "null"])
def test_garbage_input(rule):
    result = validate(rule, VALID_FIELDS)

    assert isinstance(result.passed, bool)
