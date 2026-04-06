"""
schema_linter.py — Sigma rule field validator
=============================================
Path: closed-loop-adversarial-detection/pipeline/validation/schema_linter.py

Responsibilities
----------------
- Extract every field name referenced in a candidate Sigma rule's detection
  section (before any pipeline transformation)
- Validate each field against the known fields in LogEvent (log_builder.py)
- Return a structured LintResult: pass/fail, invalid fields, suggestions
- Suggest close matches for invalid fields via difflib

Design notes
------------
- Fields are extracted from pySigma's parsed SigmaDetectionItem.field —
  handles nested conditions, lists, and modifiers without reimplementing
  pySigma's parser
- Extraction happens BEFORE any pipeline — raw Sigma field names as written
- Case-insensitive comparison: "commandline" matches "CommandLine". Suggestions
  return canonical casing from the schema, not the casing from the rule.
- keyword-only rules (field=None) are valid Sigma — they pass lint but
  LintResult.has_fields=False signals the caller that no field validation
  actually occurred
- Error types are explicit string constants defined at module level —
  prevents typo divergence at call sites
- Feedback string is token-efficient: suggestions only per invalid field,
  full valid field list appended once at the end
"""

from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass, field
from typing import Optional

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error type constants
# ---------------------------------------------------------------------------

ERR_PARSE = "parse_error"
ERR_NO_FIELDS = "no_fields_detected"
ERR_INVALID_FIELDS = "invalid_fields"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class LintResult:
    """
    Output of a single rule validation pass.

    passed         : True if every field in the rule exists in the schema
    has_fields     : True if the rule had at least one field-based condition.
                     False for keyword-only rules — lint passed but no field
                     validation occurred. Caller decides how to treat this.
    invalid_fields : field names from rule absent from schema (original casing)
    valid_fields   : full set of known-good fields (canonical casing)
    suggestions    : {lowercased_bad_field: [canonical suggestions]}
    error_type     : ERR_PARSE | ERR_INVALID_FIELDS | None
    error          : detail string when error_type is set
    """
    passed: bool
    has_fields: bool = True
    invalid_fields: list[str] = field(default_factory=list)
    valid_fields: set[str] = field(default_factory=set)
    suggestions: dict[str, list[str]] = field(default_factory=dict)
    error_type: Optional[str] = None
    error: Optional[str] = None

    def feedback(self) -> str:
        """
        Token-efficient feedback string for the defender agent retry prompt.
        Per-field: suggestions only. Full field list appended once at end.
        """
        if self.error:
            return f"Rule could not be validated ({self.error_type}): {self.error}"
        if self.passed and not self.has_fields:
            return (
                "Rule passed lint but contains no field-based conditions "
                "(keyword-only). No field validation performed."
            )
        if self.passed:
            return "All fields valid."

        lines = []
        for bad_field in self.invalid_fields:
            alts = self.suggestions.get(bad_field.lower(), [])
            if alts:
                lines.append(
                    f"Invalid field '{bad_field}' — did you mean: {', '.join(alts)}?"
                )
            else:
                lines.append(
                    f"Invalid field '{bad_field}' — no close matches found."
                )

        # Full list once at the end, not repeated per field
        lines.append(
            f"Valid fields are: {', '.join(sorted(self.valid_fields))}")
        return " | ".join(lines)


# ---------------------------------------------------------------------------
# Schema field extraction
# ---------------------------------------------------------------------------

def get_valid_fields() -> set[str]:
    """Return valid field names from LogEvent (canonical casing)."""
    try:
        from pipeline.emulator.log_builder import LogEvent  # noqa: PLC0415
        return set(LogEvent.model_fields.keys())
    except ImportError:
        try:
            from log_builder import LogEvent  # noqa: PLC0415
            return set(LogEvent.model_fields.keys())
        except ImportError as exc:
            raise ImportError(
                "Cannot import LogEvent from log_builder. "
                "Ensure pipeline/emulator is on sys.path."
            ) from exc


def _make_lower_map(valid_fields: set[str]) -> dict[str, str]:
    """lowercase -> canonical casing map. e.g. 'commandline' -> 'CommandLine'"""
    return {f.lower(): f for f in valid_fields}


# ---------------------------------------------------------------------------
# Field extraction from parsed Sigma rule
# ---------------------------------------------------------------------------

def _extract_fields_from_rule(rule_yaml: str) -> tuple[set[str], Optional[str], Optional[str]]:
    """
    Parse rule and extract field names from detection items.
    Returns (fields, error_type, error_detail).
    keyword-only items (field=None) are skipped — empty set signals keyword-only.
    """
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
    except SigmaError as exc:
        return set(), ERR_PARSE, f"SigmaError: {exc}"
    except Exception as exc:  # noqa: BLE001
        return set(), ERR_PARSE, f"{type(exc).__name__}: {exc}"

    fields: set[str] = set()
    for rule in collection.rules:
        for detection in rule.detection.detections.values():
            for item in detection.detection_items:
                if item.field is not None:
                    fields.add(item.field)

    return fields, None, None


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------

def validate(
    rule_yaml: str,
    valid_fields: Optional[set[str]] = None,
    *,
    suggestion_cutoff: float = 0.7,
    suggestion_max: int = 3,
) -> LintResult:
    """
    Validate all fields in a Sigma rule against a known-good field set.

    Parameters
    ----------
    rule_yaml        : raw Sigma rule YAML string
    valid_fields     : canonical field names. Defaults to LogEvent.model_fields.
    suggestion_cutoff: difflib similarity threshold. Default 0.7.
    suggestion_max   : max suggestions per invalid field.
    """
    if valid_fields is None:
        valid_fields = get_valid_fields()

    lower_map = _make_lower_map(valid_fields)

    rule_fields, error_type, error_detail = _extract_fields_from_rule(
        rule_yaml)
    if error_type:
        logger.warning("Schema linter parse error: %s", error_detail)
        return LintResult(
            passed=False,
            has_fields=False,
            valid_fields=valid_fields,
            error_type=error_type,
            error=error_detail,
        )

    # Keyword-only — no fields to validate
    if not rule_fields:
        logger.debug("Rule has no field-based conditions (keyword-only)")
        return LintResult(passed=True, has_fields=False, valid_fields=valid_fields)

    # Case-insensitive validation, preserve original casing in output
    invalid_original = sorted(
        f for f in rule_fields if f.lower() not in lower_map)

    if not invalid_original:
        logger.debug("Lint passed — all %d field(s) valid", len(rule_fields))
        return LintResult(passed=True, has_fields=True, valid_fields=valid_fields)

    # Suggestions: match lowercased, return canonical
    valid_lower_list = sorted(f.lower() for f in valid_fields)
    suggestions: dict[str, list[str]] = {}
    for bad in invalid_original:
        matches_lower = difflib.get_close_matches(
            bad.lower(),
            valid_lower_list,
            n=suggestion_max,
            cutoff=suggestion_cutoff,
        )
        suggestions[bad.lower()] = [lower_map[m] for m in matches_lower]
        logger.warning(
            "Invalid field '%s'%s", bad,
            f" — did you mean: {suggestions[bad.lower()]}"
            if suggestions[bad.lower()] else " — no close matches",
        )

    return LintResult(
        passed=False,
        has_fields=True,
        invalid_fields=invalid_original,
        valid_fields=valid_fields,
        suggestions=suggestions,
        error_type=ERR_INVALID_FIELDS,
    )


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def lint_rule(rule_yaml: str, valid_fields: Optional[set[str]] = None) -> LintResult:
    """Thin wrapper around validate() with one-line logging."""
    result = validate(rule_yaml, valid_fields)
    if result.error:
        logger.info("LINT ERROR  [%s] — %s", result.error_type, result.error)
    elif result.passed and not result.has_fields:
        logger.info("LINT PASS   (keyword-only, no field validation)")
    elif result.passed:
        logger.info("LINT PASS")
    else:
        logger.info("LINT FAIL   [%s] — invalid: %s",
                    result.error_type, result.invalid_fields)
    return result
