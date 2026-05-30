"""
pipeline/validation/rule_normalizer.py

Post-processes LLM-generated Sigma YAML before validation.

Normalizations:
  1. Backslash normalization — LLMs trained on Python/JSON habitually write \\
     in YAML single-quoted strings where \ has no special meaning. Converts
     \\ → \ in non-regex detection field values. Also strips erroneous leading
     \ before Windows registry hive names (TargetObject values start with the
     hive name itself, not a backslash).

  2. Missing condition injection — LLMs generating complex multi-selection
     rules sometimes omit condition: entirely. Injects a default derived from
     the detection block structure so the linter evaluates rule logic rather
     than failing on structural grounds.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Registry hive names that should never be preceded by a backslash in a
# contains/startswith value — event TargetObject starts with the hive name
# directly, not with a backslash.
_HIVE_PREFIXES = (
    "HKCU", "HKLM", "HKU", "HKCC",
    "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE",
    "HKEY_USERS", "HKEY_CURRENT_CONFIG",
)


def normalize_rule_yaml(rule_yaml: str) -> str:
    """Apply all normalizations. Returns original YAML on failure."""
    if not rule_yaml or not rule_yaml.strip():
        return rule_yaml
    rule_yaml = rule_yaml.replace("\r\n", "\n").replace("\r", "\n")
    rule_yaml = _normalize_backslashes(rule_yaml)
    rule_yaml = _inject_missing_condition(rule_yaml)
    return rule_yaml


# ---------------------------------------------------------------------------
# 1. Backslash normalizer
# ---------------------------------------------------------------------------

def _fix_value(value: str) -> str:
    """
    Normalize a single-quoted YAML string value from a detection block:
      - Replace \\\\ (literal double backslash) with \\ (single backslash)
      - Strip leading \\ if it precedes a known registry hive name
    """
    normalized = value.replace("\\\\", "\\")
    for hive in _HIVE_PREFIXES:
        if normalized.startswith(f"\\{hive}"):
            normalized = normalized[1:]
            break
    return normalized


def _normalize_backslashes(rule_yaml: str) -> str:
    """
    In detection block lines (excluding |re modifier lines), normalize
    double backslashes inside single-quoted string values.
    """
    lines = rule_yaml.splitlines()
    result = []
    in_detection = False

    for line in lines:
        stripped = line.lstrip()
        is_top_level = line and not line[0].isspace() and ":" in line

        if re.match(r"^detection\s*:", line):
            in_detection = True
        elif in_detection and is_top_level:
            in_detection = False

        if in_detection and "|re" not in line and "\\\\" in line:
            line = re.sub(
                r"'([^']*)'",
                lambda m: "'" + _fix_value(m.group(1)) + "'",
                line,
            )

        result.append(line)

    return "\n".join(result)
