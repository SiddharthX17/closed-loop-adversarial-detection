"""
pipeline/validation/rule_normalizer.py

Post-processes LLM-generated Sigma YAML before validation.

Normalizations applied in order:
  1. Backslash normalization — \\\\ → \\ in single-quoted YAML detection values
     (non-regex fields). LLMs trained on Python/JSON habitually double-escape
     backslashes in YAML single-quoted strings where \\ has no special meaning.
     Also strips erroneous leading \\ before Windows registry hive names.

  2. Negative modifier rewrite — |notcontains, |notstartswith, |notendswith
     are not valid Sigma modifiers. Rewrites to filter selection + not in
     condition. Handles single values, multi-value lists, and |all combinations.

  3. re modifier combination fix — |contains|re, |startswith|re, |endswith|re
     are invalid (re modifier only applicable to unmodified values).
     Strips the leading positional modifier, keeping only |re.

  4. Condition reordering — pySigma fails to parse conditions starting with
     'not' (raises: Expected end of text, found 'and' at char 17).
     Reorders so positive selections always precede 'not' clauses.

NOT applied:
  - Missing condition injection — guessing the correct condition is too risky;
    a structurally wrong condition passes the linter but produces bad rules.
    Prefer clean schema_linter failure and retry.
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)
_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Registry hive shorthands — TargetObject values never start with a leading
# backslash; the hive name is the first character.
_HIVE_PREFIXES = (
    "HKCU", "HKLM", "HKU", "HKCC",
    "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE",
    "HKEY_USERS", "HKEY_CURRENT_CONFIG",
)

# Negative modifier → positive equivalent
_NEG_TO_POS = {
    "notcontains":   "contains",
    "notstartswith": "startswith",
    "notendswith":   "endswith",
}

_NEG_MOD_RE = re.compile(
    r"^(\s+)([\w.]+)\|(notcontains|notstartswith|notendswith)(\|all)?(\s*:)(.*)"
)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def normalize_rule_yaml(rule_yaml: str) -> str:
    """
    Apply all normalizations in sequence.
    Returns the original YAML string on any unexpected failure.
    """
    if not rule_yaml or not rule_yaml.strip():
        return rule_yaml
    try:
        rule_yaml = rule_yaml.replace("\r\n", "\n").replace("\r", "\n")
        rule_yaml = _normalize_backslashes(rule_yaml)
        rule_yaml = _rewrite_negative_modifiers(rule_yaml)
        rule_yaml = _fix_re_modifier_combinations(rule_yaml)
        rule_yaml = _reorder_condition(rule_yaml)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "rule_normalizer: normalization failed (%s) — returning original YAML", exc
        )
    return rule_yaml


# ---------------------------------------------------------------------------
# 1. Backslash normalization
# ---------------------------------------------------------------------------

def _fix_value(value: str) -> str:
    """
    Normalize a single YAML string value from a detection block:
    - Replace \\\\ (literal double backslash) with \\ (single backslash)
    - Strip leading \\ if it erroneously precedes a registry hive name
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

    Skips unquoted values — ambiguous to parse reliably line-by-line without
    a full YAML parser. Edge case frequency does not justify the risk.
    """
    lines = rule_yaml.splitlines()
    result = []
    in_detection = False

    for line in lines:
        is_top_level = bool(line and not line[0].isspace() and ":" in line)

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


# ---------------------------------------------------------------------------
# 2. Negative modifier rewrite
# ---------------------------------------------------------------------------

def _detection_bounds(lines: list[str]) -> tuple[int, int]:
    """Return (start, end) line indices of the detection block."""
    start = -1
    for i, line in enumerate(lines):
        if re.match(r"^detection\s*:", line):
            start = i
            break
    if start == -1:
        return -1, -1
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i] and not lines[i][0].isspace():
            end = i
            break
    return start, end


def _rewrite_negative_modifiers(rule_yaml: str) -> str:
    """
    Rewrite |notcontains, |notstartswith, |notendswith to filter selections.

    Example input:
      detection:
        selection:
          Image|endswith: '\\\\cmd.exe'
          CommandLine|notcontains: 'legit_tool'
        condition: selection

    Example output:
      detection:
        selection:
          Image|endswith: '\\\\cmd.exe'
        filter_not_commandline_0:
          CommandLine|contains: 'legit_tool'
        condition: selection and not filter_not_commandline_0
    """
    lines = rule_yaml.splitlines()
    det_start, det_end = _detection_bounds(lines)
    if det_start == -1:
        return rule_yaml

    # --- Collect negative modifier entries -----------------------------------
    entries = []
    i = det_start + 1
    while i < det_end:
        m = _NEG_MOD_RE.match(lines[i])
        if m:
            indent = m.group(1)
            field = m.group(2)
            neg_mod = m.group(3)
            has_all = bool(m.group(4))
            value_part = m.group(6).strip()
            start_li = i
            values: list[str] = []

            if value_part:
                values = [value_part]
                end_li = i + 1
            else:
                # Multi-line list — collect continuation lines
                j = i + 1
                deeper = len(indent) + 2
                while j < det_end:
                    nl = lines[j]
                    if nl and (len(nl) - len(nl.lstrip())) >= deeper:
                        values.append(nl.strip().lstrip("- ").strip())
                        j += 1
                    else:
                        break
                end_li = j

            entries.append({
                "start": start_li, "end": end_li,
                "field": field,
                "pos_mod": _NEG_TO_POS[neg_mod],
                "has_all": has_all,
                "values": values,
                "indent": indent,
            })
            i = end_li
            continue
        i += 1

    if not entries:
        return rule_yaml

    # --- Determine selection-level indentation --------------------------------
    sel_indent = "  "
    for i in range(det_start + 1, det_end):
        line = lines[i]
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            sel_indent = line[: len(line) - len(stripped)]
            break
    fld_indent = sel_indent + "  "

    # --- Build filter selection blocks ----------------------------------------
    remove: set[int] = set()
    for e in entries:
        remove.update(range(e["start"], e["end"]))

    filter_names: list[str] = []
    filter_blocks: list[str] = []

    for idx, e in enumerate(entries):
        fname = f"filter_not_{e['field'].lower()}_{idx}"
        filter_names.append(fname)
        mod = f"|{e['pos_mod']}" + ("|all" if e["has_all"] else "")
        block: list[str] = [f"{sel_indent}{fname}:"]

        if len(e["values"]) == 1:
            block.append(f"{fld_indent}{e['field']}{mod}: {e['values'][0]}")
        else:
            block.append(f"{fld_indent}{e['field']}{mod}:")
            for v in e["values"]:
                block.append(f"{fld_indent}  - {v}")

        filter_blocks.append("\n".join(block))

    # --- Rebuild lines, inserting filter blocks before condition --------------
    result: list[str] = []
    for i, line in enumerate(lines):
        if i in remove:
            continue
        # Insert filter blocks immediately before the condition line
        if det_start < i < det_end and re.match(r"^\s+condition\s*:", line):
            for fb in filter_blocks:
                result.extend(fb.splitlines())
        result.append(line)

    # --- Update condition -----------------------------------------------------
    updated = "\n".join(result)
    not_clause = (
        "not 1 of filter_not_*"
        if len(filter_names) > 1
        else f"not {filter_names[0]}"
    )

    def _add_not(m: re.Match) -> str:
        prefix, cond = m.group(1), m.group(2).strip()
        if "filter_not_" in cond:
            return m.group(0)  # already contains the clause
        return f"{prefix}{cond} and {not_clause}"

    updated = re.sub(
        r"^(\s+condition\s*:\s*)(.+)$",
        _add_not,
        updated,
        flags=re.MULTILINE,
    )

    if _DEBUG:
        logger.debug(
            "rule_normalizer: rewrote %d negative modifier(s): %s",
            len(entries), [e["field"] for e in entries],
        )

    return updated


# ---------------------------------------------------------------------------
# 3. re modifier combination fix
# ---------------------------------------------------------------------------

def _fix_re_modifier_combinations(rule_yaml: str) -> str:
    """
    Fix invalid |contains|re, |startswith|re, |endswith|re combinations.

    pySigma raises: 'Regular expression modifier only applicable to
    unmodified values' when re is combined with a positional modifier.
    Strips the leading modifier, preserving |re.

    Example: field|contains|re: 'pattern' → field|re: 'pattern'
    """
    pattern = re.compile(
        r"(^\s+[\w.]+)\|(contains|startswith|endswith)\|re(\s*:)",
        re.MULTILINE,
    )
    if not pattern.search(rule_yaml):
        return rule_yaml

    fixed = pattern.sub(r"\1|re\3", rule_yaml)
    if _DEBUG:
        logger.debug("rule_normalizer: fixed |re modifier combination(s)")
    return fixed


# ---------------------------------------------------------------------------
# 4. Condition reordering
# ---------------------------------------------------------------------------

def _reorder_condition(rule_yaml: str) -> str:
    """
    Reorder condition so positive selections precede 'not' clauses.

    pySigma condition parser fails with 'Expected end of text, found and'
    when a condition starts with a 'not' expression followed by 'and'.

    Example: 'not 1 of filter_* and all of selection_*'
             → 'all of selection_* and not 1 of filter_*'
    """
    def _fix(m: re.Match) -> str:
        prefix = m.group(1)
        condition = m.group(2).strip()

        if not re.match(r"not[\s(]", condition, re.IGNORECASE):
            return m.group(0)

        parts = re.split(r"\s+and\s+", condition, flags=re.IGNORECASE)
        pos_parts = [p for p in parts if not re.match(
            r"not[\s(]", p.strip(), re.IGNORECASE)]
        neg_parts = [p for p in parts if re.match(
            r"not[\s(]", p.strip(), re.IGNORECASE)]

        if not pos_parts:
            # All-negative condition — cannot safely reorder; leave for linter
            return m.group(0)

        reordered = " and ".join(pos_parts + neg_parts)
        if reordered == condition:
            return m.group(0)

        if _DEBUG:
            logger.debug(
                "rule_normalizer: reordered condition %r → %r",
                condition, reordered,
            )
        return prefix + reordered

    return re.sub(
        r"^(\s+condition\s*:\s*)(.+)$",
        _fix,
        rule_yaml,
        flags=re.MULTILINE,
    )
