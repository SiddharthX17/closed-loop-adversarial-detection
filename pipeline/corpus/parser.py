"""
pipeline/corpus/parser.py

Extracts structured features from Sigma rule YAML for downstream embedding
and clustering. Captures operator structure, not just token soup.

Produces RuleFeatures — the canonical representation passed to the clusterer.

Known limitations (acceptable for clustering use case):
- Logical structure beyond top-level is not preserved. '(A and B) or C' and
  'A and (B or C)' both produce LOGIC:MIXED. Not fatal — LLM receives all
  member rules and disambiguates.
- Negation is not detected from condition expressions. 'selection and not filter'
  does not mark filter conditions as negated=True. Fixing this requires a full
  Sigma condition expression parser — not worth the complexity for clustering.
- Sigma selection group references (all of selection_*, 1 of, keyword-only rules)
  are not resolved. Conditions are extracted from named groups directly.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

import yaml


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class ConditionFeature:
    """A single extracted condition from a Sigma detection block."""
    field_name: str          # e.g. "CommandLine", "Image", "ParentImage"
    operator: str            # contains | startswith | endswith | equals | re | exists
    value: str               # raw value string
    negated: bool = False    # true if preceded by NOT


@dataclass
class RuleFeatures:
    """
    Structured representation of a Sigma rule for embedding and clustering.

    embedding_text is the canonical string passed to sentence-transformers.
    It encodes operator structure explicitly so that:
        CommandLine contains 'downloadstring'
        CommandLine contains 'encodedcommand'
    embed differently from:
        Image equals 'powershell.exe'
        Image startswith 'C:\\Windows\\System32'
    """
    rule_id: str
    title: str
    conditions: list[ConditionFeature]
    target_eids: list[int]
    logic: str                          # AND / OR / MIXED
    embedding_text: str                 # built by _build_embedding_text()
    raw_yaml: str

    # optional provenance
    technique_ids: list[str] = field(default_factory=list)
    # informational/low/medium/high/critical
    level: Optional[str] = None


# ---------------------------------------------------------------------------
# Sigma field extraction helpers
# ---------------------------------------------------------------------------

_OPERATOR_SUFFIXES: dict[str, str] = {
    "contains":       "contains",
    "startswith":     "startswith",
    "endswith":       "endswith",
    "re":             "re",
    "exists":         "exists",
    "contains|all":   "contains_all",
    "startswith|all": "startswith_all",
    "endswith|all":   "endswith_all",
    "base64":         "base64",
    "base64offset":   "base64offset",
    "windash":        "windash",
    "cidr":           "cidr",
    "gt":             "gt",
    "gte":            "gte",
    "lt":             "lt",
    "lte":            "lte",
}


def _parse_field_operator(raw_key: str) -> tuple[str, str]:
    """
    Split 'CommandLine|contains' → ('CommandLine', 'contains').
    Bare key 'Image' → ('Image', 'equals').
    """
    if "|" in raw_key:
        field_name, *modifier_parts = raw_key.split("|")
        modifier = "|".join(modifier_parts).lower()
        operator = _OPERATOR_SUFFIXES.get(modifier, modifier)
    else:
        field_name = raw_key
        operator = "equals"
    return field_name.strip(), operator


def _extract_conditions(detection_block: dict) -> list[ConditionFeature]:
    """
    Walk the Sigma detection block and extract ConditionFeature objects.
    Handles nested lists (OR groups) and dicts (AND groups).
    Skips 'condition' key — that's the logical expression, not a field.
    """
    conditions: list[ConditionFeature] = []

    def _walk(obj: object, negated: bool = False) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key == "condition":
                    continue
                if isinstance(val, dict):
                    _walk(val, negated)
                elif isinstance(val, list):
                    field_name, operator = _parse_field_operator(key)
                    for item in val:
                        if item is None:
                            continue
                        conditions.append(ConditionFeature(
                            field_name=field_name,
                            operator=operator,
                            value=str(item).strip(),
                            negated=negated,
                        ))
                else:
                    if val is None:
                        continue
                    field_name, operator = _parse_field_operator(key)
                    conditions.append(ConditionFeature(
                        field_name=field_name,
                        operator=operator,
                        value=str(val).strip(),
                        negated=negated,
                    ))
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, negated)

    _walk(detection_block)
    return conditions


def _extract_eids(rule_dict: dict) -> list[int]:
    """Pull EventID values from logsource or detection blocks."""
    eids: list[int] = []

    logsource = rule_dict.get("logsource", {})
    if "EventID" in logsource:
        raw = logsource["EventID"]
        eids += [int(raw)] if isinstance(raw, int) else [
            int(x) for x in raw if str(x).isdigit()
        ]

    detection = rule_dict.get("detection", {})
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            for field_key, field_val in val.items():
                if "EventID" in field_key:
                    if isinstance(field_val, list):
                        eids += [int(x) for x in field_val if str(x).isdigit()]
                    elif str(field_val).isdigit():
                        eids.append(int(field_val))

    return sorted(set(eids))


def _infer_logic(detection_block: dict) -> str:
    """
    Best-effort inference of top-level logic from the condition expression.
    Returns 'AND', 'OR', or 'MIXED'.
    """
    condition_expr = detection_block.get("condition", "")
    if not condition_expr:
        return "MIXED"
    expr = str(condition_expr).lower()
    has_and = " and " in expr or expr.startswith("all of")
    has_or = " or " in expr or expr.startswith(
        "1 of") or expr.startswith("any of")
    if has_and and not has_or:
        return "AND"
    if has_or and not has_and:
        return "OR"
    return "MIXED"


def _extract_technique_ids(rule_dict: dict) -> list[str]:
    """
    Pull ATT&CK technique IDs from tags.
    Handles both techniques (T1059) and subtechniques (T1059.001).
    """
    tags = rule_dict.get("tags", []) or []
    result = []
    for tag in tags:
        # Matches attack.t1059 and attack.t1059.001 — captures full ID
        m = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
        if m:
            result.append(m.group(1).upper())
    return result


def _build_embedding_text(
    conditions: list[ConditionFeature],
    eids: list[int],
    logic: str,
) -> str:
    """
    Canonical string for sentence-transformer embedding.

    Format encodes operator structure explicitly:
        EID:1,3 | LOGIC:AND | Image equals powershell.exe | CommandLine contains downloadstring

    This ensures:
    - 'CommandLine contains downloadstring' and 'CommandLine equals downloadstring'
      embed differently (operator is part of the token stream)
    - EID context disambiguates process vs network vs registry rules
    - Logic (AND vs OR) contributes to the embedding
    - Values are lowercased so 'PowerShell' and 'powershell' don't split clusters
    """
    eid_part = f"EID:{','.join(str(e) for e in eids)}" if eids else "EID:unknown"
    logic_part = f"LOGIC:{logic}"

    condition_parts = []
    for c in conditions:
        neg = "NOT " if c.negated else ""
        condition_parts.append(
            f"{neg}{c.field_name} {c.operator} {c.value.lower()}")

    return " | ".join([eid_part, logic_part] + condition_parts)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def parse_rule(rule_yaml: str) -> Optional[RuleFeatures]:
    """
    Parse a Sigma rule YAML string into RuleFeatures.
    Returns None if the YAML is malformed or has no detection block.
    """
    try:
        rule_dict = yaml.safe_load(rule_yaml)
    except yaml.YAMLError:
        return None

    if not isinstance(rule_dict, dict):
        return None

    detection = rule_dict.get("detection")
    if not detection:
        return None

    conditions = _extract_conditions(detection)
    eids = _extract_eids(rule_dict)
    logic = _infer_logic(detection)
    embedding_text = _build_embedding_text(conditions, eids, logic)
    technique_ids = _extract_technique_ids(rule_dict)

    return RuleFeatures(
        rule_id=str(rule_dict.get("id", "unknown")),
        title=str(rule_dict.get("title", "untitled")),
        conditions=conditions,
        target_eids=eids,
        logic=logic,
        embedding_text=embedding_text,
        raw_yaml=rule_yaml,
        technique_ids=technique_ids,
        level=rule_dict.get("level"),
    )


def parse_rules(rule_yamls: list[str]) -> list[RuleFeatures]:
    """
    Parse a batch of Sigma rule YAML strings.
    Drops rules that fail to parse. Logs dropped count and identifiers
    under PIPELINE_DEBUG so cluster drift is diagnosable later.
    """
    _debug = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true", "yes")
    results = []
    dropped_ids: list[str] = []

    for raw in rule_yamls:
        parsed = parse_rule(raw)
        if parsed is not None:
            results.append(parsed)
        else:
            # Best-effort identifier extraction for debug logging
            label = "unparseable"
            try:
                partial = yaml.safe_load(raw)
                if isinstance(partial, dict):
                    label = (
                        partial.get("title")
                        or partial.get("id")
                        or "unknown"
                    )
            except Exception:
                pass
            dropped_ids.append(str(label))

    if dropped_ids and _debug:
        print(
            f"[corpus/parser] Dropped {len(dropped_ids)}/{len(rule_yamls)} rules: "
            f"{dropped_ids}"
        )

    return results
