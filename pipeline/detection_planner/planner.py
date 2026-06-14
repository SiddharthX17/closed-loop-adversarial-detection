"""
pipeline/detection_planner/planner.py

Detection Planner — pre-analysis stage that runs between the gap scorer
and the defender agent.

Receives:
  - technique_id + MITREMetadata (name, tactic, data_sources, detection_hint)
  - missed_events (up to 5 attack log dicts)

Produces:
  - DetectionStrategy: structured analysis that the defender agent uses to
    write generalised, invariant-anchored Sigma rules rather than rules that
    overfit to the specific emulated procedure.

Wiring:
  Orchestrator stage 4.5 — synchronous call inside the gap loop, after
  _build_gap_context() and before self._defender.run(gap_context).

Failure behaviour:
  Returns None on any LLM or parse failure. The orchestrator assigns
  gap_context.detection_strategy = None and the defender agent falls back
  to its standard (non-enriched) prompt path. This stage is additive, not
  a hard dependency.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import anthropic
from dotenv import load_dotenv

from pipeline.detection_planner.prompts import build_planner_user_message, PLANNER_SYSTEM_PROMPT
from pipeline.data.stix_loader import MITREMetadata

load_dotenv()

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

MODEL = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

@dataclass
class DetectionStrategy:
    """
    Structured detection strategy produced by the planner.

    technique_objective:
        Single sentence. What the attacker is mechanically accomplishing —
        framed as a capability, not a specific tool or command.

    evidence_quality:
        Assessment of the evidence itself before any field analysis.
        unique_event_count: distinct events after content deduplication.
        diversity_note: whether the evidence is genuinely diverse or
        degenerate (identical events dressed as multiple data points).

    evidence_assessment:
        Per-field classification of the attack evidence.
        Each entry: field, value_summary, classification, rationale,
        detection_use.
        classification values: "artifact" | "instance" | "invariant"
        detection_use: direct instruction for the rule writer — ignore,
        detect a named class, or anchor a specific condition.

    detection_opportunities:
        1–3 entries ordered from specific to broad, each justified by
        the evidence quality and assessment above.
        Each entry: description, event_type, anchor_fields, coverage_type,
        fp_risk.
        coverage_type values: "specific" | "adjacent" | "family"
        Only opportunities justified by the evidence are included —
        never padded to three.

    false_positive_profile:
        Legitimate enterprise activity that produces similar observables,
        mapped to specific fields with actionable filter approaches.
        Each entry: category, manifests_via, filter_approach, applies_to.
        applies_to values: "all" | "specific" | "adjacent" | "family"

    rule_design_guidance:
        Concrete implementation recommendation for the included opportunities.
        Names anchor fields, specifies Sigma modifiers, describes condition
        structure. Engineering specification, not general advice.
    """
    technique_objective: str
    evidence_quality: dict
    evidence_assessment: list[dict]
    detection_opportunities: list[dict]
    false_positive_profile: list[dict]
    rule_design_guidance: str


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class DetectionPlanner:

    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    def run(
        self,
        technique_id: str,
        missed_events: list[dict],
        stix_metadata: Optional[MITREMetadata],
    ) -> Optional[DetectionStrategy]:
        """
        Analyse a coverage gap and produce a DetectionStrategy.

        Args:
            technique_id:    ATT&CK technique ID
            missed_events:   Attack log dicts that were not caught (from GapContext)
            stix_metadata:   MITREMetadata from stix_loader (may be None)

        Returns:
            DetectionStrategy on success, None on failure.
            Caller should treat None as graceful degradation — defender runs unassisted.
        """
        if not missed_events:
            if DEBUG:
                print(
                    f"[detection_planner] {technique_id}: no missed events — skipping")
            return None

        # Unpack STIX metadata with safe defaults
        technique_name = technique_id
        tactic = "unknown"
        data_sources: list[str] = []
        detection_hint = ""

        if stix_metadata:
            technique_name = stix_metadata.technique_name
            tactic = stix_metadata.tactic
            data_sources = stix_metadata.data_sources
            detection_hint = getattr(stix_metadata, "detection_hint", "")

        user_message = build_planner_user_message(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            missed_events=missed_events,
            data_sources=data_sources,
            detection_hint=detection_hint,
        )

        strategy = None
        for _attempt in range(2):
            raw = self._call_llm(PLANNER_SYSTEM_PROMPT, user_message)
            if raw is None:
                return None
            strategy = self._parse_response(technique_id, raw)
            if strategy is not None:
                break
            if _attempt == 0:
                if DEBUG:
                    print(f"[detection_planner] {technique_id}: parse failed — retrying once")

        if strategy and DEBUG:
            unique = strategy.evidence_quality.get("unique_event_count", "?")
            print(
                f"[detection_planner] {technique_id}: "
                f"{unique} unique event(s), "
                f"{len(strategy.detection_opportunities)} opportunit(ies) "
                f"[{', '.join(o.get('coverage_type', '?') for o in strategy.detection_opportunities)}], "
                f"{len(strategy.false_positive_profile)} FP categor(ies)"
            )

        return strategy

    # -----------------------------------------------------------------------
    # Private
    # -----------------------------------------------------------------------

    def _call_llm(self, system_prompt: str, user_message: str) -> Optional[str]:
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=4096,
                temperature=0,
                system=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[
                    {"role": "user", "content": user_message},
                    {"role": "assistant", "content": "{"},
                ],
            )

            if DEBUG:
                usage = response.usage
                if getattr(usage, "cache_creation_input_tokens", 0):
                    print(
                        f"[detection_planner] Cache WRITE: {usage.cache_creation_input_tokens} tokens")
                if getattr(usage, "cache_read_input_tokens", 0):
                    print(
                        f"[detection_planner] Cache HIT: {usage.cache_read_input_tokens} tokens")

            # Prefill was "{" — prepend it back before parsing
            raw = "{" + response.content[0].text.strip()
            end = raw.rfind("}")
            if end == -1:
                return None
            return raw[:end + 1]

        except Exception as e:
            if DEBUG:
                print(f"[detection_planner] LLM call failed: {e}")
            return None

    def _parse_response(
        self,
        technique_id: str,
        raw: str,
    ) -> Optional[DetectionStrategy]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            if DEBUG:
                print(
                    f"[detection_planner] {technique_id}: JSON parse failed: {e}\n"
                    f"Raw response:\n{raw[:400]}"
                )
            return None

        # Validate top-level fields — presence and type
        required = {
            "technique_objective": str,
            "evidence_quality": dict,
            "evidence_assessment": list,
            "detection_opportunities": list,
            "false_positive_profile": list,
            "rule_design_guidance": str,
        }

        for field_name, expected_type in required.items():
            val = data.get(field_name)
            if val is None:
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: "
                        f"missing field '{field_name}' — discarding strategy"
                    )
                return None
            if not isinstance(val, expected_type):
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: "
                        f"field '{field_name}' wrong type "
                        f"(expected {expected_type.__name__}) — discarding strategy"
                    )
                return None

        # Validate evidence_quality sub-fields
        eq = data["evidence_quality"]
        if "unique_event_count" not in eq or not isinstance(eq.get("unique_event_count"), int):
            if DEBUG:
                print(
                    f"[detection_planner] {technique_id}: "
                    f"evidence_quality missing 'unique_event_count' int — discarding strategy"
                )
            return None

        # detection_opportunities must be non-empty — no opportunities = no strategy
        if not data["detection_opportunities"]:
            if DEBUG:
                print(
                    f"[detection_planner] {technique_id}: "
                    f"detection_opportunities is empty — discarding strategy"
                )
            return None

        # Validate each opportunity has required sub-fields (warn but don't discard on partial)
        required_opp_keys = {
            "description", "event_type", "anchor_fields", "coverage_type", "fp_risk",
            "observable_invariant", "coverage_gain", "precision_estimate", "viability",
            "selection_reason",
        }
        valid_coverage_types = {"specific", "adjacent", "family"}
        valid_level_values = {"high", "medium", "low"}
        clean_opportunities = []
        for i, opp in enumerate(data["detection_opportunities"]):
            if not isinstance(opp, dict):
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: opportunity[{i}] not a dict — skipping")
                continue
            missing = required_opp_keys - opp.keys()
            if missing:
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: opportunity[{i}] missing keys {missing} — skipping")
                continue
            if opp.get("coverage_type") not in valid_coverage_types:
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: "
                        f"opportunity[{i}] invalid coverage_type '{opp.get('coverage_type')}' — skipping"
                    )
                continue
            if not isinstance(opp.get("anchor_fields"), list):
                if DEBUG:
                    print(
                        f"[detection_planner] {technique_id}: opportunity[{i}] anchor_fields not a list — skipping")
                continue
            for level_field in ("coverage_gain", "precision_estimate", "viability"):
                if opp.get(level_field) not in valid_level_values:
                    if DEBUG:
                        print(
                            f"[detection_planner] {technique_id}: "
                            f"opportunity[{i}] invalid {level_field} '{opp.get(level_field)}' — skipping"
                        )
                    continue
            clean_opportunities.append(opp)

        if not clean_opportunities:
            if DEBUG:
                print(
                    f"[detection_planner] {technique_id}: "
                    f"no valid opportunities after validation — discarding strategy"
                )
            return None

        return DetectionStrategy(
            technique_objective=data["technique_objective"],
            evidence_quality=data["evidence_quality"],
            evidence_assessment=data.get("evidence_assessment", []),
            detection_opportunities=clean_opportunities,
            false_positive_profile=data.get("false_positive_profile", []),
            rule_design_guidance=data["rule_design_guidance"],
        )
