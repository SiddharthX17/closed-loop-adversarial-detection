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

MODEL = "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

@dataclass
class DetectionStrategy:
    """
    Structured detection strategy produced by the planner.

    key_behaviors:
        What the attacker is accomplishing at the technique level.
        Framed as objectives, not specific commands or binaries.

    relevant_fields:
        Sysmon field names ranked by detection signal stability.
        These are the fields a rule-writer should anchor conditions on.

    detection_invariants:
        Conditions that remain true regardless of tooling variation —
        the non-negotiable core of any rule targeting this technique.
        A rule anchored to these survives binary renames, flag reordering,
        and procedure substitution.

    false_positive_profile:
        Broad categories of legitimate enterprise activity that produce
        similar observables. Written as category labels so the defender
        agent can construct explicit exclusion conditions.

    generalization_notes:
        How to broaden beyond the specific emulated procedure to the
        underlying technique family. Written for a rule-writing engineer.
    """
    key_behaviors: list[str]
    relevant_fields: list[str]
    detection_invariants: list[str]
    false_positive_profile: list[str]
    generalization_notes: str


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

        raw = self._call_llm(PLANNER_SYSTEM_PROMPT, user_message)

        if raw is None:
            return None

        strategy = self._parse_response(technique_id, raw)
        if strategy and DEBUG:
            print(
                f"[detection_planner] {technique_id}: "
                f"{len(strategy.key_behaviors)} behavior(s), "
                f"{len(strategy.detection_invariants)} invariant(s), "
                f"{len(strategy.false_positive_profile)} FP category(ies)"
            )

        return strategy

    # -----------------------------------------------------------------------
    # Private
    # -----------------------------------------------------------------------

    def _call_llm(self, system_prompt: str, user_message: str) -> Optional[str]:
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=1536,
                temperature=0,
                system=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_message}],
            )

            if DEBUG:
                usage = response.usage
                if getattr(usage, "cache_creation_input_tokens", 0):
                    print(
                        f"[detection_planner] Cache WRITE: {usage.cache_creation_input_tokens} tokens")
                if getattr(usage, "cache_read_input_tokens", 0):
                    print(
                        f"[detection_planner] Cache HIT: {usage.cache_read_input_tokens} tokens")

            raw = response.content[0].text.strip()

            # Extract JSON payload defensively
            start = raw.find("{")
            end = raw.rfind("}")

            if start != -1 and end != -1 and end > start:
                raw = raw[start:end + 1]

            return raw

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

        # Validate required fields are present and typed correctly
        required = {
            "key_behaviors": list,
            "relevant_fields": list,
            "detection_invariants": list,
            "false_positive_profile": list,
            "generalization_notes": str,
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

        return DetectionStrategy(
            key_behaviors=data["key_behaviors"],
            relevant_fields=data["relevant_fields"],
            detection_invariants=data["detection_invariants"],
            false_positive_profile=data["false_positive_profile"],
            generalization_notes=data["generalization_notes"],
        )
