import json
import re
import os
import random
import anthropic
from datetime import datetime, timezone
from dotenv import load_dotenv
from pipeline.emulator.log_builder import LogEvent
from pipeline.data.atomic_cleaner import CleanedAtomicTest

load_dotenv()
client = anthropic.Anthropic()

# ─── Canonical schema (RESERVED — not used in current build_log_event flow) ──
# These are kept for future pipeline stages that need normalised field names.
# Do NOT use in LogEvent construction — LogEvent expects Sysmon field names.

SIGMA_TO_CANONICAL = {
    "Image":               "process_name",
    "CommandLine":         "command_line",
    "ParentImage":         "parent_process",
    "TargetObject":        "registry_path",
    "DestinationIp":       "network_destination",
    "DestinationHostname": "network_destination",
}

CANONICAL_EVENT_FIELDS = {
    "process_creation": {"process_name", "command_line", "parent_process"},
    "registry":         {"registry_path"},
    "network":          {"network_destination"},
}

MIN_CANONICAL_FIELDS = {
    "process_creation": {"process_name", "command_line"},
    "registry":         {"registry_path"},
    "network":          {"network_destination"},
}

_LOW_PRIV_USERS = [
    "CORP\\jdoe", "CORP\\asmith", "CORP\\bwilliams",
    "CORP\\cjohnson", "CORP\\dlee", "CORP\\mthompson",
    "CORP\\kpatel", "CORP\\lwang", "CORP\\rgarcia", "CORP\\nhansen",
]

_HOSTNAMES = [
    "WORKSTATION-01", "WORKSTATION-02", "DESKTOP-A7X2",
    "LAPTOP-C9K1", "PC-JDOE", "PC-ASMITH", "DEVBOX-03",
]

_DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

# ─────────────────────────────────────────────────────────────────────────────

# Sysmon-level minimum field requirements — used in build_log_event
# network accepts either DestinationIp OR DestinationHostname
_SYSMON_MIN: dict[str, dict] = {
    "process_creation": {"required_all": {"Image", "CommandLine"}},
    "registry":         {"required_all": {"TargetObject"}},
    "network":          {"required_any": {"DestinationIp", "DestinationHostname"}},
}

# ─── EID 3 structural enrichment ─────────────────────────────────────────────
# Real Sysmon EID 3 events always carry Image and ParentImage — the process
# that opened the socket. The grounding layer correctly drops these from
# network events since they don't appear in procedure_text (which describes
# the connection, not the process). Enrich deterministically post-grounding
# using the test's known executor type.

_EXECUTOR_IMAGE: dict[str, str] = {
    "powershell":       r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmd":              r"C:\Windows\System32\cmd.exe",
    "command_prompt":   r"C:\Windows\System32\cmd.exe",
}

_EXECUTOR_PARENT: dict[str, str] = {
    "powershell":       r"C:\Windows\System32\cmd.exe",
    "cmd":              r"C:\Windows\explorer.exe",
    "command_prompt":   r"C:\Windows\explorer.exe",
}

_EID3_FALLBACK_IMAGE  = r"C:\Windows\System32\cmd.exe"
_EID3_FALLBACK_PARENT = r"C:\Windows\explorer.exe"


def _enrich_network_event(fields: dict, executor_name: str | None) -> dict:
    """
    For EID 3 events, populate Image and ParentImage from the test executor
    if they are absent after grounding.

    This is structural enrichment, not grounding — EID 3 events in real
    Sysmon telemetry always carry the initiating process. The executor IS
    that process for any Atomic test.
    """
    if fields.get("Image") and fields.get("ParentImage"):
        return fields  # already populated, nothing to do

    key = (executor_name or "").lower()
    enriched = dict(fields)

    if not enriched.get("Image"):
        enriched["Image"] = _EXECUTOR_IMAGE.get(key, _EID3_FALLBACK_IMAGE)
    if not enriched.get("ParentImage"):
        enriched["ParentImage"] = _EXECUTOR_PARENT.get(key, _EID3_FALLBACK_PARENT)

    return enriched



# ─── Prompts ──────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a threat intelligence analyst generating synthetic Windows Sysmon log artifacts from ATT&CK procedure implementations.
 
You will receive a structured description of an adversary technique execution including:
- Technique metadata (ID, name, tactic)
- Executor context (process image, elevation level)
- Pre-resolved, discrete commands ready for execution
- Optional evasion hints from the attacker agent
 
STRICT EXTRACTION RULES:
1. Only extract values EXPLICITLY present in the provided commands or evasion hints
2. Do NOT infer, generalise, or fabricate values not derivable from the commands
3. If a field value is not in the commands or evasion hints, omit that field entirely
4. Evasion hints from the attacker agent MAY be used to override command-derived values
5. Set confidence to "low" if commands lack concrete, explicit observables
6. When a command uses calc.exe, notepad.exe, or other obviously benign payloads as Atomic test stand-ins, substitute a more realistic attacker payload that's within the technique context.
 
PRIMARY ACTION RULE:
- Identify the step that represents the PRIMARY MALICIOUS ACTION — the attacker's goal.
- Setup steps, staging steps, file copies, and prerequisite downloads are NOT the primary action.
- If multiple steps exist, prefer the step that a defender would most want to detect.
- Examples:
    Setup (skip): Copy-Item -Path cmd.exe -Destination payload.exe
    Primary (use): Start-Process payload.exe
    Setup (skip): New-Item -ItemType Directory -Path C:\\staging
    Primary (use): Invoke-Mimikatz -DumpCreds
 
NETWORK EVENT RULE:
- When commands involve outbound network connections (Invoke-WebRequest, Invoke-RestMethod,
  System.Net.WebClient, curl, wget, socket connections, UploadString, DownloadString),
  generate a network connection event (EventID 3) with DestinationHostname or DestinationIp.
- Process creation (EID 1) and network connection (EID 3) events can coexist.
- If the procedure involves both execution and network activity, you may generate either
  the process creation OR the network event — choose the one with more detection value.
- For pure exfiltration techniques, prefer the EID 3 network event.
 
SYSMON EVENT TYPES AND VALID FIELD NAMES:
 
process_creation (EventID: 1)
  Required: Image, CommandLine
  Optional: ParentImage, ParentCommandLine, ProcessId, ParentProcessId,
            OriginalFileName, CurrentDirectory
 
registry — value set (EventID: 13) or key create/delete (EventID: 12)
  Required: TargetObject
  Optional: Details
 
network connection (EventID: 3)
  Required: DestinationIp OR DestinationHostname
  Optional: DestinationPort, Protocol, Initiated, SourceIp, DestinationHostname
 
STRICT OUTPUT SCHEMA — follow exactly, no extra keys:
{
  "confidence": "high" | "low",
  "reason": "<brief explanation of what was extracted or why confidence is low>",
  "event_type": "process_creation" | "registry" | "network",
  "EventID": <integer>,
  "fields": {
    "<SysmonFieldName>": "<extracted value>"
  }
}
 
FORBIDDEN TOP-LEVEL KEYS: artifacts, overall_confidence, parameters, indicators, commands, IntegrityLevel
Use Sysmon field names (Image, CommandLine, TargetObject) — NOT canonical names (process_name, command_line).
If extraction is not possible, return confidence "low" and fields as {}.
Respond ONLY with the JSON object. No markdown, no explanation outside the JSON."""

USER_PROMPT_TEMPLATE = """{formatted_input}{evasion_block}

Extract Sysmon log artifacts from the commands above.
Focus on the FIRST command that produces a loggable event if multiple steps are present."""

EVASION_BLOCK = """

Evasion hints from attacker agent (apply only where the commands support it — do not invent values):
{evasion_hints}"""

# Safe fallback returned on any LLM/parse failure — never crashes the pipeline
_FALLBACK_RESULT = {
    "confidence": "low",
    "reason":     "Extraction failed — see interpreter log",
    "event_type": None,
    "EventID":    None,
    "fields":     {},
}


_PARTIAL_MATCH_FIELDS = {"CommandLine", "ParentCommandLine"}
_PARTIAL_MATCH_MIN_TOKENS = 2  # at least 2 tokens must appear

# ─── Counter ──────────────────────────────────────────────────────────────────

_drop_stats = {"unresolved_var": 0, "ungrounded": 0}


def get_drop_stats() -> dict:
    """Return accumulated drop counts since process start."""
    return dict(_drop_stats)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _strip_markdown(raw: str) -> str:
    raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def _normalize(val):
    # Only normalizing strings — other types pass through intentionally
    if isinstance(val, str):
        return val.strip()
    return val


def _resolve_user(elevation_required: bool) -> str:
    """
    Return a realistic user context for the emulated event.
    Elevated tests run as SYSTEM. Non-elevated tests run as a
    random low-privilege domain user.
    """
    if elevation_required:
        return "SYSTEM"
    return random.choice(_LOW_PRIV_USERS)


def _resolve_host() -> str:
    return random.choice(_HOSTNAMES)


def _ground_fields(
    fields: dict,
    procedure_text: str,
    evasion_hints: dict | None = None,
) -> dict:
    """
    Drop fields whose string values are not explicitly present in the procedure text.
    - Verbatim match: full value appears in procedure_text
    - Basename match: for path-like values, basename appears in procedure_text
    - Partial match: for CommandLine fields, at least N tokens appear in procedure_text
    - Evasion hint: attacker agent explicitly provided this field+value — trusted unconditionally
    Non-string values pass through without grounding check.
    """
    grounded = {}
    text = procedure_text.lower()

    for k, v in fields.items():

        if not isinstance(v, str):
            grounded[k] = v
            continue

        v_lower = v.lower()

        # Check 1 — verbatim
        if v_lower in text:
            grounded[k] = v
            continue

        # Check 2 — basename for path-like values
        basename = os.path.basename(v).lower()
        if basename and basename != v_lower and basename in text:
            grounded[k] = v
            continue
        basename_no_ext = os.path.splitext(basename)[0].lower()
        if basename_no_ext and basename_no_ext != v_lower and basename_no_ext in text:
            grounded[k] = v
            continue

        # Check 3 — partial token match for CommandLine fields
        if k in _PARTIAL_MATCH_FIELDS:
            tokens = [
                t for t in v_lower.split()
                if len(t) > 4  # skip short tokens like '-c', 'the'
            ]
            matched = sum(1 for t in tokens if t in text)
            if matched >= _PARTIAL_MATCH_MIN_TOKENS:
                grounded[k] = v
                continue
        # Check 4 — trusted evasion hint from attacker agent
        # Values explicitly injected by the attacker bypass verbatim grounding.
        # LLM-hallucinated values that are neither in procedure_text nor in hints
        # still get dropped.
        if evasion_hints and k in evasion_hints:
            hint_val = evasion_hints[k]
        if evasion_hints and k in evasion_hints:
            hint_val = evasion_hints[k]

            if isinstance(hint_val, str):
                hint_lower = hint_val.lower()
                value_lower = str(v).lower()

                hint_base = os.path.basename(hint_lower)
                value_base = os.path.basename(value_lower)

                if (
                    hint_lower == value_lower or
                    (hint_base and hint_base == value_base)
                ):
                    grounded[k] = v
                    continue

        # OriginalFileName is a PE header field — it cannot appear verbatim
        # in procedure_text because it is embedded in the binary, not in the
        # command that runs it. Pass through unconditionally and let the
        # attack_gate backstop hallucinated values.
        if k == "OriginalFileName":
            grounded[k] = v
            continue

        print(f"[procedure_interpreter] Dropping ungrounded field {k}={v!r}")
        _drop_stats["ungrounded"] += 1

    return grounded


def _validate_minimum_sysmon_fields(event_type: str, fields: dict) -> bool:
    """
    Check that the minimum required Sysmon fields are present for the event type.
    Network accepts either DestinationIp or DestinationHostname.
    Unknown event types pass through (no constraint).
    """
    spec = _SYSMON_MIN.get(event_type)
    if spec is None:
        return True

    keys = set(fields.keys())

    if "required_all" in spec:
        return spec["required_all"].issubset(keys)

    if "required_any" in spec:
        return bool(spec["required_any"] & keys)

    return True


# ─── Canonical helpers (reserved for future pipeline stage) ───────────────────

def _map_to_canonical(fields: dict) -> dict:
    mapped = {}
    for k, v in fields.items():
        canonical = SIGMA_TO_CANONICAL.get(k)
        if canonical:
            if canonical == "network_destination":
                if "network_destination" not in mapped:
                    mapped["network_destination"] = _normalize(v)
            else:
                mapped[canonical] = _normalize(v)
    return mapped


def _enforce_canonical_constraints(event_type: str, fields: dict) -> dict:
    allowed = CANONICAL_EVENT_FIELDS.get(event_type, set())
    return {k: v for k, v in fields.items() if k in allowed}


def _validate_minimum_canonical_fields(event_type: str, fields: dict) -> bool:
    required = MIN_CANONICAL_FIELDS.get(event_type, set())
    return required.issubset(set(fields.keys()))


# ─── Core functions ───────────────────────────────────────────────────────────

def interpret_procedure(
    cleaned_test: CleanedAtomicTest,
    evasion_hints: dict | None = None,
) -> dict:
    """
    Send a CleanedAtomicTest to the LLM and return a structured extraction dict.
    Never raises — returns _FALLBACK_RESULT on any failure.
    """
    evasion_block = ""
    if evasion_hints:
        evasion_block = EVASION_BLOCK.format(
            evasion_hints=json.dumps(evasion_hints, indent=2)
        )

    prompt = USER_PROMPT_TEMPLATE.format(
        formatted_input=cleaned_test.formatted_input,
        evasion_block=evasion_block,
    )

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            temperature=0,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
    except Exception as e:
        print(f"[interpret_procedure] API call failed: {e}")
        return dict(_FALLBACK_RESULT, reason=f"API call failed: {e}")

    # Safely extract text across all content blocks
    raw = ""
    for block in response.content:
        if hasattr(block, "text"):
            raw += block.text
    raw = raw.strip()

    if _DEBUG:
        print("\n[DEBUG] Raw LLM output:")
        print(raw)

    # Strip markdown fences if present
    raw = _strip_markdown(raw)

    # Guard JSON parse
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        print(
            f"[interpret_procedure] JSON parse failed: {e}\nRaw output: {raw}")
        return dict(_FALLBACK_RESULT, reason=f"JSON parse failed: {e}")

    # Validate top-level schema
    if not isinstance(result, dict):
        print("[interpret_procedure] LLM returned non-dict JSON")
        return dict(_FALLBACK_RESULT, reason="LLM returned non-dict JSON")

    if "confidence" not in result:
        print("[interpret_procedure] Missing 'confidence' in LLM response")
        return dict(_FALLBACK_RESULT, reason="Missing confidence key")

    return result


def build_log_event(
    interpretation: dict,
    procedure_text: str,
    timestamp: str = None,
    evasion_hints: dict | None = None,
    elevation_required: bool = False,
    executor_name: str | None = None,
) -> LogEvent | None:
    """
    Build a validated LogEvent from an LLM interpretation dict.

    Pipeline:
      1. Confidence gate
      2. EventID presence check
      3. Ground fields against procedure text (kills hallucinations)
      4. Sysmon minimum field validation
      5. LogEvent construction (Sysmon field names, strict Pydantic)

    Returns None at any failing gate with a logged reason.
    """
    if interpretation.get("confidence") != "high":
        print(
            f"[build_log_event] Dropped: confidence={interpretation.get('confidence')}")
        return None

    if not interpretation.get("EventID"):
        print("[build_log_event] Dropped: missing or null EventID")
        return None

    ts = timestamp or datetime.now(timezone.utc).isoformat()
    event_type = interpretation.get("event_type")
    raw_fields = interpretation.get("fields", {})

    # 1. Ground against procedure text
    grounded_fields = _ground_fields(raw_fields, procedure_text, evasion_hints)
    if not grounded_fields:
        print("[build_log_event] Dropped: no fields survived grounding")
        return None
    
    # 1b. EID 3 structural enrichment — populate Image/ParentImage from executor
    if interpretation.get("EventID") == 3:
        grounded_fields = _enrich_network_event(grounded_fields, executor_name)

    # 2. Sysmon minimum field validation
    if not _validate_minimum_sysmon_fields(event_type, grounded_fields):
        print(
            f"[build_log_event] Dropped: minimum Sysmon fields not met "
            f"for event_type={event_type!r}, fields={set(grounded_fields)}"
        )
        return None

    try:
        return LogEvent(
            timestamp=ts,
            user=_resolve_user(elevation_required),
            host=_resolve_host(),
            EventID=interpretation["EventID"],
            event_type=event_type,
            **grounded_fields,
        )
    except Exception as e:
        print(f"[build_log_event] LogEvent construction failed: {e}")
        return None
