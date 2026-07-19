import re
from dataclasses import dataclass
from pipeline.data.atomic_loader import AtomicTest, InputArgument
from pipeline.data.stix_loader import MITREMetadata

# ─── Executor → Process Image ────────────────────────────────────────────────

EXECUTOR_TO_IMAGE: dict[str, str] = {
    "powershell":     "powershell.exe",
    "command_prompt": "cmd.exe",
    "cmd":            "cmd.exe",
    "bash":           "bash.exe",
    "sh":             "sh",
}

# ─── Known variable defaults ──────────────────────────────────────────────────
# Sorted longest-first at runtime to prevent partial substitutions
# e.g. $env:ProgramFiles(x86) must resolve before $env:ProgramFiles

ATOMIC_VAR_DEFAULTS: dict[str, str] = {
    # PowerShell env vars
    "$env:ProgramFiles(x86)":  "C:\\Program Files (x86)",
    "$env:PSModulePath":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules",
    "$env:LOCALAPPDATA":       "C:\\Users\\USER\\AppData\\Local",
    "$env:COMPUTERNAME":       "WORKSTATION-01",
    "$env:USERPROFILE":        "C:\\Users\\USER",
    "$env:SystemRoot":         "C:\\Windows",
    "$env:ProgramFiles":       "C:\\Program Files",
    "$env:APPDATA":            "C:\\Users\\USER\\AppData\\Roaming",
    "$env:SystemDrive":        "C:",
    "$env:HOMEDRIVE":          "C:",
    "$env:HOMEPATH":           "\\Users\\USER",
    "$env:USERNAME":           "USER",
    "$env:ComSpec":            "C:\\Windows\\System32\\cmd.exe",
    "$env:PUBLIC":             "C:\\Users\\Public",
    "$env:TEMP":               "C:\\Windows\\Temp",
    "$env:TMP":                "C:\\Windows\\Temp",
    "$env:windir":             "C:\\Windows",
    # Atomic-specific
    "$PathToAtomicsFolder":    "C:\\AtomicRedTeam\\atomics",
    # used in default values without $
    "PathToAtomicsFolder":     "C:\\AtomicRedTeam\\atomics",
    # Common PS aliases
    "$home":                   "C:\\Users\\USER",
    "$env:PROCESSOR_ARCHITECTURE": "AMD64",
}

# Patterns that definitively indicate an unresolved variable after substitution
_UNRESOLVED_ATOMIC = re.compile(r'#\{[^}]+\}')
_UNRESOLVED_ENV = re.compile(r'\$env:[A-Za-z_][A-Za-z0-9_()]*')

# PS built-in variables that look like $vars but are not user-defined
_PS_BUILTINS = {
    '$true', '$false', '$null', '$_', '$?', '$$', '$^', '$!',
    '$args', '$input', '$this', '$error', '$foreach', '$switch',
    '$myinvocation', '$pscmdlet', '$psboundparameters',
}


# ─── Output dataclass ─────────────────────────────────────────────────────────

@dataclass
class CleanedAtomicTest:
    technique_id:        str
    technique_name:      str
    tactic:              str
    tactics:             list[str]
    data_sources:        list[str]
    permissions_required: list[str]
    test_name:           str
    executor_image:      str
    elevation_required:  bool
    commands:            list[str]
    # preserved for mutation manifest
    input_arguments:     list[InputArgument]
    formatted_input:     str                   # what plugs into procedure_text
    has_unresolved_vars: bool                  # flagged, not dropped


# ─── Resolution helpers ───────────────────────────────────────────────────────

def _resolve_input_arguments(command: str, input_args: list[InputArgument]) -> str:
    """
    Replace #{arg_name} placeholders with their defaults.
    e.g. #{file_path} → C:\\Users\\USER\\payload.exe
    """
    for arg in input_args:
        placeholder = f"#{{{arg.name}}}"
        if placeholder in command:
            command = command.replace(placeholder, arg.default)
    return command


def _resolve_env_vars(command: str) -> str:
    """
    Replace $env:VAR, $PathToAtomicsFolder, $home etc. with known defaults.
    Sorted longest-first to avoid partial substitutions.
    """
    for var, val in sorted(ATOMIC_VAR_DEFAULTS.items(), key=lambda x: -len(x[0])):
        # Case-insensitive replace for $env: variants
        if var.lower().startswith("$env:"):
            command = re.sub(re.escape(var), lambda m: val,
                             command, flags=re.IGNORECASE)
        else:
            command = command.replace(var, val)
    return command

# ─── Line joining ─────────────────────────────────────────────────────────────


def _join_continuations(lines: list[str], continuation_char: str) -> list[str]:
    """
    Join lines ending with a continuation character.
    PowerShell uses backtick (`), cmd.exe uses caret (^).
    """
    result = []
    buffer = ""

    for line in lines:
        rstripped = line.rstrip()
        if rstripped.endswith(continuation_char):
            # Strip the continuation char and accumulate
            buffer += rstripped[:-len(continuation_char)].rstrip() + " "
        else:
            buffer += rstripped
            if buffer.strip():
                result.append(buffer.strip())
            buffer = ""

    if buffer.strip():
        result.append(buffer.strip())

    return result


# ─── Command splitting ────────────────────────────────────────────────────────

def _split_on_semicolons(command: str) -> list[str]:
    """
    Split a PowerShell command on ; but not inside single or double quotes.
    Simple state-machine — handles the common case without a full PS parser.
    """
    parts: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False

    for char in command:
        if char == "'" and not in_double:
            in_single = not in_single
            current.append(char)
        elif char == '"' and not in_single:
            in_double = not in_double
            current.append(char)
        elif char == ';' and not in_single and not in_double:
            part = ''.join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)

    last = ''.join(current).strip()
    if last:
        parts.append(last)

    return parts if parts else [command]


def _split_on_cmd_operators(command: str) -> list[str]:
    """
    Split a cmd.exe command on &&, ||, &, and | — but not inside double-quoted
    strings. cmd.exe has no semicolon-style separator; these operators are
    how it chains what are, in real process-creation telemetry, separate
    child processes (each &&-joined command is its own process, sharing the
    same parent). Without this, a chained command like
    'bitsadmin /create X && bitsadmin /addfile X && bitsadmin /resume X'
    is treated as one process's own CommandLine, which is not possible —
    bitsadmin (like most CLI tools) takes one verb per invocation.

    cmd.exe only treats double quotes as string delimiters at the shell-
    parsing level (unlike PowerShell, which respects both single and
    double) — single quotes are literal characters to cmd.exe itself.
    """
    parts: list[str] = []
    current: list[str] = []
    in_double = False
    i = 0
    n = len(command)

    while i < n:
        char = command[i]

        if char == '"':
            in_double = not in_double
            current.append(char)
            i += 1
            continue

        if not in_double:
            if command[i:i + 2] == '&&':
                part = ''.join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 2
                continue
            if command[i:i + 2] == '||':
                part = ''.join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 2
                continue
            if char in ('&', '|'):
                part = ''.join(current).strip()
                if part:
                    parts.append(part)
                current = []
                i += 1
                continue

        current.append(char)
        i += 1

    last = ''.join(current).strip()
    if last:
        parts.append(last)

    return parts if parts else [command]


def _split_commands(raw_command: str, executor_name: str) -> list[str]:
    """
    Split a multi-line/multi-command string into a list of discrete commands.
    Handles:
      - PowerShell: backtick continuation, semicolons, comment lines (#)
      - cmd.exe: caret continuation, &&/||/&/| chain operators, REM comment lines
      - Others: newline split only
    """
    lines = raw_command.split('\n')
    commands: list[str] = []

    if executor_name == "powershell":
        lines = _join_continuations(lines, '`')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            sub = _split_on_semicolons(line)
            commands.extend(sub)

    elif executor_name in ("command_prompt", "cmd"):
        lines = _join_continuations(lines, '^')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Skip REM comments (case-insensitive)
            if re.match(r'^[Rr][Ee][Mm]\s', line) or line.upper() == 'REM':
                continue
            sub = _split_on_cmd_operators(line)
            commands.extend(sub)

    else:
        # bash / sh / unknown — newline split only
        commands = [l.strip() for l in lines if l.strip()]

    return [c for c in commands if c]


# ─── Unresolved variable detection ───────────────────────────────────────────

def _has_unresolved_vars(commands: list[str]) -> bool:
    """
    Check if any command still contains unresolved variable patterns after substitution.
    Checks for #{...} (Atomic style) and $env:VAR (PS env var style).
    Does NOT flag PS built-ins like $true, $null etc.
    """

    for cmd in commands:
        if _UNRESOLVED_ATOMIC.search(cmd):
            return True
        if _UNRESOLVED_ENV.search(cmd):
            return True
    return False


# ─── Formatted input builder ──────────────────────────────────────────────────

def _build_formatted_input(
    test: AtomicTest,
    metadata: MITREMetadata,
    executor_image: str,
    commands: list[str],
) -> str:
    """
    Build the structured plaintext block that goes to the LLM as procedure_text.
    """
    lines = [
        f"Test: {test.test_name}",
        f"Technique: {metadata.technique_id} — {metadata.technique_name}",
        f"Tactic: {metadata.tactic}",
        f"Executor: {executor_image}",
        f"Elevation Required: {'Yes' if test.elevation_required else 'No'}",
    ]

    if metadata.data_sources:
        # Cap at 3 to keep prompt tight
        lines.append(f"Data Sources: {', '.join(metadata.data_sources[:3])}")

    if metadata.permissions_required:
        lines.append(
            f"Permissions Required: {', '.join(metadata.permissions_required)}")

    lines.append("")
    lines.append("Commands:")
    for i, cmd in enumerate(commands, 1):
        lines.append(f"  Step {i}: {cmd}")

    if test.input_arguments:
        lines.append("")
        lines.append(
            "Input Variables "
            "(LLM may substitute realistic alternatives of matching type — "
            "do not invent values outside the stated type):"
        )
        for arg in test.input_arguments:
            lines.append(
                f"  - {arg.name} (type: {arg.arg_type}, default: {arg.default})"
            )

    return '\n'.join(lines)


# ─── Public API ───────────────────────────────────────────────────────────────

def clean_test(
    test: AtomicTest,
    metadata: MITREMetadata,
) -> CleanedAtomicTest | None:
    """
    Full cleaning pipeline for a single AtomicTest.

    Steps:
      1. Resolve #{input_argument} placeholders
      2. Resolve $env:VAR / $PathToAtomicsFolder / $home etc.
      3. Join continuation lines (backtick/caret)
      4. Split into discrete commands (newline + semicolons for PS)
      5. Flag unresolved vars (not dropped — LLM handles ambiguous human-input cases)
      6. Build structured formatted_input string

    Returns None only if no commands remain after cleaning.
    """
    executor_name = test.executor_name
    executor_image = EXECUTOR_TO_IMAGE.get(executor_name, executor_name)

    # Step 1 — #{arg} resolution
    command = _resolve_input_arguments(test.command, test.input_arguments)

    # Step 2 — $env:VAR / known alias resolution
    command = _resolve_env_vars(command)

    # Step 3 + 4 — join continuations, split to discrete commands
    commands = _split_commands(command, executor_name)

    if not commands:
        print(f"[atomic_cleaner] No commands after cleaning: {test.test_name}")
        return None

    # Step 5 — flag unresolved vars
    has_unresolved = _has_unresolved_vars(commands)
    if has_unresolved:
        print(
            f"[atomic_cleaner] Unresolved vars remain in '{test.test_name}' "
            f"— passing to LLM for interpretation"
        )

    # Step 6 — build structured LLM input
    formatted = _build_formatted_input(
        test, metadata, executor_image, commands)

    return CleanedAtomicTest(
        technique_id=metadata.technique_id,
        technique_name=metadata.technique_name,
        tactic=metadata.tactic,
        tactics=metadata.tactics,
        data_sources=metadata.data_sources,
        permissions_required=metadata.permissions_required,
        test_name=test.test_name,
        executor_image=executor_image,
        elevation_required=test.elevation_required,
        commands=commands,
        input_arguments=test.input_arguments,
        formatted_input=formatted,
        has_unresolved_vars=has_unresolved,
    )


def clean_all_tests(
    tests: list[AtomicTest],
    metadata: MITREMetadata,
) -> list[CleanedAtomicTest]:
    """Clean a list of AtomicTests against their technique metadata."""
    cleaned = []
    for test in tests:
        result = clean_test(test, metadata)
        if result is not None:
            cleaned.append(result)
    print(
        f"[atomic_cleaner] {len(cleaned)}/{len(tests)} tests cleaned "
        f"for {metadata.technique_id}"
    )
    return cleaned
