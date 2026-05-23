import yaml
from pathlib import Path
from dataclasses import dataclass, field
import os

_DEFAULT_ATOMICS_PATH = Path(
    __file__).parents[2] / "data" / "atomic-red-team" / "atomics"

# Executors that require a human to run steps manually — no automatable command
_SKIP_EXECUTORS = {"manual"}

DEBUG = False  # set to True to see verbose loader warnings

_CUSTOM_TESTS_DIR = Path(__file__).parents[2] / "data" / "custom-tests"


@dataclass
class InputArgument:
    name: str
    description: str
    arg_type: str    # path, string, url, integer, float
    default: str     # always stored as str; cast at use time if needed


@dataclass
class AtomicTest:
    technique_id: str
    test_guid: str
    test_name: str
    description: str
    executor_name: str       # powershell, command_prompt, bash, sh
    command: str             # raw, unresolved command string
    elevation_required: bool
    input_arguments: list[InputArgument]
    supported_platforms: list[str]


def _parse_input_arguments(raw) -> list[InputArgument]:
    if not isinstance(raw, dict):
        if raw is not None and DEBUG:
            print(
                f"[atomic_loader] Unexpected input_arguments type {type(raw).__name__} — discarding")
        return []

    args = []
    for name, details in raw.items():
        if not isinstance(details, dict):
            continue
        args.append(InputArgument(
            name=str(name),
            description=str(details.get("description", "")),
            arg_type=str(details.get("type", "string")).lower().strip(),
            default=str(details.get("default", "")),
        ))
    return args


def load_tests_for_technique(
    technique_id: str,
    atomics_path: Path = _DEFAULT_ATOMICS_PATH,
) -> list[AtomicTest]:
    """
    Load and filter atomic tests for a single technique ID.
    Returns empty list if no YAML found or no valid tests pass filters.
    """
    yaml_path = atomics_path / technique_id / f"{technique_id}.yaml"

    if not yaml_path.exists():
        print(f"[atomic_loader] No YAML for {technique_id} at {yaml_path}")
        return []

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"[atomic_loader] YAML parse error for {technique_id}: {e}")
        return []
    except Exception as e:
        print(f"[atomic_loader] Failed to read {yaml_path}: {e}")
        return []

    if not isinstance(data, dict):
        print(f"[atomic_loader] Unexpected YAML structure for {technique_id}")
        return []

    tests = []
    raw_tests = data.get("atomic_tests", [])

    for raw in raw_tests:
        if not isinstance(raw, dict):
            continue

        # Filter: windows only
        platforms = [p.lower() for p in raw.get("supported_platforms", [])]
        if "windows" not in platforms:
            continue

        executor = raw.get("executor", {})
        if not isinstance(executor, dict):
            continue

        executor_name = executor.get("name", "").lower().strip()

        # Filter: skip manual and unknown executors
        if executor_name in _SKIP_EXECUTORS or not executor_name:
            continue

        raw_command = executor.get("command")
        if not isinstance(raw_command, str):
            continue
        command = raw_command.strip()

        # Filter: must have an actual command
        if not command:
            continue

        tests.append(AtomicTest(
            technique_id=technique_id,
            test_guid=str(raw.get("auto_generated_guid", "")),
            test_name=str(raw.get("name", "Unnamed Test")),
            description=str(raw.get("description", "")).strip(),
            executor_name=executor_name,
            command=command,
            elevation_required=bool(executor.get("elevation_required", False)),
            input_arguments=_parse_input_arguments(raw.get("input_arguments")),
            supported_platforms=platforms,
        ))

    return tests


def load_all_tests(
    atomics_path: Path = _DEFAULT_ATOMICS_PATH,
) -> dict[str, list[AtomicTest]]:
    """
    Walk the atomics directory and load all valid Windows tests.
    Returns a dict keyed by technique ID.
    """
    if not atomics_path.exists():
        print(f"[atomic_loader] Atomics path not found: {atomics_path}")
        return {}

    results: dict[str, list[AtomicTest]] = {}
    dirs = sorted(d for d in atomics_path.iterdir()
                  if d.is_dir() and d.name.startswith("T"))

    for tech_dir in dirs:
        technique_id = tech_dir.name
        tests = load_tests_for_technique(technique_id, atomics_path)
        if tests:
            results[technique_id] = tests

    total = sum(len(v) for v in results.values())
    print(
        f"[atomic_loader] Loaded {total} tests across {len(results)} techniques")
    return results


def load_custom_tests_for_technique(technique_id: str) -> list[AtomicTest]:
    """
    Load custom test cases from data/custom-tests/{technique_id}.yaml.
    Returns empty list if no custom file exists.
    Uses same AtomicTest schema as load_tests_for_technique — downstream
    components (cleaner, interpreter) need no changes.
    """
    custom_path = _CUSTOM_TESTS_DIR / f"{technique_id}.yaml"
    if not custom_path.exists():
        return []

    try:
        with open(custom_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(
            f"[atomic_loader] YAML parse error for custom {technique_id}: {e}")
        return []

    if not isinstance(data, dict):
        return []

    tests = []
    for raw in data.get("atomic_tests", []):
        if not isinstance(raw, dict):
            continue

        platforms = [p.lower() for p in raw.get("supported_platforms", [])]
        if "windows" not in platforms:
            continue

        executor = raw.get("executor", {})
        if not isinstance(executor, dict):
            continue

        executor_name = executor.get("name", "").lower().strip()
        if executor_name in _SKIP_EXECUTORS or not executor_name:
            continue

        raw_command = executor.get("command")
        if not isinstance(raw_command, str):
            continue
        command = raw_command.strip()
        if not command:
            continue

        tests.append(AtomicTest(
            technique_id=technique_id,
            test_guid=str(raw.get("auto_generated_guid", "")),
            test_name=str(raw.get("name", "Unnamed Custom Test")),
            description=str(raw.get("description", "")).strip(),
            executor_name=executor_name,
            command=command,
            elevation_required=bool(executor.get("elevation_required", False)),
            input_arguments=_parse_input_arguments(raw.get("input_arguments")),
            supported_platforms=platforms,
        ))

    debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")
    if debug and tests:
        print(
            f"[atomic_loader] Loaded {len(tests)} custom test(s) for {technique_id}")

    return tests


def load_tests_for_technique_with_fallback(
    technique_id: str,
    atomics_path: Path = _DEFAULT_ATOMICS_PATH,
) -> list[AtomicTest]:
    """
    Load Atomic tests for a technique and always append any custom tests
    from data/custom-tests/{technique_id}.yaml.

    Custom tests are included unconditionally when they exist — the old
    threshold gate is removed. Atomic tests are listed first so the
    complexity scorer sees them in natural YAML order; custom tests
    compete on their own merit in the weighted draw.
    """
    atomic_tests = load_tests_for_technique(technique_id, atomics_path)
    custom_tests = load_custom_tests_for_technique(technique_id)

    if custom_tests:
        debug = os.environ.get("PIPELINE_DEBUG", "").lower() in ("1", "true")
        if debug:
            print(
                f"[atomic_loader] {technique_id}: appending {len(custom_tests)} "
                f"custom test(s) to {len(atomic_tests)} Atomic"
            )
        return atomic_tests + custom_tests

    return atomic_tests
