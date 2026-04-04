import yaml
import os
from pprint import pprint

BASE_PATH = "data/atomic-red-team"


def load_atomic_tests(technique_id: str):
    path = f"{BASE_PATH}/{technique_id}/{technique_id}.yaml"

    if not os.path.exists(path):
        print(f"[!] No file for {technique_id}")
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    raw_tests = data.get("atomic_tests", [])
    print(f"\n[+] Raw tests count: {len(raw_tests)}")

    return raw_tests


def filter_and_prepare_tests(raw_tests):
    processed = []

    for i, test in enumerate(raw_tests):
        print(f"\n{'='*60}")
        print(f"[RAW TEST {i+1}]")
        pprint(test)

        platforms = test.get("supported_platforms", [])
        executor = test.get("executor", {})
        command = executor.get("command")

        print("\n--- FILTERING ---")

        if "windows" not in platforms:
            print("❌ Skipped: not Windows")
            continue

        if not command or len(command) < 10:
            print("❌ Skipped: empty/short command")
            continue

        if "#{" in command:
            print("❌ Skipped: contains placeholders")
            continue

        # Normalize command
        normalized = " ".join(command.splitlines()).strip()

        print("✅ PASSED FILTER")
        print(f"Command (normalized): {normalized}")

        # This is EXACTLY what goes to LLM
        llm_input = normalized

        processed.append({
            "name": test.get("name"),
            "description": test.get("description"),
            "command": normalized,
            "llm_input": llm_input
        })

    return processed


def inspect_technique(technique_id: str):
    print(f"\n{'#'*80}")
    print(f"INSPECTING: {technique_id}")
    print(f"{'#'*80}")

    raw_tests = load_atomic_tests(technique_id)

    if not raw_tests:
        return

    processed = filter_and_prepare_tests(raw_tests)

    print(f"\n\n🔥 FINAL LLM INPUTS ({len(processed)}):")
    for i, p in enumerate(processed):
        print(f"\n[{i+1}] {p['name']}")
        print(f"LLM INPUT:\n{p['llm_input']}")


# -------------------------
# 🔥 Run this
# -------------------------
if __name__ == "__main__":
    TEST_TECHNIQUES = ["T1059.001", "T1053.005", "T1547.001"]

    for tid in TEST_TECHNIQUES:
        inspect_technique(tid)
