"""
1.12 — LLM Smoke Test
Run interpret_procedure on 3 real techniques and inspect output.
Techniques: T1059.001, T1547.001, T1112

Run from repo root:
    python smoke_1_12.py
"""

import json
from pipeline.data.stix_loader import lookup_technique
from pipeline.data.atomic_loader import load_tests_for_technique
from pipeline.data.atomic_cleaner import clean_test
from pipeline.emulator.procedure_interpreter import interpret_procedure

TECHNIQUES = ["T1059.001", "T1547.001", "T1112"]
SEPARATOR = "=" * 72


def run_smoke_test():
    for technique_id in TECHNIQUES:
        print(f"\n{SEPARATOR}")
        print(f"TECHNIQUE: {technique_id}")
        print(SEPARATOR)

        # --- Load metadata and atomic tests ---
        metadata = lookup_technique(technique_id)
        atomic_tests = load_tests_for_technique(technique_id)

        if not atomic_tests:
            print(f"  [SKIP] No atomic tests found for {technique_id}")
            continue

        # Pick first test only — smoke test, not exhaustive
        raw_test = atomic_tests[0]
        print(f"  Test selected : {raw_test.test_name}")
        print(f"  Executor      : {raw_test.executor_name}")

        # --- Clean ---
        cleaned = clean_test(raw_test, metadata)
        if cleaned is None:
            print(f"  [SKIP] clean_test returned None — no commands after cleaning")
            continue

        print(f"  Commands      : {len(cleaned.commands)}")
        print(f"  Unresolved    : {cleaned.has_unresolved_vars}")

        # --- Interpret ---
        print(f"\n  [interpret_procedure] calling LLM...")
        result = interpret_procedure(cleaned)

        # --- Inspect output ---
        print(f"\n  --- RAW RESULT DICT ---")
        print(json.dumps(result, indent=2))

        # Summarise what matters
        confidence     = result.get("confidence", "MISSING")
        reason         = result.get("reason", None)
        extracted      = result.get("fields", {})
        fields_present = [k for k, v in extracted.items() if v not in (None, "")]

        print(f"\n  --- SUMMARY ---")
        print(f"  Confidence    : {confidence}")
        print(f"  Reason        : {reason}")
        print(f"  Fields populated ({len(fields_present)}): {fields_present}")

        if confidence == "low":
            print(f"  *** LOW CONFIDENCE — inspect this one ***")

            print(f"\n{SEPARATOR}")
            print("Smoke test complete.")
            print(SEPARATOR)


if __name__ == "__main__":
    run_smoke_test()