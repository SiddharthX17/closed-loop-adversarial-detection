
# Diagnostic script — identifies which techniques are starving due to unresolved vars.

from pipeline.data.stix_loader import get_loader, lookup_technique
from pipeline.data.atomic_cleaner import clean_test
from pipeline.data.atomic_loader import load_tests_for_technique
import sys
import re
import yaml
from pathlib import Path
from collections import defaultdict

# --- path setup ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_technique_ids() -> list[str]:
    config_path = PROJECT_ROOT / "config" / "techniques.yaml"
    with open(config_path) as f:
        data = yaml.safe_load(f)
    return data["techniques"]


def extract_unresolved_vars(commands: list[str]) -> list[str]:
    """Pull #{var_name} patterns still present after cleaning."""
    unresolved = []
    for cmd in commands:
        unresolved.extend(re.findall(r"#\{([^}]+)\}", cmd))
    return list(set(unresolved))


def main():
    stix = get_loader()
    technique_ids = load_technique_ids()

    print(f"\nScanning {len(technique_ids)} techniques...\n")
    print("=" * 70)

    summary = []

    for tid in technique_ids:
        metadata = lookup_technique(tid)

        raw_tests = load_tests_for_technique(tid)
        if not raw_tests:
            summary.append({
                "technique_id": tid,
                "total_tests": 0,
                "clean_pass": 0,
                "unresolved_skipped": 0,
                "no_clean_result": 0,
                "unresolved_vars": [],
                "status": "NO_TESTS",
            })
            continue

        clean_pass = []
        unresolved_skipped = []
        no_result = []
        all_unresolved_vars = []

        for test in raw_tests:
            cleaned = clean_test(test, metadata)

            if cleaned is None:
                no_result.append(test.get("name", "unknown"))
                continue

            if cleaned.has_unresolved_vars:
                vars_found = extract_unresolved_vars(cleaned.commands)
                unresolved_skipped.append(cleaned.test_name)
                all_unresolved_vars.extend(vars_found)
            else:
                clean_pass.append(cleaned.test_name)

        usable = len(clean_pass)
        starving = usable < 2   # threshold from load_tests_for_technique_with_fallback design

        summary.append({
            "technique_id": tid,
            "total_tests": len(raw_tests),
            "clean_pass": usable,
            "unresolved_skipped": len(unresolved_skipped),
            "no_clean_result": len(no_result),
            "unresolved_vars": list(set(all_unresolved_vars)),
            "status": "STARVING" if starving else "OK",
        })

    # --- report ---
    starving = [r for r in summary if r["status"] == "STARVING"]
    ok = [r for r in summary if r["status"] == "OK"]
    no_tests = [r for r in summary if r["status"] == "NO_TESTS"]

    print(f"{'TECHNIQUE':<14} {'STATUS':<10} {'TOTAL':>6} {'PASS':>6} {'UNRES':>6} {'NO_RESULT':>10}  UNRESOLVED VARS")
    print("-" * 90)

    for r in sorted(summary, key=lambda x: x["clean_pass"]):
        vars_str = ", ".join(r["unresolved_vars"][:5])
        if len(r["unresolved_vars"]) > 5:
            vars_str += f"  (+{len(r['unresolved_vars']) - 5} more)"
        print(
            f"{r['technique_id']:<14} "
            f"{r['status']:<10} "
            f"{r['total_tests']:>6} "
            f"{r['clean_pass']:>6} "
            f"{r['unresolved_skipped']:>6} "
            f"{r['no_clean_result']:>10}  "
            f"{vars_str}"
        )

    print("=" * 70)
    print(
        f"\nSummary: {len(ok)} OK  |  {len(starving)} STARVING  |  {len(no_tests)} NO_TESTS")

    if starving:
        print("\nStarving techniques (< 2 usable tests):")
        for r in starving:
            print(
                f"  {r['technique_id']}  —  {r['clean_pass']} usable  |  vars: {r['unresolved_vars']}")

    # --- var frequency across all techniques ---
    var_freq: dict[str, int] = defaultdict(int)
    for r in summary:
        for v in r["unresolved_vars"]:
            var_freq[v] += 1

    if var_freq:
        print("\nMost common unresolved var names (resolver priority targets):")
        for var, count in sorted(var_freq.items(), key=lambda x: -x[1])[:20]:
            print(f"  #{{{var}}}  — appears in {count} technique(s)")

    print()


if __name__ == "__main__":
    main()
