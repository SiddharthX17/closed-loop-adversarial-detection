"""
scripts/test_selection_dry_run.py

Dry-run test selection across N simulated iterations without making any LLM
calls. Shows which Atomic tests would be sent to the interpreter each
iteration, their complexity scores, seen-test state, and final weighted
priorities. Run this after changing scoring or selection logic to verify
rotation is actually happening.

Usage (from project root):
    python scripts/test_selection_dry_run.py
    python scripts/test_selection_dry_run.py --iterations 5
    python scripts/test_selection_dry_run.py --technique T1059.001 --iterations 4
    python scripts/test_selection_dry_run.py --technique T1059.001 T1053.005

Output per technique per iteration:
  - Full eligible pool: base score | seen? | effective weight | random priority
  - Which tests were selected (marked ✓)
  - Tests dropped below threshold (marked ✗)

Rotation summary at the end shows unique test coverage and selection frequency
across all iterations — the key indicator that the weighted sampling is working.
"""

from pipeline.emulator.emulator import (
    _score_complexity,
    _MAX_CANDIDATES,
    _SEEN_PENALTY,
    _prior_attempts,
    reset_seen_tests,
)
from pipeline.data.atomic_cleaner import clean_test
from pipeline.data.atomic_loader import load_tests_for_technique_with_fallback
from pipeline.data.stix_loader import lookup_technique
import yaml
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))


_CONFIG_PATH = Path("config/techniques.yaml")
_COL_NAME = 46
_COL_NUMS = 7
_COL_BUCKETS = 36 


def _load_technique_ids(path: Path) -> list[str]:
    if not path.exists():
        print(f"[dry-run] techniques.yaml not found at {path}")
        sys.exit(1)
    with open(path) as f:
        data = yaml.safe_load(f)
    ids = [str(t) for t in data.get("techniques", [])]
    if not ids:
        print("[dry-run] No techniques found in techniques.yaml")
        sys.exit(1)
    return ids


def _clean_pool(technique_id: str, metadata) -> tuple[list[tuple[str, object]], int, int]:
    """
    Load and clean all tests for a technique.
    Returns (cleaned_all, skipped_no_clean, skipped_unresolved).
    """
    raw_tests = load_tests_for_technique_with_fallback(technique_id)
    cleaned_all = []
    skipped_no_clean = 0
    skipped_unresolved = 0

    for test in raw_tests:
        cleaned = clean_test(test, metadata)
        if cleaned is None:
            skipped_no_clean += 1
            continue
        if cleaned.has_unresolved_vars:
            skipped_unresolved += 1
            continue
        cleaned_all.append((test.test_guid, cleaned))

    return cleaned_all, skipped_no_clean, skipped_unresolved


def _run_iteration(
    technique_id: str,
    metadata,
    iteration: int,
    cleaned_all: list[tuple[str, object]],
) -> list[str]:
    """
    Simulate one selection pass. Prints the full pool table including which
    scoring buckets fired per test. Returns list of selected test names.
    """
    seen = _prior_attempts.get(technique_id, set())

    # (priority, base_score, weight, guid, name, fired_buckets)
    rows: list[tuple[float, float, float, str, str, list[str]]] = []
    dropped: list[tuple[str, float]] = []

    for guid, cleaned in cleaned_all:
        base, fired = _score_complexity(cleaned)
        if base < 1.0:
            dropped.append((cleaned.test_name, base))
            continue
        weight = base * (_SEEN_PENALTY if guid in seen else 1.0)
        priority = weight * random.uniform(0.35, 1.0)
        rows.append((priority, base, weight, guid, cleaned.test_name, fired))

    rows.sort(reverse=True)
    selected_guids = {guid for _, _, _, guid, _, _ in rows[:_MAX_CANDIDATES]}

    seen_set = _prior_attempts.setdefault(technique_id, set())
    seen_set.update(selected_guids)

    # ── Print pool table ─────────────────────────────────────────────────────
    header = (
        f"  {'Test':<{_COL_NAME}} "
        f"{'Base':>{_COL_NUMS}} "
        f"{'Seen':>{_COL_NUMS}} "
        f"{'Weight':>{_COL_NUMS}} "
        f"{'Pri':>{_COL_NUMS}}  "
        f"{'Buckets':<{_COL_BUCKETS}}  Result"
    )
    divider = "  " + "─" * (len(header) - 2)

    print(f"\n  Iteration {iteration}")
    print(divider)
    print(header)
    print(divider)

    for priority, base, weight, guid, name, fired in rows:
        is_selected = guid in selected_guids
        was_seen_before = guid in (_prior_attempts.get(
            technique_id, set()) - selected_guids)
        seen_marker = "✓" if was_seen_before else ""
        result = "← selected" if is_selected else ""
        bucket_str = f"[{']['.join(fired)}]" if fired else "[base]"
        truncated = name[:_COL_NAME] if len(name) > _COL_NAME else name
        print(
            f"  {truncated:<{_COL_NAME}} "
            f"{base:>{_COL_NUMS}.2f} "
            f"{seen_marker:>{_COL_NUMS}} "
            f"{weight:>{_COL_NUMS}.2f} "
            f"{priority:>{_COL_NUMS}.3f}  "
            f"{bucket_str:<{_COL_BUCKETS}}  {result}"
        )

    for name, base in dropped:
        truncated = name[:_COL_NAME] if len(name) > _COL_NAME else name
        print(
            f"  {truncated:<{_COL_NAME}} "
            f"{base:>{_COL_NUMS}.2f} "
            f"{'':>{_COL_NUMS}} "
            f"{'':>{_COL_NUMS}} "
            f"{'[dropped < 1.0]':>{_COL_NUMS + _COL_BUCKETS + 4}}"
        )

    print(divider)
    selected_names = [name for _, _, _, guid,
                      name, _ in rows if guid in selected_guids]
    print(
        f"  Selected: {', '.join(selected_names) if selected_names else '[none]'}")

    return selected_names


def run_dry_run(technique_ids: list[str], iterations: int) -> None:
    bar = "═" * 72

    print(f"\n{bar}")
    print(f"  TEST SELECTION DRY RUN")
    print(f"  Techniques  : {', '.join(technique_ids)}")
    print(f"  Iterations  : {iterations}")
    print(
        f"  Candidates  : {_MAX_CANDIDATES}   Seen penalty: ×{_SEEN_PENALTY}")
    print(f"{bar}")

    # Pre-clean all techniques once — cleaning is deterministic, no point
    # repeating it every iteration
    pools: dict[str, tuple[list, int, int]] = {}
    metadatas: dict[str, object] = {}

    print("\n  Loading and cleaning test pools...")
    for tid in technique_ids:
        metadata = lookup_technique(tid)
        if metadata is None:
            print(f"  [!] {tid}: not found in STIX bundle — skipping")
            continue
        metadatas[tid] = metadata
        cleaned_all, s_clean, s_unresolved = _clean_pool(tid, metadata)
        pools[tid] = (cleaned_all, s_clean, s_unresolved)
        total_raw = len(load_tests_for_technique_with_fallback(tid))
        print(
            f"  {tid}: {total_raw} raw → {len(cleaned_all)} eligible "
            f"({s_clean} no-clean, {s_unresolved} unresolved)"
        )

    # ── Iteration loop ───────────────────────────────────────────────────────
    history: dict[str, list[list[str]]] = {tid: []
                                           for tid in technique_ids if tid in pools}

    for iteration in range(1, iterations + 1):
        print(f"\n{'─' * 72}")
        print(f"  ITERATION {iteration}")
        print(f"{'─' * 72}")

        for tid in technique_ids:
            if tid not in pools:
                continue
            cleaned_all, _, _ = pools[tid]
            print(f"\n  [{tid}]")

            if not cleaned_all:
                print("  [!] No eligible tests after cleaning")
                history[tid].append([])
                continue

            selected = _run_iteration(
                tid, metadatas[tid], iteration, cleaned_all)
            history[tid].append(selected)

    # ── Rotation summary ─────────────────────────────────────────────────────
    print(f"\n\n{bar}")
    print(f"  ROTATION SUMMARY  ({iterations} iterations)")
    print(f"{bar}")

    for tid in technique_ids:
        if tid not in history:
            continue
        iterations_data = history[tid]
        print(f"\n  {tid}")

        all_selected: list[str] = []
        for i, names in enumerate(iterations_data, 1):
            label = ", ".join(names) if names else "[none]"
            print(f"    iter {i}: {label}")
            all_selected.extend(names)

        unique = sorted(set(all_selected))
        total_eligible = len(pools[tid][0]) if tid in pools else "?"
        print(
            f"\n  Unique tests selected : {len(unique)} / {total_eligible} eligible"
        )
        for name in unique:
            count = all_selected.count(name)
            bar_width = min(count * 4, 20)
            bar_str = "█" * bar_width
            print(f"    {name[:50]:<50}  {count}×  {bar_str}")

    if len(technique_ids) > 1:
        total_unique = sum(
            len(set(sum(history.get(tid, []), []))) for tid in technique_ids if tid in history
        )
        print(f"\n  Total unique tests across all techniques: {total_unique}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run test selection: shows what would be sent to the LLM "
            "across N iterations without calling it."
        )
    )
    parser.add_argument(
        "--technique", "-t",
        nargs="+",
        metavar="TID",
        help="ATT&CK technique ID(s). Defaults to all in config/techniques.yaml.",
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=3,
        help="Number of iterations to simulate (default: 3).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible output (default: none — random each run).",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"[dry-run] Random seed: {args.seed}")

    technique_ids = args.technique or _load_technique_ids(_CONFIG_PATH)

    # Always start from clean state
    reset_seen_tests()
    run_dry_run(technique_ids, args.iterations)


if __name__ == "__main__":
    main()
