"""
3.16 + 3.17 — wire and test the full adversarial loop.

Runs the full pipeline for 2 iterations and verifies:
  - All stages executed without contract mismatches
  - Events generated per technique
  - Detection layer produced results
  - Defender agent attempted gap closure
  - Iteration 2 attacker plan captured for 3.18 mutation verification

Set OPEN_PRS=0 to skip PR creation during loop testing.

Usage (from project root):
    $env:PIPELINE_DEBUG="1"
    $env:OPEN_PRS="0"
    python -m scripts.run_full_loop
"""

from pipeline.data.stix_loader import get_loader
from pipeline.detection.result_parser import parse_results
from pipeline.detection.engine import DetectionEngine
from pipeline.emulator.emulator import run_emulator
from pipeline.attacker.agent import AttackerAgent, extract_emulator_inputs, CampaignPlan
from pipeline.orchestrator import Orchestrator, OrchestrationResult
from pipeline.corpus.learner import run as run_corpus_learner
from pipeline.corpus.pusher import update_outcome
from pipeline.detection_planner.planner import DetectionPlanner
from pipeline.emulator.test_history import mark_rule_generated

import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import anthropic

sys.path.insert(0, str(Path(__file__).parents[1]))


OPEN_PRS = os.getenv("OPEN_PRS", "0").lower() in ("1", "true")
ITERATIONS = 2
RULES_DIR = Path("rules")
CORPUS_ROOT = Path("corpus/benign")
OUTPUT_DIR = None  # suppress file writes during loop test


# ---------------------------------------------------------------------------
# Extended result type that captures plans per iteration for 3.18
# ---------------------------------------------------------------------------

@dataclass
class LoopTestResult:
    orchestration_result: OrchestrationResult
    plans_per_iteration: dict[int, CampaignPlan] = field(default_factory=dict)
    detection_results_per_iteration: dict[int, dict] = field(
        default_factory=dict)
    events_per_iteration: dict[int, dict] = field(default_factory=dict)


def run_instrumented_loop(
    technique_ids: list[str],
    iterations: int = 2,
) -> LoopTestResult:
    """
    Run the full loop with instrumentation to capture per-iteration state.
    Mirrors Orchestrator._run_iteration but surfaces intermediate state
    for contract verification and 3.18 mutation check.
    """
    from pipeline.orchestrator import (
        _load_technique_ids, _flatten_log_stream, _build_detection_results,
        _build_gap_context, IterationSummary, OrchestrationResult,
    )
    from pipeline.defender.agent import DefenderAgent
    from pipeline.github.pr_creator import PRCreator
    from pipeline.metrics.tracker import MetricsTracker
    from pipeline.embedding.scorer import EmbeddingScorer
    from pipeline.embedding.embedder import EMBEDDINGS_PATH
    from pipeline.embedding.gap_scorer import score_gaps

    stix = get_loader()
    attacker = AttackerAgent()
    defender = DefenderAgent(corpus_root=CORPUS_ROOT)
    metrics = MetricsTracker()

    scorer = None
    if EMBEDDINGS_PATH.exists():
        scorer = EmbeddingScorer(embeddings_path=EMBEDDINGS_PATH)

    pr_creator = None
    if OPEN_PRS:
        try:
            pr_creator = PRCreator()
        except EnvironmentError as e:
            print(f"  PR creation disabled: {e}")

    loop_result = LoopTestResult(
        orchestration_result=OrchestrationResult(iterations_run=0)
    )
    previous_results = None
    anthropic_client = anthropic.Anthropic()

    for iteration in range(1, iterations + 1):
        print(
            f"\n-- Iteration {iteration}/{iterations} --------------------------------")

        # Stage 1: Attacker
        print(f"[{iteration}] Stage 1: attacker agent")
        plan = attacker.run(
            technique_ids=technique_ids,
            previous_results=previous_results,
        )
        loop_result.plans_per_iteration[iteration] = plan
        print(f"  Plan: {len(plan)} technique(s) -- "
              f"{[tid for tid in plan]}")

        # Stage 2: Emulator -- test selection handled internally by emulator
        print(f"[{iteration}] Stage 2: emulator")
        emulator_tids, evasion_hints, evasion_hints_v2 = extract_emulator_inputs(
            plan)

        all_tids = list(dict.fromkeys(
            emulator_tids +
            [t for t in technique_ids if t not in emulator_tids]
        ))

        log_stream, stats, emulation_history = run_emulator(
            technique_ids=all_tids,
            evasion_hints=evasion_hints,
            evasion_hints_v2=evasion_hints_v2,
            output_dir=OUTPUT_DIR,
        )
        loop_result.events_per_iteration[iteration] = {
            tid: len(events) for tid, events in log_stream.items()
        }
        print(f"  Events: {stats.events_generated} total -- "
              f"{loop_result.events_per_iteration[iteration]}")

        all_events = _flatten_log_stream(log_stream)
        if not all_events:
            print(f"  WARNING: no events generated in iteration {iteration}")
            previous_results = previous_results  # preserve
            continue

        # Stage 3: Detection
        print(f"[{iteration}] Stage 3: detection")
        engine = DetectionEngine(rules_dir=RULES_DIR, events=all_events)
        rule_results = engine.run()
        detection_results = _build_detection_results(rule_results)
        loop_result.detection_results_per_iteration[iteration] = detection_results
        previous_results = detection_results

        covered = [tid for tid in technique_ids
                   if detection_results.get(tid)
                   and detection_results[tid].covered
                   and len(detection_results[tid].matched_events) >= len(log_stream.get(tid, []))]

        gaps = [tid for tid in technique_ids
                if detection_results.get(tid) and (
                    detection_results[tid].gap or
                    (detection_results[tid].covered and
                     len(detection_results[tid].matched_events) < len(log_stream.get(tid, [])))
                )]

        print(f"  Covered: {covered}")
        print(f"  Gaps:    {gaps}")
        for tid, dr in detection_results.items():
            total_attack = len(log_stream.get(tid, []))
            matched = len(dr.matched_events)
            ratio = f"{matched}/{total_attack}" if total_attack > 0 else "0/0"
            if matched == total_attack and total_attack > 0:
                label = "Fully Covered"
                marker = "+"
            elif matched > 0:
                label = "Partially Covered"
                marker = "~"
            else:
                label = "Missed" if dr.total_rules > 0 else "No Rules"
                marker = "x"
            print(f"    {marker} {tid}: {ratio} events matched -- {label}")

        # Record metrics
        for tid, dr in detection_results.items():
            metrics.record_detection(
                tid,
                rules_evaluated=dr.total_rules,
                rules_fired=len(dr.fired_rules),
                total_events=len(log_stream.get(tid, [])),
                matched_events=len(dr.matched_events),
                iteration=iteration,
            )

        # Stage 4: Gap scorer
        if scorer and gaps:
            print(f"[{iteration}] Stage 4: gap scorer")
            gap_scores = score_gaps(detection_results, scorer, log_stream)
            for tid, gs in gap_scores.items():
                if gs.top_technique:
                    score_str = f"{gs.top_score:.4f}" if gs.top_score is not None else "none"
                    print(f"  {tid}: closest = {gs.top_technique} ({score_str}), "
                          f"embedding similarity computed on {gs.num_events_matched}/{gs.num_events_scored} events")

        # Stage 5+6: Defender + Validation
        if not gaps:
            print(f"[{iteration}] No gaps -- skipping defender")
            summary = IterationSummary(
                iteration=iteration,
                techniques_attempted=len(technique_ids),
                techniques_covered=len(covered),
                techniques_with_gaps=0,
                rules_generated=0,
                rules_validated=0,
            )
            loop_result.orchestration_result.summaries.append(summary)
            loop_result.orchestration_result.iterations_run += 1
            continue

        print(f"[{iteration}] Stage 5: defender agent")
        rules_generated = 0
        rules_validated = 0
        prs_opened = []
        validated_rule_yamls: list[str] = []
        planner = DetectionPlanner()

        for technique_id in gaps:
            dr = detection_results[technique_id]
            gap_context = _build_gap_context(
                technique_id=technique_id,
                log_stream=log_stream,
                stix=stix,
                corpus_root=CORPUS_ROOT,
            )
            if not gap_context:
                continue

            # Stage 4.5: Detection planner
            strategy = planner.run(
                technique_id=technique_id,
                missed_events=gap_context.missed_events,
                stix_metadata=stix.lookup(technique_id),
            )
            gap_context.detection_strategy = strategy

            rule_yaml, validation_result = defender.run(gap_context)
            rules_generated += 1

            if validation_result:
                metrics.record_validation(
                    technique_id,
                    fp_rate=getattr(validation_result, "fp_rate", None),
                    fp_count=getattr(validation_result, "fp_count", None),
                    total_benign=getattr(
                        validation_result, "total_benign", None),
                    gate_failed=getattr(validation_result,
                                        "gate_failed", None),
                    iteration=iteration,
                )

            if not rule_yaml or not validation_result or not validation_result.passed:
                gate = getattr(validation_result, "gate_failed",
                               "unknown") if validation_result else "unknown"
                print(f"  {technique_id}: rule generation failed (gate={gate})")
                continue

            rules_validated += 1
            validated_rule_yamls.append(rule_yaml)
            print(f"  {technique_id}: rule validated + "
                  f"(FP={validation_result.fp_rate:.1%})")

            # Stage 7: PR
            if OPEN_PRS and pr_creator:
                try:
                    metadata = stix.lookup(technique_id)
                    technique_name = metadata.technique_name if metadata else technique_id
                    pr_result = pr_creator.create_pr(
                        technique_id=technique_id,
                        technique_name=technique_name,
                        rule_yaml=rule_yaml,
                        missed_events=gap_context.missed_events,
                        validation_result=validation_result,
                        fired_rules=dr.fired_rules,
                    )
                    prs_opened.append(pr_result.pr_url)
                    print(f"  PR: {pr_result.pr_url}")

                    # Mark tests used for this technique so cross-run selector
                    # deprioritises them going forward.
                    for guid in emulation_history.get(technique_id, {}):
                        mark_rule_generated(
                            emulation_history, technique_id, guid)

                except Exception as e:
                    print(f"  PR failed for {technique_id}: {e}")

        # Corpus stress-test learner
        if validated_rule_yamls:
            print(f"[{iteration}] Corpus learner: "
                  f"{len(validated_rule_yamls)} validated rule(s)")
            corpus_result = run_corpus_learner(
                rule_yamls=validated_rule_yamls,
                iteration_id=f"iter_{iteration:03d}",
                anthropic_client=anthropic_client,
            )
            print(f"  Clusters: {corpus_result.n_clusters}, "
                  f"Variants: {corpus_result.n_variants_generated}, "
                  f"Push: {'ok' if corpus_result.push_succeeded else 'failed'}")
            if corpus_result.errors:
                for err in corpus_result.errors:
                    print(f"  [corpus error] {err}")

        # Update previous iteration's outcome
        if iteration > 1:
            prev_iter_id = f"iter_{(iteration - 1):03d}"
            corpus_root = Path("corpus/benign")
            new_logs = any(corpus_root.rglob(f"*{prev_iter_id}*"))
            update_outcome(
                iteration_id=prev_iter_id,
                workflow_ran=True,
                logs_produced=new_logs,
                rules_hit=[],
            )

        summary = IterationSummary(
            iteration=iteration,
            techniques_attempted=len(technique_ids),
            techniques_covered=len(covered),
            techniques_with_gaps=len(gaps),
            rules_generated=rules_generated,
            rules_validated=rules_validated,
            prs_opened=prs_opened,
        )
        loop_result.orchestration_result.summaries.append(summary)
        loop_result.orchestration_result.iterations_run += 1

    metrics.finalise_iteration(iteration=iterations, output_dir=None)
    return loop_result


# ---------------------------------------------------------------------------
# Contract verification
# ---------------------------------------------------------------------------

def verify_contracts(loop_result: LoopTestResult, technique_ids: list[str]) -> list[str]:
    """
    Verify stage contracts between iterations.
    Returns list of failure messages -- empty = all passed.
    """
    failures = []

    for iteration, plan in loop_result.plans_per_iteration.items():
        # Attacker output contract -- plan must cover all techniques
        if not plan:
            failures.append(f"Iter {iteration}: attacker returned empty plan")
        for tid in technique_ids:
            if tid not in plan:
                failures.append(
                    f"Iter {iteration} / {tid}: technique missing from attacker plan"
                )

        # Events generated contract
        events = loop_result.events_per_iteration.get(iteration, {})
        for tid in technique_ids:
            count = events.get(tid, 0)
            if count == 0:
                failures.append(
                    f"Iter {iteration} / {tid}: no events generated -- "
                    f"emulator produced nothing for this technique"
                )

        # Detection results contract
        det = loop_result.detection_results_per_iteration.get(iteration, {})
        for tid in technique_ids:
            if tid not in det:
                failures.append(
                    f"Iter {iteration} / {tid}: no DetectionResult -- "
                    f"technique may have no curated rules"
                )

    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n-- 3.16/3.17 Full Loop Wire + Test -----------------------")
    print(f"  Iterations: {ITERATIONS}")
    print(f"  Open PRs:   {OPEN_PRS}")
    print(f"  Rules dir:  {RULES_DIR}")
    print(f"  Corpus:     {CORPUS_ROOT}")

    from pipeline.orchestrator import _load_technique_ids
    technique_ids = _load_technique_ids()
    print(f"  Techniques: {technique_ids}")

    print("\n-- Running loop ------------------------------------------")
    loop_result = run_instrumented_loop(
        technique_ids=technique_ids,
        iterations=ITERATIONS,
    )

    print("\n-- Contract verification ---------------------------------")
    failures = verify_contracts(loop_result, technique_ids)
    if failures:
        print(f"  FAILURES ({len(failures)}):")
        for f in failures:
            print(f"    x {f}")
    else:
        print(f"  + All stage contracts verified")

    print("\n-- Loop summary ------------------------------------------")
    for s in loop_result.orchestration_result.summaries:
        print(f"\n  Iteration {s.iteration}:")
        print(f"    Techniques attempted : {s.techniques_attempted}")
        print(f"    Covered              : {s.techniques_covered}")
        print(f"    Gaps                 : {s.techniques_with_gaps}")
        print(f"    Rules generated      : {s.rules_generated}")
        print(f"    Rules validated      : {s.rules_validated}")
        print(f"    PRs opened           : {len(s.prs_opened)}")

    # Save plans for 3.18 mutation verification
    import json
    plans_summary = {}
    for iteration, plan in loop_result.plans_per_iteration.items():
        plans_summary[iteration] = {
            tid: {
                "evasion_hints": task.evasion_hints,
                "evasion_hints_v2": task.evasion_hints_v2,
            }
            for tid, task in plan.items()
        }

    plans_path = Path("corpus/attack/stats/loop_plans.json")
    plans_path.parent.mkdir(parents=True, exist_ok=True)
    with open(plans_path, "w") as f:
        json.dump(plans_summary, f, indent=2)
    print(f"\n  Plans saved to {plans_path} (for 3.18 mutation check)")

    overall = "+ PASSED" if not failures else f"x FAILED ({len(failures)} contract failures)"
    print(f"\n-- 3.16/3.17 result: {overall} ---------------------------")


if __name__ == "__main__":
    main()
