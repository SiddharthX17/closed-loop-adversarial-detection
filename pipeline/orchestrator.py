"""
Coordinates all 7 pipeline stages:
  1. Attacker Agent  → structured campaign plan
  2. Emulator        → log stream per technique
  3. Detection Layer → per-technique match results
  4. Gap Scorer      → embedding proximity for missed events
  4.5 Detection Planner   → technique-level detection strategy (invariants, FP profile)
  5. Defender Agent  → candidate Sigma rules for gaps
  6. Validation      → schema linter + attack gate + noise gate (inside DefenderAgent)
  7. PR Creator      → opens GitHub PRs for validated rules

Runs up to max_iterations. Each iteration feeds previous detection results
back to the attacker agent for mutation-driven adaptation.

Usage:
    from pipeline.orchestrator import Orchestrator

    # Explicit override per call
    result: dict = Orchestrator().run(technique_ids=[...], iterations=2)

    # Or configure at construction — this is the shape app.py (FastAPI) uses
    orchestrator = Orchestrator(technique_ids=[...], max_iterations=2)
    result: dict = orchestrator.run()
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pipeline.attacker.agent import AttackerAgent, extract_emulator_inputs, CampaignPlan
from pipeline.emulator.emulator import run_emulator
from pipeline.detection.engine import DetectionEngine
from pipeline.detection.result_parser import parse_results, get_gaps, get_covered
from pipeline.embedding.scorer import EmbeddingScorer
from pipeline.embedding.gap_scorer import score_gaps
from pipeline.embedding.embedder import EMBEDDINGS_PATH
from pipeline.defender.agent import DefenderAgent, GapContext, find_existing_rule_paths
from pipeline.detection_planner.planner import DetectionPlanner
from pipeline.github.pr_creator import PRCreator, PRResult
from pipeline.metrics.tracker import MetricsTracker
from pipeline.data.stix_loader import get_loader
from pipeline.emulator.procedure_interpreter import get_drop_stats
from pipeline.corpus.learner import run as run_corpus_learner
from pipeline.corpus.pusher import update_outcome
from pipeline.emulator.test_history import mark_rule_generated
from pipeline.emulator.emulator import get_used_guids

import yaml
import anthropic

DEBUG = os.getenv("PIPELINE_DEBUG", "").lower() in ("1", "true")

RULES_DIR = Path("rules")
CORPUS_ROOT = Path("corpus/benign")
TECHNIQUES_PATH = Path("config/techniques.yaml")
OUTPUT_DIR = Path("corpus/attack")


def _dbg(msg: str) -> None:
    if DEBUG:
        print(f"[orchestrator] {msg}")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class IterationSummary:
    iteration: int
    techniques_attempted: int
    techniques_covered: int
    techniques_with_gaps: int
    rules_generated: int
    rules_validated: int
    event_coverage: dict[str, str] = field(
        default_factory=dict)  # tid → "matched/total"
    prs_opened: list[str] = field(default_factory=list)  # PR URLs

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "techniques_attempted": self.techniques_attempted,
            "techniques_covered": self.techniques_covered,
            "techniques_with_gaps": self.techniques_with_gaps,
            "rules_generated": self.rules_generated,
            "rules_validated": self.rules_validated,
            "event_coverage": self.event_coverage,
            "prs_opened": self.prs_opened,
        }


@dataclass
class OrchestrationResult:
    iterations_run: int
    summaries: list[IterationSummary] = field(default_factory=list)
    # technique_id → covered:bool
    final_coverage: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        JSON-serialisable shape for API consumers (e.g. FastAPI /run).

        Keys:
          iterations_run: int
          coverage:       {technique_id: "full" | "partial" | "missed"} — final snapshot
          pr_urls:        [str, ...] — every PR opened across all iterations
          run_summary:    {techniques_run, gaps_found, rules_generated, rules_validated}
          iterations:     [IterationSummary.to_dict(), ...] — full per-iteration detail
        """
        pr_urls = [url for s in self.summaries for url in s.prs_opened]
        techniques_run = (
            self.summaries[-1].techniques_attempted if self.summaries else 0
        )

        return {
            "iterations_run": self.iterations_run,
            "coverage": dict(self.final_coverage),
            "pr_urls": pr_urls,
            "run_summary": {
                "techniques_run": techniques_run,
                "gaps_found": sum(s.techniques_with_gaps for s in self.summaries),
                "rules_generated": sum(s.rules_generated for s in self.summaries),
                "rules_validated": sum(s.rules_validated for s in self.summaries),
            },
            "iterations": [s.to_dict() for s in self.summaries],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_technique_ids() -> list[str]:
    with open(TECHNIQUES_PATH) as f:
        data = yaml.safe_load(f)
    return [str(t) for t in data.get("techniques", [])]


def _flatten_log_stream(
    log_stream: dict,       # dict[technique_id, list[LogEvent]]
) -> list[dict]:
    """
    Flatten all LogEvents across all techniques into a single list[dict]
    for the detection engine.

    Injects _technique_id into each serialised event so the detection layer
    can attribute matched events back to their originating technique.
    Prevents cross-technique attribution where a broad rule fires on foreign
    events and falsely reports coverage. Stripped in _build_detection_results.
    """
    events = []
    for tid, technique_events in log_stream.items():
        for event in technique_events:
            d = event.model_dump(exclude_none=True)
            d["_technique_id"] = tid
            events.append(d)
    return events


def _build_detection_results(
    rule_match_results: list,
) -> dict:
    """
    Convert list[RuleMatchResult] from engine.run() into
    dict[technique_id, DetectionResult] keyed by technique ID.

    Filters matched_events in each DetectionResult to only include events
    tagged with _technique_id matching that technique — injected by
    _flatten_log_stream, stripped here after filtering.

    Fixes cross-technique attribution: a broad rule firing on technique B's
    events must not count as coverage for technique A, even if it is a
    technique A rule. covered is re-derived after filtering so a rule that
    fired only on foreign events does not mark a technique as covered.
    """
    parsed = parse_results(rule_match_results)
    result_map = {}
    for dr in parsed:
        dr.matched_events = [
            {k: v for k, v in e.items() if k != "_technique_id"}
            for e in dr.matched_events
            if e.get("_technique_id") == dr.technique_id
        ]
        dr.covered = bool(dr.matched_events)
        result_map[dr.technique_id] = dr
    return result_map


def _select_dominant_event_group(
    events: list[dict],
) -> tuple[list[dict], Optional[int]]:
    """
    When missed events span multiple EventIDs, return only the group with
    the strongest detection signal.

    A single Sigma rule targets one logsource category (one EventID type).
    Sending mixed EventIDs causes the LLM to write rules that span event
    types — structurally invalid in Sigma.

    Selection: group with most events; tie-break by total populated field count.
    """
    if not events:
        return events, None

    event_ids = {e.get("EventID") for e in events}
    if len(event_ids) <= 1:
        return events, next(iter(event_ids), None)

    groups: dict = {}
    for e in events:
        eid = e.get("EventID")
        groups.setdefault(eid, []).append(e)

    def _score(group: list[dict]) -> tuple[int, int]:
        return len(group), sum(len(e) for e in group)

    dominant_eid = max(groups, key=lambda eid: _score(groups[eid]))
    _dbg(
        f"_select_dominant_event_group: EventIDs {sorted(event_ids)} → "
        f"selected EID {dominant_eid} "
        f"({len(groups[dominant_eid])}/{len(events)} events)"
    )
    return groups[dominant_eid], dominant_eid


def _build_gap_context(
    technique_id: str,
    log_stream: dict,
    stix,
    corpus_root: Path,
) -> Optional[GapContext]:
    """
    Build GapContext for a gap technique.

    missed_events: all attack events for the technique (as dicts) — these
                   are all "missed" since gap=True means zero rules fired.
    attack_sample: same events as LogEvent objects — for validation gates.
    """
    metadata = stix.lookup(technique_id)
    if not metadata:
        _dbg(f"{technique_id}: no STIX metadata — cannot build GapContext")
        return None

    raw_events = log_stream.get(technique_id, [])
    if not raw_events:
        _dbg(f"{technique_id}: no emulated events — skipping defender")
        return None

    missed_events = [
        e.model_dump(exclude_none=True)
        if hasattr(e, "model_dump") else dict(e)
        for e in raw_events
    ]

    # If events span multiple EventIDs, focus on the dominant group.
    # A Sigma rule targets one logsource category — mixed EventIDs cause
    # the LLM to write structurally invalid multi-type rules.
    missed_events, dominant_eid = _select_dominant_event_group(missed_events)

    # Filter attack_sample to match — attack_gate only tests events of the
    # type the rule is designed for, avoiding spurious unmatched feedback.
    if dominant_eid is not None:
        attack_sample = [
            e for e in raw_events
            if getattr(e, "EventID", None) == dominant_eid
        ] or raw_events  # fallback to all if filter empties the list
    else:
        attack_sample = raw_events

    existing_rule_paths = find_existing_rule_paths(technique_id, RULES_DIR)

    return GapContext(
        technique_id=technique_id,
        technique_name=metadata.technique_name,
        tactic=metadata.tactic,
        missed_events=missed_events,
        existing_rule_paths=existing_rule_paths,
        attack_sample=raw_events,       # list[LogEvent] for validation
        corpus_root=corpus_root,
    )


def _new_corpus_files_exist(iter_id: str) -> bool:
    """Check if corpus/benign/ has files tagged with this iteration ID."""
    corpus_root = Path("corpus/benign")
    return any(corpus_root.rglob(f"*{iter_id}*"))


def _rules_fired_on_new_corpus(iter_id: str) -> list[str]:
    """
    Placeholder — returns rule IDs that fired on corpus files from this iteration.
    Wire to detection engine results when detection-on-new-corpus is implemented.
    """
    return []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:

    def __init__(
        self,
        technique_ids: Optional[list[str]] = None,
        max_iterations: int = 2,
        rules_dir: Path = RULES_DIR,
        corpus_root: Path = CORPUS_ROOT,
        output_dir: Optional[Path] = OUTPUT_DIR,
        open_prs: bool = True,
    ):
        """
        Args:
            technique_ids:  default techniques for .run() when called with no
                             override. None = resolved from techniques.yaml
                             lazily inside run() (not here — keeps __init__
                             side-effect-free for test construction).
            max_iterations: default iteration count for .run() when called
                             with no override.
            rules_dir:   directory containing curated Sigma rules
            corpus_root: root of benign corpus for noise gate
            output_dir:  where emulator writes JSONL + stats. None = suppress writes.
            open_prs:    set False to skip PR creation (useful for testing loop logic)
        """
        self._technique_ids = technique_ids
        self._max_iterations = max_iterations
        self._rules_dir = rules_dir
        self._corpus_root = corpus_root
        self._output_dir = output_dir
        self._open_prs = open_prs

        self._stix = get_loader()
        self._attacker = AttackerAgent()
        self._defender = DefenderAgent(corpus_root=corpus_root)
        self._planner = DetectionPlanner()
        self._metrics = MetricsTracker()

        # EmbeddingScorer — load once, reuse across iterations
        if EMBEDDINGS_PATH.exists():
            self._scorer = EmbeddingScorer(embeddings_path=EMBEDDINGS_PATH)
        else:
            _dbg("Embeddings not found — gap scoring disabled. Run embedder first.")
            self._scorer = None

        # PR creator — optional, only init if opening PRs
        self._pr_creator = None
        self._anthropic_client = anthropic.Anthropic()
        if open_prs:
            try:
                self._pr_creator = PRCreator()
            except EnvironmentError as e:
                print(f"[orchestrator] PR creation disabled: {e}")
                self._open_prs = False

    def run(
        self,
        technique_ids: Optional[list[str]] = None,
        iterations: Optional[int] = None,
    ) -> dict:
        """
        Run the full adversarial detection loop.

        Args:
            technique_ids: techniques to target. Resolution order:
                           this arg → __init__'s technique_ids → techniques.yaml.
            iterations:    number of attacker→emulator→detect→defend cycles.
                           Resolution order: this arg → __init__'s max_iterations.

        Returns:
            JSON-serialisable dict — see OrchestrationResult.to_dict().
        """
        if technique_ids is None:
            technique_ids = self._technique_ids
        if technique_ids is None:
            technique_ids = _load_technique_ids()

        if iterations is None:
            iterations = self._max_iterations

        print(f"[orchestrator] Starting run: {len(technique_ids)} techniques, "
              f"{iterations} iteration(s)")

        result = OrchestrationResult(iterations_run=0)
        # fed back to attacker each iteration
        previous_results: Optional[dict] = None

        for iteration in range(1, iterations + 1):
            try:
                summary, detection_results = self._run_iteration(
                    technique_ids=technique_ids,
                    iteration=iteration,
                    previous_results=previous_results,
                )
            except Exception as e:
                print(f"[orchestrator] Iteration {iteration} failed: {e}")
                detection_results = None
                summary = IterationSummary(
                    iteration=iteration,
                    techniques_attempted=len(technique_ids),
                    techniques_covered=0,
                    techniques_with_gaps=0,
                    rules_generated=0,
                    rules_validated=0,
                )

            result.summaries.append(summary)
            result.iterations_run += 1
            previous_results = detection_results

            # Feed detection results forward to attacker for next iteration
            # Stored on self during iteration, cleared before next

        # Final coverage snapshot
        if result.summaries:
            last = result.summaries[-1]
            result.final_coverage = {}
            for tid, ratio in last.event_coverage.items():
                matched, total = map(int, ratio.split("/"))
                if matched == total and total > 0:
                    result.final_coverage[tid] = "full"
                elif matched > 0:
                    result.final_coverage[tid] = "partial"
                else:
                    result.final_coverage[tid] = "missed"

        # Finalise metrics
        self._metrics.finalise_iteration(
            iteration=iterations,
            output_dir=self._output_dir / "metrics" if self._output_dir else None,
        )

        self._print_summary(result)
        return result.to_dict()

    def _run_iteration(
        self,
        technique_ids: list[str],
        iteration: int,
        previous_results: Optional[dict],
    ) -> tuple[IterationSummary, Optional[dict]]:

        summary = IterationSummary(
            iteration=iteration,
            techniques_attempted=len(technique_ids),
            techniques_covered=0,
            techniques_with_gaps=0,
            rules_generated=0,
            rules_validated=0,
        )

        # ── Stage 1: Attacker agent ───────────────────────────────
        _dbg(f"Stage 1: attacker agent (iteration {iteration})")
        plan: CampaignPlan = self._attacker.run(
            technique_ids=technique_ids,
            previous_results=previous_results,
        )
        _dbg(f"Plan generated for {len(plan)} technique(s)")

        # ── Stage 2: Emulator ─────────────────────────────────────
        _dbg("Stage 2: emulator")
        emulator_technique_ids, evasion_hints, evasion_hints_v2 = (
            extract_emulator_inputs(plan)
        )

        # Include any techniques not in the plan (attacker may have skipped some)
        all_technique_ids = list(dict.fromkeys(
            emulator_technique_ids +
            [t for t in technique_ids if t not in emulator_technique_ids]
        ))

        log_stream, emulator_stats, emulation_history = run_emulator(
            technique_ids=all_technique_ids,
            evasion_hints=evasion_hints,
            evasion_hints_v2=evasion_hints_v2,
            output_dir=self._output_dir,
        )
        _dbg(f"Emulator: {emulator_stats.events_generated} events across "
             f"{emulator_stats.techniques_with_events} technique(s)")

        # ── Stage 3: Detection layer ──────────────────────────────
        _dbg("Stage 3: detection")
        all_events = _flatten_log_stream(log_stream)

        if not all_events:
            print("[orchestrator] No events generated — skipping detection")
            return summary, previous_results

        engine = DetectionEngine(
            rules_dir=self._rules_dir,
            events=all_events,
        )
        rule_match_results = engine.run()
        detection_results = _build_detection_results(rule_match_results)
        detection_results = {
            tid: dr for tid, dr in detection_results.items() if tid in technique_ids}

        covered = [tid for tid in technique_ids
                   if detection_results.get(tid)
                   and detection_results[tid].covered
                   and len(detection_results[tid].matched_events) >= len(log_stream.get(tid, []))]

        gaps = [tid for tid in technique_ids
                if log_stream.get(tid) and (       # only if events exist to show the defender
                    # no rules = gap by definition
                    not detection_results.get(tid) or
                    detection_results[tid].gap or
                    (detection_results[tid].covered and
                     len(detection_results[tid].matched_events) < len(log_stream.get(tid, [])))
                )]
        summary.techniques_covered = len(covered)
        summary.techniques_with_gaps = len(gaps)

        print(
            f"[orchestrator] Coverage: {len(covered)}/{len(technique_ids)} techniques")
        if gaps:
            print(f"[orchestrator] Gaps: {gaps}")

        if DEBUG:
            for tid, dr in detection_results.items():
                total_attack = len(log_stream.get(tid, []))
                matched = len(dr.matched_events)
                ratio = f"{matched}/{total_attack}" if total_attack > 0 else "0/0"
                if matched == total_attack and total_attack > 0:
                    label, marker = "Fully Covered", "✓"
                elif matched > 0:
                    label, marker = "Partially Covered", "~"
                else:
                    label, marker = (
                        "Missed" if dr.total_rules > 0 else "No Rules"), "✗"
                _dbg(f"{marker} {tid}: {ratio} events matched — {label}")

        # Record detection metrics
        event_coverage = {}
        for tid in technique_ids:
            dr = detection_results.get(tid)
            if dr is None:
                total_attack = len(log_stream.get(tid, []))
                _dbg(f"  {tid}: 0/{total_attack} events matched — No Rules")
                continue
            total = len(log_stream.get(tid, []))
            matched = len(dr.matched_events) if dr else 0
            event_coverage[tid] = f"{matched}/{total}"
        summary.event_coverage = event_coverage

        for tid, dr in detection_results.items():
            self._metrics.record_detection(
                tid,
                rules_evaluated=dr.total_rules,
                rules_fired=len(dr.fired_rules),
                total_events=len(log_stream.get(tid, [])),
                matched_events=len(dr.matched_events),
                iteration=iteration,
            )

        # ── Stage 4: Gap scorer ───────────────────────────────────
        if self._scorer and gaps:
            _dbg("Stage 4: gap scorer")
            gap_scores = score_gaps(
                detection_results, self._scorer, log_stream)
            for tid, gs in gap_scores.items():
                if gs.top_technique:
                    score_str = f"{gs.top_score:.4f}" if gs.top_score is not None else "none"
                    _dbg(
                        f"{tid}: closest technique = {gs.top_technique} ({score_str})")

        # ── Stage 5+6: Defender agent + Validation ────────────────
        if not gaps:
            _dbg("No gaps — skipping defender agent")
            return summary, detection_results

        _dbg(f"Stage 5: defender agent ({len(gaps)} gap(s))")

        validated_rule_yamls: list[str] = []

        for technique_id in gaps:
            # None for no-rules techniques
            dr = detection_results.get(technique_id)
            _dbg(f"Processing gap: {technique_id}")

            gap_context = _build_gap_context(
                technique_id=technique_id,
                log_stream=log_stream,
                stix=self._stix,
                corpus_root=self._corpus_root,
            )
            if not gap_context:
                continue

            # ── Stage 4.5: Detection planner ──────────────────────
            _dbg(f"Stage 4.5: detection planner ({technique_id})")
            strategy = self._planner.run(
                technique_id=technique_id,
                missed_events=gap_context.missed_events,
                stix_metadata=self._stix.lookup(technique_id),
            )
            gap_context.detection_strategy = strategy
            if strategy:
                _dbg(
                    f"{technique_id}: planner produced strategy — "
                    f"{len(strategy.detection_opportunities)} detection opportunity(ies), "
                    f"objective: {strategy.technique_objective[:80]}"
                )
            else:
                _dbg(
                    f"{technique_id}: planner returned None — defender runs unassisted")

            rule_yaml, validation_result = self._defender.run(gap_context)
            summary.rules_generated += 1

            if validation_result:
                self._metrics.record_validation(
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
                print(
                    f"[orchestrator] {technique_id}: rule generation failed (gate={gate})")
                continue

            summary.rules_validated += 1
            validated_rule_yamls.append(rule_yaml)
            print(f"[orchestrator] {technique_id}: rule validated ✓")

            # ── Stage 7: PR creator ───────────────────────────────
            if self._open_prs and self._pr_creator:
                _dbg(f"Stage 7: opening PR for {technique_id}")
                try:
                    metadata = self._stix.lookup(technique_id)
                    technique_name = metadata.technique_name if metadata else technique_id

                    pr_result = self._pr_creator.create_pr(
                        technique_id=technique_id,
                        technique_name=technique_name,
                        rule_yaml=rule_yaml,
                        missed_events=gap_context.missed_events,
                        validation_result=validation_result,
                        fired_rules=dr.fired_rules if dr else [],
                    )
                    summary.prs_opened.append(pr_result.pr_url)
                    print(f"[orchestrator] PR opened: {pr_result.pr_url}")

                    # Mark only the test that actually produced events this
                    # iteration — not the full candidate pool. get_run_selections()
                    # includes unused fallback candidates (zero-event fallback)
                    # which must NOT be penalised as rule_generated since they
                    # were never emulated.
                    used_guid = get_used_guids().get(technique_id)
                    if used_guid:
                        mark_rule_generated(
                            emulation_history, technique_id, used_guid)

                except Exception as e:
                    print(
                        f"[orchestrator] PR creation failed for {technique_id}: {e}")

        # ── Corpus stress-test learner ────────────────────────────
        if validated_rule_yamls:
            _dbg(
                f"Corpus learner: {len(validated_rule_yamls)} validated rule(s)")
            corpus_result = run_corpus_learner(
                rule_yamls=validated_rule_yamls,
                iteration_id=f"iter_{iteration:03d}",
                anthropic_client=self._anthropic_client,
            )
            _dbg(
                f"Corpus learner: {corpus_result.n_clusters} cluster(s), "
                f"{corpus_result.n_variants_generated} variant(s), "
                f"push={'ok' if corpus_result.push_succeeded else 'failed'}"
            )
            if corpus_result.errors:
                for err in corpus_result.errors:
                    print(f"[orchestrator] [corpus error] {err}")

        # Update previous iteration's outcome now that detection has run
        if iteration > 1:
            prev_iter_id = f"iter_{(iteration - 1):03d}"
            update_outcome(
                iteration_id=prev_iter_id,
                workflow_ran=True,
                logs_produced=_new_corpus_files_exist(prev_iter_id),
                rules_hit=_rules_fired_on_new_corpus(prev_iter_id),
            )

        return summary, detection_results

    def _print_summary(self, result: OrchestrationResult) -> None:
        print(f"\n[orchestrator] ── Run Complete ────────────────────────")
        print(f"  Iterations run: {result.iterations_run}")
        for s in result.summaries:
            print(f"\n  Iteration {s.iteration}:")
            print(f"    Techniques attempted : {s.techniques_attempted}")
            print(f"    Covered              : {s.techniques_covered}")
            print(f"    Gaps                 : {s.techniques_with_gaps}")
            print(f"    Rules generated      : {s.rules_generated}")
            print(f"    Rules validated      : {s.rules_validated}")
            print(f"    PRs opened           : {len(s.prs_opened)}")
            for url in s.prs_opened:
                print(f"      {url}")

        if result.final_coverage:
            print(f"\n  Final coverage:")
            for tid, status in result.final_coverage.items():
                if status == "full":
                    print(f"    ✓ {tid}: Fully Covered")
                elif status == "partial":
                    print(f"    ~ {tid}: Partially Covered")
                else:
                    print(f"    ✗ {tid}: Missed")

        # Cumulative drop stats — printed once after all iterations
        drop_stats = get_drop_stats()
        print(f"\n  Procedure interpreter field drops (cumulative run total):")
        print(
            f"    Unresolved variables dropped : {drop_stats['unresolved_var']}")
        print(f"    Ungrounded fields dropped    : {drop_stats['ungrounded']}")
        print(f"[orchestrator] ────────────────────────────────────────")
