"""
scripts/run_regression_check.py

Deterministic regression check for the Sigma ruleset in rules/.
Zero LLM calls — runs entirely against frozen per-rule fixtures
(tests/fixtures/regression/) and the committed benign corpus
(corpus/benign/). Safe to run on every PR without burning API cost
or hitting LLM non-determinism.

Modes:
  --mode=check
      Diffs current results against data/coverage_baseline.json.
      Writes a markdown report (--output), exits 1 on any regression.
      Used on pull_request.

  --mode=update-baseline
      Recomputes results and overwrites data/coverage_baseline.json.
      No diffing, no exit-code logic.
      Used on push to main, AFTER a PR has merged — this is what keeps
      the baseline current automatically.

A rule with no matching fixture folder is silently skipped from scoring
(not flagged, not failed) — dropped deliberately for now. Worth revisiting
once manually-curated rules (which never go through pr_creator.py) are a
live question, since they'll never get a fixture through that mechanism.

VERIFY before fully trusting this: the two spots marked VERIFY below
assume RuleMatchResult exposes a `.match_count` attribute. This is my
best understanding from project notes, not confirmed against the real
pipeline/detection/result_parser.py source — adjust if the actual
attribute name differs.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

from pipeline.detection.engine import BASELINE_COLUMNS, DetectionEngine

RULES_DIR = Path("rules")
FIXTURES_DIR = Path("tests/fixtures/regression")
BENIGN_CORPUS_DIR = Path("corpus/benign")
BASELINE_PATH = Path("data/coverage_baseline.json")

# Absolute FP-rate increase over baseline that counts as a regression.
# Matches the noise_gate's own existing FP threshold (0.01) for consistency.
FP_REGRESSION_DELTA = 0.01

TECHNIQUE_TAG_PATTERN = re.compile(
    r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# Build a case-insensitive lookup so event keys can be mapped to exactly
# the casing BASELINE_COLUMNS uses. This prevents _infer_columns from seeing
# both "Channel" (from BASELINE_COLUMNS) and "channel" (from a lowercased
# event) as distinct strings — SQLite treats them as duplicate column names.
_BASELINE_KEY_MAP: dict[str, str] = {
    col.lower(): col for col in BASELINE_COLUMNS}


def _normalize_event(event: dict) -> dict:
    """
    Normalize event keys to match BASELINE_COLUMNS casing where a match exists.
    Keys not in BASELINE_COLUMNS are lowercased as a fallback.
    Result: _infer_columns never sees two strings that SQLite would treat as
    the same column name.
    """
    return {_BASELINE_KEY_MAP.get(k.lower(), k.lower()): v for k, v in event.items()}


def extract_technique_id(rule_path: Path) -> str | None:
    """Pulls the ATT&CK technique ID from a Sigma rule's `tags:` field."""
    rule = yaml.safe_load(rule_path.read_text())
    for tag in rule.get("tags", []) or []:
        match = TECHNIQUE_TAG_PATTERN.match(str(tag))
        if match:
            return match.group(1).upper()
    return None


def load_jsonl(path: Path) -> list[dict]:
    # utf-8-sig automatically strips BOM if present, no-ops if absent.
    # Belt-and-suspenders against corpus files committed with Windows BOM.
    return [json.loads(line.lstrip('\ufeff')) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def load_benign_events() -> list[dict]:
    events = []
    for jsonl_path in BENIGN_CORPUS_DIR.rglob("*.jsonl"):
        events.extend(load_jsonl(jsonl_path))
    return events


def compute_results() -> tuple[dict[str, bool], dict[str, bool]]:
    """
    Each rule is tested ONLY against its own fixture, in isolation —
    mirrors exactly how attack_gate validated it originally. Deliberate:
    running the full ruleset against a merged multi-rule event pool risks
    a broad, unrelated rule firing on a DIFFERENT rule's fixture and
    masking that the intended rule actually broke — the same class of
    cross-contamination bug already fixed once in the live detection
    engine, just at the rule level instead of the technique level.

    Returns:
        rule_fired:         {rule_filename: bool} — per-rule pass/fail,
                             so the report can name the exact rule that
                             broke, not just the technique it maps to.
        technique_coverage: {technique_id: bool} — True if ANY rule
                             mapped to that technique still fires on
                             ITS OWN fixture (OR across isolated results,
                             never a shared-event-pool check).
    """
    # rules_dir is required by the constructor but irrelevant to this call
    # path — run_single_rule takes rule_yaml directly and events overrides
    # whatever self.events was set to. See VERIFY note below.
    # Instantiate once — run_single_rule accepts events as a parameter
    # so it never uses self.events, but the constructor still requires it.
    engine = DetectionEngine(rules_dir=RULES_DIR, events=[])

    rule_fired: dict[str, bool] = {}
    technique_coverage: dict[str, bool] = {}

    for rule_path in sorted(RULES_DIR.rglob("*.yml")):
        fixture_path = FIXTURES_DIR / rule_path.stem / "attack_sample.jsonl"
        if not fixture_path.exists():
            continue

        technique_id = extract_technique_id(rule_path)
        if technique_id is None:
            continue

        events = [_normalize_event(e) for e in load_jsonl(fixture_path)]
        # run_single_rule returns RuleMatchResult — .fired is the bool,
        # .matched_events is the list. No .match_count on RuleMatchResult
        # (that's on RuleBreakdown, which computes len(matched_events)).
        result = engine.run_single_rule(rule_path.read_text(), events=events)
        fired = result.fired

        rule_fired[rule_path.name] = fired
        technique_coverage[technique_id] = technique_coverage.get(
            technique_id, False) or fired

    return rule_fired, technique_coverage


def compute_fp_rate(benign_events: list[dict]) -> float:
    if not benign_events:
        return 0.0
    # Normalize all keys to lowercase before hitting the engine — benign corpus
    # mixes Sysmon-native casing (User, Image) from GH Actions collection with
    # LogEvent-normalized lowercase keys. SQLite sees user + User as duplicate
    # column names and refuses to CREATE TABLE. Fix at source, not in engine.
    normalized = [_normalize_event(e) for e in benign_events]
    engine = DetectionEngine(rules_dir=RULES_DIR, events=normalized)
    results = engine.run()
    fp_count = sum(len(r.matched_events) for r in results)
    return fp_count / len(benign_events)


def load_baseline() -> dict:
    if not BASELINE_PATH.exists():
        return {}
    return json.loads(BASELINE_PATH.read_text())


def save_baseline(rule_fired: dict[str, bool], coverage: dict[str, bool], fp_rate: float) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(
        {"rules": rule_fired, "coverage": coverage, "fp_rate": fp_rate},
        indent=2, sort_keys=True,
    ))


def build_report(
    rule_fired: dict[str, bool],
    coverage: dict[str, bool],
    fp_rate: float,
    baseline: dict,
) -> tuple[str, bool]:
    lines = ["## Regression Check Results\n"]
    regression_found = False
    baseline_rules = baseline.get("rules", {})
    baseline_coverage = baseline.get("coverage", {})
    baseline_fp_rate = baseline.get("fp_rate", 0.0)

    if not baseline:
        lines.append(
            "_No baseline yet — this run establishes the first reference point. "
            "The baseline is created automatically once this merges to main._\n"
        )
        return "\n".join(lines), False

    # Per-rule detail — this is what actually names the broken rule,
    # not just the technique it happens to map to.
    lines.append("### Per-rule results\n")
    lines.append("| Rule | Before | After | Status |")
    lines.append("|---|---|---|---|")
    for rule_name in sorted(set(baseline_rules) | set(rule_fired)):
        before = baseline_rules.get(rule_name)
        after = rule_fired.get(rule_name)
        if before is True and after is not True:
            status = "REGRESSION"
            regression_found = True
        elif before != after:
            status = "changed"
        else:
            status = "no change"
        lines.append(f"| {rule_name} | {before} | {after} | {status} |")

    # Technique-level summary — aggregate view only, no longer what
    # determines pass/fail by itself.
    lines.append("\n### Per-technique coverage\n")
    lines.append("| Technique | Before | After |")
    lines.append("|---|---|---|")
    for technique_id in sorted(set(baseline_coverage) | set(coverage)):
        before = baseline_coverage.get(technique_id)
        after = coverage.get(technique_id)
        lines.append(f"| {technique_id} | {before} | {after} |")

    fp_delta = fp_rate - baseline_fp_rate
    fp_status = "REGRESSION" if fp_delta > FP_REGRESSION_DELTA else "ok"
    if fp_status == "REGRESSION":
        regression_found = True
    lines.append(
        f"\n**FP rate:** {baseline_fp_rate:.2%} -> {fp_rate:.2%} ({fp_status})")

    return "\n".join(lines), regression_found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=["check", "update-baseline"], required=True)
    parser.add_argument("--output", default="regression_report.md")
    args = parser.parse_args()

    rule_fired, coverage = compute_results()
    fp_rate = compute_fp_rate(load_benign_events())

    if args.mode == "update-baseline":
        save_baseline(rule_fired, coverage, fp_rate)
        print(
            f"Baseline updated: {len(rule_fired)} rules, {len(coverage)} techniques, fp_rate={fp_rate:.4f}")
        return

    baseline = load_baseline()
    report, regression_found = build_report(
        rule_fired, coverage, fp_rate, baseline)
    Path(args.output).write_text(report)
    print(report)

    if regression_found:
        sys.exit(1)


if __name__ == "__main__":
    main()
