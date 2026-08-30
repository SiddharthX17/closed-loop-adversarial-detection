# Architecture

This system runs a autonomous loop from red team testing to blue team rule validation
end to end. It emulates attacker behavior grounded in Atomic Red Team tests for 
different MITRE ATT&CK techniques, generates synthetic Sysmon logs from that emulation, 
evaluates them against a Sigma detection ruleset. It analyzes the gap where coverage is missing,
writes and validates a rule which is opened as a pull request for a human reviewer.


## 1. System overview

The system runs the same eight-stage loop across multiple iterations:

| Stage | What it does |
|---|---|
| 1. Attacker Agent | Picks a real Atomic Red Team test and generates a base variant and a plausible evasion variant |
| 2. Emulator | Turns that test into realistic Sysmon log events |
| 3. Detection Layer | Runs the existing Sigma ruleset against those events |
| 4. Detection Planner *(gaps only)* | Works out what's actually detectable about the technique, beyond the one observed procedure |
| 5. Defender Agent *(gaps only)* | Writes a candidate Sigma rule to close the gap |
| 6. Validation *(inside stage 5)* | Checks the candidate rule's syntax, whether it fires on the attack, and whether it stays quiet on benign traffic |
| 7. PR Creator | Opens a GitHub pull request for the validated rule |
| 8. Corpus stress-test *(conditional)* | Tries to break the new rule against real, independently-generated Windows activity |

The loop then repeats: whatever got caught this round informs how the attacker agent
mutates its approach next round.

## 2. The loop, stage by stage

Each stage outlines its input, how it works, why it exists, output and key features.

### 2.1 Attacker Agent — `pipeline/attacker/agent.py`, `prompts.py`
Consumes the technique ID(s) selected for this run (resolved by the orchestrator —
either an explicit override or its own default from `config/techniques.yaml`), and,
from iteration 2 onward, the previous iteration's per-technique detection results.

An LLM (Haiku, temperature 0.2) is asked to propose a plausible evasion for that
technique — explicitly steered toward changing the execution chain, binary, or
context. On iteration 2+, it's additionally shown the exact Sysmon field values
that fired a rule last time and instructed not to reuse them verbatim, and to change
the approach rather than just the string. One call produces two things at once: a
base hint set and an *initial* guess at a second variant — the second one isn't
final yet, it gets shown the real interpreted first event and revised again later,
inside the emulator stage.

Produces a campaign plan — technique plus evasion hints — consumed directly by the
Emulator.

#### Features:

Per technique, per iteration: pulls candidate Atomic Red Team tests via
`atomic_loader` (Windows-only, non-manual executor, non-empty command), filters to
tests with at least one concrete observable, scores candidates by complexity and
executor diversity, and passes exactly one candidate to the LLM (`MAX_CANDIDATES = 1`,
the broader scoring pool used to pick that one candidate lives in `emulator.py`
covered in §2.2).

The prompt draws an explicit line between two kinds of mutation, with examples:
*syntactic* mutation (`-enc` → `-EncodedCommand` — same bytes, trivially caught) is
discouraged in favor of *behavioral* mutation (changing the execution chain —
`powershell.exe→cmd.exe` becomes `mshta.exe→powershell.exe`, a different parent, a
different binary context). A LOLBin list (`rundll32`, `mshta`, `wscript`, `cscript`,
`regsvr32`, `certutil`, `msiexec`, `installutil`, `regasm`, `msbuild`, `forfiles`) is
given as illustrative rather than exhaustive, with an explicit instruction to actively
vary which one gets used. Hints are also required to stay scoped to their originating 
event type.

**Two variants, tethered, not generated blind.** The attacker produces
`evasion_hints` (variant 1) and an initial `evasion_hints_v2` in one call. But
`evasion_hints_v2` isn't used as-is — a second, separate LLM call
(`refine_evasion_hints_v2()`, invoked from `emulator.py` after variant 1's event
already exists) shows the attacker the actual interpreted variant-1 event and asks it
to revise its earlier guess against that real event. This keeps the two variants 
as genuine alternates of the same underlying action rather than two potentially 
incoherent ones.

On iteration 2+, the attacker is given `caught_fields` — the specific Sysmon values
that fired a rule last run and instructed not to reuse them verbatim, and to change
the execution approach.


### 2.2 Emulator — `pipeline/emulator/`
Consumes the campaign plan's evasion hints, plus the raw Atomic Red Team test
definitions and MITRE metadata for that technique.

Test selection and evasion-hint generation are two separate concerns: the emulator
picks *which* Atomic Red Team test to actually run itself, using a weighted scoring
system that favors interesting behavior (LOLBins, obfuscation, network/registry
activity) while penalizing tests already tried this run or in past runs. Once a test
is picked, its cleaned command text plus the attacker's hints go to an LLM that
extracts concrete log field values — and only accepts a value if it can trace back to
something actually present in the test's own text; anything it can't verify is
dropped, not guessed. That produces the first event. A second, separate LLM call then
shows the model that real first event and asks it to revise its second-variant hints
against it; a third call constructs the second event under a hard instruction to
match the first event's type and step, so both variants represent the same underlying
action rather than two independently-imagined ones. If a test produces nothing
usable, the emulator retries with a different candidate before giving up on that
technique for this iteration.

This exists because none of the downstream evaluation means anything if the "attack"
data is just plausible-sounding fiction — every field has to be traceable to what a
real attacker running this real test would actually produce.

Produces a stream of structured Sysmon-shaped log events per technique, consumed by
the Detection Layer.

Chain: `stix_loader → atomic_loader → atomic_cleaner → interpret_procedure →
build_log_event`, orchestrated by `emulator.py`.

#### Features:

**Test selection** (`_select_candidates` / `_select_tests`): a 7-bucket weighted
scoring system — HIGH weight (+0.5) for LOLBin/obfuscation signals, MEDIUM (+0.25) for
network/registry/process-spawn/post-exploitation signals, MINOR (+0.10) for
suspicious-path signals, base weight 1.0, capped at 3.10. Selection applies
`priority = weight * uniform(0.35, 1.0)`, with a within-run penalty against tests
already tried this run, and a cross-run penalty read from persistent state
(`data/test_selection_history.json`, `test_history.py`) that deprioritizes
previously-seen tests and heavily penalizes tests that already produced a validated
rule. Set `CLEAR_TEST_HISTORY=1` to wipe that file before a run.

**Grounding layer** (`procedure_interpreter.py`, `_ground_fields`): the core
anti-hallucination mechanism. every field value is accepted only if it 
traces back to the actual Atomic test, checked in order: (1) verbatim match 
against `procedure_text` combined with the attacker's `evasion_hints`,
(2) basename match for path-like values, (3) partial-token match (≥2 tokens, each >4
chars) for `CommandLine`/`ParentCommandLine` specifically, (4) explicit trust for a
value the attacker agent itself supplied. Field-specific carve-outs: `OriginalFileName`
passes through unconditionally (PE metadata can't appear in test prose to match
against), `TargetObject` gets `\(Default)` suffix-stripped before re-checking, and
`DestinationPort`/`Protocol`/`Initiated` are structural TCP facts that grounding would
otherwise always incorrectly drop. Anything that fails every check is logged and
dropped.

**Two variants per event, tethered.** For each selected test, the emulator generates
a base event (variant 1) and a second event (variant 2, via the refinement call
described in §2.1). `event_type` and `selected_step` from variant 1 are then passed as
hard constraints (`required_event_type`, `required_step`) into variant 2's
interpretation call, overriding the interpreter's own latitude to independently choose
either event type for network-capable techniques. This exists specifically so two
independent LLM calls land on the same underlying action rather than two different
steps of a multi-step test.

**Prompt content, beyond grounding.** The system/user prompts encode three explicit
rules on top of the grounding mechanics above. A PRIMARY ACTION RULE establishes
which single command within a (possibly multi-step) test the interpretation should
represent. A dedicated MULTI-STEP FUSION section — added after this exact failure
mode recurred in testing — instructs the model never to combine multiple discrete
commands into one event's `CommandLine` or `ParentCommandLine`, with a worked example
using a three-verb `bitsadmin` sequence (`/create` → `/addfile` → `/resume`) showing
correct (pick one) versus incorrect (all three ANDed together) output. A NETWORK
EVENT RULE gives the model latitude to choose either a process-creation or a network
event by default for network-capable techniques — the exact default that
`required_event_type` (above) overrides for variant 2.

**Zero-event fallback:** if a selected test produces zero events on both variants 
(complete grounding failure, or the model correctly self-rejecting a test its evasion
hints don't actually support), the emulator falls back through its candidate pool 
(4 candidates total) until one succeeds or the pool is exhausted.

`run_emulator()` returns three values: `(log_stream, stats, history)`.

### 2.3 Detection Layer — `pipeline/detection/`
Consumes the emulated log stream and the existing Sigma ruleset, freshly synced from
GitHub before the run starts.

Every rule is converted to SQL and run against the events, loaded into an in-memory
database Results are aggregated per technique into one of four states: full coverage 
(every event caught), partial (some but not all), missed (none), or no_rules 
(nothing exists for this technique yet).

This is the actual measurement the whole system exists to produce. Everything before
it generates the test case; everything after it only runs at all if this stage finds
a gap.

Produces per-technique coverage verdicts, plus — for gap cases — the specific missed
events that the Planner and Defender both need to see.

#### Features:

Sigma rules are converted to SQL via `pysigma-backend-sqlite`
(`sysmon_pipeline() + windows_logsource_pipeline()` for field mapping) and executed
against an in-memory sqlite3 database. `REGEXP` is registered as a Python UDF since
sqlite3 has no native regex support. A fresh pySigma processing pipeline is
instantiated per rule, since pySigma pipeline objects are stateful and reusing one
across rules causes cross-contamination.

`result_parser.py` groups per-rule results into per-technique detection results.
Coverage for a technique is computed by comparing matched events against total
events for that technique: **full** coverage when every event is caught, **partial**
when some but not all are caught, **missed** when none are, and **no_rules** when no
rule exists for the technique at all. Matched events across multiple firing rules are
deduplicated by content hash before being handed downstream, so the defender isn't
shown the same event twice under two different rule IDs.

### 2.4 Detection Planner — `pipeline/detection_planner/`
Consumes a GapContext — the technique's metadata plus up to five missed events —
only for techniques the Detection Layer just flagged as a gap.

An LLM (Sonnet, adaptive thinking) works through a fixed six-phase framework
and translate all of that into concrete rule-design guidance, at the level 
of required/supporting/negative conditions — not Sigma syntax, which is left 
to the Defender.

This exists because an LLM asked to "write a rule that catches these three events"
will overfit to exactly those three events.

Produces a DetectionStrategy, consumed directly by the Defender.

#### Features:

Sits between the detection layer's gap output and the defender agent. Model: Sonnet
5, adaptive thinking enabled — it's doing real judgment work (classifying evidence,
assessing false-positive risk), as opposed to the defender's more mechanical
translation step, where thinking is disabled.

The system prompt walks the model through six phases in order: establish the
technique's actual mechanical objective; think through adjacent behavior (what
precedes it, what follows it, what interchangeable tooling exists) *before* looking at
the evidence, specifically so detection opportunities aren't limited to the one
observed procedure; classify each evidence field as **artifact** (test-specific, never
anchor on it), **instance** (one example of a detectable class — must name the class
explicitly), or **invariant** (structurally required by the technique regardless of
tooling — the actual anchor); rank and score detection opportunities by coverage gain,
precision, viability, and FP risk; build a field-specific false-positive profile; and
finally produce concrete rule-design guidance (required conditions, supporting
conditions, negative conditions, FP filters) — deliberately at the level of detection
logic, not Sigma syntax, leaving translation to the defender.

Two hard checks are embedded directly in the reasoning framework rather than left
implicit: a same-event plausibility check (before combining two fields with AND,
explicitly confirm both could appear on one log line from one process invocation —
otherwise use OR, or split into two separate opportunities), and a filter-breadth
check (don't default to umbrella exclusions like all of Program Files; reason through
whether the thing being excluded could plausibly be abused before excluding it).

If evidence is degenerate — fewer than 2 distinct events after deduplication — the
prompt instructs the model to weight technique knowledge over observed values rather
than risk overfitting a rule to one data point.

Output is a `DetectionStrategy`, consumed directly by the defender agent. This stage
is additive: on any LLM or parse failure it returns `None`, and the defender falls
back to its non-enriched prompt path.

### 2.5 Defender Agent — `pipeline/defender/agent.py`, `prompts.py`
Consumes the same GapContext, the Planner's strategy if it's available, and
summarized existing rules for the technique.

An LLM (Sonnet) produces a candidate rule as schema-constrained JSON.
Deterministic metadata (ID, date, status, the MITRE reference URL) is filled in by
code afterward, not generated. On a validation failure, it retries with the specific
gate feedback — up to 2 attempts normally, 3 if the failure was a gate failure
specifically rather than a schema-lint failure.

This is the stage actually accountable for what ships — the Planner's guidance shapes
it, but the candidate still has to survive validation regardless of how it got there.

Produces a candidate Sigma rule, handed to validation within this same retry loop.

#### Features:

Model: Sonnet 5. Receives a `GapContext` (technique, missed events, existing rules for
that technique — summarized to title + detection block only, to control token cost
across retries — and, if available, the planner's `DetectionStrategy`). Output is
schema-constrained JSON (`output_config.format` / json_schema); `id`, `date`,
`status`, and `references` are filled in after the LLM call rather than generated by
the model, since those are deterministic values that don't benefit from spending
tokens or giving the model a place to get something trivially wrong.

The system prompt encodes a specific set of detection-engineering positions, applied
whether or not the planner's enriched strategy is present:

- **Write to the behavior, not the artifact** — a rule keyed on `powershell.exe`
  breaks the moment the binary is renamed; a rule keyed on "script interpreter loading
  encoded content from a user-writable path" doesn't.
- **No field is unspoofable identity.** When writing an identity or exemption
  condition, a field describing an inherent property of the entity itself (its own
  `Image`) is preferred over one describing its relationship to something else
  (`ParentImage`, `CurrentDirectory`) — relational fields are set by the caller and
  are attacker-influenceable regardless of whether the entity itself is genuine.
  `CurrentDirectory` is explicitly disallowed for any security-relevant scoping.
- **Filter honesty** — name and scope a filter for what it literally matches, not what
  it's intended to represent (`Image|startswith: 'C:\Program Files\'` exempts
  everything in Program Files, not just the one vendor that was meant).
- **Encoded-content matching requires a behavioral anchor, never shape alone.** A
  base64/hex-shaped regex by itself will match benign data (GUIDs, hashes, tokens,
  certificates) at least as often as malicious payloads. Every encoded-content
  selection must pair with a corroborating condition.
- **Single-event scope, enforced as a hard check.** Rules evaluate one event at a
  time — no cross-event correlation. Before ANDing two field values, confirm both
  could plausibly appear together in a single event from the same process invocation;
  if the two artifacts come from separate, sequential commands, use OR instead of
  faking co-occurrence that will rarely or never actually match real telemetry.
- **Filter breadth — avoiding blind spots, treated as a hard check.** The prompt
  explicitly warns against umbrella exclusion filters: excluding an entire directory
  (Program Files) or failing to account for LOLBin/admin-tooling abuse can let a rule
  correctly identify malicious activity and then silently let it through anyway via
  its own false-positive filter. The same check is mirrored in the Detection Planner's 
  prompt (§2.4).

The retry budget is not flat: `MAX_RETRIES = 2` by default, but
`MAX_RETRIES_GATE_FAILURE = 3` when a retry is triggered specifically by
`attack_gate` or `noise_gate` failing rather than `schema_linter` — a lint failure
indicates a prompt-quality problem, not something more attempts fixes; a gate failure
on an otherwise sound rule is more plausibly one specific detail away from passing.

### 2.6 Validation — `pipeline/validation/`
Consumes a candidate rule, the attack sample, and the benign corpus.

Three gates run in sequence, all required to pass. The schema linter checks every
field the rule actually references against the real log schema. The attack gate 
runs the rule against the real attack sample and requires every single event to match.
The noise gate runs the rule against the relevant slice of the benign corpus 
and requires the false-positive rate to stay under 1%. Any failure returns
specific, structured feedback — not just pass/fail — that goes straight into the
Defender's next retry attempt.

This exists because an LLM-authored rule isn't trustworthy by default. This is the
actual boundary between "the model produced something" and "a human ever sees it."

Produces a pass/fail verdict; only a pass proceeds to PR creation.

#### Features:

Runs inside the defender agent's own retry loop via `validation_pipeline.validate()`.
Three gates, sequential, all must pass:

- **`schema_linter.py`** — extracts every field the candidate rule actually
  references (via pySigma's own parsed `SigmaDetectionItem.field`) and checks each
  against the `LogEvent` model's known fields. Invalid fields get a close-match
  suggestion via `difflib.get_close_matches()` — Python's standard-library fuzzy
  string matcher — so a typo'd field name comes back with the actual valid field name
  in the retry feedback rather than leaving the model to guess again blind.

- **`attack_gate.py`** — runs the candidate against the emulated attack sample,
  asserts it fires, `min_match_ratio=1.0` by default (every event must match). 
  Matched/unmatched comparison is done by content hash rather than object 
  identity: events reconstructed from SQLite query rows and the original 
  Pydantic-model events are separate Python objects in memory even when they represent 
  the exact same logical event, so comparing them by object identity would always 
  report "different" even for a genuine match. Hashing their actual field content 
  instead sidesteps that. On a partial match, feedback shows both matched and unmatched 
  events side by side, so the defender can directly compare what currently works 
  against what doesn't.

- **`noise_gate.py`** — runs the candidate against the benign corpus, asserts the
  false-positive rate stays under threshold (default 1%). Corpus subdirectory
  selection is driven by the EventIDs actually present in the attack sample.
  process-creation rule only gets tested against the `process/` corpus, supplemented by
  `benign_generator`'s synthetic events for corpus depth.

### 2.7 PR Creator — `pipeline/github/pr_creator.py`
Consumes a validated rule, its evidence, and the reasoning behind it.

Opens or updates a pull request via the GitHub API directly. A regression 
fixture is also written from the attack sample, which is what every future
rule change gets tested against in CI.

This exists because the entire premise of the system is that a human reviews the
final output rather than anything shipping unsupervised — this stage is what actually
creates that review surface, evidence attached.

Produces a GitHub pull request, and a regression fixture that closes a separate,
longer-running loop.

#### Features:

Opens a GitHub PR per validated rule via the GitHub API — no local git operations for
the write side. Branch naming is `rule/{technique_id}`, stable and reused across runs
rather than creating a new branch each time, so a technique's PR history stays on one
branch. Rule content and PR body are both diffed against what's already committed; a
PR is skipped entirely if neither changed.

If a human closed a prior PR for the same technique without merging it, the rejected
rule file(s) still exist on the branch. Before opening the next PR, `create_pr()`
removes them via a dedicated commit.

If an `attack_sample` is supplied, `create_pr()` also writes or updates a regression
fixture at `tests/fixtures/regression/{rule_filename_stem}/attack_sample.jsonl`, as a
separate additive commit — this is what `regression.yml` (§4) later runs against on
every future PR touching `rules/`.

A companion module, `rules_sync.py`, handles the read side this creates: since
`pr_creator.py` writes exclusively via the API, the local `rules/` checkout would go
stale as PRs merge outside of any local `git pull`. `rules_sync.py` runs before every
pipeline run, comparing local files against GitHub via git blob SHA — an unchanged
file costs nothing, no extra API call, no rewrite — and pulls down anything that's
actually different. A sync failure logs and continues rather than aborting the run.

### 2.8 Corpus stress-test — `pipeline/corpus/`
Consumes whatever rules validated during this iteration — only runs at all if there's
at least one.

An LLM generates a few distinct, realistic benign activity scripts specifically 
designed to exercise each rule's detection logic from the legitimate side, and 
that script is pushed to trigger a real GitHub Actions Windows runner — actually 
executing PowerShell and producing real telemetry, not synthetic LLM output. 

This exists because everything up to this point — even most of the benign corpus —
has only ever been tested against data generated by the same system that wrote the
rule. This is the one point where a rule meets something genuinely independent of the
system being evaluated.

Produces real telemetry committed into the benign corpus for future noise-gate runs,
and an outcome record the next iteration checks back on.

#### Features:

Triggered from inside the orchestrator's own iteration loop — conditionally, only if
at least one rule validated that iteration — right after that iteration's PR-creation
attempts. What it triggers runs somewhere else entirely: a real PowerShell script,
executed on a live GitHub Actions Windows runner, generating real telemetry rather
than synthetic LLM-authored events.

The chain: `parser.py` extracts structured features (operator structure, referenced
fields, EventIDs, inferred `AND`/`OR`/`MIXED` logic shape) from each validated rule's
Sigma YAML. `clusterer.py` groups rules by similarity — at this project's scope, with
a deliberately small and distinct set of ATT&CK techniques, generated rules rarely
embed similarly enough to cluster meaningfully, so in practice each rule ends up in
its own singleton cluster. `yaml_generator.py` calls an LLM (Haiku) once per cluster
to produce 2–3 distinct benign activity variants meant to exercise that rule's
detection logic from the *legitimate* side — the prompt explicitly frames this as
"what does a real [IT admin / end user / installer / file operation] workflow
naturally do that produces these event types as a side effect," not "how do I make
attacker behavior look benign," with concrete guidance toward realistic paths and tool
usage. `pusher.py` commits the generated script and a workflow file to a branch and 
triggers it via `workflow_dispatch`; the static `corpus_runner.yml` workflow (§4) 
is what actually executes it and commits the resulting logs back.

The orchestrator does not wait for that GitHub Actions run to finish — it's
deliberately async relative to the main loop. At the start of the *next* iteration,
the orchestrator checks whether the previous iteration's triggered workflow actually
ran and produced new tagged files in `corpus/benign/`, and records that outcome.

This stage currently has script-generation issues and GitHub Actions runner quirks 
meaning the triggered workflow sometimes fails to produce usable logs. Work is in
progress to fix this.

## 3. Infrastructure

### 3.1 Deployment

A single Cloud Run v2 service on GCP (`asia-south1`), scaling to zero between
invocations (`min_instances=0`, `max_instances=1`). Terraform manages 11 resources: a
dedicated service account, four Secret Manager secret containers
(`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `PIPELINE_RUN_SECRET`,
`PIPELINE_VIEWER_SECRET` — containers only; secret *versions* are populated via
`gcloud`, kept out of Terraform state), four corresponding IAM bindings, the Cloud Run
service itself, and a public-invoker IAM binding on that service. `GITHUB_REPO` is
injected as a plain environment variable rather than a secret, since it isn't
sensitive.

### 3.2 FastAPI service — `pipeline/api/app.py`

Three endpoints: `POST /run` (triggers a pipeline run, non-blocking, returns a
`run_id`), `GET /results/{run_id}`, and `GET /health`. Two auth tiers, matching the
two secrets above: `PIPELINE_RUN_SECRET` gates the one cost-incurring endpoint;
`PIPELINE_VIEWER_SECRET` gates the two read-only endpoints. `/health` returning `ok`
means the process is alive and responding — not a claim about recent run success or
detection correctness.

### 3.3 GitHub Actions

Four workflows, each with a distinct trigger model:

- `regression.yml` → `check` — runs every rule in isolation against its frozen
  fixture to test if the rules have regressed or have become more false positive
  prone.
- `regression.yml` → `update-baseline` — recomputes the coverage and FP baseline
  automatically after a merge to main.
- `pipeline.yml` → `run-pipeline` — triggers a live pipeline run against the deployed
  Cloud Run service, polls it, and posts a run summary.
- `collect_benign.yml` → `collect` — generates a week's worth of realistic benign
  Windows telemetry for the noise-gate corpus.
- `corpus_runner.yml` → `run-corpus-scripts` — executes the corpus-learner's
  generated stress-test script and commits the resulting logs.

**`regression.yml`** — two jobs on one file. The `check` job runs on every pull
request; rather than a GitHub-level path filter, it checks relevance itself via a
`git diff` step against `rules/` and `tests/fixtures/regression/`, and skips the
expensive steps entirely if nothing relevant changed. When relevant, it runs every
rule in isolation against its frozen fixture (zero LLM calls, entirely deterministic),
posts the result as a PR comment, and — using `continue-on-error` on the check step
specifically so the comment still posts even on failure — fails the job explicitly in
a separate step afterward if a regression was found. The second job, `update-baseline`,
runs only on push to `main` (i.e., after a PR has merged) and recomputes
`data/coverage_baseline.json` automatically, so the "known good" snapshot never
depends on a human remembering to update it by hand.

**`pipeline.yml`** — `workflow_dispatch`. Three steps, each a dedicated Python script
subcommand rather than inline bash/YAML scripting: `trigger` (`POST /run`), `poll`
(polls `/results/{run_id}` until completed/failed/timeout), `summarize` (writes a
markdown run summary to the GitHub Actions step summary). A final step fails the job
loudly if the run didn't complete successfully, rather than letting a failed pipeline
run report green.

**`collect_benign.yml`** — weekly cron plus manual trigger. Installs Sysmon with the
SwiftOnSecurity config on a `windows-latest` runner, runs a sequence of fixed
baseline activities (process chains, registry reads, outbound network) plus
randomized activity pools (process spawning, registry writes, network/port activity,
scheduled task lifecycle, file operations), exports the resulting event logs filtered
to the run's own time window, commits them into `corpus/benign/`, then uninstalls
Sysmon before the runner is torn down.

**`corpus_runner.yml`** — triggered by a push matching a specific path (the branch the
corpus-learner pushes its generated script to). Installs Sysmon, executes the
generated script, commits the resulting logs, uninstalls Sysmon.

## 4. Known limitations

- **No multi-event correlation.** Sigma Correlations require ES|QL or SPL backends;
  the sqlite3 backend here only supports single-event atomic rules. A technique whose
  detection genuinely depends on sequencing across multiple events can't be expressed.

- **Log source scope is Sysmon only in practice.** Every `LogEvent`, every detection 
  rule, and every corpus source is Sysmon-only.

- **Reproducibility is only partial.** `temperature=0` on LLM calls was the intended
  mechanism for near-deterministic output; Sonnet 5 rejects any non-default
  temperature value outright, so the planner and defender agents (both Sonnet 5) run
  without it.

- **Inevitable hallucination risk exists.** Given that most of the artifacts in 
  the system are generated by LLMs, there's a real risk of hallucinated reasoning
  logs and rules being produced despite multiple checks, grounding and prompt nudges.
  A human in the loop to review the final artifact does mitigate this to an extent.

- **Emulator realism, benign corpus quality, and FP/precision threshold calibration
  are explicit human-judgment calls**, not something the system is designed to
  self-certify.