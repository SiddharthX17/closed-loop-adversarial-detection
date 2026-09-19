# closed-loop-adversarial-detection

[![Health Check](../../actions/workflows/health_check.yml/badge.svg)](../../actions/workflows/health_check.yml)
![Techniques Covered](https://img.shields.io/github/directory-file-count/SiddharthX17/closed-loop-adversarial-detection/rules/generated?type=dir&label=techniques%20covered)
[![Regression Check](../../actions/workflows/regression.yml/badge.svg)](../../actions/workflows/regression.yml)

Most teams measure detection coverage by counting rules. This system measures it by attacking them. 
It runs an autonomous red team-to-blue team detection lifecycle through an eight-stage loop: emulating ATT&CK-aligned attacks, generating synthetic Sysmon logs from that emulation, and running a detection engine against the existing ruleset to identify the attacks and expose gaps. The surfaced gaps are analyzed and closed by generating rules which are validated and improved iteratively through feedback loops before being presented for review as pull requests.

The system runs the same eight-stage loop across multiple iterations:

| Stage | Objective |
|---|---|
| 1. Attacker Agent | **Choose an evasion strategy.** Given an ATT&CK technique, reasons about how an adversary could execute it while sidestepping existing detection, producing intent for both a baseline attack and an evasion variant. |
| 2. Emulator | **Turn attack intent into grounded telemetry.** Synthesizes realistic telemetry events grounded in real Atomic Red Team procedures. |
| 3. Detection Layer | **Run the detection engine to identify coverage gaps.** Evaluates the generated telemetry against the existing ruleset and determines whether the attack is detected, exposing any coverage gap. |
| 4. Detection Planner | **Generalize the gap into detection logic.** Works out durable detection invariants, relevant fields, and false-positive considerations from the observed behavior beyond just the event(s) that revealed it. |
| 5. Defender Agent | **Translate detection guidance into a rule.** Generates a candidate Sigma rule from the planner's guidance, targeting the underlying behavior. |
| 6. Validation *(inside stage 5)* | **Prove the rule works before it leaves the loop.** Checks syntax, confirms the rule fires on the attack, and confirms it stays quiet on benign data; failures feed back into the Defender Agent until the candidate passes. |
| 7. PR Creator | **Package the validated rule for review.** Opens a GitHub pull request with the rule and its supporting evidence, keeping deployment behind a human decision. |
| 8. Corpus stress-test | **Challenge the rule with real noise.** Generates targeted benign activity on real infrastructure to stress tests the new rule. |

The loop then repeats: whatever got caught this round informs how the attacker agent mutates its approach next round.

Full detail on every stage is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Results

Every validated rule ships as a reviewable pull request with evidence and reasoning attached. The rules that were reviewed and approved for deployment can be found in:

- **Generated rules:** [`rules/generated/`](../../tree/main/rules/generated)
- **Merged rule PRs:** [search `is:pr is:merged label:automated`](../../pulls?q=is%3Apr+is%3Amerged+label%3Aautomated)

## Built With

**Language & Validation:** Python 3.11 · Pydantic v2

**AI:** Claude Sonnet 5 · Claude Haiku 4.5 (Anthropic APIs)

**Detection Engine:** pySigma · pysigma-backend-sqlite · pysigma-pipeline-sysmon · SQLite

**Grounding Data:** Atomic Red Team · MITRE ATT&CK (STIX) · SigmaHQ

**API Layer:** FastAPI

**Infrastructure:** Google Cloud Run v2 · GCP Secret Manager · GCP Artifact Registry · Terraform · Docker

**CI/CD:** GitHub Actions · PyGithub


## Quick Start

The pipeline runs live on Cloud Run, gated behind a shared secret. 
If you want to actually trigger a run please ask for access.

**Getting a secret:** open an issue, or reach out directly.

### Trigger a run

```bash
curl -X POST https://<cloud-run-url>/run \
  -H "X-Pipeline-Run-Secret: <your run secret>" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_ids": ["T1059.001"],
    "max_iterations": 2
  }'
```

`technique_ids` are MITRE ATT&CK technique IDs.
`max_iterations` is 1 to 3. 

Returns immediately (HTTP 202) with a `run_id`


```bash
curl https://<cloud-run-url>/results/<run_id> \
  -H "X-Pipeline-Viewer-Secret: <your viewer secret>"
```

Once completed, this includes per-technique coverage, any PR URLs opened, and per-iteration detail.


## License

MIT, see [`LICENSE`](LICENSE.txt).