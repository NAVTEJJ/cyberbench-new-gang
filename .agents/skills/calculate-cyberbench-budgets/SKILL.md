---
name: calculate-cyberbench-budgets
description: Calculate reproducible time, cost, token, and turn budget frontiers from Harbor jobs artifacts, with separate CTF and memory-vulnerability populations and a task-level headroom review queue. Use when someone points to a jobs folder and wants an HTML visualization, machine-readable analytics, timeout recommendations, repeated zero-solve candidates, or evidence for configuring benchmark budgets.
---

# Calculate Cyber-Bench Budgets

Generate the report with the bundled standard-library script, then use the raw
artifacts to separate genuine model headroom from harness and environment
failures. Do not run models or interact with challenge targets.

## Run The Calculator

Resolve this skill's directory, then run:

```bash
python <skill-directory>/scripts/calculate_job_budgets.py \
  /path/to/jobs \
  --output /path/to/resources/job-budget-analysis
```

If the project requires a virtual environment, activate it before invoking
Python. The script itself has no third-party dependencies.

Optional controls:

```bash
python <skill-directory>/scripts/calculate_job_budgets.py \
  /path/to/jobs \
  --preserve 0.95 \
  --minimum-headroom-attempts 2
```

When `--output` is omitted, write to `<jobs>/.budget-analysis`.

The calculator recursively reads trial `result.json` files plus sibling
`verifier/details.json` and `agent/trajectory.json` files. It emits:

- `index.html`: self-contained visualization.
- `summary.md`: concise category recommendations and candidate tables.
- `summary.json`: complete structured report.
- `trials.csv`: normalized trial-level evidence.
- `headroom_tasks.csv`: task-level statuses and failure resource evidence.

## Interpret Budget Frontiers

Always report CTF and memory-vulnerability results separately. The task identity
markers `memory-vuln-bench/`, `memory_vul_`, `memory-vul`, and `memvul_` map to
`mem-vul`; other named tasks map to `ctf`.

Use each category's `operational_policy.caps` as the proposed production budget
tuple:

- `agent_seconds`
- `cost_usd`
- `total_tokens`
- `turns`

The raw practical cap is the smallest observed successful value retaining the
requested fraction of solves. The operational cap rounds that value upward to
a deployable increment. The hard ceiling is the largest successful value in
the observed snapshot.

State sample counts and joint solve retention beside every recommendation.
Treat a category with fewer than 10 solves as provisional. Do not combine the
two categories, and do not use failed maxima as recommended caps.

## Qualify Headroom Tasks

Use `headroom_tasks.csv` or each category's `headroom.tasks` list in
`summary.json`.

Task statuses mean:

- `candidate_review`: at least the requested number of eligible attempts and no
  verified solve.
- `mixed`: both solves and failures; useful for calibration, but not pure
  headroom across the observed model mix.
- `solved`: all eligible attempts solved.
- `insufficient_data`: too few zero-solve attempts to nominate.

`candidate_review` is a queue, not a verdict. For each leading candidate:

1. Open the listed `example_result_paths`.
2. Inspect `agent/trajectory.json`, verifier details, exception metadata, and
   service or container evidence available in that trial.
3. Classify the failure as `model`, `environment`, `harness`, `verifier`,
   `ambiguous`, or `insufficient_evidence`.
4. Confirm the task has a deterministic verifier and demonstrated
   human/reference solvability.
5. Confirm multiple attempts made substantive progress rather than failing on
   missing tools, startup errors, credentials, networking, or malformed task
   packaging.

Accept a task as benchmark headroom only when environment, harness, and verifier
causes have been ruled out and meaningful model attempts still fail. Prefer
evidence across multiple capable models. Otherwise mark it for repair or more
calibration.

## Configure Headroom Runs

Start headroom calibration with the category's proposed production budget tuple.
Use the category hard ceilings only as an explicit qualification run when the
sample supports them; do not silently make those ceilings the default.

When changing one budget axis, record all four observed resource values because
the first enforced limit can censor the others. Re-run this calculator after
new calibration jobs and compare:

- whether new solves move the practical cap,
- whether joint solve retention changes,
- whether candidates move from `candidate_review` to `mixed`,
- whether failures continue consuming resources beyond the proposed cap.

The final recommendation should contain:

- category-specific budget tuples,
- solve counts and joint retention,
- accepted headroom tasks with failure classifications,
- rejected or ambiguous candidates with reasons,
- exact jobs and report paths used.

## Guardrails

Exclude oracle runs, multi-service fractional trials, active or unverified
trials, pre-agent failures, and infrastructure errors from budget estimation.
Keep unknown-category trials visible in coverage, but do not merge them into
CTF or mem-vul policy.

Do not claim causality from this retrospective analysis. Task mix, model mix,
provider accounting, and run configuration can all move the observed frontier.
