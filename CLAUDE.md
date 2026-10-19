# CLAUDE.md — dependabot-alert-triager

Plan of record: `docs/VALIDATION_AND_PLAN.md`. Read it before starting any task.

## Workflow

- Work on exactly one task from the Phase 6 table (T0–T11) at a time. When it is done, stop and
  show the "Evidence for done" listed for that task. Do not start the next task until the user
  approves.
- If a task's "Stop and reconsider if" condition is hit, stop and report; do not work around it.
- Ask before adding any dependency (runtime or dev).
- Ask before deleting files or doing anything irreversible (history rewrites, force pushes,
  overwriting data or labels).

## Claims and numbers

- Label claims **FACT** / **PRELIM** / **HYPOTHESIS** (and **REC** for recommendations), as the
  plan does.
- Never invent or estimate a metric. Every number in docs must come from a saved run
  (`runs/<id>/`) or a committed script's output, and must cite it.
- State n, confidence intervals, snapshot SHAs/dates and model id next to every reported metric.

## Evaluation integrity

- Once the test set is frozen (T7), it is never used for tuning prompts, rules or thresholds.
  Tune on dev only.
- Test-set runs happen at most twice (final report, plus one bug-fix rerun if needed). Every
  test-set run is logged with its run id and reason, and a second run is disclosed.

## Verdicts and wording

- The tool's verdicts are `REACHABLE`, `NOT_FOUND` or `UNKNOWN` only.
- The tool never says "safe" or "unreachable", and never closes or dismisses an alert.
  `NOT_FOUND` always comes with its list of blind spots.

## Architecture

- Keep vulnerable-function identification (which function is flawed) separate from reachability
  (does user code get to it), in code (separate modules) and in docs/output.
- No agents, vector DBs, dashboards or servers unless the user approves them after a measured need.

## Data and licensing

- Data from github/advisory-database, pypa/advisory-database and golang/vulndb is CC BY 4.0. Keep
  attribution in README and in any published dataset.
- Snapshots are pinned in `config/snapshots.yaml`. Do not change a pin silently.
- Fix-commit source code belongs to each project: analyse it, cache locally, do not redistribute
  bulk source.

## Local setup

- Python 3.12, managed with `uv`. Run tests with `uv run pytest`, lint with `uv run ruff check`.
- The repo lives on an external drive (APFS); see README "Local setup".
