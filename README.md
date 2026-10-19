# dependabot-alert-triager

Conservative triage of Dependabot alerts for Python (PyPI) library advisories. Two questions are
kept separate throughout:

- **Vulnerable-function identification** — which function in the dependency contains the flaw?
- **Reachability** — does the user's code get to it?

Verdicts are `REACHABLE`, `NOT_FOUND` or `UNKNOWN` only. The tool never declares an alert safe and
never dismisses one.

Status: early setup (task T0). No results yet. Plan: `docs/VALIDATION_AND_PLAN.md`.

## Local setup

Requires [uv](https://docs.astral.sh/uv/). The project uses a uv-managed CPython 3.12
(`python-preference = "only-managed"` in `pyproject.toml`); install it once with
`uv python install 3.12`.

```bash
uv sync
uv run pytest
uv run ruff check
```

**Drive / file system note.** This repo is kept on an external drive ("thanu's T7"). On
2026-10-19 `diskutil info` reported `File System Personality: APFS` for that volume, so the
virtual environment lives in the repo as usual (`.venv/`, git-ignored). No
`UV_PROJECT_ENVIRONMENT` override is needed.

If the repo is ever moved to an exFAT volume (which does not support the symlinks and metadata a
venv relies on, and litters `._*` files), keep the repo there but put the environment on the
internal disk:

```bash
export UV_PROJECT_ENVIRONMENT="$HOME/.venvs/dependabot-triager"
uv sync
```

uv may warn "Failed to hardlink files; falling back to full copy" because its cache is on the
internal disk and the repo is on another volume. It is harmless; silence it with
`export UV_LINK_MODE=copy`.

## Data and attribution

scripts/survey_ghsa.py produced the FACT numbers in docs/VALIDATION_AND_PLAN.md Phase 1.1 against the github/advisory-database snapshot in config/snapshots.yaml; it is kept unchanged for provenance.

Pinned snapshots are listed in `config/snapshots.yaml`.

This project uses data from:

- [github/advisory-database](https://github.com/github/advisory-database) — © GitHub, Inc.,
  licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- [pypa/advisory-database](https://github.com/pypa/advisory-database) — Python Packaging
  Authority, licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- [golang/vulndb](https://github.com/golang/vulndb) — data licensed
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (code in that repo is BSD).

Any dataset published from this project carries the same attribution. Fix-commit source code
belongs to each upstream project under its own licence and is not redistributed.
