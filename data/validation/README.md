# data/validation

Phase 2 validation data (`docs/VALIDATION_AND_PLAN.md` §2). Advisory content is derived from
[github/advisory-database](https://github.com/github/advisory-database), © GitHub, Inc., licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

| File | Produced by | Notes |
|---|---|---|
| `g1_coverage.json` | `scripts/count_vulnerable_functions.py` (T1) | Live GitHub REST API, 2026-10-19. The only file here not from the pinned snapshot. |
| `sample_v1.txt` | `scripts/sample.py` (T2) | 50 advisory IDs. Header records snapshot SHA, seed, pool definition and size, cap, and the sha256 of `config/package_families.yaml` used. Never resampled silently: the script refuses to run if a fresh draw differs. |
| `family_review.yaml` | `scripts/sample.py` (T2) | Candidate package families for human review; nothing in it is applied. |
| `labels_v1.csv` | `scripts/sample.py` (T2), then hand-labelled | One row per sampled advisory. The script never overwrites it once it exists. |
| `fix_commits_v1.csv` | `scripts/resolve_fix_commits.py` (T3) | One row per sampled advisory: fix-commit resolution and per-check verification. Kept separate from `labels_v1.csv` so hand labelling and scripts never write the same file. |
| `fix_commit_candidates_v1.csv` | `scripts/resolve_fix_commits.py` (T3) | One row per candidate commit checked (several per advisory possible). |
| `manual_fix_candidates.csv` | Hand-maintained (optional) | Columns `ghsa_id, commit_url, how_found`. Read by `scripts/resolve_fix_commits.py`; each row gets the same four checks with source `manual`. |
| `diff_baseline_v1.csv` | `scripts/diff_baseline.py` (T4) | Diff-baseline candidate symbols, one row per advisory with a verified fix (22). Not scored. |
| `diff_baseline_symbols_v1.csv` | `scripts/diff_baseline.py` (T4) | One row per (advisory, symbol, commit, file) with the pre-fix line numbers that mapped to it. |
| `diff_baseline_v1.meta.json` | `scripts/diff_baseline.py` (T4) | Provenance and the distribution of function counts. |
| `symbol_tables/<ghsa_id>.json.gz` | `scripts/build_symbol_tables.py` (T5) | AST symbol table of the affected package at its vulnerable ref (gzipped JSON: repo, `ref_kind`, `ref`, `commit`, import roots, unparsed files, symbols with kind/file/lines). |
| `symbol_tables_v1.csv`, `symbol_tables_v1.meta.json` | `scripts/build_symbol_tables.py` (T5) | One row per sampled advisory: ref used and symbol counts, or why no table was built. |
| `text_baseline_v1.csv` | `scripts/text_baseline.py` (T5) | Text-baseline predictions per advisory (exact + unique-suffix matches only). Not scored. |
| `text_baseline_matches_v1.csv`, `text_baseline_v1.meta.json` | `scripts/text_baseline.py` (T5) | Every extracted string with its pattern(s), match type and candidate symbols; hit counts. |
| `fix_commits_v1.meta.json` | `scripts/resolve_fix_commits.py` (T3) | Provenance (snapshot, repo commit, run time, API auth) and counts. |

Snapshot: github/advisory-database `b16e369438ef2ab329b4c224cae8224f144bf5d5` (2026-10-19), as
pinned in `config/snapshots.yaml`. Pool: github-reviewed, affects PyPI, published >= 2025-01-01,
not withdrawn (2,953 advisories; no two share a CVE alias, so no units were merged).

## `labels_v1.csv` columns

Multi-valued cells are separated by `; `.

### Pre-filled mechanically by `scripts/sample.py`

| Column | Source |
|---|---|
| `ghsa_id` | OSV `id` of the sampled advisory (the unit representative if CVE aliases ever merge advisories). |
| `aliases` | OSV `aliases` (CVE / PYSEC ids), plus ids of any merged advisories. Empty when the record has none. |
| `published` | OSV `published`. |
| `package_family` | Family of each PyPI package under `config/package_families.yaml` (confirmed families only); otherwise the PEP 503-normalised package name. |
| `packages` | `affected[].package.name` where ecosystem is PyPI, PEP 503-normalised. |
| `github_vulnerable_functions` | Always `[]`. Not looked up per advisory: T1 found the field empty on every reviewed pip advisory published >= 2025-01-01 (0 of 3,118; `g1_coverage.json`, commits `e19a648` / `903e518`). |
| `fix_commits` | OSV `references` URLs matching `github.com/<owner>/<repo>/commit/<sha>` or `.../pull/<n>`, in reference order, deduplicated. **Unverified candidates only**: a PR link is not yet a commit, and nothing has been checked against tags (that is T3). |
| `package_type_proposed` | **Helper, heuristic.** Proposal from `triager.package_type.propose`: regex signals on advisory summary + details, and PyPI summary/classifiers. The type with the most signals wins; ties go by `model_format > native_ext > application > cli > library`; no signals → `other`. |
| `package_type_reason` | **Helper.** Every signal that fired, per type (`text:*` from the advisory, `pypi:*` from PyPI). PyPI metadata is live (fetched 2026-10-19, cached in `data/cache/pypi/`), not pinned. |

### Filled later by tasks

| Column | Filled by |
|---|---|
| `fix_commit_source`, `fix_verified`, `diff_files_total`, `diff_files_src` | T3 writes these to `fix_commits_v1.csv` (same column names, keyed by `ghsa_id`), not into this file. |
| `diff_funcs_changed_src` | T4 (diff baseline). |

### Filled by hand (left empty by the script)

`package_type`, `usable`, `unusable_reason`, `text_names_function`, `named_symbols_text`,
`gold_vulnerable_symbols`, `gold_entry_points`, `label_confidence`, `label_basis`,
`minutes_spent`, `labeler`, `notes`. Allowed values are in plan §2.2. `package_type` is the
human label; `package_type_proposed` is only a hint and must not be copied without checking.

## `fix_commits_v1.csv` columns (T3, plan §2.3)

Resolution runs in order and falls through only if the earlier stage yields no verified commit:
`reference` (commit URLs in references) → `pr_merge` (PR URL → merge commit via the GitHub
REST API, responses cached) → `tag_diff_inferred` (commits between the last affected and first
fixed tags whose message contains the GHSA or a CVE id; lower trust). Rows from
`manual_fix_candidates.csv` are then always checked as source `manual`, a separate trust level;
they set `fix_commit_source = manual` only if no automated candidate verified.

| Column | Meaning |
|---|---|
| `repo` | GitHub `owner/repo` of the selected candidate. |
| `fix_links_commit`, `fix_links_pr`, `fix_commits_linked` | Number of commit / PR links in the advisory references, and their sum. |
| `stages_tried` | Resolution stages attempted. |
| `fix_commit_source` | Stage that produced the verified commit(s): `reference` / `pr_merge` / `tag_diff_inferred` / `manual`, or `none`. |
| `fix_verified` | `yes` if at least one candidate passed all four checks. |
| `fix_commits` | Verified SHAs; if none verified, the best candidate (most checks passed). |
| `check_repo_matches_pypi` | Candidate repo is among GitHub repos in the PyPI project URLs / home page (cached PyPI JSON). |
| `check_in_fixed_tag` | Commit is an ancestor of the first fixed release tag of some affected range (`git merge-base --is-ancestor`). |
| `check_not_in_affected_tag` | Commit is not an ancestor of the last affected release tag of that range (OSV `last_affected` / GHSA `<=` bound if given, else the highest stable tag below the fixed version and at or above `introduced`). |
| `check_changes_src` | Commit changes at least one non-test, non-doc source file (`triager.fixcommit.classify`). |
| `fixed_version`, `fixed_tag`, `last_affected_tag` | Versions and tags used by the containment checks. |
| `diff_files_total`, `diff_files_src`, `diff_files_test` | Files changed (against first parent), union over the verified commits (or the best candidate). |
| `failure_reason` | For unverified advisories: failing checks of the best candidate, their details, and resolution errors. |

Check values: `pass` / `fail` / `unknown`. `unknown` (e.g. no tag found for a version, PyPI
lists no GitHub repo) does not count as a pass. Known limits: a "source file" is any code file
outside test/doc paths anywhere in the repo, not only inside the affected package's directory;
tag/version matching handles a PEP 440 subset and common tag prefixes only.

## `diff_baseline_v1.csv` columns (T4)

Method: `triager.baselines.diff` (module docstring). Vulnerable-function *identification* only;
nothing here concerns reachability. Symbols are fully qualified (`pkg.mod.Class.method`; nested
functions as `pkg.mod.outer.<locals>.inner`; module-level code as `pkg.mod.<module>`).

| Column | Meaning |
|---|---|
| `import_roots`, `import_root_method` | Repo directories treated as the affected package's import path; `auto:<variant>` (matched PyPI-name variant), `override` (`config/import_paths.yaml`) or `unresolved`. |
| `files_changed` | Files changed by the fix commit(s). |
| `files_python_in_scope` | Python files inside the import root(s) that were analysed. |
| `files_non_python_in_scope` | Non-Python source inside the import root(s) (C, Cython, templates...): not mapped to symbols. |
| `files_out_of_scope` | Counts by reason: `outside_import_root`, `test`, `doc`, `example`, `packaging`, `other`. |
| `unparsed_files` | In-scope Python files whose pre-fix version failed `ast.parse`. |
| `new_files` | In-scope Python files added by the fix (no pre-fix version, so no symbols). |
| `n_functions`, `functions` | Function/method candidates. |
| `n_classes`, `n_module`, `classes_and_modules` | Class-body and module-level changes, kept separate from function candidates. |

## Symbol tables and text baseline (T5)

Vulnerable ref (`ref_kind`): `fix_parent` = first parent of the verified fix commit;
`last_affected_tag` = highest last-affected release tag over the advisory's ranges (from a
fixed version, or a GHSA `<=` bound); `latest_tag_unfixed` = no fix listed, newest stable tag
at or above `introduced`. Symbol names follow the T4 conventions (`pkg.mod.Class.method`,
`pkg.mod.outer.<locals>.inner`, `pkg.mod.<module>`); files are the package's Python files
under its import root(s), excluding tests, docs, examples and packaging files.

Text baseline match types: `exact` (full qualname or module path), `unique_suffix` (one symbol
ends with the string, `<locals>` ignored; leading `self.`/`cls.` or the package's own
top-level name may be dropped), `ambiguous` (several candidates, listed, not predicted),
`unresolved`. `scripts/check_gold.py` validates hand-filled gold symbols against these tables.
