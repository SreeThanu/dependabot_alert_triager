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
| `fix_commit_source`, `fix_verified`, `diff_files_total`, `diff_files_src`, `diff_funcs_changed_src` | T3 / T4 (fix-commit resolver and diff baseline), per plan §2.3 |

### Filled by hand (left empty by the script)

`package_type`, `usable`, `unusable_reason`, `text_names_function`, `named_symbols_text`,
`gold_vulnerable_symbols`, `gold_entry_points`, `label_confidence`, `label_basis`,
`minutes_spent`, `labeler`, `notes`. Allowed values are in plan §2.2. `package_type` is the
human label; `package_type_proposed` is only a hint and must not be copied without checking.
