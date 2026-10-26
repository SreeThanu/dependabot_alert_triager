# Validation (Phase 2) — results

Go / no-go checks G1–G5 from `docs/VALIDATION_AND_PLAN.md` §2.6. Labels: **FACT**, **PRELIM**,
**HYPOTHESIS** as in the plan. Every number cites the file and commit that produced it.

**Data source from here on.** G1 below is the only measurement taken from the live GitHub REST
API. All later analysis (sampling, labelling, baselines) uses the pinned
github/advisory-database snapshot in `config/snapshots.yaml`
(`b16e369438ef2ab329b4c224cae8224f144bf5d5`, 2026-10-19), not the live API.

---

## G1 — GitHub-curated `vulnerable_functions` coverage

Source: `data/validation/g1_coverage.json`, produced by `scripts/count_vulnerable_functions.py`
at commit `e19a648` (output committed in `903e518`). Query: `GET /advisories`,
`ecosystem=pip&type=reviewed`, API version `2022-11-28`, unauthenticated, cursor pagination.
Pages fetched 2026-10-19 12:56–13:33 UTC.

Definition: an advisory counts if any entry in its `vulnerabilities` list has
`package.ecosystem == "pip"` and a non-empty `vulnerable_functions` list.

| Window | `published` filter | Advisories | Withdrawn | With `vulnerable_functions` | Label |
|---|---|---|---|---|---|
| 2025 onward | `>=2025-01-01` | 3,118 | 164 | **0** | FACT |
| Vulnerable-calls feature live | `2022-04-14..2024-12-13` | 2,363 | 52 | **0** | FACT |

- **FACT:** The `vulnerable_functions` key is present on every vulnerability entry returned
  (3,724 entries in the 2025-onward window, 4,338 in the 2022–2024 window, all ecosystems), and it
  is an empty list on every one of them. The zero is therefore not caused by a missing field or a
  parsing error. Every advisory returned fell inside the requested window
  (`published_outside_window = 0`).
- **HYPOTHESIS:** GitHub cleared the curated function data when it retired the Python
  vulnerable-calls feature (docs removed 2024-12-13), or never exposed it through the public API.
  Advisories published while the feature was live are also empty, which fits either explanation.
  The public API cannot distinguish them; untested.
- G1 is defined on L (usable library-type advisories in the 50-sample). L is a subset of the
  2025-onward pool, where coverage is 0, so G1 on L is 0% regardless of how L turns out.

**G1: Proceed (0% < 30%).**

---

## G4 definition (recorded before computing)

Recorded 2026-10-19, after T3 (fix-commit resolution, `data/validation/fix_commits_v1.csv`) and
before any usable labels exist. G4 has not been computed.

**G4 = verified fixes / usable library advisories that list a fixed version.**

- Numerator: advisories in that denominator with `fix_verified = yes` in
  `fix_commits_v1.csv` (all four checks pass).
- Denominator: advisories in the 50-sample with `usable = yes` and `package_type = library`
  (hand labels in `labels_v1.csv`) whose OSV record lists a fixed version in the pinned snapshot.
- Advisories with no fixed version at snapshot time are reported separately as **unfixed**. They
  are labelled from advisory text and code reading only; the diff baseline does not apply to
  them. They are not counted in G4's numerator or denominator.
- Thresholds are unchanged from the plan (§2.6): Proceed ≥ 70%, Modify 50–70%, Abandon < 50%.

---

## Classification of the 50-sample (`package_type`, `usable`)

Source: `data/validation/labels_v1.csv` at `718b06f`; proposals in
`data/validation/classify_proposals_v1.csv` (meta: `classify_proposals_v1.meta.json`).

- **FACT:** Classification: 50 proposed by Claude (Claude Code, model `claude-opus-5-5`), reviewed
  by a human, 0 overrides (`classify_source`: accepted 50, overridden 0).
- **FACT:** `package_type` counts (n = 50): application 24, library 20, cli 2, native_ext 2,
  other 1, model_format 1. Usable: 22 (library 20, native_ext 2); unusable 28 (APP 24, OTHER 4).

Counts from `data/validation/g2_g4_v1.json` (`scripts/g2_g4.py`, run at `051d10f`).

---

## G2 — L as a share of the sample

Source: `data/validation/g2_g4_v1.json`, produced by `scripts/g2_g4.py` at `051d10f`. Inputs:
`labels_v1.csv` (sha256 `3086d363…`), pinned snapshot `b16e369` (2026-10-19). 95% intervals are
Wilson score intervals.

L uses the recorded definition: `usable = yes` and `package_type = library`.

| View | L | n | G2 | 95% CI | Label |
|---|---|---|---|---|---|
| **L (library) — primary** | 20 | 50 | **40.0%** | 27.6–53.8% | FACT |
| library + native_ext (secondary) | 22 | 50 | 44.0% | 31.2–57.7% | FACT |

- **PRELIM:** n = 50; the interval is wide. Its lower bound (27.6%) is above the 25% Proceed line.

**G2: Proceed (40% ≥ 25%).**

---

## G4 — verified fix commits for L

Source: `data/validation/g2_g4_v1.json` (`scripts/g2_g4.py` at `051d10f`), from
`data/validation/fix_commits_v1.csv` (sha256 `0e5b14a1…`) written by
`scripts/resolve_fix_commits.py` at `04ee527` (run 2026-10-26 13:03 UTC; meta
`fix_commits_v1.meta.json`). Definition as recorded above. Denominator: L advisories that list a
fixed version in snapshot `b16e369`. 95% intervals are Wilson score intervals.

G4 is reported twice: **automated-only** (sources `reference`, `pr_merge`, `tag_diff_inferred`)
and **including manual** fix candidates (`data/validation/manual_fix_candidates.csv`, human
picks, checked with the same four checks).

| View | Denominator | Automated-only | 95% CI | Including manual | 95% CI | Label |
|---|---|---|---|---|---|---|
| **L (library) — primary** | 17 | **12/17 = 70.6%** | 46.9–86.7% | **16/17 = 94.1%** | 73.0–99.0% | FACT |
| library + native_ext (secondary) | 19 | 14/19 = 73.7% | 51.2–88.2% | 18/19 = 94.7% | 75.4–99.1% | FACT |

Verified by source, primary view (n = 17): reference 11, tag_diff_inferred 1, manual 4; not
verified 1. Secondary view (n = 19): reference 13, tag_diff_inferred 1, manual 4; not verified 1.
Unfixed (no fixed version at snapshot time, excluded from both): GHSA-3hh9-752g-5g22 (lmcache),
GHSA-9cfw-f3f9-7mm7 (apscheduler), GHSA-rpqr-j937-6qr9 (openviking).

Manual fixes (all four checks pass; `fix_commit_candidates_v1.csv`):

| Advisory | Commit(s) | how_found |
|---|---|---|
| GHSA-wrpj-755p-x363 (apache-airflow) | `a8c12067fbe9` | PR #63704. Tags overridden to `providers-databricks/7.12.0` / `7.11.0`: GHSA package/range does not match any release line (data defect); see `docs/upstream_reports/GHSA-wrpj-755p-x363.md` |
| GHSA-5rvq-cxj2-64vf (python-multipart) | `d69df35cd2ca` | commit title matches advisory (separator fix) |
| GHSA-7545-fcxq-7j24 (gitpython) | `25ba54dd3fb3`, `4af8463cca31` | fix + review follow-up in same change |
| GHSA-6rfw-mq36-jm8h (bedrock-agentcore) | `ed953b58a96b` | allowlist fix for install_packages() |

Not verified: **GHSA-f2h6-7xfr-xm8w (praisonai)**: fix not found in the advisory's tag range
(the only commit doesn't touch recipe/registry.py). The range `v4.5.127..v4.5.128` contains one
commit, `b4e3a8a84ade` "Release v4.5.128".

- **PRELIM:** Automated-only G4 on the primary view (70.6%) is just above the 70% Proceed line,
  and its interval (46.9–86.7%) reaches into the Abandon band. With manual picks the point
  estimate is 94.1% and the lower bound (73.0%) clears 70%.
- **FACT:** The manual picks were made by a human from lists of commits (sha, date, title, files
  changed) between the last affected and fixed tags; the lists did not include baseline outputs.
  They are a human judgement, not an automated result; the automated-only figure is what the
  pipeline achieves unaided.

**G4: Proceed (70.6% automated-only ≥ 70%; 94.1% including manual).** The automated figure is
borderline at n = 17; the plan's fallback for 50–70% (lean more on text and code-reading labels)
stays available if a larger sample lowers it.
