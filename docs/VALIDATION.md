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
