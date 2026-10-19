# Dependabot Alert Triager for Python — Validation and Plan

Prepared 19 Oct 2026. Labels used throughout:

- **FACT** — checked against a primary source or measured on public data (source or command given).
- **PRELIM** — measured, but on too small a sample or with too crude a method to rely on yet.
- **HYPOTHESIS** — plausible, not yet checked. Must be tested before it is relied on.
- **REC** — my recommendation.

No performance numbers for the proposed system appear anywhere in this document, because none exist yet.

---

## Bottom line

**REC: Modify, then proceed.** The core idea survives, but three things found today change the scope:

1. **GitHub built and then retired exactly this feature for Python.** In April 2022 Dependabot started flagging alerts where your code calls a vulnerable function (Python only, beta), using vulnerable functions that GitHub curates when publishing advisories. In December 2024 GitHub's docs removed the feature under a commit titled "Closing Down: Vulnerability Exposure Analysis / Reachability in Dependabot". So the free gap is real, but GitHub may still hold curated function labels for many Python advisories (the REST API has a `vulnerable_functions` field). How many it holds decides how much your LLM contributes. **Measuring this is task 1.**
2. **Most Python advisories are not about libraries you call.** In a quick read of 12 recent advisories, roughly two-thirds were for applications people deploy (Open WebUI, Langflow, Superset, pyLoad), native C/C++ code, or withdrawn duplicates. Reachability from your code is meaningless for those. The project must be scoped to **library-type advisories**.
3. **Prior work already covers parts of this, so novelty is low.**
   - LLM-based vulnerable-function identification was published at ASE 2024 (VFFinder).
   - Duo Labs' `narrow` already does the diff-based baseline for Python: it extracts the functions a fix patch changes and searches your code's control flow graph for them.
   - ReachGuard does OSV-plus-call-graph reachability for Python.
   - Oligo sells LLM-enriched vulnerable-function data.

   Your defensible contribution is a **rigorous, conservative, measured** comparison on modern Python library advisories, not a new capability.

---

## Phase 1 — Validate the premise

### 1.1 What the data says (measured today)

Snapshots used (pin these in the repo):

| Source | Commit | Date | Licence |
|---|---|---|---|
| github/advisory-database | `b16e369438ef2ab329b4c224cae8224f144bf5d5` | 2026-10-19 | CC BY 4.0 (repo `LICENSE.md`) — FACT |
| pypa/advisory-database | `a8810dcf9b0d3ce4f0d2db53fd30198f7afce289` | 2026-10-18 | CC BY 4.0 (repo `LICENSE`) — FACT |
| golang/vulndb | `d5e0cfac5d260523df858cd4c0f849e248468fb6` | 2026-10-10 | Data under CC BY 4.0 (`data/LICENSE`); code BSD — FACT |

Measurements on github-reviewed advisories affecting PyPI (script: `scripts/survey_ghsa.py`):

| Measure | Value | Label |
|---|---|---|
| Reviewed PyPI advisories | 6,578 (236 withdrawn) | FACT |
| Published 2024 or later | 3,809 | FACT |
| With at least one GitHub commit link in references | 4,055 (61.6%) | FACT |
| With more than one commit link | 828 | FACT |
| Function-level fields in the open OSV JSON (`ecosystem_specific`) | 0 | FACT — the open export carries no vulnerable-function data |
| Details text contains a backticked identifier | 44.8% | PRELIM — crude proxy for "names a function" |
| Top 15 packages' share of all advisories | 38% | FACT |
| TensorFlow, tensorflow-cpu, tensorflow-gpu | 434 / 423 / 427 | FACT — same advisories repeated across package names → leakage risk |
| Largest 2026 contributors | open-webui 138, praisonai 121, nltk 74, praisonaiagents 58, apache-airflow 56 | FACT — several are applications, not libraries |

Qualitative read of 12 randomly sampled 2023+ advisories (seed `20261019`): about a third were library-type advisories you could reach from your own code (e.g. pypdf, chatterbot, praisonaiagents, tensorflow via `tf.io.decode_gif`). The rest were applications, native C++ code (Open Babel's MOL2 parser) or a withdrawn duplicate. — PRELIM, n = 12.

Many advisories **do** name a function or method in the text (e.g. `get_response()`, `set_session`, `ProjectService.get_stats()`, `tf.io.decode_gif`). But the named function is often **internal**, while the user's code calls a **public entry point**. That gap, between the vulnerable function and how users reach it, is where real value may lie. — PRELIM.

### 1.2 The six questions you asked

| Question | Status | Finding |
|---|---|---|
| Do Python advisories already name vulnerable functions often enough to weaken the LLM contribution? | **Open — the biggest risk** | The open OSV export has no function fields (FACT). But GitHub curates `vulnerable_functions` for Python advisories and exposes it in the REST API: the field is in the global-advisories schema, and the endpoint works without authentication for public data (FACT). How many advisories have it filled is **unknown** — my sandbox could not reach the API. Also, advisory text often names a function (PRELIM), so a simple text-matching baseline may be strong. |
| Does the Go database give suitable labels, and do they transfer to Python? | **Partly** | 853 reviewed Go reports list affected symbols **and** link a fix (FACT, golang/vulndb). Good for testing the *method* (advisory + diff → symbol). Transfer to Python is a HYPOTHESIS: Go symbols are statically resolvable and curated by one team; Python has dynamic dispatch and different packaging. Treat Go as an auxiliary benchmark, never as evidence about Python. |
| Do free tools already do comparable reachability? | **Partly** | `narrow` (Apache-2.0) does fix-patch function extraction + control-flow reachability for Python, but supports Python 3.9 and not 3.10 (FACT, README). ReachGuard (free, first release July 2026, one maintainer) does import-level filtering plus an optional PyCG call graph, but only knows which function to look for if the advisory says so (FACT, PyPI page). OSV-Scanner call analysis covers Go (default), Rust and Java JARs (experimental); its docs as summarised don't mention Python (FACT, secondary write-up). GitHub's Python feature is retired (FACT). |
| Do fix commits reliably identify vulnerable functions? | **No, not on their own** | 828 advisories link multiple commits (FACT). A 2025 ESORICS paper building labels from fix commits notes developers bundle unrelated changes, and restricts itself to single-commit, single-file fixes to cope (FACT, FuncVul). Expect tests, refactors and version bumps in diffs. Noise rate for your sample: unknown — measure on day 3. |
| Enough legally usable public data? | **Yes** | All three advisory databases are CC BY 4.0 (attribution required). Fix-commit code belongs to each project under its own licence: analyse it, store diffs only as needed, don't redistribute bulk source. |
| Can a credible Python eval set be built in time? | **Probably, if scoped** | About a third library-type (PRELIM) of 3,809 recent advisories is still more than 1,000 candidates. You need about 150 hand-labelled advisories (100 dev, 50 test). At an estimated 15–20 minutes each, that's 40–50 hours — the dominant cost of the project. GitHub's curated labels, if they exist at volume, could cut this sharply. |

### 1.3 Other facts that shape the design

- **Python static call graphs are imprecise.** PyCG was archived in November 2023 (FACT, repo). JARVIS, its research successor, reports application-centred precision of 0.35 vs PyCG's 0.19 and recall of about 0.60 vs 0.48 on six real projects (FACT, arXiv 2305.05949). So "no call path found" is weak evidence. The tool must never call that "safe".
- **Model memorisation risk.** An LLM may have seen older advisories and their fixes during training, which would inflate scores. The test set must be **published after the chosen model's training cutoff** (check the model card).

---

## Phase 2 — The smallest credible experiment (days 1–5)

### 2.1 Sampling

1. From the pinned GHSA snapshot, take reviewed advisories affecting PyPI, **published 2025-01-01 or later**, not withdrawn.
2. Collapse package families: tensorflow / tensorflow-cpu / tensorflow-gpu count as one family. Merge advisories that share a CVE alias.
3. Draw a **stratified random sample of 50**: at most 2 advisories per package family, to avoid 20 TensorFlow cases. Fixed seed, recorded.
4. Save the 50 IDs and the snapshot SHA to `data/validation/sample_v1.txt`. Never resample silently.

### 2.2 Fields to record per advisory (`data/validation/labels_v1.csv`)

| Field | Values / notes |
|---|---|
| `ghsa_id`, `aliases`, `published`, `package_family`, `packages` | from JSON |
| `package_type` | `library` · `application` · `cli` · `native_ext` · `model_format` · `other` |
| `usable` | yes / no |
| `unusable_reason` | `APP`, `NATIVE`, `CONFIG_DEFAULT`, `DESIGN_NO_FUNCTION`, `NO_FIX_LINK`, `FIX_UNRESOLVABLE`, `WITHDRAWN_DUP`, `MULTI_REPO`, `OTHER` |
| `github_vulnerable_functions` | value from the REST API (empty / list) |
| `text_names_function` | `explicit` (a symbol that exists in the source, module-qualified or unique) · `partial` (endpoint, component or ambiguous name) · `absent` |
| `named_symbols_text` | as written in the advisory |
| `fix_commits` | URLs; `fix_commit_source` = `reference` · `pr_merge` · `tag_diff_inferred` |
| `fix_verified` | yes / no (see 2.3) |
| `diff_files_total`, `diff_files_src`, `diff_funcs_changed_src` | counts from the diff, excluding tests/docs |
| `gold_vulnerable_symbols` | fully qualified, e.g. `pypdf.filters.FlateDecode.decode` |
| `gold_entry_points` | public API symbols a user would call, if different |
| `label_confidence` | high / medium / low |
| `label_basis` | text / diff / both / code-reading |
| `minutes_spent`, `labeler`, `notes` | |

### 2.3 Finding and verifying the fix commit

1. Prefer `references` URLs matching `github.com/<owner>/<repo>/commit/<sha>`.
2. Otherwise follow a PR link and take its merge commit.
3. Otherwise diff the git tags of the last affected and first fixed versions, and search commit messages for the CVE/GHSA id. Mark this `tag_diff_inferred`; it is lower trust.
4. **Verify** all four:
   - the repo really is the package's source (check PyPI project URLs);
   - the commit is contained in the fixed release tag (`git tag --contains <sha>`);
   - it is not contained in the last affected tag;
   - it changes non-test source of the affected package.

   Fail any check → `fix_verified = no`.

### 2.4 Ambiguous or unusable examples

- Never drop them silently. Keep every sampled advisory in the CSV with its reason code. The share of unusable advisories is itself a result.
- Several plausible vulnerable functions → list all as gold and set `label_confidence = medium`.
- Root cause in native code but reachable through a Python API → `package_type = native_ext`. Record the Python entry point as `gold_entry_points` and keep it, because it's still useful for reachability.
- **Consistency check:** re-label 15 random advisories after at least 48 hours without looking at your first labels. Report symbol-level agreement.

### 2.5 Preventing leakage between dev and test

- **Split by time:** dev = published before a cutoff date; test = after it, and after the LLM's training cutoff.
- **Group by package family:** no family appears in both dev and test.
- **Group by CVE alias:** duplicates stay together.
- **Freeze the test set:** after labelling, store the file's SHA-256 in `data/test_manifest.json`. Prompts and rules are tuned on dev only. Run on test at most twice — once for the final report, plus once if a bug fix is needed, and disclose it.

### 2.6 Go / no-go criteria (decide on day 5)

Let **L** = usable library-type advisories in the 50-sample.

| # | Check | Proceed | Modify | Abandon |
|---|---|---|---|---|
| G1 | Share of L with a non-empty GitHub `vulnerable_functions` field | < 30% | 30–70%: use GitHub's labels as **extra gold data** and focus the LLM on the rest and on entry-point mapping | > 70% **and** G3 baseline F1 ≥ 0.85 (the problem is largely solved) |
| G2 | L as a share of the sample | ≥ 25% (≈ ≥ 780 of the 3,117 advisories published 2025 or later) | 15–25%: narrow to the top library families | < 15% |
| G3 | Best simple baseline F1 on L (text-name match ∪ changed-functions-in-source) | ≤ 0.70: real headroom | 0.70–0.85: headroom is thin; shift focus to entry points and abstention quality | ≥ 0.85 together with G1 > 70% |
| G4 | Fix commit verified for L | ≥ 70% | 50–70%: rely more on text and code-reading labels | < 50% |
| G5 | Labelling cost and agreement | ≤ 25 min per advisory, ≥ 85% agreement on re-label | slower → shrink test set to 40, report wider error bars | agreement < 70% (the task is ill-defined) |

Decision rule: **any Abandon cell triggers a stop-and-discuss.** Two or more Modify cells → rewrite the project claims before writing code.

---

## Phase 3 — Minimum viable architecture

Keep two questions separate everywhere in code, output and README:

- **Vulnerable-function identification:** *which* function in the dependency contains the flaw? This is where the ML/LLM work happens.
- **Reachability:** *does the user's code get to it?* This is static analysis, and it has hard limits.

```
advisory DB snapshot (git, pinned SHA)
        │
   ingest/normalise ──► Advisory records (pydantic)
        │
   fixcommit/resolve ──► verified fix diffs (git, local cache)
        │
   ┌────┴─────────────────────────┐
   │ identification                │
   │  baseline_text  (regex ∩ AST symbols)
   │  baseline_diff  (changed funcs in non-test src)   ← narrow-style
   │  llm_extract    (constrained to AST candidate symbols)
   │  verify_symbols (every output must exist in vulnerable-version source)
   └────┬─────────────────────────┘
        │  vulnerable symbols + entry points + confidence
   reachability/usage (user repo: AST import resolution + call sites)
        │
   verdict (rules) ──► REACHABLE | NOT_FOUND | UNKNOWN + evidence
        │
   eval harness ──► runs/<id>/{config, predictions.jsonl, metrics.json}
```

| Component | What it does | Tools (why) |
|---|---|---|
| Advisory ingestion | Read GHSA OSV JSON from the pinned clone; normalise; package-family mapping; alias merge | Standard library `json` + `pydantic` (typed records, validation). No API needed: works offline |
| GitHub labels (optional) | Fetch `vulnerable_functions` per advisory from the REST API; cache to disk | `httpx` with a personal token (higher rate limit). Store responses in `data/cache/` |
| Fix-commit retrieval | Clone source repos with `git clone --filter=blob:none`, `git show <sha>`, tag-containment checks | `git` via `subprocess` (transparent and debuggable). Avoid hosted-API dependency for diffs |
| Diff baseline | Parse unified diffs; map changed lines to enclosing functions using `ast` (`lineno`/`end_lineno`) on the pre-fix file; drop tests/docs/setup files | `unidiff` (robust diff parsing) + standard library `ast` |
| Text baseline | Find identifiers in advisory text; keep those that match real symbols in the vulnerable source | `re` + the AST symbol table |
| LLM extraction | Input: advisory text + top diff hunks + **candidate symbol list from AST**. Output: JSON of symbols with role (`root_cause` / `entry_point`), evidence quote, confidence, or an explicit abstain | Provider adapter (Claude Haiku 5.5 or Gemini). Structured output validated by `pydantic`. Choosing from a candidate list prevents invented names |
| Symbol verifier | Rejects any symbol not in the vulnerable-version source | Same AST symbol table |
| Reachability v1 | In the user's repo: resolve imports and aliases, find call sites of vulnerable symbols or their public entry points | `ast` (dependable, fast). Report blind spots explicitly |
| Reachability v2 (stretch) | Call graph inside the dependency, from public API to internal vulnerable function | Evaluate JARVIS (research prototype) only if time remains. Don't build on archived PyCG |
| Verdict | Rule table below | Pure function, unit-tested |
| CLI | `triage scan <repo>`, `triage explain <ghsa>`, `triage eval` | `typer` + `rich` |
| Eval and logging | Each run gets config, model id, prompt hash, data SHAs, token counts, predictions, metrics | Plain JSONL + `pytest` |

**Not included unless a measured problem demands it:** agents, vector databases, dashboards, servers, distillation.

**Verdict rules (conservative by construction):**

| Condition | Verdict |
|---|---|
| Symbol unknown, low confidence, abstained, or package is an application / native-only with no Python entry point | `UNKNOWN` |
| A concrete call site in user code to a vulnerable symbol or a known entry point | `REACHABLE` + file:line evidence |
| Symbols known with high confidence, and no reference found in analysed files | `NOT_FOUND` + list of blind spots (`getattr`/`importlib`, string-based plugins, callbacks passed to frameworks, notebooks, generated code, unanalysed dependency internals, C extensions) |

`NOT_FOUND` is never phrased as "safe" or "unreachable". The tool never closes or dismisses an alert.

**Python static-analysis limits to document in the README:** dynamic dispatch (duck typing, `__getattr__`), reflection (`getattr`, `importlib`, `eval`), callbacks registered with frameworks (Flask/Django routes, Celery tasks, pytest fixtures), monkey-patching, conditional imports, missing dependency source or binary-only wheels, and code generated at runtime. Published call-graph precision for Python is low (Phase 1.3).

---

## Phase 4 — Evaluation methodology

### 4.1 Identification (main result)

- **Unit:** one (advisory, gold symbol) pair. Matching = exact fully qualified name after normalisation. Report two lenient variants separately: class-level match when the gold is a method, and module-level match.
- **Metrics:** precision, recall and F1 at symbol level (micro), plus per-advisory macro F1 and top-1 accuracy.
- **Systems compared on the same test set:**
  1. text baseline;
  2. diff baseline (narrow-style);
  3. text ∪ diff;
  4. LLM;
  5. LLM + verifier;
  6. GitHub `vulnerable_functions` where available — as a reference point, not a competitor.
- **Uncertainty:** 95% bootstrap confidence intervals, resampling advisories. Paired bootstrap for LLM vs best baseline. With about 50 test advisories, intervals will be wide — say so.
- **Abstention:** report coverage (share answered) vs precision as a curve, and the abstention rate. An LLM that abstains on hard cases and is right on the rest is useful; hiding abstentions inside F1 is misleading.
- **Slices:** explicit vs partial vs absent naming; single vs multi-commit fixes; internal vs public symbol; native-root-cause; label confidence; package families.
- **Go auxiliary benchmark:** same methods on reviewed Go reports with symbols. Reported as "method sanity check", never as Python evidence.

### 4.2 Reachability (secondary, honest scope)

Ground truth exists only where you construct it. Build a **controlled client benchmark**: for about 20 test advisories, write small client projects per case:
- *positive* — a direct call to the vulnerable entry point;
- *negative* — imports the package, never calls the entry point;
- *tricky* — aliased import, `getattr` call, callback registration, wrapper function, call from a test file only.

Labels are true by construction. Optionally add 10–20 real GitHub repos you label by reading the code, and report them separately.

### 4.3 False-safe rate (the key safety metric)

- **Denominator:** cases whose ground truth is *reachable* (positive + reachable tricky cases).
- **Numerator:** cases among those where the tool says `NOT_FOUND`.
- `UNKNOWN` is not counted as false-safe, but the `UNKNOWN` rate is always reported next to it. Otherwise a tool that always says `UNKNOWN` would score perfectly.
- Also report: false-alarm rate (`REACHABLE` on negatives) and the share of all alerts receiving a definite verdict.

### 4.4 Avoiding misleading claims

- State n, confidence intervals, data snapshot dates and model id next to every number.
- Claim nothing beyond **library-type PyPI advisories published in the stated window**.
- Report label confidence and the re-label agreement score.
- Never write "X% of alerts are false positives / unreachable". The tool can't know that, and Phase 1.3 says static analysis misses calls.
- Publish the dev and test CSVs (CC BY attribution to GitHub) so others can check them.

---

## Phase 5 — Roadmap (21–28 days)

### Days 1–5: validation (daily)

| Day | Tasks | Done when |
|---|---|---|
| 1 | Create repo; pin snapshots; run `scripts/survey_ghsa.py`; write a script to fetch `vulnerable_functions` for all 2025+ reviewed PyPI advisories (token, cache) | Coverage numbers for G1 on the full 2025+ pool, saved as JSON |
| 2 | Draw the stratified 50-sample; classify `package_type` and `usable` for all 50 | `labels_v1.csv` with type and usability filled; G2 computed |
| 3 | Resolve and verify fix commits for usable ones; run a quick diff-baseline script | `fix_verified`, `diff_*` columns filled; G4 computed |
| 4 | Hand-label gold symbols and entry points; record minutes spent | Gold columns filled; text and diff baselines scored → G3 |
| 5 | Re-label 15 (only if 48 hours have passed; otherwise do it on day 7); write `docs/VALIDATION.md` with G1–G5 and the decision | Decision recorded: proceed / modify / abandon |

### Week 2 (days 6–12): data pipeline and baselines

- **Deliverables:** ingestion, fix-commit resolver, text and diff baselines as tested modules; dev set 100 / test set 50, split per 2.5 and frozen.
- **Acceptance:** `pytest` green; baselines reproduce the day-4 numbers from the module code (not the throwaway script); test-set manifest hash committed.

### Week 3 (days 13–19): LLM extraction and evaluation

- **Deliverables:** provider adapter; constrained extraction prompt; symbol verifier; eval harness with bootstrap confidence intervals and slices; Go auxiliary run.
- **Acceptance:** one command produces `runs/<id>/metrics.json` and a markdown report; the LLM vs baseline comparison exists on **dev**. Test set still unopened.

### Week 4 (days 20–26): reachability, verdicts, CLI, report

- **Deliverables:** usage scanner; verdict rules; controlled client benchmark; CLI; single final test-set run; README with limitations; short terminal demo recording.
- **Acceptance:** false-safe rate, `UNKNOWN` rate and false-alarm rate reported with their denominators; every README number traces to a run id.

**Days 27–28:** buffer. Optional GitHub Action only if everything above is done.

### Likely blockers

- Labelling takes longer than estimated (most likely).
- Repos that moved or were deleted, or force-pushed commits.
- GitHub API rate limits (use a token and a cache).
- LLM training-cutoff contamination.
- Native-code advisories dominating some families.

### Reduced scope if behind (in this order)

1. Drop the GitHub Action.
2. Drop dependency-internal call graphs (v2); keep the user-code usage scanner.
3. Shrink the test set to 40 and say so.
4. Drop the Go auxiliary benchmark.

**Never cut:** the frozen test set, baselines, confidence intervals, false-safe reporting.

### Final resume-ready deliverable

A public repo with:
- a CLI;
- a dataset card and labelled CSVs (with attribution);
- `eval/report.md` with confidence intervals;
- a README stating scope and limits;
- a demo recording.

Bullet template (fill only with measured values):

> Built a conservative vulnerability-triage CLI for Python dependencies; on N held-out library advisories, LLM-based vulnerable-function identification reached F1 X [CI] vs Y for a fix-diff baseline, with Z% abstention; on a controlled reachability benchmark the false-safe rate was W/D.

---

## Phase 6 — Working with Claude Code

### First concrete action (today)

On your Mac, run this unauthenticated test of GitHub's curated labels (60 requests/hour without a token). It counts how many recent reviewed Python advisories on one page have `vulnerable_functions` filled:

```bash
curl -s "https://api.github.com/advisories?ecosystem=pip&type=reviewed&per_page=100&published=%3E2025-01-01" \
  | python3 -c "import json,sys; a=json.load(sys.stdin); n=len(a); k=sum(any(v.get('vulnerable_functions') for v in x.get('vulnerabilities',[])) for x in a); print(f'{k}/{n} advisories have vulnerable_functions')"
```

- **0 or close to 0:** GitHub stopped curating them; the premise strengthens.
- **Most of them:** run the full day-1 script before anything else. G1 may push the project towards "modify".

### Task sequence (small, verifiable — give Claude Code one task at a time)

| ID | Objective | Files | Evidence for done | Stop and reconsider if |
|---|---|---|---|---|
| T0 | Repo skeleton, pinned snapshot config | `pyproject.toml`, `config/snapshots.yaml`, `CLAUDE.md`, `README.md` | `uv run pytest` passes a smoke test; SHAs recorded | — |
| T1 | GitHub labels fetcher with disk cache | `src/triager/sources/github_api.py`, `tests/test_github_api.py` | Coverage JSON for 2025+ PyPI; test with recorded responses | Coverage > 70% (G1 abandon zone) |
| T2 | Stratified sampler + label CSV template | `scripts/sample.py`, `data/validation/` | `sample_v1.txt` + seed + SHA; re-running gives identical IDs | Fewer than 25% library-type after classification |
| T3 | Fix-commit resolver + verifier (tag containment) | `src/triager/fixcommit.py`, tests with a local fixture repo | `fix_verified` filled for the sample; unit tests for each check | Under 50% verifiable |
| T4 | Diff baseline (unidiff + ast) | `src/triager/baselines/diff.py`, tests on hand-made diffs | Changed-function lists for the sample; tests for nested functions, methods, decorators | — |
| T5 | Text baseline + AST symbol table | `src/triager/symbols.py`, `src/triager/baselines/text.py` | Precision/recall vs day-4 gold on the 50 | Baseline F1 ≥ 0.85 (G3) |
| T6 | Validation report | `docs/VALIDATION.md` | G1–G5 table with numbers and decision | Any abandon cell |
| T7 | Dataset split + freeze | `scripts/split.py`, `data/test_manifest.json` | No package family or alias overlaps (test asserts it) | — |
| T8 | LLM adapter + constrained extraction + verifier | `src/triager/llm/`, `src/triager/extract.py` | Dev-set run; 0 symbols outside the candidate list (test asserts it) | LLM ≤ best baseline on dev after 2 prompt iterations |
| T9 | Eval harness (bootstrap, slices, abstention curve) | `src/triager/eval/`, `eval/report.md` | Report regenerates from `runs/<id>` | — |
| T10 | Usage scanner + verdict rules | `src/triager/reach.py`, `src/triager/verdict.py` | Client benchmark passes positive/negative cases; tricky cases recorded honestly | False-safe rate on positives > 20% with no fix in sight |
| T11 | CLI + final test run + README | `src/triager/cli.py`, `README.md` | One test-set run id cited by every README number | — |

Approve tasks one at a time. Claude Code should not write the next module until the previous task's evidence exists.

---

## The four things you asked for at the end

1. **Recommendation:** **Modify, then proceed.** Scope to library-type PyPI advisories. Make identification (LLM vs baselines, with abstention) the main result and reachability a conservative secondary layer. Treat novelty as low and rigour as the selling point.
2. **The three biggest risks:**
   1. GitHub's curated `vulnerable_functions` may already cover most library advisories, shrinking the LLM's contribution (G1).
   2. Simple baselines (text naming + changed functions) may already be strong, leaving little headroom (G3).
   3. Labelling cost and label noise from tangled fix commits may make a credible test set too small or too uncertain in 3–4 weeks (G4/G5).
3. **First task today:** run the `curl` check above. Then run the full G1 measurement (task T1) on all 2025+ reviewed PyPI advisories.
4. **Evidence required before the main implementation:** `docs/VALIDATION.md` containing:
   - G1 coverage on the full pool;
   - the 50-advisory CSV with type, usability, verified fix commits and gold labels;
   - baseline F1 on that sample;
   - labelling time and re-label agreement;
   - a written proceed/modify/abandon decision.

---

## Sources

- GitHub changelog, 14 Apr 2022: Dependabot alerts show vulnerable function calls (Python beta) — https://github.blog/changelog/2022-04-14-dependabot-alerts-show-vulnerable-function-calls-python-beta
- github/docs PR #35656, merged 13 Dec 2024, removing vulnerable-calls docs ("Closing Down: Vulnerability Exposure Analysis / Reachability") — https://github.com/github/docs/pull/35656/files
- GitHub REST API: global security advisories (`vulnerable_functions` field; works without auth for public data) — https://docs.github.com/de/enterprise-server@3.17/rest/security-advisories/global-advisories
- github/advisory-database (CC BY 4.0) — https://github.com/github/advisory-database
- pypa/advisory-database (CC BY 4.0) — https://github.com/pypa/advisory-database
- Go Vulnerability Database (symbols, curation, review status) — https://go.dev/security/vuln/database ; data repo https://github.com/golang/vulndb
- Wu et al., "Effective Vulnerable Function Identification based on CVE Description Empowered by Large Language Models", ASE 2024 — https://conf.researchr.org/details/ase-2024/ase-2024-research/32/Effective-Vulnerable-Function-Identification-based-on-CVE-Description-Empowered-by-La
- Halder et al., "FuncVul", ESORICS 2025 (fix-commit labels, tangled changes) — https://arxiv.org/html/2506.19453v1
- duo-labs/narrow (Python, patch-based reachability) — https://github.com/duo-labs/narrow
- ReachGuard (PyPI) — https://pypi.org/project/reachguard/
- OSV-Scanner call analysis (secondary write-up) — https://oneuptime.com/blog/post/2026-07-23-osv-scanner-call-analysis/markdown
- PyCG (archived Nov 2023) — https://github.com/vitsalis/PyCG
- Huang et al., "JARVIS: Scalable and Precise Application-Centered Call Graph Construction for Python" — https://arxiv.org/pdf/2305.05949v4
- Oligo Security blog (vendor claims on vulnerable-function coverage; unverified) — https://www.oligo.security/blog/uncovering-the-hidden-risks-how-oligo-identifies-1100-more-vulnerable-functions
- arXiv 2603.18693 (possibly related; could not be read — check in week 1) — https://arxiv.org/abs/2603.18693
