# Survey of github-reviewed PyPI advisories in a local clone of github/advisory-database.
# Usage: python3 -I scripts/survey_ghsa.py <path-to-advisory-database-clone> <output-sample-ids.txt>
# Signals here are crude (regex); see docs/VALIDATION_AND_PLAN.md for how they are used.
import json, os, re, sys, random, collections
root = sys.argv[1]
recs = []
for dp, dn, fn in os.walk(os.path.join(root, "advisories", "github-reviewed")):
    for f in fn:
        if not f.endswith(".json"): continue
        with open(os.path.join(dp, f)) as fh:
            d = json.load(fh)
        if not any(a.get("package", {}).get("ecosystem") == "PyPI" for a in d.get("affected", [])):
            continue
        refs = [r.get("url", "") for r in d.get("references", [])]
        commit = [u for u in refs if re.search(r"github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", u)]
        pr = [u for u in refs if re.search(r"github\.com/[^/]+/[^/]+/pull/\d+", u)]
        det = d.get("details", "") or ""
        # crude explicit-function signals
        call_pat = re.findall(r"`?([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+)\(\)?`?", det)
        tick = re.findall(r"`([A-Za-z_][\w\.]*)(?:\(\))?`", det)
        fn_word = re.search(r"\b(function|method|class|endpoint|API)\b", det, re.I)
        recs.append(dict(id=d["id"], year=d.get("published", "")[:4], commit=len(commit) > 0,
                         ncommit=len(commit), pr=len(pr) > 0, dotted_or_call=len(call_pat) > 0,
                         backticked=len(tick) > 0, fn_word=bool(fn_word),
                         ecospec=any("ecosystem_specific" in a for a in d.get("affected", [])),
                         dbspec_keys=sorted({k for a in d.get("affected", []) for k in (a.get("database_specific") or {}).keys()})))
n = len(recs)
print("PyPI github-reviewed advisories:", n)
def pct(k): return f"{sum(r[k] for r in recs)} ({100*sum(r[k] for r in recs)/n:.1f}%)"
for k in ["commit", "pr", "backticked", "dotted_or_call", "fn_word", "ecospec"]:
    print(f"  {k}: {pct(k)}")
print("  multi-commit refs:", sum(r['ncommit'] > 1 for r in recs))
print("  affected.database_specific keys:", collections.Counter(k for r in recs for k in r['dbspec_keys']).most_common(5))
yrs = collections.Counter(r["year"] for r in recs)
print("  by year:", dict(sorted(yrs.items())))
recent = [r for r in recs if r["year"] >= "2024"]
print("  2024+ advisories:", len(recent), "with commit link:", sum(r['commit'] for r in recent))
random.seed(20261019)
sample = random.sample([r for r in recs if r["year"] >= "2023"], 50)
with open(sys.argv[2], "w") as fh:
    for r in sample: fh.write(r["id"] + "\n")
print("wrote sample of 50 ids (2023+)")
