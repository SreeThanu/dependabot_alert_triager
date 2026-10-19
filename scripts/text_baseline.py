"""T5: text baseline over the 50 sampled advisories (no scoring).

Usage:
    uv run python scripts/text_baseline.py

Extracts identifier-like strings from each advisory's summary + details (pinned
snapshot) and keeps those that resolve in its symbol table
(data/validation/symbol_tables/<ghsa_id>.json.gz). Writes text_baseline_v1.csv (one
row per advisory), text_baseline_matches_v1.csv (one row per extracted string) and
text_baseline_v1.meta.json. Does not read labels_v1.csv.
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime

from triager import advisories, snapshots, symbols
from triager.baselines import text as tb
from triager.fsutil import atomic_write_text

ROOT = snapshots.ROOT
VAL = ROOT / "data" / "validation"
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
TABLES = VAL / "symbol_tables"
OUT = VAL / "text_baseline_v1.csv"
OUT_MATCHES = VAL / "text_baseline_matches_v1.csv"
OUT_META = VAL / "text_baseline_v1.meta.json"

COLUMNS = [
    "ghsa_id", "symbol_table", "n_extracted", "extracted", "n_exact", "n_unique_suffix",
    "n_ambiguous", "n_unresolved", "n_predicted", "predicted", "note",
]  # fmt: skip
MATCH_COLUMNS = ["ghsa_id", "string", "patterns", "match_type", "matched_on", "symbols"]


def csv_text(columns, rows) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main() -> None:
    snap = snapshots.load("github_advisory_database")
    snapshots.verify_head(SNAPSHOT_DIR, snap)
    text = (VAL / "sample_v1.txt").read_text()
    ids = [ln.split()[0] for ln in text.splitlines() if ln and ln[0] != "#"]
    advs = advisories.load_ids(SNAPSHOT_DIR, ids)
    rows, match_rows = [], []
    for gid in ids:
        adv = advs[gid]
        body = f"{adv.summary}\n{adv.details}"
        extracted = tb.extract(body)
        path = TABLES / f"{gid}.json.gz"
        row = dict.fromkeys(COLUMNS, "")
        row.update(ghsa_id=gid, n_extracted=len(extracted), extracted="; ".join(extracted))
        table = symbols.load(path) if path.exists() else None
        if not table or not table["symbols"]:
            row.update(symbol_table="no", n_predicted=0, note="no symbol table: nothing resolved")
            rows.append(row)
            continue
        idx = tb.SymbolIndex.build(table["symbols"])
        matches, predicted = tb.predict(body, idx)
        counts = Counter(m.match_type for m in matches)
        row.update(
            symbol_table="yes",
            n_exact=counts["exact"],
            n_unique_suffix=counts["unique_suffix"],
            n_ambiguous=counts["ambiguous"],
            n_unresolved=counts["unresolved"],
            n_predicted=len(predicted),
            predicted="; ".join(sorted(predicted)),
        )
        rows.append(row)
        for m in matches:
            match_rows.append(
                {
                    "ghsa_id": gid,
                    "string": m.string,
                    "patterns": "; ".join(extracted[m.string]),
                    "match_type": m.match_type,
                    "matched_on": m.matched_on,
                    "symbols": "; ".join(m.symbols),
                }
            )
    atomic_write_text(OUT, csv_text(COLUMNS, rows))
    atomic_write_text(OUT_MATCHES, csv_text(MATCH_COLUMNS, match_rows))
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    with_table = [r for r in rows if r["symbol_table"] == "yes"]
    meta = {
        "script": "scripts/text_baseline.py",
        "repo_commit": head,
        "run_started_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "snapshot": snap.commit,
        "advisories": len(rows),
        "with_symbol_table": len(with_table),
        "with_any_extracted_string": sum(r["n_extracted"] > 0 for r in rows),
        "with_at_least_one_resolved_symbol": sum(r["n_predicted"] > 0 for r in rows),
        "with_only_ambiguous_matches": sum(
            r["n_predicted"] == 0 and (r["n_ambiguous"] or 0) > 0 for r in with_table
        ),
    }
    atomic_write_text(OUT_META, json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
