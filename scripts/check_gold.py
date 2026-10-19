"""Check hand-filled gold columns in data/validation/labels_v1.csv (read-only).

Usage (only once the labeller says the labels are ready):
    uv run python scripts/check_gold.py [path/to/labels.csv]

Every gold symbol (gold_vulnerable_symbols, gold_entry_points; ';'-separated) must
exist in that advisory's symbol table (data/validation/symbol_tables/<ghsa_id>.json.gz);
close matches are suggested for typos. Enumerated columns must use the values in
docs/VALIDATION_AND_PLAN.md §2.2. Exit status 1 if any error is found.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from triager import snapshots, symbols
from triager.baselines.text import SymbolIndex
from triager.eval.gold import check_rows

ROOT = snapshots.ROOT
LABELS = ROOT / "data" / "validation" / "labels_v1.csv"
TABLES = ROOT / "data" / "validation" / "symbol_tables"


def load_indexes(ids: list[str], tables_dir: Path) -> dict[str, SymbolIndex | None]:
    out: dict[str, SymbolIndex | None] = {}
    for gid in ids:
        path = tables_dir / f"{gid}.json.gz"
        out[gid] = SymbolIndex.build(symbols.load(path)["symbols"]) if path.exists() else None
    return out


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else LABELS
    with path.open(newline="") as fh:  # read-only
        rows = list(csv.DictReader(fh))
    issues = check_rows(rows, load_indexes([r["ghsa_id"] for r in rows], TABLES))
    errors = [i for i in issues if i.severity == "error"]
    for i in issues:
        hint = f"  (did you mean: {i.suggestion})" if i.suggestion else ""
        print(f"{i.severity.upper():7} {i.ghsa_id} {i.column}: {i.value!r} {i.problem}{hint}")
    labelled = sum(bool(r.get("gold_vulnerable_symbols", "").strip()) for r in rows)
    print(f"\n{len(rows)} rows, {labelled} with gold_vulnerable_symbols; "
          f"{len(errors)} errors, {len(issues) - len(errors)} warnings")  # fmt: skip
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
