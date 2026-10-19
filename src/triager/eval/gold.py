"""Checks for hand-filled gold columns in labels_v1.csv (plan §2.2).

Read-only: reports problems for the labeller to fix; never edits the labels.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from triager.baselines.text import SymbolIndex

SEP = ";"

ALLOWED = {
    "package_type": {"library", "application", "cli", "native_ext", "model_format", "other"},
    "usable": {"yes", "no"},
    "unusable_reason": {
        "APP", "NATIVE", "CONFIG_DEFAULT", "DESIGN_NO_FUNCTION", "NO_FIX_LINK",
        "FIX_UNRESOLVABLE", "WITHDRAWN_DUP", "MULTI_REPO", "OTHER",
    },
    "text_names_function": {"explicit", "partial", "absent"},
    "label_confidence": {"high", "medium", "low"},
    "label_basis": {"text", "diff", "both", "code-reading"},
}  # fmt: skip
SYMBOL_COLUMNS = ("gold_vulnerable_symbols", "gold_entry_points")


@dataclass(frozen=True)
class Issue:
    ghsa_id: str
    column: str
    value: str
    problem: str
    suggestion: str = ""
    severity: str = "error"  # error | warning


def split_symbols(cell: str) -> list[str]:
    return [s.strip() for s in (cell or "").split(SEP) if s.strip()]


def _suggest(sym: str, idx: SymbolIndex) -> str:
    cands = idx.suffix_matches(sym.rsplit(".", 1)[-1])
    close = difflib.get_close_matches(sym, cands or list(idx.symbols), n=3, cutoff=0.6)
    return "; ".join(close)


def check_row(row: dict[str, str], idx: SymbolIndex | None) -> list[Issue]:
    gid = row.get("ghsa_id", "")
    issues: list[Issue] = []
    for col, allowed in ALLOWED.items():
        val = (row.get(col) or "").strip()
        if val and val not in allowed:
            issues.append(Issue(gid, col, val, f"not one of {sorted(allowed)}"))
    if (row.get("usable") or "").strip() == "no" and not (row.get("unusable_reason") or "").strip():
        issues.append(Issue(gid, "unusable_reason", "", "usable = no needs a reason"))
    has_gold = False
    for col in SYMBOL_COLUMNS:
        for sym in split_symbols(row.get(col, "")):
            has_gold = True
            if idx is None:
                issues.append(
                    Issue(gid, col, sym, "no symbol table for this advisory", severity="warning")
                )
            elif sym not in idx.symbols:
                issues.append(Issue(gid, col, sym, "not in symbol table", _suggest(sym, idx)))
    if has_gold:
        for col in ("label_confidence", "label_basis"):
            if not (row.get(col) or "").strip():
                issues.append(Issue(gid, col, "", "empty while gold symbols are set"))
    return issues


def check_rows(rows: list[dict[str, str]], indexes: dict[str, SymbolIndex | None]) -> list[Issue]:
    return [i for row in rows for i in check_row(row, indexes.get(row.get("ghsa_id", "")))]
