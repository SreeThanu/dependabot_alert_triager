"""Text baseline (plan §3, task T5): symbols named in the advisory text.

Vulnerable-function *identification* only; nothing here concerns reachability.

1. ``extract`` pulls identifier-like strings from summary + details:
   backticked names, dotted names, ``name()`` / ``name(args)`` calls, and
   "the X function/method/class" / "function X" phrases. Paths like ``pkg/mod.py``
   become module names.
2. ``resolve`` keeps only strings that resolve against the advisory's symbol table
   (``triager.symbols``):
   - ``exact``: the string is a full qualname (or a full module name);
   - ``unique_suffix``: exactly one symbol ends with ``.<string>`` (``<locals>`` segments
     ignored), possibly after dropping leading components the text added (e.g. a
     public re-export ``pkg.Class`` defined at ``pkg.sub.Class``);
   - ``ambiguous``: several symbols match; all are listed and none is predicted.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

MODULE = "<module>"

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DOTTED_FULL = re.compile(rf"^{_IDENT}(?:\.{_IDENT})*$")
_BACKTICK = re.compile(r"`([^`\n]{1,200})`")
_DOTTED = re.compile(rf"(?<![\w/.:@-])({_IDENT}(?:\.{_IDENT})+)(?![\w/-])")
_CALL = re.compile(rf"(?<![\w.])({_IDENT}(?:\.{_IDENT})*)\((?=[^()\n]{{0,80}}\))")
_PHRASE_AFTER = re.compile(
    rf"\b[`'\"]?({_IDENT}(?:\.{_IDENT})*)(?:\(\))?[`'\"]?\s+"
    r"(?:function|method|class|endpoint|handler|API|decorator)\b"
)
_PHRASE_BEFORE = re.compile(
    rf"\b(?:function|method|class)\s+[`'\"]?({_IDENT}(?:\.{_IDENT})*)(?:\(\))?[`'\"]?"
)
_PATH = re.compile(rf"(?<![\w/])((?:{_IDENT}/)*{_IDENT})\.py\b")

STOPWORDS = {
    "the", "a", "an", "this", "that", "these", "those", "vulnerable", "affected", "same",
    "following", "internal", "public", "helper", "new", "default", "custom", "user", "its",
    "any", "each", "which", "e", "g", "i", "etc", "eg", "ie", "and", "or", "of", "in", "to",
    "for", "with", "by", "via", "from", "on", "at", "is", "as", "not", "but", "into", "one",
    "another", "other", "such", "some", "their", "his", "her", "our", "your", "every",
}  # fmt: skip
URLISH = re.compile(r"\.(com|org|net|io|dev|ai|html?|json|ya?ml|txt|md|toml|cfg)$", re.I)


def _clean(token: str) -> str | None:
    t = token.strip().strip("'\"")
    t = re.sub(r"\(.*\)$", "", t)  # drop call arguments
    t = t.replace("::", ".").rstrip(".")
    if t.endswith(".py"):
        t = t[:-3].replace("/", ".")
    if not _DOTTED_FULL.match(t) or URLISH.search(t):
        return None
    if t.lower() in STOPWORDS or len(t.rsplit(".", 1)[-1]) < 3:
        return None
    return t


def extract(text: str) -> dict[str, list[str]]:
    """Return {identifier string: [patterns that found it]} in first-seen order."""
    found: dict[str, list[str]] = {}

    def add(raw: str, pattern: str) -> None:
        t = _clean(raw)
        if t is not None and pattern not in found.setdefault(t, []):
            found[t].append(pattern)

    for m in _BACKTICK.finditer(text):
        add(m.group(1), "backtick")
    for m in _PATH.finditer(text):
        add(m.group(1).replace("/", ".") + ".py", "path")
    for m in _DOTTED.finditer(text):
        add(m.group(1), "dotted")
    for m in _CALL.finditer(text):
        add(m.group(1), "call")
    for rx in (_PHRASE_AFTER, _PHRASE_BEFORE):
        for m in rx.finditer(text):
            add(m.group(1), "phrase")
    return {k: v for k, v in found.items() if v}


def _collapse(sym: str) -> str:
    return sym.replace(".<locals>", "")


@dataclass
class SymbolIndex:
    """Lookup structure over one symbol table."""

    symbols: set[str]
    kinds: dict[str, str]
    by_last: dict[str, list[str]] = field(default_factory=dict)
    modules: dict[str, str] = field(default_factory=dict)  # "pkg.mod" -> "pkg.mod.<module>"

    @classmethod
    def build(cls, table_symbols: Iterable[dict]) -> SymbolIndex:
        kinds = {s["symbol"]: s["kind"] for s in table_symbols}
        idx = cls(set(kinds), kinds)
        by_last: dict[str, list[str]] = defaultdict(list)
        for sym, kind in kinds.items():
            if kind == "module":
                mod = sym[: -len(MODULE) - 1]
                idx.modules[mod] = sym
                by_last[mod.rsplit(".", 1)[-1]].append(sym)
            else:
                by_last[sym.rsplit(".", 1)[-1]].append(sym)
        idx.by_last = dict(by_last)
        return idx

    def _display(self, sym: str) -> str:
        return sym[: -len(MODULE) - 1] if self.kinds.get(sym) == "module" else sym

    def suffix_matches(self, s: str) -> list[str]:
        last = s.rsplit(".", 1)[-1]
        out = []
        for sym in self.by_last.get(last, []):
            full = _collapse(self._display(sym))
            if full == s or full.endswith("." + s):
                out.append(sym)
        return sorted(out)


@dataclass(frozen=True)
class Match:
    string: str
    match_type: str  # exact | unique_suffix | ambiguous | unresolved
    symbols: tuple[str, ...]
    matched_on: str


def resolve(s: str, idx: SymbolIndex) -> Match:
    if s in idx.symbols:
        return Match(s, "exact", (s,), s)
    if s in idx.modules:
        return Match(s, "exact", (idx.modules[s],), s)
    parts = s.split(".")
    for i in range(len(parts)):
        part = ".".join(parts[i:])
        cands = idx.suffix_matches(part)
        if len(cands) == 1:
            return Match(s, "unique_suffix", tuple(cands), part)
        if len(cands) > 1:
            return Match(s, "ambiguous", tuple(cands), part)
    return Match(s, "unresolved", (), "")


def predict(text: str, idx: SymbolIndex) -> tuple[list[Match], set[str]]:
    """All matches for the extracted strings, and the predicted set (exact + unique)."""
    matches = [resolve(s, idx) for s in extract(text)]
    predicted = {sym for m in matches if m.match_type in ("exact", "unique_suffix")
                 for sym in m.symbols}  # fmt: skip
    return matches, predicted
