"""Symbol-level scoring for vulnerable-function identification (plan §4.1).

Unit: one (advisory, symbol) pair. Gold and predictions are ``{advisory_id: set[str]}``.

Variants (reported separately, never merged):
  - ``exact``: fully qualified name equality;
  - ``class``: lenient; methods are projected to their class on both sides, so a
    gold method is matched by predicting its class (or any method of that class);
  - ``module``: lenient; every symbol is projected to its module.

Policies:
  - advisories with empty gold are excluded from every metric and counted;
  - an advisory with no predictions is an *abstention*: it contributes its gold symbols
    as false negatives to micro recall/F1, is excluded from macro precision, and counts
    toward the abstention rate (coverage = answered / scored);
  - macro F1 averages over all scored advisories with abstentions scored as 0;
  - 95% CIs: percentile bootstrap over advisories (resampled with replacement) with a
    fixed seed, for micro precision / recall / F1.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

Sets = dict[str, set[str]]
Projector = Callable[[str], str]

MODULE = "<module>"
LOCALS = "<locals>"


def _parent(sym: str) -> str | None:
    return sym.rsplit(".", 1)[0] if "." in sym else None


def class_projector(kinds: dict[str, str] | None = None) -> Projector:
    """Method -> its class. With ``kinds`` (from a symbol table) the parent must be a
    class; without, a parent whose last component starts upper-case is taken as a class.
    Nested functions (``<locals>``) are not methods and stay unchanged."""

    def is_class(sym: str) -> bool:
        if kinds is not None:
            return kinds.get(sym) == "class"
        last = sym.rsplit(".", 1)[-1]
        return last[:1].isupper() and last != LOCALS

    def project(sym: str) -> str:
        parent = _parent(sym)
        if parent and not parent.endswith(LOCALS) and is_class(parent):
            return parent
        return sym

    return project


def module_projector(modules: Iterable[str]) -> Projector:
    """Symbol -> the longest known module that prefixes it (``pkg.mod``)."""
    mods = sorted(set(modules), key=len, reverse=True)

    def project(sym: str) -> str:
        if sym.endswith("." + MODULE):
            return sym[: -len(MODULE) - 1]
        return next((m for m in mods if sym == m or sym.startswith(m + ".")), sym)

    return project


def union(*predictions: Sets) -> Sets:
    """Per-advisory union of several predictors (e.g. text ∪ diff)."""
    out: Sets = {}
    for pred in predictions:
        for aid, syms in pred.items():
            out.setdefault(aid, set()).update(syms)
    return out


@dataclass
class AdvisoryScore:
    advisory: str
    n_gold: int
    n_pred: int
    tp: int
    fp: int
    fn: int
    abstained: bool
    precision: float | None
    recall: float
    f1: float


@dataclass
class Report:
    variant: str
    scored: int
    excluded_empty_gold: list[str]
    abstained: int
    coverage: float | None
    micro_precision: float | None
    micro_recall: float | None
    micro_f1: float | None
    macro_precision_answered: float | None
    macro_recall: float | None
    macro_f1: float | None
    ci95: dict[str, tuple[float, float] | None] = field(default_factory=dict)
    per_advisory: list[AdvisoryScore] = field(default_factory=list)


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None:
        return None
    return 0.0 if p + r == 0 else 2 * p * r / (p + r)


def score_advisory(aid: str, gold: set[str], pred: set[str]) -> AdvisoryScore:
    tp = len(gold & pred)
    fp = len(pred - gold)
    fn = len(gold - pred)
    precision = tp / len(pred) if pred else None
    recall = tp / len(gold)
    f1 = _f1(precision, recall) or 0.0
    return AdvisoryScore(aid, len(gold), len(pred), tp, fp, fn, not pred, precision, recall, f1)


def _micro(rows: list[AdvisoryScore]) -> tuple[float | None, float | None, float | None]:
    tp = sum(r.tp for r in rows)
    fp = sum(r.fp for r in rows)
    fn = sum(r.fn for r in rows)
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    return p, r, _f1(p, r)


def _mean(xs: list[float]) -> float | None:
    return sum(xs) / len(xs) if xs else None


def bootstrap_ci(
    rows: list[AdvisoryScore], n_boot: int = 2000, seed: int = 20261019
) -> dict[str, tuple[float, float] | None]:
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {"micro_precision": [], "micro_recall": [], "micro_f1": []}
    if not rows:
        return dict.fromkeys(samples)
    for _ in range(n_boot):
        draw = [rows[rng.randrange(len(rows))] for _ in rows]
        for name, value in zip(samples, _micro(draw), strict=True):
            if value is not None:
                samples[name].append(value)
    out: dict[str, tuple[float, float] | None] = {}
    for name, vals in samples.items():
        if not vals:
            out[name] = None
            continue
        vals.sort()
        lo = vals[int(0.025 * (len(vals) - 1))]
        hi = vals[int(round(0.975 * (len(vals) - 1)))]
        out[name] = (lo, hi)
    return out


def score(
    gold: Sets,
    pred: Sets,
    variant: str = "exact",
    project: Projector | None = None,
    n_boot: int = 2000,
    seed: int = 20261019,
) -> Report:
    """Score ``pred`` against ``gold`` over the advisories in ``gold``."""
    proj = project or (lambda s: s)
    excluded = sorted(a for a, g in gold.items() if not g)
    rows = []
    for aid in sorted(a for a, g in gold.items() if g):
        g = {proj(s) for s in gold[aid]}
        p = {proj(s) for s in pred.get(aid, set())}
        rows.append(score_advisory(aid, g, p))
    mp, mr, mf = _micro(rows)
    answered = [r for r in rows if not r.abstained]
    return Report(
        variant=variant,
        scored=len(rows),
        excluded_empty_gold=excluded,
        abstained=len(rows) - len(answered),
        coverage=len(answered) / len(rows) if rows else None,
        micro_precision=mp,
        micro_recall=mr,
        micro_f1=mf,
        macro_precision_answered=_mean([r.precision for r in answered]),
        macro_recall=_mean([r.recall for r in rows]),
        macro_f1=_mean([r.f1 for r in rows]),
        ci95=bootstrap_ci(rows, n_boot, seed),
        per_advisory=rows,
    )
