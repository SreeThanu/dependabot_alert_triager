import pytest

from triager.eval import score as sc


def test_exact_scores_and_micro_macro():
    gold = {"A": {"m.f", "m.g"}, "B": {"m.h"}, "C": set()}
    pred = {"A": {"m.f", "m.x"}, "B": set()}
    r = sc.score(gold, pred, n_boot=200)
    assert r.scored == 2 and r.excluded_empty_gold == ["C"]
    assert r.abstained == 1 and r.coverage == 0.5
    a, b = r.per_advisory
    assert (a.tp, a.fp, a.fn, a.precision, a.recall) == (1, 1, 1, 0.5, 0.5)
    assert b.abstained and b.precision is None and (b.recall, b.f1, b.fn) == (0, 0, 1)
    # micro: TP 1, FP 1, FN 2 (abstained B contributes its gold as FN)
    assert r.micro_precision == 0.5
    assert r.micro_recall == pytest.approx(1 / 3)
    assert r.micro_f1 == pytest.approx(0.4)
    assert r.macro_precision_answered == 0.5
    assert r.macro_f1 == pytest.approx(0.25)  # (0.5 + 0) / 2


def test_class_level_lenient_variant():
    gold = {"A": {"pkg.mod.Reader.read"}}
    pred = {"A": {"pkg.mod.Reader"}}
    assert sc.score(gold, pred, n_boot=10).micro_f1 == 0
    r = sc.score(gold, pred, "class", sc.class_projector(), n_boot=10)
    assert r.micro_f1 == 1
    # Kinds from a symbol table override the capitalisation heuristic.
    kinds = {"pkg.mod.reader": "class"}
    proj = sc.class_projector(kinds)
    assert proj("pkg.mod.reader.read") == "pkg.mod.reader"
    assert proj("pkg.mod.outer.<locals>.inner") == "pkg.mod.outer.<locals>.inner"


def test_module_level_lenient_variant():
    proj = sc.module_projector({"pkg.mod", "pkg"})
    assert proj("pkg.mod.Reader.read") == "pkg.mod"
    assert proj("pkg.mod.<module>") == "pkg.mod"
    gold = {"A": {"pkg.mod.Reader.read"}}
    pred = {"A": {"pkg.mod.helper"}}
    assert sc.score(gold, pred, "module", proj, n_boot=10).micro_f1 == 1


def test_all_abstain_and_all_empty_gold():
    r = sc.score({"A": {"x"}}, {}, n_boot=10)
    assert r.micro_precision is None and r.micro_recall == 0 and r.micro_f1 is None
    assert r.coverage == 0
    r = sc.score({"A": set()}, {"A": {"x"}}, n_boot=10)
    assert r.scored == 0 and r.excluded_empty_gold == ["A"] and r.micro_f1 is None


def test_bootstrap_is_seeded_and_brackets_point_estimate():
    gold = {f"A{i}": {"f", "g"} for i in range(30)}
    pred = {f"A{i}": ({"f"} if i % 3 else {"f", "g"}) for i in range(30)}
    r1 = sc.score(gold, pred, n_boot=500, seed=7)
    r2 = sc.score(gold, pred, n_boot=500, seed=7)
    assert r1.ci95 == r2.ci95
    lo, hi = r1.ci95["micro_recall"]
    assert lo <= r1.micro_recall <= hi and lo < hi
    assert r1.ci95["micro_precision"] == (1.0, 1.0)


def test_union_predictor():
    u = sc.union({"A": {"f"}, "B": {"g"}}, {"A": {"h"}, "C": {"k"}})
    assert u == {"A": {"f", "h"}, "B": {"g"}, "C": {"k"}}
