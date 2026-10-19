import csv

from triager.baselines.text import SymbolIndex
from triager.eval import gold

IDX = SymbolIndex.build(
    [
        {"symbol": "pkg.mod.<module>", "kind": "module"},
        {"symbol": "pkg.mod.Reader", "kind": "class"},
        {"symbol": "pkg.mod.Reader.read", "kind": "function"},
        {"symbol": "pkg.api.open_file", "kind": "function"},
    ]
)


def row(**kw):
    base = {"ghsa_id": "GHSA-1", "gold_vulnerable_symbols": "", "gold_entry_points": ""}
    return {**base, **kw}


def test_valid_row_has_no_issues():
    r = row(
        gold_vulnerable_symbols="pkg.mod.Reader.read",
        gold_entry_points="pkg.api.open_file",
        label_confidence="high",
        label_basis="both",
        usable="yes",
        package_type="library",
    )
    assert gold.check_row(r, IDX) == []


def test_typo_symbol_reported_with_suggestion():
    [issue] = gold.check_row(
        row(gold_vulnerable_symbols="pkg.mod.Reader.raed", label_confidence="low",
            label_basis="diff"), IDX)  # fmt: skip
    assert issue.problem == "not in symbol table"
    assert "pkg.mod.Reader.read" in issue.suggestion


def test_enumerations_and_required_fields():
    issues = gold.check_row(
        row(gold_vulnerable_symbols="pkg.mod.Reader.read; pkg.api.open_file",
            label_confidence="sure", label_basis="", usable="no"), IDX)  # fmt: skip
    problems = {(i.column, i.problem.split(" ")[0]) for i in issues}
    assert ("label_confidence", "not") in problems
    assert ("label_basis", "empty") in problems
    assert ("unusable_reason", "usable") in problems


def test_missing_symbol_table_is_a_warning(tmp_path):
    [issue] = gold.check_row(
        row(gold_vulnerable_symbols="x.y", label_confidence="low", label_basis="text"), None
    )
    assert issue.severity == "warning"


def test_check_gold_script_on_synthetic_csv(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    path = tmp_path / "labels.csv"
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["ghsa_id", "gold_vulnerable_symbols",
                                           "gold_entry_points", "label_confidence",
                                           "label_basis"])  # fmt: skip
        w.writeheader()
        w.writerow({"ghsa_id": "GHSA-1", "gold_vulnerable_symbols": "pkg.mod.Reader.raed",
                    "label_confidence": "high", "label_basis": "diff"})  # fmt: skip
    script = Path(__file__).resolve().parent.parent / "scripts" / "check_gold.py"
    spec = importlib.util.spec_from_file_location("check_gold", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "load_indexes", lambda ids, d: {"GHSA-1": IDX})
    assert mod.main(["check_gold.py", str(path)]) == 1
