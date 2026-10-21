import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from triager import symbols

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "label.py"
REAL_LABELS = REPO / "data" / "validation" / "labels_v1.csv"

spec = importlib.util.spec_from_file_location("label", SCRIPT)
label = importlib.util.module_from_spec(spec)
spec.loader.exec_module(label)

LABEL_FIELDS = REAL_LABELS.open().readline().strip().split(",")
FORBIDDEN = ("diff_baseline", "text_baseline")
SENTINEL = "SENTINEL_BASELINE_OUTPUT"
TABLE_SYMBOLS = [
    "pkg.secret.<module>",
    "pkg.hidden.Secret",
    "pkg.mod.Reader.read",
    "pkg.api.open_file",
]

# Audit hook (cannot be removed once added), so it only records while OPENED is a list.
OPENED: list[str] | None = None


def _audit(event, args):
    if event == "open" and OPENED is not None and isinstance(args[0], str | Path):
        OPENED.append(str(args[0]))


sys.addaudithook(_audit)


def osv(gid, details=""):
    return {
        "id": gid, "aliases": [f"CVE-{gid[-4:]}"], "published": "2025-06-01T00:00:00Z",
        "summary": f"summary of {gid}", "details": details or f"details of {gid}",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Pkg"}}],
        "references": [{"type": "WEB", "url": f"https://example.org/{gid}"}],
    }  # fmt: skip


def label_row(gid, **kw):
    row = dict.fromkeys(LABEL_FIELDS, "")
    row.update(ghsa_id=gid, aliases=f"CVE-{gid[-4:]}", packages="pkg",
               package_type_proposed="library", package_type_reason="pypi:summary-lib")  # fmt: skip
    row.update(kw)
    return row


def write(path, fields, rows):
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def read(path):
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake snapshot + validation dir with 20 advisories; GHSA-0000 has a symbol table."""
    snap = tmp_path / "ghsa"
    val = tmp_path / "validation"
    (val / "symbol_tables").mkdir(parents=True)
    ids = [f"GHSA-{i:04d}" for i in range(20)]
    for gid in ids:
        d = snap / "advisories" / "github-reviewed" / "2025" / "06" / gid
        d.mkdir(parents=True)
        (d / f"{gid}.json").write_text(json.dumps(osv(gid)))
    write(val / "labels_v1.csv", LABEL_FIELDS, [label_row(g) for g in ids])
    write(val / "fix_commits_v1.csv", ["ghsa_id", "repo", "fix_verified", "fix_commits"], [
        {"ghsa_id": "GHSA-0000", "repo": "o/r", "fix_verified": "yes", "fix_commits": "abc1234"},
        {"ghsa_id": "GHSA-0001", "repo": "o/r", "fix_verified": "no", "fix_commits": "dead999"},
    ])  # fmt: skip
    write(val / "symbol_tables_v1.csv", ["ghsa_id", "repo", "ref_kind", "ref", "commit"],
          [{"ghsa_id": "GHSA-0000", "repo": "o/r", "ref_kind": "fix_parent", "ref": "abc1234^",
            "commit": "fff0000"}])  # fmt: skip
    symbols.save(val / "symbol_tables" / "GHSA-0000.json.gz",
                 {"symbols": [{"symbol": s, "kind": "x"} for s in TABLE_SYMBOLS]})  # fmt: skip
    for name in ("diff_baseline_v1.csv", "diff_baseline_symbols_v1.csv", "text_baseline_v1.csv",
                 "text_baseline_matches_v1.csv"):  # fmt: skip
        (val / name).write_text(f"ghsa_id,functions\nGHSA-0000,{SENTINEL}\n")
    monkeypatch.setattr(label, "SNAPSHOT_DIR", snap)
    for attr, name in [("LABELS", "labels_v1.csv"), ("FIX_COMMITS", "fix_commits_v1.csv"),
                       ("REF_TABLE", "symbol_tables_v1.csv"), ("TABLES", "symbol_tables"),
                       ("RELABEL", "relabel_v1.csv"), ("RELABEL_META", "relabel_v1.meta.json"),
                       ("MANUAL", "manual_fix_candidates.csv")]:  # fmt: skip
        monkeypatch.setattr(label, attr, val / name)
    return val


class Term:
    """Scripted answers in, captured output out."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.lines: list[str] = []
        self.prompts: list[str] = []

    def ask(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def out(self, line):
        self.lines.append(line)

    @property
    def text(self):
        return "\n".join(self.lines + self.prompts)


def set_rows(val, **by_id):
    path = val / "labels_v1.csv"
    rows = read(path)
    for r in rows:
        r.update(by_id.get(r["ghsa_id"], {}))
    write(path, LABEL_FIELDS, rows)


# --- saving --------------------------------------------------------------------------------


def test_save_row_round_trips_real_labels_byte_for_byte(tmp_path):
    copy = tmp_path / "labels.csv"
    copy.write_bytes(REAL_LABELS.read_bytes())
    gid = read(copy)[0]["ghsa_id"]
    label.save_row(copy, gid, {})
    assert copy.read_bytes() == REAL_LABELS.read_bytes()


def test_save_row_refuses_unknown_column(tmp_path):
    copy = tmp_path / "labels.csv"
    copy.write_bytes(REAL_LABELS.read_bytes())
    with pytest.raises(KeyError):
        label.save_row(copy, read(copy)[0]["ghsa_id"], {"not_a_column": "x"})


# --- phase 1 -------------------------------------------------------------------------------


def test_classify_validates_and_changes_only_its_columns(env):
    before = read(env / "labels_v1.csv")
    t = Term(["lib", "library", "yes", "application", "no", "BAD", "APP", ":q"])
    assert label.cmd_classify(t.ask, t.out, None) == 2
    after = read(env / "labels_v1.csv")
    assert (after[0]["package_type"], after[0]["usable"], after[0]["unusable_reason"]) == (
        "library", "yes", "")  # fmt: skip
    assert (after[1]["package_type"], after[1]["usable"], after[1]["unusable_reason"]) == (
        "application", "no", "APP")  # fmt: skip
    for b, a in zip(before, after, strict=True):
        assert {k: v for k, v in a.items() if k not in label.CLASSIFY_COLUMNS} == {
            k: v for k, v in b.items() if k not in label.CLASSIFY_COLUMNS
        }
    assert "must be one of" in t.text
    assert "Proposed package_type" in t.text
    assert "https://github.com/o/r/commit/abc1234" in t.text
    assert "https://github.com/o/r/tree/fff0000" in t.text
    assert "dead999" not in t.text  # unverified candidate is not shown


def test_classify_resumes_and_revisits_by_id(env):
    set_rows(env, **{"GHSA-0000": {"package_type": "library", "usable": "yes"}})
    t = Term([":q"])
    label.cmd_classify(t.ask, t.out, None)
    assert "GHSA-0001" in t.text and "[1/" in t.text
    assert "] GHSA-0000" not in t.text
    t = Term(["", "no", "NATIVE"])  # Enter keeps the current package_type
    label.cmd_classify(t.ask, t.out, "GHSA-0000")
    row = read(env / "labels_v1.csv")[0]
    assert (row["package_type"], row["usable"], row["unusable_reason"]) == (
        "library",
        "no",
        "NATIVE",
    )


def test_skip_and_quit_leave_row_unchanged(env):
    before = (env / "labels_v1.csv").read_bytes()
    t = Term(["library", ":s", ":q"])
    assert label.cmd_classify(t.ask, t.out, None) == 0
    assert (env / "labels_v1.csv").read_bytes() == before


# --- phase 2 -------------------------------------------------------------------------------


def usable(val, *ids):
    set_rows(val, **{g: {"package_type": "library", "usable": "yes"} for g in ids})


def test_gold_validates_symbols_without_suggestions(env):
    usable(env, "GHSA-0000")
    clock = iter([0.0, 400.0])
    t = Term(["pkg.mod.Reader.raed", "pkg.mod.Reader.read", "pkg.api.open_fil; pkg.api.open_file",
              "pkg.api.open_file", "high", "both", "", "a note"])  # fmt: skip
    assert label.cmd_gold(t.ask, t.out, None, clock=lambda: next(clock)) == 1
    row = read(env / "labels_v1.csv")[0]
    assert row["gold_vulnerable_symbols"] == "pkg.mod.Reader.read"
    assert row["gold_entry_points"] == "pkg.api.open_file"
    assert (row["label_confidence"], row["label_basis"], row["notes"]) == ("high", "both", "a note")
    assert row["minutes_spent"] == "7"  # 400 s, rounded up
    assert "  not found: pkg.mod.Reader.raed" in t.lines
    assert "  not found: pkg.api.open_fil" in t.lines
    typed = {"pkg.mod.Reader.read", "pkg.api.open_file"}
    for sym in set(TABLE_SYMBOLS) - typed:
        assert sym not in t.text  # never lists or suggests candidates
    assert "Proposed package_type" not in t.text


def test_gold_only_usable_rows_and_minutes_editable(env):
    usable(env, "GHSA-0003")
    set_rows(env, **{"GHSA-0004": {"usable": "no", "unusable_reason": "APP"}})
    t = Term(["x.y", "", "low", "text", "12", ""])
    label.cmd_gold(t.ask, t.out, None, clock=lambda: 0.0)
    rows = {r["ghsa_id"]: r for r in read(env / "labels_v1.csv")}
    assert rows["GHSA-0003"]["minutes_spent"] == "12"
    assert rows["GHSA-0003"]["gold_vulnerable_symbols"] == "x.y"  # no table: saved as typed
    assert "No symbol table" in t.text
    assert not rows["GHSA-0004"]["gold_vulnerable_symbols"]
    assert "1/1 to do, 1 in phase" in t.text


# --- source-only guarantee -----------------------------------------------------------------


def test_helper_never_reads_baseline_outputs(env):
    global OPENED
    usable(env, *[f"GHSA-{i:04d}" for i in range(20)])
    OPENED = []
    try:
        terms = [Term(["", ""]), Term(["pkg.mod.Reader.read", "", "high", "diff", "", ""]
                                      + ["a.b", "", "low", "text", "", ""] * 19)]  # fmt: skip
        label.cmd_classify(terms[0].ask, terms[0].out, "GHSA-0000")
        label.cmd_gold(terms[1].ask, terms[1].out, None, clock=lambda: 0.0)
        terms.append(Term([":q"]))
        label.cmd_relabel(terms[2].ask, terms[2].out, None)
        terms.append(Term(["GHSA-0000", "https://github.com/o/r/commit/abc1234", "advisory", ""]))
        label.cmd_manual_fix(terms[3].ask, terms[3].out)
        opened = list(OPENED)
    finally:
        OPENED = None
    assert any("labels_v1.csv" in p for p in opened)  # the hook does see the helper's reads
    assert not [p for p in opened if any(f in Path(p).name for f in FORBIDDEN)]
    assert all(SENTINEL not in t.text for t in terms)
    source = SCRIPT.read_text()
    assert "baselines" not in source.replace("baseline outputs", "")
    for f in FORBIDDEN:
        assert f + "_" not in source.split('"""', 2)[2]  # no path to them outside the docstring


# --- relabel -------------------------------------------------------------------------------


def test_relabel_refuses_until_gold_is_complete(env):
    usable(env, "GHSA-0000")
    with pytest.raises(SystemExit):
        label.cmd_relabel(Term([]).ask, Term([]).out, None)
    assert not (env / "relabel_v1.csv").exists()


def test_relabel_draws_fixed_15_and_hides_first_answers(env):
    ids = [f"GHSA-{i:04d}" for i in range(18)]
    usable(env, *ids)
    set_rows(env, **{g: {"gold_vulnerable_symbols": f"first.answer{i}", "label_confidence": "high",
                         "label_basis": "diff", "minutes_spent": "3", "notes": f"firstnote{i}"}
                     for i, g in enumerate(ids)})  # fmt: skip
    for g in ("GHSA-0018", "GHSA-0019"):
        set_rows(env, **{g: {"package_type": "application", "usable": "no",
                             "unusable_reason": "APP"}})  # fmt: skip
    labels_before = (env / "labels_v1.csv").read_bytes()
    t = Term([":q"])
    label.cmd_relabel(t.ask, t.out, None)
    drawn = [r["ghsa_id"] for r in read(env / "relabel_v1.csv")]
    assert len(drawn) == 15 and set(drawn) <= set(ids)
    meta = json.loads((env / "relabel_v1.meta.json").read_text())
    assert (meta["seed"], meta["n"], meta["usable_pool"]) == (label.RELABEL_SEED, 15, 18)
    assert "first.answer" not in t.text and "firstnote" not in t.text
    assert "Proposed package_type" not in t.text

    # Answers go to relabel_v1.csv; labels_v1.csv is untouched; the draw is frozen.
    first = drawn[0]
    t = Term(["new.sym", "", "medium", "code-reading", "", ""])
    label.cmd_relabel(t.ask, t.out, first, clock=lambda: 0.0)
    rel = {r["ghsa_id"]: r for r in read(env / "relabel_v1.csv")}
    assert rel[first]["gold_vulnerable_symbols"] == "new.sym"
    assert [r["ghsa_id"] for r in read(env / "relabel_v1.csv")] == drawn
    assert (env / "labels_v1.csv").read_bytes() == labels_before
    assert "first.answer" not in t.text and "firstnote" not in t.text


# --- manual fix candidates -----------------------------------------------------------------


def test_manual_fix_creates_header_and_appends(env):
    t = Term(["GHSA-9999", "GHSA-0001", "not a url", "https://github.com/o/r/commit/abc1234",
              "found in changelog", "GHSA-0002", "https://github.com/o/r/commit/def5678", "PR",
              ""])  # fmt: skip
    assert label.cmd_manual_fix(t.ask, t.out) == 2
    path = env / "manual_fix_candidates.csv"
    assert path.read_text().splitlines()[0] == "ghsa_id,commit_url,how_found"
    assert [r["ghsa_id"] for r in read(path)] == ["GHSA-0001", "GHSA-0002"]
    assert "is not in labels_v1.csv" in t.text and "must be https" in t.text
    t = Term(["GHSA-0003", "https://github.com/o/r/commit/0123456", "manual", ":q"])
    label.cmd_manual_fix(t.ask, t.out)
    assert [r["ghsa_id"] for r in read(path)] == ["GHSA-0001", "GHSA-0002", "GHSA-0003"]


def test_manual_columns_match_resolver():
    src = (REPO / "scripts" / "resolve_fix_commits.py").read_text()
    assert f"MANUAL_COLUMNS = {label.MANUAL_COLUMNS!r}".replace("'", '"') in src
