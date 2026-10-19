import subprocess

from helpers import adv
from triager import symbols
from triager.advisories import VersionRange

SRC = (
    "X = 1\n\nclass A:\n    def m(self):\n        def inner():\n            pass\n\n"
    "async def f():\n    pass\n"
)


def test_file_symbols_conventions():
    syms = {s["symbol"]: s["kind"] for s in symbols.file_symbols(SRC, "pkg.mod", "pkg/mod.py")}
    assert syms == {
        "pkg.mod.<module>": "module",
        "pkg.mod.A": "class",
        "pkg.mod.A.m": "function",
        "pkg.mod.A.m.<locals>.inner": "function",
        "pkg.mod.f": "function",
    }


TAGS = ["v1.0.0", "v1.1.0", "v1.2.0rc1", "v2.0.0", "v2.0.1", "v3.0.0"]


def test_vulnerable_ref_prefers_fix_parent():
    a = adv("G", ["pkg"], ranges=(VersionRange("pkg", "0", "2.0.1", None),))
    assert symbols.vulnerable_ref(a, TAGS, "abc", lambda s: s + "^") == ("fix_parent", "abc^", "")


def test_vulnerable_ref_last_affected_tag_over_ranges():
    a = adv("G", ["pkg"], ranges=(VersionRange("pkg", "0", "1.1.0", None),
                                  VersionRange("pkg", "2.0.0", "2.0.1", None)))  # fmt: skip
    assert symbols.vulnerable_ref(a, TAGS, None)[:2] == ("last_affected_tag", "v2.0.0")


def test_vulnerable_ref_unfixed_uses_latest_stable_tag():
    a = adv("G", ["pkg"], ranges=(VersionRange("pkg", "2.0.0", None, None),))
    assert symbols.vulnerable_ref(a, TAGS, None)[:2] == ("latest_tag_unfixed", "v3.0.0")
    a = adv("G", ["pkg"], ranges=(VersionRange("pkg", "0", None, "1.1.0"),))
    assert symbols.vulnerable_ref(a, TAGS, None)[:2] == ("last_affected_tag", "v1.1.0")
    assert symbols.vulnerable_ref(a, [], None) is None


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)  # fmt: skip


def test_build_table_on_local_repo_and_roundtrip(tmp_path):
    work = tmp_path / "w"
    for path, text in {
        "src/pkg/__init__.py": "",
        "src/pkg/mod.py": SRC,
        "src/pkg/broken.py": "def (:\n",
        "src/pkg/tests/test_mod.py": "def test_x():\n    pass\n",
        "docs/conf.py": "x = 1\n",
    }.items():
        f = work / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    _git(work.parent, "init", "-q", str(work))
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "-m", "c")
    table = symbols.build_table(work, "HEAD", ["pkg"])
    assert table["import_roots"] == ["src/pkg"]
    assert table["files_unparsed"] == ["src/pkg/broken.py"]
    names = {s["symbol"] for s in table["symbols"]}
    assert "pkg.mod.A.m.<locals>.inner" in names and "pkg.<module>" in names
    assert not any("test_x" in n for n in names)
    out = tmp_path / "t.json.gz"
    symbols.save(out, table)
    assert symbols.load(out) == table
    first = out.read_bytes()
    symbols.save(out, table)
    assert out.read_bytes() == first  # deterministic gzip (mtime=0)
