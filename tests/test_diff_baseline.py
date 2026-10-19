import textwrap

import pytest

from triager.baselines import diff as db

SRC = textwrap.dedent(
    """\
    import os
    LIMIT = 10


    class Reader:
        mode = "r"

        def read(self, path):
            return open(path).read()

        @staticmethod
        @cache
        def helper(x):
            return x


    def outer(a):
        def inner(b):
            return b + 1
        return inner(a)


    async def fetch(url):
        return await get(url)
    """
)
# Line numbers in SRC:
#  1 import os            5 class Reader:        8 def read            9 return open...
#  2 LIMIT = 10           6 mode = "r"          11 @staticmethod      12 @cache
# 13 def helper          14 return x            17 def outer          18 def inner
# 19 return b + 1        20 return inner(a)     23 async def fetch    24 return await


def _diff(hunks, path="pkg/mod.py"):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n" + hunks


def _hits(hunks):
    [fc] = db.parse_diff(_diff(hunks))
    return {(h.symbol, h.kind) for h in db.map_changes(fc, SRC, "pkg.mod", "c1")}


def test_method_change():
    hits = _hits("@@ -9 +9 @@\n-        return open(path).read()\n+        return safe(path)\n")
    assert hits == {("pkg.mod.Reader.read", "function")}


def test_nested_function_uses_qualname_locals():
    assert _hits("@@ -19 +19 @@\n-        return b + 1\n+        return b + 2\n") == {
        ("pkg.mod.outer.<locals>.inner", "function")
    }
    # The outer function's own line maps to outer, not inner.
    assert _hits("@@ -20 +20 @@\n-    return inner(a)\n+    return inner(abs(a))\n") == {
        ("pkg.mod.outer", "function")
    }


def test_decorator_line_belongs_to_decorated_function():
    assert _hits("@@ -12 +12 @@\n-    @cache\n+    @lru_cache\n") == {
        ("pkg.mod.Reader.helper", "function")
    }


def test_async_def():
    hunk = "@@ -24 +24 @@\n-    return await get(url)\n+    return await get(url, t=5)\n"
    assert _hits(hunk) == {("pkg.mod.fetch", "function")}


def test_module_level_and_class_level_changes():
    hits = _hits(
        '@@ -2 +2 @@\n-LIMIT = 10\n+LIMIT = 5\n@@ -6 +6 @@\n-    mode = "r"\n+    mode = "rb"\n'
    )
    assert hits == {("pkg.mod.<module>", "module"), ("pkg.mod.Reader", "class")}


def test_insertion_inside_body_vs_new_method_at_class_level():
    # Inserted after line 8 ('def read') with body indentation -> inside read().
    assert _hits("@@ -8,0 +9 @@\n+        check(path)\n") == {("pkg.mod.Reader.read", "function")}
    # Inserted after line 9 (end of read) at method indentation -> class-level (new method).
    assert _hits("@@ -9,0 +10,2 @@\n+    def write(self):\n+        pass\n") == {
        ("pkg.mod.Reader", "class")
    }
    # Inserted after line 0 (top of file) -> module.
    assert _hits("@@ -0,0 +1 @@\n+import re\n") == {("pkg.mod.<module>", "module")}


def test_unparsable_pre_fix_file_raises_syntax_error():
    [fc] = db.parse_diff(_diff("@@ -1 +1 @@\n-print 'x'\n+print('x')\n"))
    with pytest.raises(SyntaxError):
        db.map_changes(fc, "print 'x'\n", "pkg.mod", "c1")


def test_added_and_removed_files_are_marked():
    added = (
        "diff --git a/pkg/new.py b/pkg/new.py\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/pkg/new.py\n@@ -0,0 +1 @@\n+x = 1\n"
    )
    [fc] = db.parse_diff(added)
    assert fc.old_path is None and fc.new_path == "pkg/new.py"


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("src/pkg/mod.py", "python"),
        ("src/pkg/_speedups.pyx", "non_python_source"),
        ("src/pkg/tests/test_mod.py", "test"),
        ("src/pkg/docs/usage.md", "doc"),
        ("src/pkg/examples/demo.py", "example"),
        ("src/pkg/_version.py", "packaging"),
        ("setup.py", "outside_import_root"),
        ("frontend/src/App.tsx", "outside_import_root"),
        ("src/other/mod.py", "outside_import_root"),
    ],
)
def test_file_status(path, status):
    assert db.file_status(path, ["src/pkg"]) == status


def test_module_name():
    assert db.module_name("src/urllib3/util/url.py", "src/urllib3") == "urllib3.util.url"
    assert db.module_name("django/contrib/__init__.py", "django") == "django.contrib"
    root = "airflow-core/src/airflow"
    assert db.module_name(f"{root}/api.py", root) == "airflow.api"


def test_import_roots_monorepo_src_layout_and_renamed_import():
    paths = [
        "airflow-core/src/airflow/__init__.py",
        "airflow-core/src/airflow/models/__init__.py",
        "providers/amazon/src/airflow/providers/amazon/__init__.py",
        "airflow-core/tests/unit/__init__.py",
        "src/OpenSSL/__init__.py",
    ]
    airflow = (["airflow-core/src/airflow"], "auto:airflow")
    assert db.import_roots(paths, ["apache-airflow"]) == airflow
    assert db.import_roots(paths, ["pyopenssl"]) == (["src/OpenSSL"], "auto:openssl")
    assert db.import_roots(paths, ["nothing-here"]) == ([], "unresolved")
    assert db.import_roots(paths, ["pyopenssl"], {"pyopenssl": ["x/y"]}) == (["x/y"], "override")


def test_combine_unions_symbols_across_commits_with_provenance():
    a = db.Hit("pkg.mod.f", "function", "c1", "pkg/mod.py", (3,))
    b = db.Hit("pkg.mod.f", "function", "c2", "pkg/mod.py", (3,))
    c = db.Hit("pkg.mod.g", "function", "c2", "pkg/mod.py", (9,))
    out = db.combine([a, b, c])
    assert list(out) == [("pkg.mod.f", "function"), ("pkg.mod.g", "function")]
    assert [h.commit for h in out[("pkg.mod.f", "function")]] == ["c1", "c2"]


def test_import_roots_ignore_package_dirs_under_docs():
    paths = ["docs/api_reference/theme/mlflow/__init__.py", "mlflow/__init__.py"]
    assert db.import_roots(paths, ["mlflow"]) == (["mlflow"], "auto:mlflow")
