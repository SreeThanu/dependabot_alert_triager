from triager.baselines import text as tb

TABLE = [
    {"symbol": "pypdf.filters.<module>", "kind": "module"},
    {"symbol": "pypdf.filters.FlateDecode", "kind": "class"},
    {"symbol": "pypdf.filters.FlateDecode.decode", "kind": "function"},
    {"symbol": "pypdf.filters.LZWDecode.decode", "kind": "function"},
    {"symbol": "pypdf._reader.<module>", "kind": "module"},
    {"symbol": "pypdf._reader.PdfReader", "kind": "class"},
    {"symbol": "pypdf._reader.PdfReader.get_object", "kind": "function"},
    {"symbol": "pypdf._utils.outer", "kind": "function"},
    {"symbol": "pypdf._utils.outer.<locals>.inner", "kind": "function"},
    {"symbol": "pypdf._utils.rmtree", "kind": "function"},
    {"symbol": "pypdf.repo.<module>", "kind": "module"},
]
IDX = tb.SymbolIndex.build(TABLE)


def test_extract_patterns():
    text = (
        "A crafted PDF triggers an infinite loop in `FlateDecode.decode()` when "
        "pypdf.PdfReader.get_object(idx) is called. The read_stream function and "
        "method parse_xref are also involved; see pypdf/filters.py and https://x.com/a.b."
    )
    got = tb.extract(text)
    assert got["FlateDecode.decode"] == ["backtick", "dotted", "call"]
    assert "call" in got["pypdf.PdfReader.get_object"]
    assert got["read_stream"] == ["phrase"]
    assert got["parse_xref"] == ["phrase"]
    assert "path" in got["pypdf.filters"]
    assert not any("x.com" in k for k in got)
    assert "The" not in got and "and" not in got


def test_resolve_kinds():
    assert tb.resolve("pypdf.filters.FlateDecode.decode", IDX).match_type == "exact"
    m = tb.resolve("pypdf.filters", IDX)
    assert (m.match_type, m.symbols) == ("exact", ("pypdf.filters.<module>",))
    m = tb.resolve("FlateDecode.decode", IDX)
    assert (m.match_type, m.symbols) == ("unique_suffix", ("pypdf.filters.FlateDecode.decode",))
    m = tb.resolve("decode", IDX)
    assert m.match_type == "ambiguous" and len(m.symbols) == 2
    assert tb.resolve("nothing_like_this", IDX).match_type == "unresolved"


def test_resolve_public_reexport_and_locals():
    # Text uses a re-export path (pypdf.PdfReader) that is defined in pypdf._reader.
    m = tb.resolve("pypdf.PdfReader.get_object", IDX)
    assert (m.match_type, m.matched_on) == ("unique_suffix", "PdfReader.get_object")
    m = tb.resolve("outer.inner", IDX)
    assert m.symbols == ("pypdf._utils.outer.<locals>.inner",)


def test_predict_keeps_only_exact_and_unique():
    _, predicted = tb.predict("Bug in `FlateDecode.decode` and in `decode`.", IDX)
    assert predicted == {"pypdf.filters.FlateDecode.decode"}


def test_foreign_prefixes_receivers_and_bare_module_words():
    # Stdlib-qualified names must not fall back to a same-named package function.
    assert tb.resolve("shutil.rmtree", IDX).match_type == "unresolved"
    assert tb.resolve("os.path.join", IDX).match_type == "unresolved"
    # Receivers are dropped.
    m = tb.resolve("self.get_object", IDX)
    assert m.symbols == ("pypdf._reader.PdfReader.get_object",)
    # A bare word does not name a module; a dotted module path does.
    assert tb.resolve("repo", IDX).match_type == "unresolved"
    assert tb.resolve("pypdf.repo", IDX).symbols == ("pypdf.repo.<module>",)
