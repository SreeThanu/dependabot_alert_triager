import triager


def test_package_imports_with_version():
    assert triager.__version__ == "0.1.0"
