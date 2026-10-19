import pytest

from helpers import adv
from triager import families


def test_load_normalises_names_and_rejects_conflicts(tmp_path):
    cfg = tmp_path / "f.yaml"
    cfg.write_text("families:\n  praisonai: [PraisonAI, praisonai_agents]\n")
    assert families.load(cfg) == {"praisonai": "praisonai", "praisonai-agents": "praisonai"}
    cfg.write_text("families:\n  a: [x]\n  b: [X]\n")
    with pytest.raises(ValueError, match="x is in families a and b"):
        families.load(cfg)


def test_name_pattern_detection():
    names = [
        "praisonai", "praisonaiagents", "praisonai-platform",  # prefix + suffix
        "foo-cpu", "foo-gpu",                                  # siblings, base absent
        "requests", "requests-hardened",                       # prefix only (plugin-like)
        "pillow",                                              # alone
        "tensorflow", "tensorflow-gpu",                        # already one family
    ]  # fmt: skip
    mapping = {"tensorflow": "tensorflow", "tensorflow-gpu": "tensorflow"}
    got = families.detect_candidates(names, mapping)
    assert got == {
        "foo": ["foo-cpu", "foo-gpu"],
        "praisonai": ["praisonai", "praisonai-platform", "praisonaiagents"],
        "requests": ["requests", "requests-hardened"],
    }


def test_shared_repo_uses_package_refs_of_single_package_advisories_only():
    pool = [
        adv("GHSA-1", ["langflow"], package_refs=["https://github.com/langflow-ai/langflow"]),
        adv("GHSA-2", ["langflow-base"], package_refs=["https://github.com/Langflow-AI/langflow"]),
        # Multi-package advisory: its repo must not be attributed to either package.
        adv("GHSA-3", ["open-webui", "starlette"], package_refs=["https://github.com/x/shared"]),
        adv("GHSA-4", ["other"], package_refs=["https://github.com/x/shared"]),
    ]
    repos = families.repos_by_package(pool)
    assert repos["langflow-base"] == {"langflow-ai/langflow"}
    assert "starlette" not in repos
    assert families.detect_shared_repo(repos, {}) == {
        "langflow-ai/langflow": ["langflow", "langflow-base"]
    }
    # Already one confirmed family -> not a candidate.
    assert families.detect_shared_repo(repos, {"langflow-base": "langflow"}) == {}


def test_review_folds_name_pattern_into_repo_group_and_marks_pending():
    review = families.build_review(
        {"langflow-ai/langflow": ["langflow", "langflow-base"]},
        {"langflow": ["langflow", "langflow-base"], "requests": ["requests", "requests-hardened"]},
    )
    assert [(e["id"], e["proposed"], e["decision"]) for e in review] == [
        ("repo:langflow-ai/langflow", "merge", "pending"),
        ("name:requests", "pending", "pending"),
    ]
    assert review[0]["evidence"] == [
        "shared_source_repo: langflow-ai/langflow",
        "name_pattern: langflow",
    ]


def test_with_groups_merges_transitively_without_mutating_input():
    mapping = {"tensorflow-gpu": "tensorflow"}
    out = families.with_groups(mapping, [["tensorflow", "tf-extra"], ["tf-extra", "tf-more"]])
    assert {out["tensorflow"], out["tensorflow-gpu"], out["tf-extra"], out["tf-more"]} == {
        "tensorflow"
    }
    assert mapping == {"tensorflow-gpu": "tensorflow"}
