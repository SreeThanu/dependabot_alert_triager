"""Heuristic *proposal* for the package_type label (plan §2.2).

This only pre-fills the helper columns package_type_proposed / package_type_reason.
The real package_type label is set by a human. Every signal that fired is listed in
the reason so the proposal can be checked rather than trusted.
"""

from __future__ import annotations

import re
from typing import Any

from triager.advisories import Advisory

# (type, label, pattern). Text patterns run on summary + details.
TEXT_SIGNALS: list[tuple[str, str, re.Pattern[str]]] = [
    ("model_format", "pickle", re.compile(r"\bpickle\b|\bunpickl", re.I)),
    (
        "model_format",
        "model-file",
        re.compile(
            r"malicious (model|checkpoint)|model files?\b"
            r"|\.(pt|pth|ckpt|safetensors|gguf|keras|h5)\b",
            re.I,
        ),
    ),
    (
        "native_ext",
        "memory-safety",
        re.compile(
            r"heap[- ]|buffer overflow|out[- ]of[- ]bounds|use[- ]after[- ]free|null pointer"
            r"|segmentation fault|segfault|memory corruption|double free",
            re.I,
        ),
    ),
    ("native_ext", "c-source", re.compile(r"\b\w+\.(c|cc|cpp|cxx|h|hpp)\b|\bC\+\+")),
    (
        "application",
        "web-ui",
        re.compile(
            r"web ?ui|dashboard|admin (panel|interface|page)|user interface|front-?end", re.I
        ),
    ),
    (
        "application",
        "web-attack",
        re.compile(r"cross-site|\bXSS\b|\bCSRF\b|\bSSRF\b|open redirect", re.I),
    ),
    (
        "application",
        "server-endpoint",
        re.compile(r"\bendpoint\b|/api/|\bself-hosted\b|authenticated users?\b|\blogin\b", re.I),
    ),
    ("cli", "command-line", re.compile(r"command[- ]line|\bCLI\b", re.I)),
    (
        "library",
        "named-callable",
        re.compile(r"`[A-Za-z_][\w.]*(\(\))?`|\b[A-Za-z_][\w]*(\.[A-Za-z_]\w*)+\(\)"),
    ),
    ("library", "api-word", re.compile(r"\b(function|method|class|API|library)\b")),
]

PYPI_SUMMARY_SIGNALS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "application",
        "summary-app",
        re.compile(
            r"web ?ui|web app|application|platform|server|dashboard|self-hosted|interface", re.I
        ),
    ),
    ("cli", "summary-cli", re.compile(r"command[- ]line|\bCLI\b", re.I)),
    (
        "library",
        "summary-lib",
        re.compile(r"\blibrary\b|\bSDK\b|\btoolkit\b|\bframework\b|\bbindings?\b", re.I),
    ),
]

CLASSIFIER_SIGNALS: list[tuple[str, str, str]] = [
    ("native_ext", "clf-lang-c", "Programming Language :: C"),
    ("application", "clf-web-env", "Environment :: Web Environment"),
    ("cli", "clf-console", "Environment :: Console"),
    ("library", "clf-libraries", "Topic :: Software Development :: Libraries"),
]

PRECEDENCE = ["model_format", "native_ext", "application", "cli", "library"]


def propose(adv: Advisory, pypi: dict[str, dict[str, Any]]) -> tuple[str, str]:
    """Return (proposed_type, reason). Highest signal count wins; ties by PRECEDENCE."""
    hits: dict[str, list[str]] = {t: [] for t in PRECEDENCE}
    text = f"{adv.summary}\n{adv.details}"
    for typ, label, pat in TEXT_SIGNALS:
        if pat.search(text):
            hits[typ].append(f"text:{label}")
    missing = []
    for pkg in adv.packages:
        info = (pypi.get(pkg) or {}).get("info")
        if info is None:
            missing.append(pkg)
            continue
        summary = info.get("summary") or ""
        for typ, label, pat in PYPI_SUMMARY_SIGNALS:
            if pat.search(summary):
                hits[typ].append(f"pypi:{label}")
        classifiers = info.get("classifiers") or []
        for typ, label, prefix in CLASSIFIER_SIGNALS:
            if any(c.startswith(prefix) for c in classifiers):
                hits[typ].append(f"pypi:{label}")
    scored = [(len(hits[t]), -PRECEDENCE.index(t), t) for t in PRECEDENCE if hits[t]]
    proposed = max(scored)[2] if scored else "other"
    parts = [f"{t}=[{', '.join(sorted(set(hits[t])))}]" for t in PRECEDENCE if hits[t]]
    if missing:
        parts.append(f"pypi-missing=[{', '.join(missing)}]")
    return proposed, "; ".join(parts) or "no signals"
