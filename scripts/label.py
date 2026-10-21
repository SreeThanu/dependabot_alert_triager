"""Terminal labelling helper for data/validation/labels_v1.csv (plan §2.2, §2.4).

Usage:
    uv run python scripts/label.py classify [--id GHSA-...]   # phase 1: all 50 rows
    uv run python scripts/label.py gold [--id GHSA-...]       # phase 2: usable rows only
    uv run python scripts/label.py relabel [--id GHSA-...] [--force]  # re-label 15 rows (§2.4)
    uv run python scripts/label.py manual-fix                 # append manual fix candidates

Shows source material only: advisory text and references from the pinned snapshot, the
verified fix commit link (fix_commits_v1.csv) and a link to browse the repo at the vulnerable
ref (symbol_tables_v1.csv: repo and commit only). It never reads baseline outputs
(diff_baseline_*, text_baseline_*) and never prints symbol-table contents: typed gold symbols
are accepted or rejected with "not found", with no suggestions. package_type_proposed and the
classification proposals (classify_proposals_v1.csv) are read and shown in phase 1 only; the
proposal is the default answer, and classify_source records whether it was accepted or
overridden.

Rows already filled are skipped; --id revisits one row. Each finished row is saved at once
(atomic temp file + os.replace), and only that row's labelling columns are changed.
At any prompt, `:s` skips the row (nothing saved) and `:q` quits.

Each gold-phase save records its time in labels_v1.meta.json (`last_gold_save`); relabel
refuses to start until 48 hours after it unless --force is given.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import re
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from triager import advisories, snapshots, symbols
from triager.eval.gold import ALLOWED, split_symbols
from triager.fsutil import atomic_write_text

ROOT = snapshots.ROOT
SNAPSHOT_DIR = ROOT / "data" / "raw" / "ghsa"
VAL = ROOT / "data" / "validation"
LABELS = VAL / "labels_v1.csv"
FIX_COMMITS = VAL / "fix_commits_v1.csv"
REF_TABLE = VAL / "symbol_tables_v1.csv"  # repo + vulnerable commit per advisory
TABLES = VAL / "symbol_tables"
RELABEL = VAL / "relabel_v1.csv"
RELABEL_META = VAL / "relabel_v1.meta.json"
LABELS_META = VAL / "labels_v1.meta.json"
PROPOSALS = VAL / "classify_proposals_v1.csv"  # phase 1 only
MANUAL = VAL / "manual_fix_candidates.csv"
MANUAL_COLUMNS = ["ghsa_id", "commit_url", "how_found"]  # as read by resolve_fix_commits.py

CLASSIFY_COLUMNS = ("package_type", "usable", "unusable_reason")
GOLD_COLUMNS = (
    "text_names_function", "named_symbols_text", "gold_vulnerable_symbols", "gold_entry_points",
    "label_confidence", "label_basis", "minutes_spent", "notes", "labeler",
)  # fmt: skip
RELABEL_COLUMNS = ["ghsa_id", *GOLD_COLUMNS]
LABELER = "TB"
RELABEL_WAIT = timedelta(hours=48)
RELABEL_N = 15
RELABEL_SEED = 20261021

_COMMIT_URL = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+/commit/[0-9a-f]{7,40}$")
SYMBOL_FORMAT = (
    "Symbols: fully qualified, e.g. pkg.mod.Class.method; nested functions "
    "pkg.mod.outer.<locals>.inner; module-level code pkg.mod.<module>. Separate with '; '."
)

Ask = Callable[[str], str]
Out = Callable[[str], None]


class Skip(Exception):
    """Labeller typed :s; leave the row unchanged."""


class Quit(Exception):
    """Labeller typed :q (or EOF); stop the session."""


# --- CSV I/O -----------------------------------------------------------------------------


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    atomic_write_text(path, buf.getvalue())


def save_row(
    path: Path, gid: str, values: dict[str, str], new_columns: tuple[str, ...] = ()
) -> None:
    """Re-read ``path`` and set ``values`` on row ``gid`` only; every other cell is kept.

    ``new_columns`` missing from the file are appended (empty in every other row).
    """
    fields, rows = read_csv(path)
    for col in new_columns:
        if col not in fields:
            fields.append(col)
            for r in rows:
                r[col] = ""
    unknown = set(values) - set(fields)
    if unknown:
        raise KeyError(f"{path.name}: no columns {sorted(unknown)}")
    [row] = [r for r in rows if r["ghsa_id"] == gid]
    row.update(values)
    write_csv(path, fields, rows)


# --- source material ---------------------------------------------------------------------


def load_advisory(gid: str) -> advisories.Advisory:
    paths = list((SNAPSHOT_DIR / "advisories" / "github-reviewed").glob(f"*/*/{gid}/{gid}.json"))
    if len(paths) != 1:
        raise FileNotFoundError(f"{gid}: expected one snapshot record, found {len(paths)}")
    adv = advisories.parse(json.loads(paths[0].read_text()))
    if adv is None:
        raise ValueError(f"{gid}: snapshot record has no PyPI package")
    return adv


def fix_links() -> dict[str, list[str]]:
    """Commit URLs of verified fixes only (unverified best candidates are not shown)."""
    _, rows = read_csv(FIX_COMMITS)
    return {
        r["ghsa_id"]: [
            f"https://github.com/{r['repo']}/commit/{sha}"
            for sha in split_symbols(r["fix_commits"])
        ]
        for r in rows
        if r["fix_verified"] == "yes"
    }


def browse_links() -> dict[str, str]:
    """GitHub tree link at the vulnerable ref (only the repo/commit/ref columns are used)."""
    _, rows = read_csv(REF_TABLE)
    return {
        r["ghsa_id"]: f"https://github.com/{r['repo']}/tree/{r['commit']}  "
        f"({r['ref_kind']}: {r['ref']})"
        for r in rows
        if r["repo"] and r["commit"]
    }


def show_source(
    out: Out, row: dict[str, str], adv: advisories.Advisory, fixes: list[str], browse: str,
    pos: str, phase1: bool,
) -> None:  # fmt: skip
    out("")
    out("=" * 100)
    aliases = f"  ({row['aliases']})" if row.get("aliases") else ""
    out(f"[{pos}] {adv.ghsa_id}{aliases}  published {adv.published[:10]}")
    out(f"Package(s): {', '.join(adv.packages)}")
    out(f"Summary: {adv.summary}")
    out("Details:")
    out(adv.details.rstrip() or "(none)")
    out("References:")
    for url in adv.references:
        out(f"  {url}")
    out("Verified fix commit(s):" if fixes else "Verified fix commit: none")
    for url in fixes:
        out(f"  {url}")
    out(f"Browse at vulnerable ref: {browse or 'not resolved'}")
    if phase1:
        out(
            f"Proposed package_type (heuristic hint, check it): {row['package_type_proposed']}"
            f"  [{row['package_type_reason']}]"
        )
    out("-" * 100)


# --- prompts -----------------------------------------------------------------------------


def _read(ask: Ask, prompt: str, default: str) -> str:
    """One answer; Enter keeps ``default``, '-' clears it."""
    try:
        val = ask(f"{prompt} [{default}]: " if default else f"{prompt}: ").strip()
    except EOFError:
        raise Quit from None
    if val == ":q":
        raise Quit
    if val == ":s":
        raise Skip
    if val == "-":
        return ""
    return val or default


def ask_choice(
    ask: Ask, out: Out, prompt: str, allowed: set[str], default: str = "", required: bool = True
) -> str:
    while True:
        val = _read(ask, f"{prompt} ({' / '.join(sorted(allowed))})", default)
        if val in allowed or (not val and not required):
            return val
        out(f"  must be one of: {', '.join(sorted(allowed))}")


def ask_text(ask: Ask, prompt: str, default: str = "") -> str:
    return _read(ask, prompt, default)


def ask_symbols(
    ask: Ask, out: Out, prompt: str, table: set[str] | None, default: str = "",
    required: bool = True,
) -> str:  # fmt: skip
    """Accept only symbols present in the table; a rejection says "not found" and nothing else."""
    while True:
        syms = split_symbols(_read(ask, prompt, default))
        if not syms:
            if not required:
                return ""
            out("  at least one symbol is required (or :s to skip this row)")
            continue
        missing = [] if table is None else [s for s in syms if s not in table]
        if not missing:
            return "; ".join(dict.fromkeys(syms))
        for s in missing:
            out(f"  not found: {s}")


def ask_minutes(ask: Ask, out: Out, default: int) -> str:
    while True:
        val = _read(ask, "minutes_spent (auto-timed)", str(default))
        if val.isdigit():
            return val
        out("  must be a whole number of minutes")


def load_table(gid: str) -> set[str] | None:
    path = TABLES / f"{gid}.json.gz"
    return {s["symbol"] for s in symbols.load(path)["symbols"]} if path.exists() else None


# --- phases ------------------------------------------------------------------------------


def classify_done(row: dict[str, str]) -> bool:
    return bool(row["package_type"] and row["usable"]) and (
        row["usable"] == "yes" or bool(row["unusable_reason"])
    )


def gold_done(row: dict[str, str]) -> bool:
    if row["text_names_function"] in ("explicit", "partial") and not row["named_symbols_text"]:
        return False
    return all(row[c] for c in ("text_names_function", "gold_vulnerable_symbols",
                                "label_confidence", "label_basis", "minutes_spent"))  # fmt: skip


def load_proposals() -> dict[str, dict[str, str]]:
    if not PROPOSALS.exists():
        return {}
    _, rows = read_csv(PROPOSALS)
    return {r["ghsa_id"]: r for r in rows}


def prompt_classify(
    ask: Ask, out: Out, row: dict[str, str], prop: dict[str, str] | None
) -> dict[str, str]:
    """Defaults: the row's own values if already labelled, else the proposal."""
    if prop:
        reason = prop["unusable_reason"] or "-"
        out(f"Proposal (Claude, from advisory text): package_type={prop['package_type']}  "
            f"usable={prop['usable']}  unusable_reason={reason}")  # fmt: skip
        out(f"  Rationale: {prop['rationale']}")
        out("  Enter accepts each default; typing overrides it.")
    else:
        out("No proposal for this advisory.")
    prop = prop or {}

    def default(col: str) -> str:
        return row[col] or prop.get(col, "")

    ptype = ask_choice(ask, out, "package_type", ALLOWED["package_type"], default("package_type"))
    usable = ask_choice(ask, out, "usable", ALLOWED["usable"], default("usable"))
    reason = ""
    if usable == "no":
        reason = ask_choice(ask, out, "unusable_reason", ALLOWED["unusable_reason"],
                            default("unusable_reason"))  # fmt: skip
    values = {"package_type": ptype, "usable": usable, "unusable_reason": reason}
    if not prop:
        source = "no_proposal"
    elif all(values[c] == prop[c] for c in CLASSIFY_COLUMNS):
        source = "accepted"
    else:
        source = "overridden"
    return {**values, "classify_source": source}


def prompt_gold(
    ask: Ask, out: Out, prev: dict[str, str], table: set[str] | None, started: float,
    clock: Callable[[], float],
) -> dict[str, str]:  # fmt: skip
    """Gold columns for one row; ``prev`` holds this file's own earlier answers (or blanks)."""
    out("  Judge from the advisory text only (not the fix diff or the code).")
    names = ask_choice(ask, out, "text_names_function", ALLOWED["text_names_function"],
                       prev["text_names_function"])  # fmt: skip
    named = ""
    while names != "absent" and not named:
        named = ask_text(ask, "named_symbols_text (as written in the advisory; '; '-separated)",
                         prev["named_symbols_text"])  # fmt: skip
    if table is None:
        out(
            "  No symbol table for this advisory: symbols cannot be checked and are saved as typed."
        )
    out(f"  {SYMBOL_FORMAT}")
    gold = ask_symbols(ask, out, "gold_vulnerable_symbols", table,
                       prev["gold_vulnerable_symbols"])  # fmt: skip
    entry = ask_symbols(ask, out, "gold_entry_points (optional)", table,
                        prev["gold_entry_points"], required=False)  # fmt: skip
    conf = ask_choice(ask, out, "label_confidence", ALLOWED["label_confidence"],
                      prev["label_confidence"])  # fmt: skip
    basis = ask_choice(ask, out, "label_basis", ALLOWED["label_basis"], prev["label_basis"])
    earlier = int(prev["minutes_spent"]) if prev["minutes_spent"].isdigit() else 0
    timed = earlier + max(1, math.ceil((clock() - started) / 60))
    minutes = ask_minutes(ask, out, timed)
    notes = ask_text(ask, "notes (optional)", prev["notes"])
    return {
        "text_names_function": names, "named_symbols_text": named,
        "gold_vulnerable_symbols": gold, "gold_entry_points": entry, "label_confidence": conf,
        "label_basis": basis, "minutes_spent": minutes, "notes": notes, "labeler": LABELER,
    }  # fmt: skip


def select(rows: list[dict[str, str]], gid: str | None, done: Callable) -> list[dict[str, str]]:
    if gid:
        picked = [r for r in rows if r["ghsa_id"] == gid]
        if not picked:
            sys.exit(f"{gid} is not in this phase's rows")
        return picked
    return [r for r in rows if not done(r)]


def run_rows(
    out: Out, todo: list[dict[str, str]], total: int, phase1: bool,
    label_one: Callable[[dict[str, str]], dict[str, str]], save: Callable,
) -> int:  # fmt: skip
    """Show each row's source, collect answers, save immediately. Returns rows saved."""
    if not todo:
        out("Nothing left to label in this phase.")
        return 0
    fixes, browse = fix_links(), browse_links()
    saved = 0
    for i, row in enumerate(todo, 1):
        gid = row["ghsa_id"]
        adv = load_advisory(gid)
        show_source(out, row, adv, fixes.get(gid, []), browse.get(gid, ""),
                    f"{i}/{len(todo)} to do, {total} in phase", phase1)  # fmt: skip
        try:
            values = label_one(row)
        except Skip:
            out(f"  skipped {gid} (unchanged)")
            continue
        except Quit:
            out(f"Quit. {saved} row(s) saved this session; {gid} unchanged.")
            return saved
        save(gid, values)
        saved += 1
        out(f"  saved {gid}")
    out(f"Done. {saved} row(s) saved this session.")
    return saved


def cmd_classify(ask: Ask, out: Out, gid: str | None) -> int:
    _, rows = read_csv(LABELS)
    props = load_proposals()

    def save(gid: str, values: dict[str, str]) -> None:
        save_row(LABELS, gid, values, new_columns=("classify_source",))

    return run_rows(out, select(rows, gid, classify_done), len(rows), True,
                    lambda row: prompt_classify(ask, out, row, props.get(row["ghsa_id"])),
                    save)  # fmt: skip


def now_utc() -> datetime:
    return datetime.now(UTC)


def record_gold_save(when: datetime) -> None:
    """Keep the time of the latest gold-phase save (relabel waits 48 hours after it)."""
    meta = json.loads(LABELS_META.read_text()) if LABELS_META.exists() else {}
    meta["last_gold_save"] = when.isoformat(timespec="seconds")
    atomic_write_text(LABELS_META, json.dumps(meta, indent=2) + "\n")


def save_gold(gid: str, values: dict[str, str], now: Callable[[], datetime]) -> None:
    save_row(LABELS, gid, values)
    record_gold_save(now())


def relabel_wait(now: datetime) -> timedelta | None:
    """Time left before relabel may start, or None if no gold save is recorded."""
    if not LABELS_META.exists():
        return None
    last = json.loads(LABELS_META.read_text()).get("last_gold_save")
    if not last:
        return None
    return max(timedelta(0), datetime.fromisoformat(last) + RELABEL_WAIT - now)


def cmd_gold(
    ask: Ask, out: Out, gid: str | None, clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = now_utc,
) -> int:  # fmt: skip
    _, rows = read_csv(LABELS)
    usable = [r for r in rows if r["usable"] == "yes"]

    def one(row: dict[str, str]) -> dict[str, str]:
        started = clock()
        return prompt_gold(ask, out, row, load_table(row["ghsa_id"]), started, clock)

    return run_rows(out, select(usable, gid, gold_done), len(usable), False, one,
                    lambda g, v: save_gold(g, v, now))  # fmt: skip


def create_relabel(out: Out) -> None:
    """Freeze the 15-row draw once; later runs resume from relabel_v1.csv."""
    _, rows = read_csv(LABELS)
    usable = sorted(r["ghsa_id"] for r in rows if r["usable"] == "yes")
    pending = [r["ghsa_id"] for r in rows if not classify_done(r)]
    pending += [r["ghsa_id"] for r in rows if r["usable"] == "yes" and not gold_done(r)]
    if pending:
        sys.exit(f"Finish classify and gold first; {len(pending)} row(s) incomplete: {pending}")
    if len(usable) < RELABEL_N:
        sys.exit(f"Only {len(usable)} usable rows; relabel needs {RELABEL_N}")
    chosen = random.Random(RELABEL_SEED).sample(usable, RELABEL_N)
    write_csv(RELABEL, RELABEL_COLUMNS,
              [{"ghsa_id": g, **dict.fromkeys(GOLD_COLUMNS, "")} for g in chosen])  # fmt: skip
    meta = {
        "seed": RELABEL_SEED, "n": RELABEL_N, "usable_pool": len(usable),
        "labels_sha256": hashlib.sha256(LABELS.read_bytes()).hexdigest(),
        "created_at": now_utc().isoformat(timespec="seconds"),
        "note": "Plan §2.4: re-label at least 48 hours after the first labels, without them.",
    }  # fmt: skip
    atomic_write_text(RELABEL_META, json.dumps(meta, indent=2) + "\n")
    out(f"Drew {RELABEL_N} of {len(usable)} usable rows (seed {RELABEL_SEED}) into {RELABEL.name}.")


def cmd_relabel(
    ask: Ask, out: Out, gid: str | None, clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = now_utc, force: bool = False,
) -> int:  # fmt: skip
    left = relabel_wait(now())
    if left is None or left > timedelta(0):
        if left is None:
            msg = f"No gold-phase save recorded in {LABELS_META.name}."
        else:
            hours, rest = divmod(int(left.total_seconds()), 3600)
            msg = f"Relabel opens 48h after the last gold save: {hours}h {rest // 60}m to go."
        if not force:
            sys.exit(f"{msg} Use --force to start anyway.")
        out(f"{msg} Starting anyway (--force).")
    if not RELABEL.exists():
        create_relabel(out)
    _, rows = read_csv(RELABEL)
    # Display needs aliases/package_type_proposed keys; gold answers come from relabel_v1.csv only.
    shown = [{**r, "aliases": "", "package_type_proposed": "", "package_type_reason": ""}
             for r in rows]  # fmt: skip

    def one(row: dict[str, str]) -> dict[str, str]:
        started = clock()
        return prompt_gold(ask, out, row, load_table(row["ghsa_id"]), started, clock)

    return run_rows(out, select(shown, gid, gold_done), len(rows), False, one,
                    lambda g, v: save_row(RELABEL, g, v))  # fmt: skip


def cmd_manual_fix(ask: Ask, out: Out) -> int:
    _, labels = read_csv(LABELS)
    ids = {r["ghsa_id"] for r in labels}
    added = 0
    out("Add manual fix candidates (Enter on ghsa_id, or :q, to stop).")
    while True:
        try:
            gid = _read(ask, "ghsa_id", "")
            if not gid:
                break
            if gid not in ids:
                out(f"  {gid} is not in labels_v1.csv")
                continue
            url = _read(ask, "commit_url (https://github.com/<owner>/<repo>/commit/<sha>)", "")
            while not _COMMIT_URL.match(url):
                out("  must be https://github.com/<owner>/<repo>/commit/<sha>")
                url = _read(ask, "commit_url", "")
            how = ""
            while not how:
                how = _read(ask, "how_found", "")
        except (Quit, Skip):
            break
        if MANUAL.exists():
            fields, rows = read_csv(MANUAL)
            if fields != MANUAL_COLUMNS:
                sys.exit(f"{MANUAL.name}: columns must be {MANUAL_COLUMNS}, got {fields}")
        else:
            rows = []
        rows.append({"ghsa_id": gid, "commit_url": url, "how_found": how})
        write_csv(MANUAL, MANUAL_COLUMNS, rows)
        added += 1
        out(f"  appended to {MANUAL.name}")
    out(f"{added} row(s) added. Re-run scripts/resolve_fix_commits.py to check them.")
    return added


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("classify", "gold", "relabel"):
        sub.add_parser(name).add_argument("--id", help="revisit one row by GHSA id")
    sub.choices["relabel"].add_argument("--force", action="store_true",
                                        help="start before the 48-hour wait is over")  # fmt: skip
    sub.add_parser("manual-fix")
    args = p.parse_args(argv)
    snapshots.verify_head(SNAPSHOT_DIR, snapshots.load("github_advisory_database"))
    if args.cmd == "classify":
        cmd_classify(input, print, args.id)
    elif args.cmd == "gold":
        cmd_gold(input, print, args.id)
    elif args.cmd == "relabel":
        cmd_relabel(input, print, args.id, force=args.force)
    else:
        cmd_manual_fix(input, print)
    return 0


if __name__ == "__main__":
    sys.exit(main())
