#!/usr/bin/env python3
"""Regenerate SUMMARY.md from the empirical per-run ``cells.json`` matrix.

Source of truth is what was actually driven, not the grading envelopes: every
row lists the cells it holds, so the table can never claim more than the PoCs
prove. ``poc/row.py`` writes the same cells, so regenerate with

    python3 build.py            # needs poc/verification.log or RCE_LOG
    RCE_LOG=/tmp/my_run.log python3 build.py
"""
import json
import os
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent

FAMILIES = [
    "request_line_split",
    "body_replay_desync",
    "cache_exec_poison",
    "1xx_nesting",
    "pct2f_split",
    "config_quoted_space",
    "multi_hop_chain",
    "retry_double_exec",
]

# Cells that are confirmed by source/lane evidence but did **not** reproduce in
# the harness, with the reason. They stay in the row and are never counted.
KNOWN_NEGATIVE = {
    ("f2b3415b", "cache_exec_poison"): "negative*",
}


def load_rows():
    rows = []
    for cells_file in sorted(OUT.glob("*/cells.json")):
        spec = json.loads(cells_file.read_text())
        run = cells_file.parent.name
        held = {cell["family"]: cell for cell in spec.get("cells", [])}
        rows.append((run, spec.get("build", run), held))
    return rows


def load_results(path):
    """Read the last verdict per (run, family) out of a row.py log."""
    verdicts = {}
    if not path or not path.is_file():
        return verdicts
    for line in path.read_text().splitlines():
        if line.startswith(("PASS ", "FAIL ")):
            state, run, family = line.split(" ")[:3]
            verdicts[(run, family)] = state
    return verdicts


def main():
    log = pathlib.Path(os.environ.get("RCE_LOG", OUT / "poc" / "verification.log"))
    verdicts = load_results(log)
    rows = load_rows()

    header = ["run"] + FAMILIES + ["total positive"]
    lines = [
        "# RCE matrix - one folder per run, one cell per family",
        "",
        "Generated from each run's `cells.json` by `build.py`; the cells are the ones `poc/row.py`",
        "actually drives. Status is the harness verdict when a verification log is present, otherwise",
        "the cell is reported as `positive` because a PoC exists for it.",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
    ]

    totals = {family: 0 for family in FAMILIES}
    counts = {"positive": 0, "unverified": 0, "negative": 0}
    for run, build, held in rows:
        cells = []
        positives = 0
        for family in FAMILIES:
            if family in held:
                verdict = verdicts.get((run, family))
                if verdict is None:
                    mark, kind = "positive", "unverified"
                elif verdict == "PASS":
                    mark, kind = "positive", "positive"
                else:
                    mark, kind = "negative", "negative"
                positives += mark == "positive"
                totals[family] += mark == "positive"
            else:
                mark = KNOWN_NEGATIVE.get((build, family), "negative")
                kind = "negative"
            counts[kind] += 1
            cells.append(mark)
        lines.append("| " + " | ".join([run] + cells + [str(positives)]) + " |")

    lines += ["", "**Column totals (positive)**"]
    lines += [f"- {family}: {totals[family]}" for family in FAMILIES]
    lines += [
        "",
        f"Rows: {len(rows)}. Cells: {sum(counts.values())} "
        f"({counts['positive']} verified positive, {counts['unverified']} unverified, "
        f"{counts['negative']} negative).",
        "",
        "A cell is positive when the harness drives real request bytes at the build and the control",
        "peer sees the effect upstream: an executed request line, a replay the peer accepted as its",
        "own request, an inner response after a 1xx, or a victim served from cache with no fetch.",
        '"A request was sent" is never enough. Severity of the underlying finding is not a criterion,',
        "so the medium retry double-exec counts because a command that already ran runs again.",
        "",
        "`*` `f2b3415b` has a cacheable source line but never served the victim from cache in this",
        "harness, so its cache cell stays negative and is not counted.",
    ]
    (OUT / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print(f"{len(rows)} runs, {sum(counts.values())} cells -> {OUT / 'SUMMARY.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
