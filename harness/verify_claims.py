#!/usr/bin/env python3
"""Check that what the documentation claims matches what the repo can prove.

The project's stated rule is that a finding is not claimed until its
ground-truth log is in the repo. That rule was enforced by remembering it, and
it had already slipped: the README quoted harness rates (`2/3`, `3/3`, `6/9`)
that appear in no committed result file, while the committed results said
something else. Prose drifts away from evidence silently and in one direction --
toward the more impressive number.

So this is the same discipline pointed at the documentation. It reads the
committed evidence and fails if the docs claim more than the evidence supports.
Wire it into CI and the standard stops depending on anyone's memory.

Exit code 0 = consistent, 1 = drift. Run:  python harness/verify_claims.py
"""

import json
import os
import re
import sys

try:
    import yaml
except ImportError:                                  # pragma: no cover
    sys.exit("pyyaml is required: .venv/bin/pip install -r requirements.txt")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))

import sigma_eval                                    # noqa: E402

RESULTS = os.path.join(ROOT, "evidence", "harness-results.json")
CASES = os.path.join(ROOT, "harness", "cases.yaml")
README = os.path.join(ROOT, "README.md")
FINDINGS = os.path.join(ROOT, "FINDINGS.md")

problems = []
notes = []


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def check_rule_titles_resolve():
    """Every `detects:` title must name a rule that actually exists.

    A typo here is invisible: the case simply never matches its rule and is
    reported as a detection blind spot. That is a false finding pointing the
    wrong way -- it invents a gap in the defences rather than hiding one.
    """
    cases = yaml.safe_load(read(CASES))["cases"]
    titles = {r.get("title") for r in sigma_eval.load_rules()}
    for case in cases:
        for want in case.get("detects") or []:
            if want not in titles:
                problems.append(
                    f"case {case['id']}: detects '{want}', which is not the title "
                    f"of any rule in detection/rules")
    notes.append(f"{len(cases)} cases, {len(titles)} rule titles, all detects: resolve")


def check_case_ids_are_documented():
    """Every case must correspond to a finding the docs actually describe."""
    cases = yaml.safe_load(read(CASES))["cases"]
    findings = read(FINDINGS)
    readme = read(README)
    for case in cases:
        base = case["id"].rstrip("abcdefgh")          # F-09b exercises F-09
        if base not in findings and base not in readme:
            problems.append(
                f"case {case['id']} exercises {base}, which appears in neither "
                f"FINDINGS.md nor README.md")


def check_results_match_readme():
    """The headline A/B numbers must match the committed results file."""
    if not os.path.exists(RESULTS):
        problems.append(f"no committed results at {os.path.relpath(RESULTS, ROOT)}; "
                        f"run: harness/run.py --mode both --repeat 3 --json that path")
        return

    data = json.load(open(RESULTS, encoding="utf-8"))
    readme = read(README)
    by_mode = {}
    for run in data.get("runs", []):
        rs = run["results"]
        by_mode[run["mode"]] = {
            "n": len(rs),
            "succeeded": sum(1 for r in rs if r["result"] == "success"),
            "repeat": max((r.get("attempts", 1) for r in rs), default=1),
        }

    for mode, want in by_mode.items():
        notes.append(f"evidence: {mode} {want['succeeded']}/{want['n']} "
                     f"succeeded at repeat={want['repeat']}")

    # The README states the A/B as "N/M succeed" in the hardened-mode table.
    # Pull every such claim and require each to match some committed total.
    claimed = set(re.findall(r"\*\*(\d+)/(\d+) succeed\*\*", readme))
    committed = {(str(v["succeeded"]), str(v["n"])) for v in by_mode.values()}
    for c in claimed:
        if c not in committed:
            problems.append(
                f"README claims **{c[0]}/{c[1]} succeed**, but committed evidence "
                f"shows only {sorted(f'{a}/{b}' for a, b in committed)}. Re-run the "
                f"harness and commit the JSON, or correct the claim.")

    # Any "n/m" rate quoted in prose must use a denominator the evidence used.
    denominators = {v["repeat"] for v in by_mode.values()}
    for m in re.finditer(r"\*\*(\d+)/(\d+)\*\*", readme):
        num, den = int(m.group(1)), int(m.group(2))
        if num <= den <= 10 and den not in denominators and den not in {v["n"] for v in by_mode.values()}:
            problems.append(
                f"README quotes a rate of **{num}/{den}**, but committed evidence "
                f"was run at repeat={sorted(denominators)}. Nothing in the repo "
                f"supports a /{den} rate.")


def check_case_count_claim():
    """'N cases' in the README must equal the number of cases in cases.yaml."""
    n = len(yaml.safe_load(read(CASES))["cases"])
    for m in re.finditer(r"(\d+)\s+cases", read(README)):
        if int(m.group(1)) != n:
            problems.append(
                f"README says '{m.group(1)} cases' but cases.yaml defines {n}")


def check_pending_findings_are_marked():
    """A finding without committed evidence must be visibly marked as such."""
    readme = read(README)
    for m in re.finditer(r"^\|\s*\*{0,2}(F-\d+)\*{0,2}\s*\|", readme, re.M):
        fid = m.group(1)
        row = readme[m.start():readme.index("\n", m.start())]
        if "pending" in row.lower() and "⏳" not in row:
            problems.append(f"{fid} is described as pending without the ⏳ marker")


def main():
    check_rule_titles_resolve()
    check_case_ids_are_documented()
    check_results_match_readme()
    check_case_count_claim()
    check_pending_findings_are_marked()

    print("\nclaims verification")
    print("=" * 60)
    for n in notes:
        print(f"  ok    {n}")
    if not problems:
        print("\n  No drift: every documented claim is backed by committed evidence.\n")
        return 0
    print()
    for p in problems:
        print(f"  DRIFT {p}")
    print(f"\n  {len(problems)} claim(s) not supported by the evidence in this repo.")
    print("  Fix the claim or commit the evidence. Do not do neither.\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
