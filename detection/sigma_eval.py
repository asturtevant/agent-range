#!/usr/bin/env python3
"""Evaluate the Sigma rules in `rules/` against a tool-layer log.

Why this exists
---------------
Detection rules that have never been run against real telemetry are a wish, not
a control. This project already insists that an *attack* is only claimed once
its ground-truth log line is in the repo; the same standard has to apply to the
*defences*. So the rules are executed against the same evidence the findings are
scored from, and a rule that never fires on an attack it claims to cover is a
reportable defect rather than a comment nobody checks.

What it is not
--------------
Not a Sigma engine. It supports the subset this project's rules actually use --
exact field match, `|contains`, list-of-values OR, `and`/`or`/`not` over named
selections, one aggregation (`count() by <field> > n`) and one correlation type
(`temporal_ordered`). Anything outside that subset is reported as UNSUPPORTED,
loudly, rather than silently scored as "did not fire". A rule that quietly never
matches is the exact failure this file exists to catch.

The parser below is the part a real deployment would have to write itself, and
writing it surfaced the gap documented in `README.md`: the tool-layer lines carry
no identity of their own. `[TOOL EXECUTED]` says what ran, never who asked. Role
arrives on a separate `[AGENT]` line, so identity has to be carried forward from
the most recent request -- which is only sound because the range is
single-threaded. Under concurrency this attribution breaks, and any rule keyed on
`user` or `role` breaks with it. That is a property of the telemetry, not of the
rules.
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

try:
    import yaml
except ImportError:                                  # pragma: no cover
    sys.exit("pyyaml is required: .venv/bin/pip install -r requirements.txt")

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

# "2026-08-12T08:52:26 [TOOL EXECUTED] query_customers(SELECT ...)"
LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\[(?P<ev>[A-Z][A-Z ]*[A-Z])\]\s*(?P<rest>.*)$")
CALL_RE = re.compile(r"^(?P<tool>\w+)\((?P<args>.*)\)\s*$")
AGENT_RE = re.compile(r"user=(?P<user>\S+)\s+role=(?P<role>\S+)")
# A continuation: timestamped, but no [EVENT] of its own.
CONT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\s+(?P<rest>.*)$")


# --------------------------------------------------------------------------
# Parsing: log lines -> events with the field contract detection/README states
# --------------------------------------------------------------------------

def parse_log(path):
    """Turn a tool log into events carrying (event_type, tool, arguments, user, role...).

    Identity is carried forward from the most recent `[AGENT]` line because the
    tool lines do not carry it themselves. See the module docstring: this is
    sound only for a single-threaded range.
    """
    events = []
    user = role = None
    last = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = LINE_RE.match(line)

            if not m:
                # `logbook.log()` stamps EVERY line of a multi-line message, so a
                # multi-line event arrives as one `[EVENT]` line followed by bare
                # timestamped continuations. Dropping those (the obvious reading
                # of "not a match") truncates each event's content at its first
                # newline -- and since the injection payloads carry their lure on
                # line 1 and their instruction on line 2, that alone makes the
                # ingestion rule unfireable. Fold continuations into the open
                # event instead.
                if last is not None:
                    cont = CONT_RE.match(line)
                    if cont:
                        last["content"] += "\n" + cont.group("rest")
                        last["raw"] += "\n" + cont.group("rest")
                continue

            ev, rest = m.group("ev"), m.group("rest")

            if ev == "AGENT":
                a = AGENT_RE.search(rest)
                if a:
                    user, role = a.group("user"), a.group("role")
                last = None
                continue

            event = {
                "event_type": ev,
                "user": user,
                "role": role,
                "content": rest,
                "raw": line,
                "ts": datetime.fromisoformat(m.group("ts")),
            }
            if ev in ("TOOL EXECUTED", "TOOL BLOCKED"):
                c = CALL_RE.match(rest.strip())
                if c:
                    event["tool"] = c.group("tool")
                    event["arguments"] = c.group("args")
                else:
                    event["tool"], event["arguments"] = rest.strip(), ""
            events.append(event)
            last = event
    return events


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

class Unsupported(Exception):
    """A rule uses Sigma this evaluator does not implement."""


def _match_field(event, key, expected):
    """One `field: value` (or `field|contains: value`) clause."""
    field, _, modifier = key.partition("|")
    if modifier not in ("", "contains"):
        raise Unsupported(f"field modifier '|{modifier}'")

    actual = event.get(field)
    if actual is None:
        return False
    actual = str(actual).lower()

    wanted = expected if isinstance(expected, list) else [expected]
    for w in wanted:                          # a list is an OR
        w = str(w).lower()
        if (w in actual) if modifier == "contains" else (w == actual):
            return True
    return False


def _match_selection(event, selection):
    """A named selection: every field clause must hold (AND)."""
    if isinstance(selection, list):           # list of alternative maps = OR
        return any(_match_selection(event, s) for s in selection)
    return all(_match_field(event, k, v) for k, v in selection.items())


def _eval_condition(condition, matched):
    """Evaluate a Sigma `condition` over which named selections matched.

    Supports the `and`/`or`/`not`/parentheses subset. Aggregations are handled
    by the caller before this is reached.
    """
    expr = condition.strip()
    if "|" in expr:
        raise Unsupported(f"aggregation in condition: {condition!r}")
    if expr.startswith("all of ") or expr.startswith("1 of "):
        raise Unsupported(f"quantifier: {condition!r}")

    # Rewrite selection names to their truth values, then let Python evaluate
    # the boolean expression. Names are \w+ and the only other tokens permitted
    # are and/or/not/parens, so nothing else can reach eval().
    def sub(m):
        name = m.group(0)
        if name in ("and", "or", "not"):
            return name
        if name not in matched:
            raise Unsupported(f"unknown selection {name!r} in condition")
        return str(matched[name])

    py = re.sub(r"\b\w+\b", sub, expr)
    # After substitution nothing may remain but booleans, operators and parens.
    # Assert that explicitly rather than trusting the rewrite: eval() is only
    # safe here because this check is exhaustive.
    if not re.fullmatch(r"(?:True|False|and|or|not|[()\s])*", py):
        raise Unsupported(f"unparsable condition: {condition!r}")
    return bool(eval(py))                     # noqa: S307 - input constrained above


def _agg_condition(condition):
    """Parse `selection | count() by user > 5`. Returns (name, field, op, n)."""
    m = re.match(r"^(?P<sel>\w+)\s*\|\s*count\(\)\s*by\s+(?P<by>\w+)\s*(?P<op>>=|>|==)\s*(?P<n>\d+)$",
                 condition.strip())
    if not m:
        raise Unsupported(f"aggregation form: {condition!r}")
    return m.group("sel"), m.group("by"), m.group("op"), int(m.group("n"))


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

def load_rules(rules_dir=RULES_DIR):
    """Load every rule, including multi-document files (base events + correlation)."""
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path, "r", encoding="utf-8") as f:
            for doc in yaml.safe_load_all(f):
                if not doc:
                    continue
                doc["_file"] = os.path.basename(path)
                # A rule's addressable name is `name:` if present (correlation
                # rules reference each other by it), else the title.
                doc["_name"] = doc.get("name") or doc.get("title", "<untitled>")
                rules.append(doc)
    return rules


def _fires_simple(rule, events):
    """Non-correlation rule: return the matching events, or raise Unsupported."""
    det = rule.get("detection") or {}
    condition = det.get("condition")
    if not condition:
        raise Unsupported("no condition")

    selections = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}

    if "|" in str(condition):                 # aggregation
        sel, by, op, n = _agg_condition(str(condition))
        if sel not in selections:
            raise Unsupported(f"aggregation over unknown selection {sel!r}")
        counts, keep = {}, {}
        for e in events:
            if _match_selection(e, selections[sel]):
                key = e.get(by)
                counts[key] = counts.get(key, 0) + 1
                keep.setdefault(key, []).append(e)
        hot = [k for k, c in counts.items()
               if (c > n if op == ">" else c >= n if op == ">=" else c == n)]
        return [e for k in hot for e in keep[k]]

    out = []
    for e in events:
        matched = {name: _match_selection(e, sel) for name, sel in selections.items()}
        if _eval_condition(str(condition), matched):
            out.append(e)
    return out


def _fires_correlation(rule, events, by_name):
    """`temporal_ordered`: referenced rules must fire in order, within timespan."""
    corr = rule["correlation"]
    if corr.get("type") != "temporal_ordered":
        raise Unsupported(f"correlation type {corr.get('type')!r}")

    span = str(corr.get("timespan", "0s"))
    unit = span[-1]
    factor = {"s": 1, "m": 60, "h": 3600}.get(unit)
    if factor is None:
        raise Unsupported(f"timespan unit {unit!r}")
    window = int(span[:-1]) * factor
    group_by = (corr.get("group-by") or [None])[0]

    # Events matching each referenced rule, in order.
    stages = []
    for ref in corr.get("rules", []):
        target = by_name.get(ref)
        if target is None:
            raise Unsupported(f"correlation references unknown rule {ref!r}")
        stages.append(_fires_simple(target, events))
    if len(stages) < 2:
        raise Unsupported("correlation needs at least two stages")

    hits = []
    for first in stages[0]:
        cursor = first
        chain = [first]
        for stage in stages[1:]:
            nxt = next((e for e in stage
                        if e["ts"] >= cursor["ts"]
                        and (e["ts"] - cursor["ts"]).total_seconds() <= window
                        and (group_by is None or e.get(group_by) == first.get(group_by))
                        and e is not cursor), None)
            if nxt is None:
                chain = None
                break
            cursor = nxt
            chain.append(nxt)
        if chain:
            hits.append(chain[-1])
    return hits


def evaluate(events, rules=None):
    """Run every rule. Returns {rule_title: {...}} including unsupported ones."""
    rules = rules if rules is not None else load_rules()
    by_name = {r["_name"]: r for r in rules}
    out = {}
    for rule in rules:
        title = rule.get("title", rule["_name"])
        entry = {"file": rule["_file"], "level": rule.get("level", "unknown"),
                 "correlation": "correlation" in rule}
        try:
            hits = (_fires_correlation(rule, events, by_name) if "correlation" in rule
                    else _fires_simple(rule, events))
            entry.update(fired=bool(hits), count=len(hits),
                         sample=hits[0]["raw"][:160] if hits else None)
        except Unsupported as e:
            entry.update(fired=False, count=0, unsupported=str(e), sample=None)
        out[title] = entry
    return out


def fired_titles(events, rules=None):
    """Just the titles that fired -- what the harness records per case."""
    return sorted(t for t, r in evaluate(events, rules).items() if r["fired"])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", nargs="+", help="tool log(s) to evaluate")
    ap.add_argument("--rules", default=RULES_DIR)
    ap.add_argument("--json", help="write results here")
    ap.add_argument("--quiet", action="store_true", help="only print rules that fired")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    events = []
    for path in args.logfile:
        if not os.path.exists(path):
            sys.exit(f"no such log: {path}")
        events.extend(parse_log(path))
    events.sort(key=lambda e: e["ts"])

    results = evaluate(events, rules)
    counts = {}
    for e in events:
        counts[e["event_type"]] = counts.get(e["event_type"], 0) + 1

    print(f"\nparsed {len(events)} events from {len(args.logfile)} log(s)")
    print("  " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    identified = sum(1 for e in events if e.get("role"))
    print(f"  {identified}/{len(events)} events carry an identity "
          f"(attributed from the preceding [AGENT] line)\n")

    print(f"  {'rule':<52}{'level':<14}result")
    print("  " + "-" * 76)
    for title, r in sorted(results.items(), key=lambda kv: (not kv[1]["fired"], kv[0])):
        if args.quiet and not r["fired"]:
            continue
        if "unsupported" in r:
            state = f"UNSUPPORTED ({r['unsupported']})"
        else:
            state = f"fired x{r['count']}" if r["fired"] else "-"
        print(f"  {title[:50]:<52}{r['level']:<14}{state}")

    n_fired = sum(1 for r in results.values() if r["fired"])
    n_unsup = sum(1 for r in results.values() if "unsupported" in r)
    print(f"\n  {n_fired}/{len(results)} rules fired"
          + (f", {n_unsup} unsupported by this evaluator" if n_unsup else ""))
    print("\n  A rule that did not fire is not necessarily wrong: it may cover an")
    print("  attack these logs do not contain. Read this next to the case matrix")
    print("  from harness/run.py --detect, which pairs each rule with its attack.\n")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"  wrote {args.json}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
