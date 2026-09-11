#!/usr/bin/env python3
"""Redact host identifiers from captured evidence before committing it.

Running the range executes real commands on a real machine, so `whoami` returns
a real account name and paths contain a real home directory. Those land in the
evidence logs, which are committed so findings are verifiable.

This has to be a tool rather than a one-off edit, because every harness run
regenerates the logs. It also has to handle the model's *mangled* renderings of
the account name: llama3.1 has variously returned the account as a spaced
two-word name, a capitalised variant, and a misspelling with a dropped letter.
A literal find-and-replace misses those, so the account name is matched
fuzzily (optional letters, optional internal spacing) and every variant maps to
the same placeholder. That keeps finding F-06 legible: a single lowercase token
still becomes a spaced, capitalised two-word name after redaction.

Usage:
    python harness/redact.py                 # redact evidence/ and the docs
    python harness/redact.py --check         # exit 1 if anything remains
"""

import argparse
import getpass
import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLACEHOLDER = "hostuser"
PLACEHOLDER_TITLE = "HostUser"

SKIP = {"LICENSE"}

# A real evidence file mentions the account name a few dozen times at most.
# Anything beyond this means the matcher has gone wrong; see the guard in main().
MAX_HITS = 400
MAX_GROWTH = 0.25


def _letters(tok):
    return "".join(c for c in tok if c.isalpha()).lower()


def _edit_distance(a, b, cap):
    """Levenshtein distance, giving up once it exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


TOKEN_RE = re.compile(r"[A-Za-z]+")


def redact_name(text, name):
    """Replace the account name and the model's manglings of it.

    Token-based rather than one big regex: an earlier version built a pattern
    with an optional group per letter, which backtracks exponentially and hangs
    on real logs. This scans word tokens once, and also checks adjacent PAIRS of
    tokens, because the observed manglings included the single lowercase account
    name rendered as a spaced two-word proper noun.
    """
    target = _letters(name)
    cap = 2 if len(target) > 8 else 1
    toks = list(TOKEN_RE.finditer(text))
    spans = []
    i = 0
    while i < len(toks):
        # Try a two-token join first, so a name split across two words is caught whole.
        if i + 1 < len(toks):
            a, b = toks[i], toks[i + 1]
            between = text[a.end():b.start()]
            if between.strip() == "" and len(between) <= 2:
                joined = _letters(a.group() + b.group())
                if len(joined) >= len(target) - cap and \
                        _edit_distance(joined, target, cap) <= cap:
                    spans.append((a.start(), b.end(), True))
                    i += 2
                    continue
        t = toks[i]
        lt = _letters(t.group())
        if len(lt) >= max(6, len(target) - cap) and \
                _edit_distance(lt, target, cap) <= cap:
            spans.append((t.start(), t.end(), t.group()[:1].isupper()))
        i += 1

    out, last = [], 0
    for start, end, titled in spans:
        out.append(text[last:start])
        # Preserve whether it read as a Title-Cased rendering, so F-06's point
        # (one lowercase token became a spaced proper noun) survives redaction.
        out.append(PLACEHOLDER_TITLE if titled else PLACEHOLDER)
        last = end
    out.append(text[last:])
    return "".join(out)


def has_name(text, name):
    return redact_name(text, name) != text


def targets():
    out = []
    for pat in ("evidence/*.log", "evidence/*.json", "*.md", "detection/*.md"):
        out += glob.glob(os.path.join(ROOT, pat))
    return [p for p in out if os.path.basename(p) not in SKIP]


def redact_text(s, name, home):
    s = s.replace(home, f"/Users/{PLACEHOLDER}")
    s = s.replace(f"/home/{name}", f"/home/{PLACEHOLDER}")
    return redact_name(s, name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report leftovers and exit non-zero instead of editing")
    ap.add_argument("--name", default=getpass.getuser(),
                    help="account name to redact (defaults to the current user)")
    args = ap.parse_args()

    name = args.name
    home = os.path.expanduser("~")
    if len(name) < 4:
        print(f"refusing to redact a {len(name)}-character name ({name!r}): "
              f"too short to match safely", file=sys.stderr)
        return 2

    leftovers, changed, refused = [], [], []
    for path in targets():
        s = io.open(path, encoding="utf-8", errors="ignore").read()
        if args.check:
            if has_name(s, name) or home in s:
                leftovers.append(path)
            continue
        new = redact_text(s, name, home)
        if new != s:
            # Corruption guard. Redaction touches a handful of tokens; if it
            # rewrote a large share of the file, the matcher is wrong and the
            # file is being destroyed rather than redacted. An earlier version
            # of this script did exactly that -- it matched the empty string and
            # inserted the placeholder at every word boundary -- and the damage
            # was committed before anyone read the output. Refuse instead.
            hits = new.count(PLACEHOLDER) + new.count(PLACEHOLDER_TITLE)
            growth = abs(len(new) - len(s)) / max(len(s), 1)
            if hits > MAX_HITS or growth > MAX_GROWTH:
                print(f"  REFUSING {os.path.relpath(path, ROOT)}: "
                      f"{hits} replacements, size change {growth:.0%}. "
                      f"That is not redaction, it is corruption -- "
                      f"check the matcher before rerunning.", file=sys.stderr)
                refused.append(path)
                continue
            io.open(path, "w", encoding="utf-8").write(new)
            changed.append(os.path.relpath(path, ROOT))

    if args.check:
        for p in leftovers:
            print(f"  UNREDACTED: {os.path.relpath(p, ROOT)}")
        print("clean" if not leftovers else f"{len(leftovers)} file(s) need redaction")
        return 1 if leftovers else 0

    print(f"redacted {len(changed)} file(s):" if changed else "nothing to redact")
    for p in changed:
        print(f"  {p}")
    if refused:
        print(f"\n{len(refused)} file(s) REFUSED as likely corruption; nothing written "
              f"for them. Fix the matcher, do not force it.", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
