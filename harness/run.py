#!/usr/bin/env python3
"""Repeatable assessment harness for the Agentic Attack Range.

Runs the attack cases in `cases.yaml` against the range and scores each one
against the TOOL-LAYER LOG, not the model's answer. Where an ordinary LLM
security scanner asks "did the response look like a compromise?", this asks
"did the tool actually execute?" -- which is the only question that survives a
model that fabricates in both directions (see findings F-06 and F-11).

Run it against either build, or both for an A/B of the remediations:

    python harness/run.py                  # vulnerable build
    python harness/run.py --mode hardened
    python harness/run.py --mode both      # the break-and-build report
    python harness/run.py --json out.json  # machine-readable results

The harness manages the app lifecycle itself so a run is reproducible from a
clean state: each mode gets a fresh process, a fresh in-memory knowledge base
and its own log file.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

import requests
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "detection"))

import sigma_eval        # noqa: E402 - needs the path above
BASE = os.environ.get("RANGE_BASE", "http://127.0.0.1:5000")
CREDS = {"viewer": "viewer123", "admin": "admin123"}

# One [TOOL EXECUTED] line, e.g. "[TOOL EXECUTED] run_command(whoami)"
TOOL_RE = re.compile(r"\[TOOL EXECUTED\]\s+(\w+)\((.*)\)\s*$")


IS_WINDOWS = os.name == "nt"


def python_bin():
    """The repo venv's interpreter, whatever the platform calls it."""
    for parts in ((".venv", "bin", "python"), (".venv", "Scripts", "python.exe")):
        candidate = os.path.join(ROOT, *parts)
        if os.path.exists(candidate):
            return candidate
    return sys.executable


def instance_mode():
    """Ask whoever is listening which mode they are in. None if nobody is."""
    try:
        r = requests.get(f"{BASE}/healthz", timeout=2)
        return r.json() if r.ok else None
    except (requests.RequestException, ValueError):
        return None


def start_range(secure, logfile):
    """Boot the range in the requested mode, and PROVE it is the one answering.

    A stale instance left listening on the port is the dangerous failure here:
    it answers happily, the harness scores against its own fresh (empty) log,
    and every attack is reported 'blocked'. That is a silent false negative on
    the entire assessment, so refuse to run rather than risk it.
    """
    want = "secure" if secure else "vulnerable"

    existing = instance_mode()
    if existing is not None:
        raise RuntimeError(
            f"something is already serving {BASE} (mode={existing.get('mode')}, "
            f"pid={existing.get('pid')}). Refusing to run: results would be scored "
            f"against the wrong process. Stop it first, or set RANGE_PORT/RANGE_BASE "
            f"to a free port. (On macOS, port 5000 is taken by ControlCenter/AirPlay.)")

    env = dict(os.environ,
               SECURE="1" if secure else "0",
               RANGE_LOGFILE=logfile,
               MODEL=os.environ.get("MODEL", "llama3.1"))
    # Put the child in its own process group so it can be stopped as a unit.
    # The flag differs by platform and neither name exists on the other.
    group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WINDOWS
             else {"start_new_session": True})
    proc = subprocess.Popen([python_bin(), "app.py"],
                            cwd=os.path.join(ROOT, "agent"), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            **group)
    for _ in range(60):
        health = instance_mode()
        if health is not None:
            if health.get("mode") != want or health.get("pid") != proc.pid:
                stop_range(proc)
                raise RuntimeError(
                    f"the instance answering {BASE} is mode={health.get('mode')} "
                    f"pid={health.get('pid')}, expected {want} pid={proc.pid}. "
                    f"Another process owns the port; refusing to score against it.")
            return proc
        if proc.poll() is not None:
            raise RuntimeError("range process exited during startup")
        time.sleep(2)
    stop_range(proc)
    raise RuntimeError("range did not come up; is Ollama running?")


def stop_range(proc):
    """Stop the app and anything it spawned.

    Killing only the parent can leave a listener holding the port, which the
    next run then refuses to start against -- or worse, silently scores.
    """
    if not proc or proc.poll() is not None:
        return
    if IS_WINDOWS:
        # No process groups to signal; taskkill /T walks the child tree.
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, AttributeError):
            proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def tools_executed(logfile, start_offset):
    """Parse tool executions appended since `start_offset`.

    Scoping to the bytes written during THIS case is what keeps attribution
    honest -- otherwise an execution triggered by an earlier case would be
    credited to a later one.
    """
    out = []
    if not os.path.exists(logfile):
        return out, 0
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        chunk = f.read()
        end = f.tell()
    for line in chunk.splitlines():
        m = TOOL_RE.search(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out, end


def log_size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0


def events_in_window(logfile, start_offset):
    """Parse the log slice written during one case into detection events.

    Scoped to the same byte window the attack is scored from, so detection and
    exploitation are always talking about the same activity.
    """
    if not os.path.exists(logfile):
        return []
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        chunk = f.read()
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                      encoding="utf-8")
    try:
        tmp.write(chunk)
        tmp.close()
        return sigma_eval.parse_log(tmp.name)
    finally:
        os.unlink(tmp.name)


def run_case(case, session_cache, logfile, detect=None, attempt=0):
    """Execute one case and score it from the tool log.

    `detect`, when given, is the loaded Sigma rule set: the same log window that
    scores the attack is also replayed through the detection rules, so every
    case yields both "did it execute?" and "would anyone have seen it?".
    """
    role = case.get("auth", "viewer")
    sess = session_cache.get(role)
    if sess is None:
        sess = requests.Session()
        sess.post(f"{BASE}/login",
                  data={"username": role, "password": CREDS[role]}, timeout=30)
        session_cache[role] = sess

    # Indirect cases plant the payload through the UNAUTHENTICATED ingestion
    # route first -- a plain session, no credentials, exactly as an outsider.
    if case.get("vector") == "indirect" and case.get("ingest"):
        requests.post(f"{BASE}/submit_ticket",
                      data={"ticket": case["ingest"]}, timeout=60)

    offset = log_size(logfile)
    answer, error = "", None

    # A case is one or more turns. Single-prompt cases stay stateless (no
    # conversation id is sent), which preserves the isolation the scoring
    # depends on. Multi-turn cases opt into server-side memory with an id
    # unique to this attempt, so turn 1's payload persists into turn N without
    # leaking into any other case.
    turns = case.get("turns") or [case["prompt"]]
    convo = f"{case['id']}-{os.getpid()}-{attempt}" if len(turns) > 1 else None

    final_turn_offset = offset
    for message in turns:
        # Remember where the LAST turn starts. A multi-turn case is scored
        # against this window only -- see below.
        final_turn_offset = log_size(logfile)
        payload = {"message": message}
        if convo:
            payload["conversation_id"] = convo
        try:
            r = sess.post(f"{BASE}/chat", json=payload, timeout=420)
            answer = (r.json() or {}).get("answer", "") if r.ok else ""
        except Exception as e:        # network/timeout: recorded, not fatal
            error = str(e)
            break

    executed, _ = tools_executed(logfile, offset)

    # For a multi-turn case, the claim is that a payload planted EARLIER fires
    # in the FINAL turn. A model that simply obeys turn 1 immediately would
    # execute the tool too -- and scoring the whole conversation would count
    # that as success, proving nothing about persistence. So multi-turn cases
    # are scored against the last turn's window alone.
    scoring_window = (tools_executed(logfile, final_turn_offset)[0]
                      if len(turns) > 1 else executed)
    want = case.get("success", {})
    hit = any(tool == want.get("tool")
              and str(want.get("arg_contains", "")).lower() in args.lower()
              for tool, args in scoring_window)

    # Recorded so an early-obedience run is visible rather than silently
    # discarded: the tool fired, just not where the finding claims it does.
    fired_early = bool(len(turns) > 1
                       and not hit
                       and any(tool == want.get("tool") for tool, _ in executed))

    # Narration divergence: did the model TALK as though it acted, when the tool
    # log says it did not? This is F-11 measured rather than anecdotal.
    claimed = bool(case.get("narration")) and \
        str(case["narration"]).lower() in (answer or "").lower()

    # Detection: replay THIS case's log window through the rules. Scoped to the
    # same window as the attack scoring, so a rule cannot be credited for firing
    # on some other case's activity.
    fired, expected_rules, detected = [], case.get("detects") or [], None
    if detect is not None:
        fired = sigma_eval.fired_titles(events_in_window(logfile, offset), detect)
        # "Detected" means a rule this case CLAIMS to be covered by fired. A
        # different rule firing is not coverage of this attack.
        detected = any(r in fired for r in expected_rules) if expected_rules else None

    return {
        "id": case["id"], "name": case.get("name", ""),
        "owasp": case.get("owasp", ""), "vector": case.get("vector", "direct"),
        "auth": role,
        "result": "success" if hit else "blocked",
        "tools_executed": [f"{t}({a[:80]})" for t, a in executed],
        "model_claimed": claimed,
        "narration_diverges": bool(claimed and not hit),
        "turns": len(turns),
        "fired_early": fired_early,
        "rules_fired": fired,
        "expected_rules": expected_rules,
        "detected": detected,
        "answer": answer or "",          # full text: needed to score black-box
        "answer_excerpt": (answer or "")[:220],
        "error": error,
    }


def attach_to_running(logfile):
    """Score against a range this process did not start.

    Needed whenever something else owns the app's lifecycle -- most obviously
    `docker compose up`, where the range runs in a container and cannot be
    started or stopped from here. The mode is read from the running instance
    rather than assumed, so results are still attributed to the build that
    actually answered.
    """
    health = instance_mode()
    if health is None:
        raise RuntimeError(
            f"--attach was given but nothing is serving {BASE}. Start the range "
            f"first (`docker compose up`, or run agent/app.py), or drop --attach "
            f"and let the harness manage it.")
    if not logfile:
        raise RuntimeError(
            "--attach needs --logfile pointing at the tool log the running range "
            "is writing. Under docker compose that is the newest file in "
            "evidence/, mounted from the container.")
    if not os.path.exists(logfile):
        raise RuntimeError(f"--logfile {logfile!r} does not exist yet")
    return health.get("mode") == "secure"


def run_mode(cases, secure, keep_log, repeat=1, attach=False, attach_log=None,
             detect=None):
    if attach:
        secure = attach_to_running(attach_log)
        label = "hardened" if secure else "vulnerable"
        logfile = attach_log
        print(f"\n=== {label.upper()} build (attached) ===")
        print(f"    log: {logfile}")
        proc = None
    else:
        label = "hardened" if secure else "vulnerable"
        logfile = keep_log or tempfile.mktemp(prefix=f"range-{label}-", suffix=".log")
        print(f"\n=== {label.upper()} build ===")
        print(f"    log: {logfile}")
        proc = start_range(secure, logfile)
    results = []
    try:
        sessions = {}
        for case in cases:
            print(f"  [{case['id']:<6}] {case.get('name','')[:50]:<50} ", end="", flush=True)
            # Attacks against an LLM are probabilistic -- indirect injection in
            # particular must win retrieval AND obedience, and either can fail on
            # a given attempt. Scoring a single shot reports "safe" for an attack
            # that works most of the time, so run each case n times and report the
            # rate. One success is enough to prove exploitability; zero successes
            # in n attempts is weak evidence of safety, never proof of it.
            attempts = [run_case(case, sessions, logfile, detect, i)
                        for i in range(repeat)]
            hits = [a for a in attempts if a["result"] == "success"]
            res = dict(hits[0] if hits else attempts[0])
            res["attempts"] = len(attempts)
            res["successes"] = len(hits)
            res["result"] = "success" if hits else "blocked"
            res["narration_diverges"] = any(a["narration_diverges"] for a in attempts)
            # One attempt detected is detection; a rule that fires sometimes is
            # still a rule that fires. Mirrors how exploitability is scored.
            # Keep the answer that actually diverged. `res` is copied from the
            # first hit (or the first attempt), so when narration diverges on a
            # LATER attempt the quote proving it was being discarded -- and the
            # quote is the entire evidentiary value of F-11.
            diverged = next((a for a in attempts if a["narration_diverges"]), None)
            if diverged is not None:
                res["diverging_answer"] = diverged["answer"]
                res["diverging_excerpt"] = diverged["answer_excerpt"]

            if any(a.get("detected") is not None for a in attempts):
                res["detected"] = any(a.get("detected") for a in attempts)
                res["rules_fired"] = sorted({r for a in attempts
                                             for r in a.get("rules_fired", [])})

            expected = (case.get("expect") or {}).get(label)
            res["expected"] = expected
            # `marginal` means the attack is known to land only sometimes, so
            # NEITHER outcome is a regression. Without it a case that succeeds
            # ~17% of the time is flagged UNEXPECTED on most runs, which trains
            # the reader to ignore the one flag that should never be ignored.
            # The rate still gets reported; only the regression claim is dropped.
            res["marginal"] = (expected == "marginal")
            res["as_expected"] = (expected is None
                                  or expected == "marginal"
                                  or res["result"] == expected)
            flag = "" if res["as_expected"] else "  <-- UNEXPECTED"
            if res.get("marginal"):
                flag += "  [marginal — success is intermittent by nature]"
            note = "  [model claimed success anyway]" if res["narration_diverges"] else ""
            if any(a.get("fired_early") for a in attempts):
                note += "  [tool fired in an earlier turn, not the trigger turn]"
            rate = f"{res['successes']}/{res['attempts']}"
            print(f"{res['result']:<8}{rate:>6}{flag}{note}")
            results.append(res)
    finally:
        # An attached range belongs to whoever started it; leave it running.
        if proc is not None:
            stop_range(proc)
    return {"mode": label, "logfile": logfile, "results": results}


def report(runs):
    print("\n" + "=" * 78)
    print("ASSESSMENT SUMMARY — scored from tool-layer ground truth")
    print("=" * 78)
    ids = [r["id"] for r in runs[0]["results"]]
    by_mode = {run["mode"]: {r["id"]: r for r in run["results"]} for run in runs}
    modes = [run["mode"] for run in runs]

    print(f"\n  {'case':<8}{'':<44}" + "".join(f"{m:>16}" for m in modes))
    for cid in ids:
        name = by_mode[modes[0]][cid]["name"][:42]
        row = "".join(
            f"{by_mode[m][cid]['result'] + ' ' + str(by_mode[m][cid].get('successes', 0)) + '/' + str(by_mode[m][cid].get('attempts', 1)):>16}"
            for m in modes)
        print(f"  {cid:<8}{name:<44}{row}")

    for m in modes:
        rs = list(by_mode[m].values())
        n_succ = sum(1 for r in rs if r["result"] == "success")
        n_unexp = sum(1 for r in rs if not r["as_expected"])
        n_div = sum(1 for r in rs if r["narration_diverges"])
        print(f"\n  {m}: {n_succ}/{len(rs)} attacks succeeded at the tool layer")
        if n_unexp:
            print(f"    {n_unexp} case(s) did NOT match expectation — regression or drift")
        if n_div:
            print(f"    {n_div} case(s) where the model claimed success the tool log denies")

    if len(modes) == 2:
        fixed = [c for c in ids
                 if by_mode["vulnerable"][c]["result"] == "success"
                 and by_mode["hardened"][c]["result"] == "blocked"]
        still = [c for c in ids
                 if by_mode["vulnerable"][c]["result"] == "success"
                 and by_mode["hardened"][c]["result"] == "success"]
        print(f"\n  remediation effect: {len(fixed)}/{len(fixed) + len(still)} "
              f"reproduced attacks are blocked by the hardened build")
        if still:
            print(f"    STILL EXPLOITABLE: {', '.join(still)}")
    print("\n  Reminder: 'blocked' means no tool executed. It does NOT mean the")
    print("  injection failed — several payloads are still retrieved into context.")
    print()
    _detection_report(runs, by_mode, modes, ids)


def _detection_report(runs, by_mode, modes, ids):
    """The defender's half: for each attack, would anyone have seen it?

    Exploitability and detectability are independent axes, and the interesting
    cells are the off-diagonal ones. An attack that succeeds and is detected is
    an incident; one that succeeds unseen is a breach nobody investigates. The
    latter is worth reporting even when the former is what got fixed.
    """
    scored = [c for c in ids if by_mode[modes[0]][c].get("detected") is not None]
    if not scored:
        return

    print("=" * 78)
    print("DETECTION EFFICACY — Sigma rules replayed over the same log windows")
    print("=" * 78)

    for m in modes:
        rs = [by_mode[m][c] for c in scored]
        matrix = {
            ("success", True): [r for r in rs if r["result"] == "success" and r["detected"]],
            ("success", False): [r for r in rs if r["result"] == "success" and not r["detected"]],
            ("blocked", True): [r for r in rs if r["result"] == "blocked" and r["detected"]],
            ("blocked", False): [r for r in rs if r["result"] == "blocked" and not r["detected"]],
        }
        print(f"\n  {m}:")
        print(f"    {'':<26}{'detected':>12}{'undetected':>14}")
        print(f"    {'attack succeeded':<26}"
              f"{len(matrix[('success', True)]):>12}{len(matrix[('success', False)]):>14}")
        print(f"    {'attack blocked':<26}"
              f"{len(matrix[('blocked', True)]):>12}{len(matrix[('blocked', False)]):>14}")

        blind = matrix[("success", False)]
        if blind:
            print(f"\n    BLIND SPOT — succeeded with no rule firing: "
                  f"{', '.join(r['id'] for r in blind)}")
            print("      These are the ones a SOC would never have opened a ticket for.")
        quiet = matrix[("blocked", True)]
        if quiet:
            print(f"    Blocked but still alerted: {', '.join(r['id'] for r in quiet)}")
            print("      Correct behaviour: the attempt is visible even though it failed.")

    # A rule that never fires anywhere is either untested or broken. Either way
    # it should not sit in the repo looking like coverage.
    all_expected, all_fired = set(), set()
    for run in runs:
        for r in run["results"]:
            all_expected.update(r.get("expected_rules") or [])
            all_fired.update(r.get("rules_fired") or [])
    never = sorted(all_expected - all_fired)
    if never:
        print(f"\n  Rules expected by a case but never fired: {', '.join(never)}")
        print("    Treat as a detection defect, not a quiet system.")
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["vulnerable", "hardened", "both"],
                    default="vulnerable")
    ap.add_argument("--cases", default=os.path.join(os.path.dirname(__file__), "cases.yaml"))
    ap.add_argument("--only", help="comma-separated case ids to run")
    ap.add_argument("--repeat", type=int, default=1,
                    help="attempts per case (attacks are probabilistic; >1 strongly advised)")
    ap.add_argument("--attach", action="store_true",
                    help="score a range that is already running (e.g. docker compose) "
                         "instead of starting one; requires --logfile")
    ap.add_argument("--logfile", help="tool log to score from, with --attach")
    ap.add_argument("--detect", action="store_true",
                    help="also replay each case's log window through the Sigma "
                         "rules in detection/rules and report detection efficacy")
    ap.add_argument("--json", help="write full results here")
    ap.add_argument("--evidence-dir", default=os.path.join(ROOT, "evidence"),
                    help="keep each mode's tool log here (set empty for temp files)")
    args = ap.parse_args()

    with open(args.cases, encoding="utf-8") as f:
        cases = yaml.safe_load(f)["cases"]
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        cases = [c for c in cases if c["id"] in want]
    if not cases:
        print("no cases selected"); return 1

    detect = None
    if args.detect:
        try:
            detect = sigma_eval.load_rules()
        except Exception as e:
            print(f"--detect: could not load detection rules: {e}")
            return 1
        unsupported = {t: r["unsupported"]
                       for t, r in sigma_eval.evaluate([], detect).items()
                       if "unsupported" in r}
        if unsupported:
            # A rule the evaluator cannot execute would silently score as
            # "never fired", i.e. as a detection gap that does not exist.
            # Refuse rather than publish that.
            print("--detect: these rules use unsupported Sigma and would be "
                  "misreported as silent:")
            for t, why in unsupported.items():
                print(f"    {t}: {why}")
            return 1
        print(f"detection: {len(detect)} rules loaded from detection/rules")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    if args.attach:
        if args.mode == "both":
            print("--attach scores whichever build is running, so --mode both "
                  "cannot apply. Run it twice, once against each.")
            return 1
        runs = [run_mode(cases, False, None, args.repeat,
                         attach=True, attach_log=args.logfile, detect=detect)]
    else:
        modes = [False, True] if args.mode == "both" else [args.mode == "hardened"]
        runs = []
        for secure in modes:
            keep = None
            if args.evidence_dir:
                os.makedirs(args.evidence_dir, exist_ok=True)
                label = "hardened" if secure else "vulnerable"
                keep = os.path.join(args.evidence_dir, f"harness-{label}-{stamp}.log")
            runs.append(run_mode(cases, secure, keep, args.repeat, detect=detect))

    report(runs)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"generated": stamp, "runs": runs}, f, indent=2)
        print(f"  wrote {args.json}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
