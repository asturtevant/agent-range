"""Ground-truth event log for the range.

Every tool execution, RAG retrieval and policy decision is written here — to
stdout as before, and additionally appended to a file under `evidence/` so a
finding's proof survives the terminal session that produced it.

This exists because the project's evidence discipline depends on it: a finding
is only claimed once its `[TOOL EXECUTED]` line is in the repo, and console
scrollback is not a durable record. The line format is unchanged, so existing
findings and any grep/harness over them keep working.

Disable with `RANGE_LOGFILE=` (empty) if you need stdout only.
"""

import datetime
import os

_DEFAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "evidence")


def _logfile():
    """Resolve the log path, honouring RANGE_LOGFILE (empty disables file output)."""
    if "RANGE_LOGFILE" in os.environ:
        return os.environ["RANGE_LOGFILE"] or None
    stamp = datetime.datetime.now().strftime("%Y-%m-%d")
    return os.path.join(_DEFAULT_DIR, f"run-{stamp}.log")


def log(message):
    """Print an event and append it to the evidence log with a timestamp."""
    print(message, flush=True)
    path = _logfile()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        with open(path, "a", encoding="utf-8") as f:
            for line in str(message).splitlines():
                f.write(f"{ts} {line}\n")
    except OSError as e:
        # Logging must never break the range itself.
        print(f"[LOGBOOK ERROR] could not write {path}: {e}", flush=True)


def tool_executed(call, result=None, error=None):
    """Log a tool invocation in the established two-line format."""
    if error is not None:
        log(f"[TOOL EXECUTED] {call}\n[TOOL ERROR]   {error}")
    else:
        log(f"[TOOL EXECUTED] {call}\n[TOOL RESULT]  {str(result)[:300]}")


def blocked(call, reason):
    """Log a tool call refused by the security policy (hardened mode only)."""
    log(f"[TOOL BLOCKED]  {call}\n[POLICY]        {reason}")
