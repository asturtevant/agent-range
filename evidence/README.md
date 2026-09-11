# Evidence

Tool-layer logs and harness results backing the findings in `../FINDINGS.md`.

These are the record. A finding in this project is not claimed as verified until
its `[TOOL EXECUTED]` line is here — see `../METHODOLOGY.md` §2.

## Files

- `run-<date>.log` — tool executions, policy blocks, RAG retrievals and ticket
  ingestion from an interactive session. Written automatically by
  `agent/logbook.py`.
- `harness-<mode>-<timestamp>.log` — the same, captured during a harness run.
  One file per build so the vulnerable and hardened runs can never be confused.
- `harness-results.json` — structured results: per case, per attempt, which
  tools executed and whether the model's answer agreed with them.

## Redaction

The host account name returned by `run_command(whoami)` has been replaced with
`hostuser`, and home-directory paths with `/Users/hostuser`, throughout these
logs and the findings that quote them.

This affects one thing worth stating plainly: F-06 documents the model
*garbling* real tool output, and the garbled forms are redacted consistently
with the original. A single lowercase token came back from the tool and the
model rendered it as a spaced, capitalised two-word name — that transformation
is preserved by the substitution, so the finding is still legible.

Nothing else is redacted. The customer records (including the SSNs) are the
fixtures in `agent/db.py` and are fabricated.
