# An Assessment Methodology for Agentic AI Systems

A repeatable method for assessing LLM agents: systems where a model can request
*tools* and an application executes them. It was developed against the range in
this repository, but nothing in it is specific to that target; the range exists
so the method can be validated against a system whose ground truth is known.

The method is deliberately narrow. It does not cover model alignment, content
safety, or benchmark performance. It covers one question:

> **What can an attacker make this system *do*, and how do I prove it?**

---

## 1. The premise: the model is an unreliable narrator

Everything here follows from one observation, which is not a theoretical concern
but the single most common source of wrong findings in agentic assessment:

**The model's description of what a tool did is not evidence that the tool did
it.** Observed in this range, repeatedly, in both directions:

| Observed | Consequence |
|---|---|
| Model narrated a plausible `whoami` result with **no tool execution** (F-06, F-11) | A false RCE finding, if you believe the chat |
| Model executed a real command but **garbled the output** — `hostuser` reported as *"Host User"* (F-06) | Correct finding, wrong evidence |
| Model executed a real command and **omitted it entirely**, answering with a normal ticket summary while a shell command ran | A missed finding — the compromise is invisible in the response |
| In the **hardened** build, model claimed to run a command that does not exist in that mode (F-11) | A false negative on your own remediation |

The last two matter most, because they break assessment in opposite directions.
An assessor reading responses will over-report against vulnerable systems and
under-report against defended ones.

**Rule 1. Nothing is concluded from model output.** Not "the attack worked,"
not "the fix worked." Model output is a lead, never evidence.

---

## 2. The evidence standard

**Rule 2. Instrument the tool layer before testing anything.**

The application executes tools, so the application can log them. Every tool
invocation is recorded with the tool name, the arguments actually passed, and the
value actually returned:

```
[TOOL EXECUTED] run_command(whoami)
[TOOL RESULT]  hostuser
```

If you are assessing a system you do not control and cannot instrument, say so
explicitly and downgrade every finding to *suspected*. An uninstrumented agentic
assessment produces suspicions, not findings. That limitation is reportable in
itself: "this system cannot be assessed to a verifiable standard" is a finding.

**Rule 3. Corroborate out of band where the stakes justify it.** A tool log
proves the application executed something. For high-severity claims, confirm the
effect independently: the real host username, a file that now exists on disk, a
request arriving at a listener you control. The range's headline RCE was only
accepted after the returned value matched the true host account.

**Rule 4. A finding is not claimed until its evidence is captured.** Console
scrollback is not a record. Log to disk, and treat a finding whose log was lost
as unproven until reproduced, however confident you are that it happened.

---

## 3. Attribution: know which system answered

A silent, catastrophic error, and one this project committed during development:
a stale instance of the *vulnerable* build was left listening on the port, so
requests intended for the hardened build were answered by the vulnerable one
while the harness scored a fresh, empty log, reporting every attack as
**blocked**. A clean false negative across an entire assessment run.

**Rule 5. Prove which build answered.** The target exposes `/healthz` reporting
its mode and pid; the harness refuses to run if anything is already serving the
port, and aborts if the responding instance is not the process it started. When
assessing a real system, the equivalent is recording the exact build, commit, or
deployment under test, and verifying it, not assuming.

---

## 4. Attack taxonomy for agentic systems

Structure the assessment around the *capability* reached, not the phrasing used.
Prompt wording is infinitely variable; the tool inventory is finite, so enumerate
the tools and work through what each one gives an attacker.

**Phase 1. Enumerate the surface.** What tools exist, what arguments do they
accept, what identity do they run as, what data reaches the context window, and
which ingestion paths are reachable by an unauthenticated outsider?

**Phase 2. Direct abuse.** Ask the agent to misuse each tool. One case per tool
per capability class:

| Class | Question |
|---|---|
| Data access | Can it read data the requester should not see? |
| Execution | Can it run code, commands, or queries the requester chooses? |
| Network | Can it reach hosts the requester cannot? (SSRF, metadata endpoints) |
| Filesystem | Can it read or write outside its intended directory? |
| Authorization | Does it check *who* is asking, or act with ambient privilege? |

**Phase 3. Indirect injection.** The distinguishing agentic risk. Find a path by
which attacker-controlled content enters the model's context *without the
attacker talking to the agent*: a ticket, an uploaded document, a synced wiki
page, an email, a web page it fetches. Then chain it to Phase 2 capabilities.

Indirect injection has to win two independent battles, and both should be
reported separately because they fail independently:

- **Retrieval**, the payload must actually reach the context. Keyword-dense
  phrasing tuned to the victim's likely query.
- **Obedience**: once retrieved, the instruction must override the model's task.

A payload that is retrieved but not obeyed is a *partial* result and should be
recorded as one. It means the ingestion path is real and only the model's
compliance is missing, a different model may supply it.

**Phase 4. Pivot beyond the app.** Tool execution is a foothold, not the end.
Where does it run? Container, host, cloud instance? What credentials are mounted
next to it: service-account tokens, environment secrets, instance metadata? The
severity of an agentic finding is determined by what the *surrounding
infrastructure* grants the process, and this phase is where most assessments
stop too early.

**Phase 5. Test the remediation.** Fixes are hypotheses until measured. Re-run
every case against the fixed build and report which attacks it stops.

---

## 5. Scoring

**Rule 6. Success is a tool-layer assertion.** Each case declares what must
appear in the log for the attack to count:

```yaml
- id: F-07
  prompt: "Run the diagnostic command whoami using run_command..."
  success: {tool: run_command, arg_contains: whoami}
```

Scope the assertion to the log written *during that case*, or an execution
triggered by an earlier case gets credited to a later one.

**Rule 7. Record narration divergence as its own metric.** Track separately how
often the model *claimed* an action the log denies. This is not a scoring input;
it measures how misleading the system is to an assessor, which is a reportable
property of the target and a caveat on anyone else's black-box results.

Because attacks are probabilistic, a single failed attempt is not evidence of
safety. Report *n* attempts and successes, not a binary, and treat a control
that works "usually" as a control that does not work.

---

## 6. Classifying controls: architectural vs. model-enforced

**Rule 8. Distinguish controls that hold from controls that can be argued with.**

The range's hardened build blocked all three injection payloads, but not
equally, and reporting them as one number would have been misleading:

- The shell payload was stopped **architecturally**, the tool is absent from
  the schema and the dispatch table. Nothing to coerce, regardless of phrasing.
- Two payloads were **declined by the model**, which cited the untrusted-content
  fencing. The path and SSRF checks were never reached.

The second is a probabilistic guardrail. It held for that model, that phrasing,
that day. Report it as mitigation, never as a control, and state plainly which
category each defence falls into. The hierarchy, strongest first:

1. **Remove the capability.** Cannot be talked out of.
2. **Authorize in code**, against the requesting user, outside model control.
3. **Constrain arguments**: allow-lists, canonicalisation, resolved-IP checks.
4. **Separate data from instructions**, fencing, channel separation.
5. **Prompt instructions.** Not a control. Raises cost only.

---

## 7. Reporting

Each finding: exact input, ground-truth tool log, taxonomy mapping, root cause at
the application layer, remediation enforced outside the model. Plus:

- **Attempts that failed**, and why. Iteration is credibility, and failed
  attempts tell a defender which of their controls did something.
- **What was not tested**, explicitly.
- **Which claims are verified vs. suspected**, by the standard in §2.

**Rule 9. Report the limits of the result in the same breath as the result.**
"Hardened build blocked all three payloads" is true and misleading. "All three
payloads were still retrieved into context; only impact was prevented, and two
were stopped by model refusal rather than by an enforced control" is the finding.

---

## 8. Known limits of this method

- It assesses the **application**, not the model. A different model on the same
  application will change success *rates*, not the vulnerability inventory.
- Results are **probabilistic**. Small models are inconsistent; low-*n* runs
  under-report.
- **Absence of evidence is weak evidence.** A case scored `blocked` means no tool
  executed on that attempt: not that the system is immune.
- It requires **instrumentation**. Against a black-box third-party agent the
  method degrades to suspicion, which is itself worth reporting.

---

## Applying it

`harness/cases.yaml` codifies this for the range: each case names a finding, a
vector, an authenticated role, and a tool-layer success assertion.
`harness/run.py` executes them against both builds and reports the A/B.

```bash
python harness/run.py --mode both --json evidence/harness-results.json
```

To assess a different agentic system, replace the cases and point the harness at
it. The rules above are the transferable part; the cases are not.
