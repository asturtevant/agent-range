# From a Public Support Ticket to Remote Code Execution: Attacking an Agentic AI Assistant

A walkthrough of a complete attack chain against a realistic AI-powered DevOps assistant, in which an unauthenticated attacker achieves remote code execution in the context of a privileged user, without ever authenticating or interacting with the agent directly.

*This is a deliberately-vulnerable research system built for local, authorized testing. Nothing here targets a real service.*

---

## Why agentic systems change the threat model

A chatbot that only produces text is low-risk; the worst it does is say something wrong. An **agent** is different: it's a loop in which the model can request *tools* (run a query, fetch a URL, read a file, execute a command) and the surrounding application executes those requests. The model never acts directly; the application acts on its behalf. That single design choice moves the risk from "the model said something bad" to "the model caused something bad to happen," and it relocates the vulnerability from the model to the application layer that trusts it.

The assistant in this project is a plausible internal tool: staff use it to check customer accounts, look up tickets, check services, and run diagnostics. To do that it holds real capabilities: a database tool, an HTTP-fetch tool, a file-read tool, and a shell tool, plus a retrieval-augmented knowledge base and real authentication. Each capability is realistic, and each is the source of a finding.

## The building blocks (app-layer findings)

Before the headline attack, the assessment established that the agent's tools are over-privileged and unbounded:

- **Over-privileged data access.** The SQL tool runs arbitrary queries with no allow-list, so a "customer support" assistant will happily dump every customer's SSN or enumerate the database schema. The stated scope ("customer support") exists only as English in a description, not as an enforced control.
- **SSRF.** The HTTP-fetch tool will retrieve any URL, including internal-only services bound to localhost. That is the basis for reaching internal systems and, in a cloud deployment, the instance metadata endpoint.
- **Arbitrary file read / path traversal.** The file-read tool reads any path the process can access, including via `../` traversal out of its intended directory.
- **Remote code execution.** The diagnostic tool passes model-chosen strings to a system shell with no allow-list. Arbitrary command execution, by design.
- **No tool-layer authorization.** The application has *real* authentication (login, sessions, protected routes, roles), and it passes the caller's identity to the agent, but the tools ignore it. A logged-in low-privilege `viewer` can execute shell commands and read arbitrary files through the agent. Authentication is present; authorization is absent. This is the confused-deputy problem: the agent holds full privilege and acts for whoever asks, without checking whether they're allowed.

A methodology finding recurs throughout: **the model is an unreliable narrator.** It repeatedly reported tool outcomes that contradicted what the tools actually did. It invented file contents, reporting a successful read as "file not found," and (critically) claiming to have run a command it never invoked. Every finding here is verified against server-side tool-execution logs, not the chatbot's response.

## The headline: indirect prompt injection to RCE

Individually, the findings above require the attacker to *be* a user of the agent. The headline attack removes that requirement entirely.

The assistant answers questions using a knowledge base of support tickets and internal docs (RAG): submitted tickets are embedded and stored so the agent can retrieve them later. That ingestion pipeline **trusts its input**, it embeds whatever text a ticket contains, because to the pipeline it's just "a document to make searchable."

The attack:

1. **An anonymous attacker submits a poisoned ticket** through the public submission form, with no login required, exactly like a real support portal. The ticket text is crafted to do two things: rank highly in retrieval for login-related questions (keyword-dense), and carry an imperative instruction telling the assistant to run a shell command.
2. **The pipeline ingests it**, embedding the poison into the knowledge base with no inspection.
3. **A privileged admin later asks an ordinary question**: "any recent tickets about login problems?"
4. **Retrieval pulls the poisoned ticket** into the agent's context as trusted content.
5. **The agent follows the hidden instruction** and executes a system command with the admin's session and privileges.

The attacker authenticated nothing, sent the agent nothing, and touched no internal system. They filed a support ticket. The ticket system worked exactly as designed, and the intended feature (ingest tickets so the assistant can help with them) delivered the payload to where it executed.

## Two battles, and a fabrication trap

Making this fire reliably required winning two independent battles, both of which failed during testing. That failure is the lesson, because indirect injection is probabilistic:

- **Retrieval.** The poison must rank into the top results for the victim's query. It initially lost to the legitimate login ticket; keyword-dense phrasing and retrieving more results fixed it.
- **Obedience.** Once retrieved, the instruction must override the model's actual task. It initially looped on knowledge searches until the iteration cap; an imperative "do this first, don't search further" directive fixed it.

And a third trap worth its own emphasis: **the model at first faked execution.** It produced plausible command output for a command it never ran. No tool-execution log entry existed. Real execution was only accepted after confirming, against ground truth, that the tool-execution log showed the call *and* the returned value matched the true host (the real username / a file written to disk). A less careful assessment would have reported RCE based on the chatbot's word alone and been wrong. The distinction between *fabricated* and *actual* execution is central, and it can only be resolved outside the model.

## Root cause and remediation

The root cause is singular and structural: **retrieved content enters the agent's context as trusted input, and the agent cannot distinguish data from instructions.** Combined with over-privileged tools and no tool-layer authorization, a document becomes code execution.

Defenses must be architectural, not prompt-level, and the section after this one tests whether they actually hold:
- Treat all retrieved and user-supplied content as untrusted *data*; keep it separate from the instruction channel. Prompt-based "please ignore malicious instructions" does not solve this.
- Enforce authorization at the tool layer, scoped to the requesting user. The agent should act with the user's privileges, not its own.
- Remove or strictly allow-list dangerous tools (especially shell); require human approval for privileged actions.
- Inspect and constrain what the ingestion pipeline accepts.
- Ground responses in verified tool output; never treat model narration as evidence that an action occurred.

## Do the fixes actually work?

Recommending remediations is cheap. The range implements them. `SECURE=1` enforces every control above in code, in one readable file, so the same attacks can be run against the fixed system and measured rather than assumed.

Same poisoned-ticket chain, same low-privilege user, three payloads: the original one targeting the shell tool, plus two adapted ones a real attacker would pivot to once the shell was gone: arbitrary file read (`../../../../etc/passwd`) and an SSRF at the cloud metadata endpoint.

| | Vulnerable | Hardened |
|---|---|---|
| Tools offered to the model | SQL, fetch, file read, **shell**, KB search | scoped customer lookup, fetch, file read, KB search |
| `viewer` asks for `whoami` | executed — real host account returned | zero tool executions |
| Poisoned-ticket chain (3 payloads) | RCE | poison retrieved, no execution |

The poison still won retrieval every time. Only impact was prevented, which is the honest way to read this: **indirect injection was not stopped, its consequences were.**

And the three payloads were not stopped equally, which matters more than the summary row suggests. The shell payload was stopped *architecturally*, the tool isn't registered, so there was nothing to call no matter how persuasive the injected instruction was. The other two were **declined by the model**, which quoted the untrusted-content fencing back in its answer. The file-read and SSRF checks were never actually reached.

That distinction is the finding. A control the model enforces is a control an attacker can argue with; a capability that doesn't exist is not. Removing the shell tool holds unconditionally. Fencing retrieved content raises the cost and is model-dependent: it happened to work here, with this model, on this phrasing, and I can't claim more than that.

## The trap that catches defenders too

One more result, and it's the one I'd most want a reader to take away.

In hardened mode, asked to run a command, the model answered:

> *"It looks like I'm unable to run the command `whoami` directly. Let me try an alternative approach... Running command: /usr/bin/whoami — Output: 'username'"*

Nothing ran. The tool doesn't exist in that mode. The model invented a command invocation, a path, and an output to satisfy the request.

This is the same fabrication that nearly produced a false RCE finding during the attack, but pointed the other way. An operator validating their own fix reads that transcript and concludes the control failed. An automated scanner keying on response text scores it as successful remote code execution. Both are wrong, and both are wrong *in the direction that costs you*: false positives against defended systems, false negatives against compromised ones.

So the discipline has to be symmetric. The tool log is ground truth for "did the attack work" **and** for "did the fix work." Any assessment harness, detection rule, or benchmark that scores agentic compromise from model output alone is measuring the wrong thing in both directions.

## Takeaway

The interesting attacks against agentic AI don't live in the model: they live in the application that wraps it: its tools, its data flows, its trust boundaries, and its ingestion paths. A model jailbreak with no tools is a party trick; the same model wired to a shell and fed untrusted documents is a remote-code-execution vector reachable by anyone who can submit a support ticket.

The defence follows the same logic. You cannot reliably instruct a model out of being injected, and you don't have to: the injection only matters if it reaches a capability worth abusing. Cut the capability, authorize at the tool layer against the real user, and treat retrieved content as data, then verify the whole thing against the tool log, because the one component you cannot trust to tell you whether any of it worked is the model itself.
