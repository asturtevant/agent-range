# Agentic Attack Range — Master Project Plan

The definitive plan. Supersedes all earlier scattered planning docs. Reflects the goals and corrections established through build: realism as a first-class goal, hiring signal as the priority, break-and-build as the thesis.

---

## What the project is

A deliberately-vulnerable **agentic AI system** — an "AcmeCloud DevOps Assistant," an LLM wired to real tools, a database, retrieval, and a real deployment — built to be realistic, then attacked end-to-end. You document a single kill chain from a poisoned input to cloud infrastructure compromise, and build the automated harness that runs those attacks at scale. One coherent artifact, built in the open, that is both résumé centerpiece and interview story.

**Thesis it proves:** agentic AI risk isn't a model problem, it's a whole-stack problem — and I break whole stacks.

## Why this project (given the goals)

Moving out of slow, documentation-heavy work into offensive AI security; motivated by the break-in; deep infra/AD/network/host experience, less web-app depth, modest Python; wants maximum hiring signal. This project is break-centered, its hardest layer (infra escape) is an existing strength most entrants lack, it deliberately drills the web-app patterns that are rusty, and it produces public proof. The competition is web-app people who can't do infrastructure or newcomers who can't do either — the full-stack kill chain is what neither can produce.

## What makes it stand out (hiring priorities, in order)

This ordering drives every sequencing decision.

1. **The repo reads as professional in 90 seconds** — clean structure, real README, genuine commit history, findings log. Cheapest, highest-return, cannot be retrofitted → set up now, commit as you go.
2. **Depth of attack reasoning over count** — one kill chain explained with real app-layer understanding beats ten shallow bugs.
3. **The full-stack kill chain** — the prompt-to-cloud pivot; the single most distinguishing technical piece.
4. **The break-and-build harness** — automating attacks is an explicit job requirement and makes you an offensive engineer, not just a tester.

Everything else (auth, detection, threat model, richer data) is *supporting* — enough to make the kill chain authentic and the demo believable, no more.

## Realism principle

Realism means two things, held to deliberately: the target should **resemble a real deployment** (real UI, real endpoint, multiple tools, real deployment context) and you **attack it like a real one** (UI for recon, Burp to intercept/tamper, endpoint as the true attack surface, ground-truth logging to verify). The chat UI is part of the build, not deferred polish.

## Architecture

An LLM (llama3.1 via Ollama — the swappable inference layer) behind an application layer where every vulnerability lives:
- a chat UI users hit, and a `/chat` HTTP endpoint attackers hit
- tools the agent can invoke: SQL, HTTP-fetch (SSRF vector), file-read (disclosure vector), diagnostic/shell (RCE vector)
- a RAG knowledge base it retrieves from
- a light auth/identity notion so privilege boundaries are real
- ground-truth tool logging throughout (verify what tools did, don't trust model narration)
- final phase (dropped): containerized on Kubernetes with realistic misconfigurations

## The kill chain (the spine)

One continuous path, each step mapped to OWASP LLM/Agentic Top 10 + MITRE ATLAS:

1. **Poisoned input** — indirect prompt injection via a retrieved document/ticket (RAG). *LLM01/LLM08.*
2. **Enumerate** — agent reveals its tools and system prompt. *LLM07.*
3. **Abuse a tool** — coerce a privileged tool call with your arguments (confused deputy). *LLM06.*
4. **Cross the privilege boundary** — use the agent's identity to reach what the user shouldn't. *(why the auth layer exists.)*
5. **Escape to infrastructure** — pivot from the tool foothold to cloud creds (SA token, over-broad RBAC, SSRF to metadata endpoint). *(differentiator.)*
6. **Persist via supply chain** — malicious model file (pickle RCE) for persistence. *(ML-infra differentiator; Tier 2.)*

## Status (updated 2026-08-12)

Phases A, 0, 1 and 2 are complete. **Phase 3 is complete**: `harness/` runs the
findings as repeatable cases scored from the tool layer, against both the
vulnerable and hardened builds. Phase 4 is partly done: the detection layer
(`detection/`) and the assessment methodology (`METHODOLOGY.md`) exist; the
threat model and the published blog series do not yet.

Two deviations from the plan below, both deliberate:

- **MCP integration (Phase 1) was never built.** The RAG ingestion path proved
  sufficient to demonstrate indirect injection, and MCP would have added surface
  without adding a new finding class. Still worth doing, but as an extension
  rather than a gap.
- **The harness does not extend PyRIT or Garak.** Both score from model
  responses, and this project's central finding is that response text is a poor
  proxy for what a tool actually did (see the measurement study in FINDINGS.md:
  75% precision, 33% recall). Building on their scoring would have inherited the
  flaw being documented. Using PyRIT as an attack *generator* feeding this
  harness's tool-layer scoring remains the sensible next step.

## Phases (sequenced for hiring signal; always shippable)

- **Phase A — Repo foundation (now).** git, clean structure, requirements.txt, .gitignore, README scaffold. Commit existing work as the first real commit.
- **Phase 0 — Realistic agent (mostly built).** Agent loop, real tool-calling, SQL tool, Flask endpoint, chat UI, ground-truth logging. ADD: HTTP-fetch, file-read, diagnostic/shell tools; a light auth/identity layer. Establish the Burp workflow. *Findings logged so far: excessive agency, sensitive-data disclosure, arbitrary SQL, raw-error disclosure.*
- **Phase 1 — RAG + MCP, app-layer chain.** Retrieval KB (nomic-embed-text) + MCP integration. Execute/document kill-chain steps 1–4. The heart of the writeup.
- **Phase 2 — Infrastructure & escape. DROPPED, not deferred.** Designed but never executed, so it was removed from the repo rather than carried as a pending finding. Containerisation itself shipped (`Dockerfile`, `docker-compose.yml`); the cluster escape did not. See FINDINGS.md, "Removed from scope".
- **Phase 3 — Automation harness (break-and-build). SHIPPED, but not as planned.** The harness does NOT extend PyRIT or Garak, for the reason in the deviations above: both score from response text, which is the flaw being documented. It scores from the tool layer instead. Using PyRIT as an attack *generator* feeding that scorer remains the sensible next step.
- **Phase 4 — Polish & publish.** Threat model up front, light detection layer (defender's view), README with kill-chain diagram, writeup as a blog series. Publish each phase as finished.

## Supporting elements (light touch)

Threat model at the front (assets, trust boundaries, entry points). Detection layer at the end of each phase (defender's view). Realistic-enough data/scenario. Seasoning, not the meal.

## Documentation discipline (throughout)

`FINDINGS.md` captures every finding: exact input, ground-truth tool execution, OWASP/ATLAS mapping, app-layer root cause, real remediation — plus failed attempts (iteration = credibility). Raw material for the writeup.

## How we work (given modest Python)

Generate code → read-understand-modify → explain past-basics inline. Small blocks, run and confirm before moving on. Ground-truth logging so you always see what actually happened. Keep checking the "fast path to mechanics" bias against the real goal of a realistic, complete, understood artifact.

## Risk & guardrail

Scope is complete but large; the failure mode is never shipping. Rule: **every phase is independently shippable and published when done.** Tier 1 (through Phase 2) is already standout; Phases 3–4 turn standout into exceptional.
