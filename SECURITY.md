# Security & Responsible Use

## This is intentionally vulnerable software

This repository contains a **deliberately vulnerable** agentic AI application,
built for security research and education. It intentionally includes:

- a tool that executes arbitrary shell commands (RCE by design)
- a tool that reads arbitrary files (path traversal by design)
- a tool that fetches arbitrary URLs (SSRF by design)
- a tool that runs arbitrary SQL (injection by design)
- no authorization at the tool layer
- a public ingestion path that trusts all input (prompt-injection by design)

**Do not deploy this. Do not expose it to any network. Do not run it on a
machine you care about or that holds sensitive data.** It is meant to be run
locally, in isolation, as a target you attack yourself to learn how agentic AI
systems fail.

## Intended use

This project exists to demonstrate and document how agentic AI systems can be
attacked — indirect prompt injection, excessive agency, tool abuse, and the
pivot from a poisoned document to code execution. It is intended for:

- security researchers and red teamers learning agentic AI attack surfaces
- developers learning what *not* to build
- educational and portfolio purposes

Every vulnerability is documented with its real-world remediation in
[`FINDINGS.md`](FINDINGS.md), so the project teaches defense as well as offense.

## Not for malicious use

The techniques here are for testing systems you own or are explicitly authorized
to test. Using them against systems without authorization is illegal. This
material is provided for defensive and educational purposes.
