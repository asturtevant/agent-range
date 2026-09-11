# Detection

The defender's view of the same attacks. Every finding in `../FINDINGS.md` is an
attack; each rule here is what a SOC would need to see it happen.

These are [Sigma](https://github.com/SigmaHQ/sigma) rules: a vendor-neutral YAML
format for detection logic. Written once, converted to whatever the defender
actually runs (`sigma convert -t splunk|elastic|kusto ...`), so a detection can
be shared without assuming anyone's SIEM.

## What they run against

The tool-layer log written by `agent/logbook.py`:

```
[TOOL EXECUTED] run_command(whoami)
[TOOL RESULT]  hostuser
[TOOL BLOCKED]  http_get(https://example.com/status)
[POLICY]        host 'example.com' is not in the fetch allow-list
[RAG SEARCH] query='login problems'
[RAG RESULT]  [...retrieved documents...]
[INGEST] added document id=1000: LOGIN ISSUE - cannot log in...
[AGENT] request from user=viewer role=viewer mode=VULNERABLE
```

The rules assume these lines are shipped as events with fields parsed out
(`event_type`, `tool`, `arguments`, `user`, `role`). A parser for that is
deployment-specific and out of scope here; the field names above are the
contract.

## "Doesn't this assume a SIEM?"

Yes, and that assumption is most of the point.

Sigma rules need someone collecting the logs. But the prior question is whether
the logs exist at all, and in most LLM agent deployments **they do not**. What
gets retained is the chat transcript, if anything. The tool layer, which is the
only place the truth lives, is usually not logged, not shipped, and not
retained.

So read these two ways:

1. **If you have a SIEM**, this is the detection content, and the field contract
   above is what your parser needs to produce.
2. **If you don't**, this is a requirements document. Each rule states what
   telemetry must exist before the corresponding attack is detectable at all.
   Work backwards from the rules to the instrumentation.

Reading (2) is the more common situation and the more useful one. An
organisation running an agent with a shell tool and no tool-layer logging cannot
detect F-07 by any means, cannot investigate it afterwards, and would not know it
happened. That is a finding about the deployment, and it is worth reporting
alongside the vulnerabilities: *the attacks below are undetectable here as
built.*

The same gap explains why the assessment methodology insists on instrumenting
before testing. Detection and assessment need identical telemetry, so building
one gets you most of the other.

## The detection thesis

**Detecting the prompt is a losing game. Detect the effect.**

Injection payloads are natural language with unbounded variation, so a rule that
matches payload text is bypassed by rewording. What cannot be reworded is the
outcome: a shell command executed, a file read outside the allowed path, a
request to link-local address space. Those are finite, enumerable, and are what
these rules target.

The one exception is `agent_injection_ingested.yml`, which looks for
instruction-shaped language arriving through a content ingestion path. It is
deliberately low-confidence and exists to enrich, not to alert.

## Rules

| Rule | Detects | Level |
|------|---------|-------|
| `agent_shell_execution.yml` | any shell command through the agent (F-07) | high |
| `agent_privileged_tool_by_low_role.yml` | privileged tool invoked for a low-privilege caller (F-08) | high |
| `agent_ssrf_internal_target.yml` | fetch aimed at loopback, RFC1918 or cloud metadata (F-04) | high |
| `agent_path_traversal.yml` | file read escaping the intended directory (F-05) | high |
| `agent_tool_after_retrieval.yml` | privileged tool call immediately after a RAG retrieval (F-09) | critical |
| `agent_injection_ingested.yml` | instruction-shaped text entering the knowledge base | low |
| `agent_policy_block_burst.yml` | repeated policy refusals, i.e. someone probing a hardened build | medium |

## Known limits

- **`agent_tool_after_retrieval` is the important one and the noisiest.** A
  privileged tool call following a retrieval is exactly the F-09 signature, but
  it is also legitimate behaviour for an assistant that looks something up and
  then acts. Tune the correlation window per deployment, and expect to allow-list
  benign pairs. A rule this valuable is worth the tuning; do not ship it untuned.
- These detect **execution, not intent**. An injection that is retrieved but not
  obeyed produces no tool call and no alert. That is a deliberate trade: the
  alternative is alerting on natural language and drowning.
- Nothing here detects a **fabricated** tool call, because nothing happened. The
  model claiming to have run a command produces no event. That asymmetry is
  finding F-11 and is the reason detection must be built on the tool layer rather
  than on model output.
