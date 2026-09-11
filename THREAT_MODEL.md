# Threat Model — AcmeCloud DevOps Assistant

What the system holds, where it stops trusting its input, and who can reach
which part of it. Written before the findings so the attacks can be read as
consequences of the design rather than a list of tricks.

The framing throughout: an LLM does not act. The application acts on its behalf.
So the question is never "what will the model say" but "what will the
application do when the model asks."

---

## 1. What the system is

An internal assistant for a fictional cloud provider. Staff sign in and ask it
to look up customer accounts, check whether a service is responding, read a
config file, run a diagnostic, or search past support tickets.

| Component | What it is |
|---|---|
| Web app | Flask. Login, chat UI, `/chat` endpoint, public ticket form |
| Agent loop | Sends the conversation to the model; executes any tool the model asks for; feeds the result back, up to 8 iterations |
| Tools | `query_customers` (raw SQL), `http_get`, `read_file`, `run_command` (shell), `search_knowledge_base` |
| Customer database | SQLite, in-memory. Columns: `id`, `name`, `plan`, `ssn` |
| Knowledge base | ChromaDB vector store of support tickets and internal notes |
| Inference | Ollama, reached over HTTP. Not in-process |
| Deployment | Container (Docker). A clustered deployment is modelled below but **not assessed** — see boundary 4→5 |

---

## 2. Assets

Ranked by what an attacker gains, not by how the data is classified.

| Asset | Where it lives | Why it matters |
|---|---|---|
| **Cloud credentials** | Wherever the deployment stores them (orchestrator secret, env, mounted file) | Compromise leaves the application entirely. The blast radius is the cloud account, not the app. **Modelled, not assessed** |
| **Service-account token** | Mounted in the pod at `/var/run/secrets/kubernetes.io/serviceaccount/token` | Kubernetes puts it there automatically. It is the key to the credential above |
| **Code execution on the host** | The `run_command` tool | Not an asset in itself. It is the universal solvent that reaches every other asset |
| **Customer PII** | `customers.ssn` in the database | The obvious prize, and the one a compliance team will ask about first |
| **Internal network reachability** | The `http_get` tool | The agent sits inside the perimeter and will fetch on request |
| **Filesystem contents** | The `read_file` tool | Configs, credentials, tokens |
| **The knowledge base's integrity** | ChromaDB | Not confidentiality. If an attacker can write to it, they can influence what the agent does later |

The last one is the least obvious and is the root of the headline finding. A
store that anyone can write to and the agent trusts on read is a code path, not
a data store.

---

## 3. Actors

| Actor | How they get access | What they can reach |
|---|---|---|
| **Anonymous internet user** | No credentials at all | `/submit_ticket`, `/login`, `/healthz` |
| **`viewer`** | Valid low-privilege login | Everything above, plus `/chat` and therefore every tool |
| **`admin`** | Valid high-privilege login | The same as `viewer`. The roles differ in the session and nowhere else |
| **The model** | Not a user, but treat it as an actor | Requests tool calls. Influenced by anyone whose text reaches its context |

That third row is the finding, stated as a design fact. The application
distinguishes the two roles, passes the distinction to the agent, and the tools
ignore it. Authentication exists; authorization does not.

---

## 4. Entry points

Every place attacker-influenced text can enter the system.

| Entry point | Auth | What the attacker controls |
|---|---|---|
| `POST /submit_ticket` | **none** | Arbitrary text, stored verbatim into the knowledge base |
| `POST /chat` | session | The full user message |
| `GET /login` | none | Credentials, subject to guessing |
| `GET /healthz` | none | Nothing. Discloses the build mode and pid |
| Tool *results* | indirect | Whatever a fetched URL or read file returns, which re-enters the model's context |

The last row is easy to miss. `http_get` output goes back into the conversation,
so any server the agent can be made to fetch becomes an injection channel.

---

## 5. Trust boundaries

Five, and the interesting failures are all at a boundary that was never enforced.

```
  ┌─ 1 ─ Internet ──────────────────────────────────────────────┐
  │  anonymous: /submit_ticket, /login                          │
  │                                                             │
  │  ┌─ 2 ─ Authenticated session ─────────────────────────┐    │
  │  │  viewer or admin: /chat                             │    │
  │  │                                                     │    │
  │  │  ┌─ 3 ─ The model's context window ───────────┐     │    │
  │  │  │  system prompt + user message + RETRIEVED   │     │    │
  │  │  │  DOCUMENTS + tool results, all one string   │     │    │
  │  │  │                                             │     │    │
  │  │  │  ┌─ 4 ─ The tool layer ──────────────┐      │     │    │
  │  │  │  │  SQL, HTTP, file, shell           │      │     │    │
  │  │  │  │                                   │      │     │    │
  │  │  │  │  ┌─ 5 ─ Pod / cluster / cloud ─┐  │      │     │    │
  │  │  │  │  │  SA token, RBAC, secrets    │  │      │     │    │
  │  │  │  │  └─────────────────────────────┘  │      │     │    │
  │  │  │  └───────────────────────────────────┘      │     │    │
  │  │  └─────────────────────────────────────────────┘     │    │
  │  └─────────────────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────────────────┘
```

**Boundary 1 → 2, internet to session.** Enforced. Real login, server-side
sessions, protected routes. This one works.

**Boundary 2 → 3, session to model context.** Not a boundary at all. The system
prompt, the user's message, retrieved documents and tool results arrive as one
undifferentiated block of text. The model has no reliable way to tell developer
instructions from attacker content, and no mechanism exists to help it.

**Boundary 3 → 4, model to tools.** The critical one, and it is unguarded in the
vulnerable build. Whatever the model asks for is executed. The caller's identity
is passed to the agent and then dropped. A `viewer` reaches the same tools as an
`admin`.

**Boundary 4 → 5, process to infrastructure.** Governed by the pod's service
account, not by the application. `agent-sa` is bound to a Role granting
`get` and `list` on `secrets`, so anything that executes in the pod can read the
cluster's secrets, including `cloud-credentials`.

**The ingestion path cuts across all of them.** Text submitted at boundary 1 with
no credentials is retrieved inside boundary 3 during someone else's privileged
session. That is the whole attack: the trust boundary is crossed by the *data*,
asynchronously, while the attacker is not present.

---

## 6. What an attacker controls, by position

**Anonymous, no account.** The full text of a support ticket, and therefore a
document that will later sit in a privileged user's model context. They control
*when* only loosely: the payload fires when someone asks a question that
retrieves it, so the payload is written to win that retrieval.

**Authenticated as `viewer`.** Everything above, plus the full user message, and
therefore direct requests for any tool the model is offered.

**Neither controls** the system prompt, the tool implementations, or the model
itself. They do not need to. Every finding in this project comes from
controlling text that the application chooses to act upon.

---

## 7. Assumptions

Stated so a reader knows what was deliberately not defended.

- **The model is not adversarial.** It is treated as a confused deputy that can
  be talked into things, not as an attacker in its own right. A backdoored model
  is a supply-chain problem and out of scope here.
- **Inference is a trusted network peer.** The app talks to Ollama over plain
  HTTP with no authentication. Anyone able to intercept that link controls every
  response, which is a real weakness in a real deployment and simply assumed
  away here.
- **The host is trusted until the agent runs code on it.** No hardening of the
  container or the node beyond the deliberate misconfigurations.
- **Credentials are weak on purpose.** `admin/admin123` is not a finding. It is a
  door left unlocked so the interesting parts can be reached.
- **Denial of service is out of scope.** The agent loop caps at 8 iterations and
  nothing else is rate-limited. That is exploitable and uninteresting.

---

## 8. Where the findings land

Every finding is a boundary that was described but not enforced.

| Boundary | Failure | Findings |
|---|---|---|
| 3 → 4, model to tools | Tools execute what the model asks, with no constraint on the arguments | F-01, F-02, F-04, F-05, F-07 |
| 3 → 4, identity | The caller's role reaches the agent and is then ignored | F-08 |
| 2 → 3, data versus instructions | Retrieved documents enter the context as trusted text | F-09 |
| 1 → 3, ingestion | Anonymous input is stored and later trusted on read | F-09 |
| 4 → 5, process to cluster | An over-permissioned service account, and secrets it can read | **not assessed** |
| Verification, not a boundary | The model misreports what the tools did, in both directions | F-03, F-06, F-11 |

The last row is why this project logs every tool execution server-side. Three of
eleven findings are about the assessment being wrong rather than the system being
broken, and they are the reason no finding here rests on what the chatbot said.

---

## 9. What the hardened build changes

`SECURE=1` enforces boundaries 3 → 4 in code. See `agent/policy.py` and the
measured results in `README.md`.

The one thing the threat model makes clear, and the reason the hardened result is
reported with a caveat: **boundary 2 → 3 is still not enforced, and cannot be.**
Retrieved content still enters the model's context, and the injection still wins
retrieval every time. The hardened build removes the capabilities the injection
was reaching for. It does not stop the injection, because nothing at that layer
reliably can.
