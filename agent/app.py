from agent_core import run_agent

from flask import Flask, request, jsonify, render_template_string, session, redirect
from knowledge import ingest_ticket

app = Flask(__name__)
app.secret_key = "dev-only-insecure-key-change-me"   # signs the session cookie

# Two hardcoded users. In reality this'd be a database with hashed passwords;
# hardcoding two is enough to demonstrate the privilege-crossing finding.
USERS = {
    "viewer": {"password": "viewer123", "role": "viewer"},
    "admin":  {"password": "admin123",  "role": "admin"},
}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        # Check the credentials are real.
        if user and user["password"] == password:
            # Correct login: store identity in the session (the signed cookie).
            session["username"] = username
            session["role"] = user["role"]
            return redirect("/")
        return "Invalid credentials", 401
    # GET: show a simple login form.
    return """
    <h2>AcmeCloud Login</h2>
    <form method="post">
      <input name="username" placeholder="username"><br>
      <input name="password" type="password" placeholder="password"><br>
      <button>Log in</button>
    </form>
    <p>Try: viewer/viewer123 or admin/admin123</p>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")



CHAT_PAGE = """
<!doctype html>
<title>AcmeCloud DevOps Assistant</title>
<h2>AcmeCloud DevOps Assistant</h2>
<div id="log" style="white-space:pre-wrap;border:1px solid #ccc;padding:1em;height:300px;overflow:auto;"></div>
<input id="msg" style="width:80%" placeholder="Ask about a customer account...">
<button onclick="send()">Send</button>
<script>
async function send() {
  const box = document.getElementById('msg'), log = document.getElementById('log');
  const text = box.value; log.textContent += "You: " + text + "\\n"; box.value = "";
  const res = await fetch('/chat', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: text})
  });
  const data = await res.json();
  log.textContent += "Bot: " + data.answer + "\\n\\n";
}
</script>
"""

@app.route("/healthz")
def healthz():
    """Identify the instance actually answering on this port.

    Exists because scoring an assessment against the wrong process is a silent,
    catastrophic error: a stale VULNERABLE instance left listening will happily
    answer requests intended for the hardened build, and the harness would score
    a fresh, empty log as 'blocked'. That false negative was observed during
    development. Any tooling must assert this matches the mode it started.
    """
    import os as _os
    import policy as _policy
    return jsonify({"mode": "secure" if _policy.secure_mode() else "vulnerable",
                    "pid": _os.getpid()})


@app.route("/")
def home():
    # Not logged in? Send them to login. This is the lock on the door.
    if "username" not in session:
        return redirect("/login")
    return render_template_string(CHAT_PAGE)

# In-memory conversation store. A dict is right for a single-process range;
# it is deliberately NOT persisted, so restarting the app clears all memory and
# each harness run starts from a known-empty state.
CONVERSATIONS = {}
MAX_HISTORY_MESSAGES = 20


@app.route("/chat", methods=["POST"])
def chat():
    # Protect the endpoint too — not just the page. An attacker hits /chat
    # directly (like your send.py did), so the page check alone isn't enough.
    if "username" not in session:
        return jsonify({"error": "not authenticated"}), 401

    user_message = request.json.get("message", "")

    # Conversation memory is OPT-IN, keyed by a client-supplied id. Absent one,
    # /chat stays stateless exactly as before.
    #
    # Opt-in rather than automatic on purpose: the assessment harness reuses one
    # authenticated session across many unrelated cases, and per-user history
    # would let case N's payload sit in context for case N+1 -- silently
    # crediting an execution to the wrong case. Attribution is the whole basis
    # of the scoring, so memory is scoped to an explicit conversation instead.
    convo_id = (request.json.get("conversation_id") or "").strip()
    history = CONVERSATIONS.get(convo_id, []) if convo_id else []

    # Pass the caller's identity + role down to the agent.
    answer = run_agent(user_message, username=session["username"],
                       role=session["role"], history=history)

    if convo_id:
        turns = history + [{"role": "user", "content": user_message},
                           {"role": "assistant", "content": answer}]
        # Bounded so a long conversation cannot grow the context without limit.
        CONVERSATIONS[convo_id] = turns[-MAX_HISTORY_MESSAGES:]

    return jsonify({"answer": answer})

# Public ticket submission. NO auth — anyone can file a ticket, exactly like a
# real support portal. Whatever they submit gets ingested into the knowledge
# base the agent later searches. This is the attacker's front door.
@app.route("/submit_ticket", methods=["GET", "POST"])
def submit_ticket():
    if request.method == "POST":
        text = request.form.get("ticket", "")
        ticket_id = ingest_ticket(text)          # trusts and stores the input
        return f"Ticket submitted. Reference: #{ticket_id}"
    # GET: a simple public submission form.
    return """
    <h2>AcmeCloud Support — Submit a Ticket</h2>
    <form method="post">
      <textarea name="ticket" rows="6" cols="60" placeholder="Describe your issue..."></textarea><br>
      <button>Submit Ticket</button>
    </form>
    """

if __name__ == "__main__":
    import os
    import policy

    # SAFETY: this application is deliberately vulnerable — in its default mode
    # it exposes arbitrary shell execution reachable through an unauthenticated
    # ingestion path. It binds to loopback only. Exposing it on a routable
    # interface hands code execution to anyone who can reach the port, so the
    # override is explicit and deliberately awkward.
    #
    # Containers are the legitimate exception: in Docker the process
    # must bind 0.0.0.0 to be reachable via port-forward, and the container
    # boundary is the isolation. docker-compose.yml sets RANGE_BIND accordingly.
    host = os.environ.get("RANGE_BIND", "127.0.0.1")
    # macOS binds port 5000 to ControlCenter (AirPlay Receiver) by default, which
    # produces confusing "it's already running" behaviour. Override with RANGE_PORT.
    port = int(os.environ.get("RANGE_PORT", "5000"))
    # debug=True enables the Werkzeug debugger, which is itself an RCE console.
    # Off unless asked for, and never combine it with a non-loopback bind.
    debug = os.environ.get("RANGE_DEBUG", "0") == "1"

    if host != "127.0.0.1":
        print(f"\n*** WARNING: binding {host} — this range is intentionally "
              f"vulnerable and offers remote code execution. Only do this inside "
              f"an isolated container or lab network. ***\n")
        if debug:
            raise SystemExit(
                "Refusing to start: RANGE_DEBUG=1 with a non-loopback bind would "
                "expose the Werkzeug debug console. Unset one of them.")

    mode = "SECURE (hardened)" if policy.secure_mode() else "VULNERABLE (default)"
    print(f"[RANGE] mode={mode}  bind={host}:{port}  debug={debug}")
    app.run(host=host, port=port, debug=debug)