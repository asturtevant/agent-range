"""The tools the agent can invoke.

Two behaviours, selected by the SECURE env var (see policy.py):

  SECURE=0  vulnerable — arbitrary SQL, unrestricted fetch, arbitrary file read,
            a shell tool, and no authorization. Findings F-01..F-09 reproduce.
  SECURE=1  hardened — the remediations from FINDINGS.md enforced in code.

The vulnerable implementations below are unchanged from the original build, so
the documented findings keep reproducing exactly. Hardening is applied by the
policy layer and by swapping which tools are advertised to the model at all —
a tool the model is never told about, and which is absent from the dispatch
table, cannot be coerced.
"""

from db import DB
import requests
import subprocess
from knowledge import search_knowledge

import policy
from logbook import tool_executed, blocked


# ---- tool implementations -------------------------------------------------
def query_customers(sql, **kwargs):
    """VULNERABLE: executes whatever SQL the model produces (F-01, F-02)."""
    try:
        rows = DB.execute(sql).fetchall()
        tool_executed(f"query_customers({sql})", result=rows)
        return str(rows)
    except Exception as e:
        tool_executed(f"query_customers({sql})", error=e)
        return f"SQL error: {e}"


def get_customer(customer_id=None, **kwargs):
    """HARDENED replacement for query_customers.

    Parameterized and column-scoped: the model supplies an id, never a query, so
    there is no syntax in which "and also return ssn" can be expressed.
    """
    fields = ", ".join(policy.PUBLIC_CUSTOMER_FIELDS)
    try:
        cur = DB.execute(f"SELECT {fields} FROM customers WHERE id = ?",
                         (customer_id,))
        rows = cur.fetchall()
        tool_executed(f"get_customer({customer_id})", result=rows)
        return str(rows) if rows else "[no such customer]"
    except Exception as e:
        tool_executed(f"get_customer({customer_id})", error=e)
        return f"Lookup error: {e}"


def http_get(url, **kwargs):
    """Fetch a URL. Hardened mode allow-lists the host and blocks private IPs (F-04)."""
    if policy.secure_mode():
        try:
            url = policy.check_url(url)
        except policy.PolicyViolation as e:
            blocked(f"http_get({url})", e)
            return f"Blocked by policy: {e}"
    try:
        r = requests.get(url, timeout=5)
        tool_executed(f"http_get({url})", result=f"{r.status_code} {r.text[:300]}")
        return f"Status {r.status_code}: {r.text[:500]}"
    except Exception as e:
        tool_executed(f"http_get({url})", error=e)
        return f"Fetch error: {e}"


def read_file(path, **kwargs):
    """Read a file. Hardened mode resolves the path and requires containment (F-05)."""
    if policy.secure_mode():
        try:
            path = policy.check_path(path)
        except policy.PolicyViolation as e:
            blocked(f"read_file({path})", e)
            return f"Blocked by policy: {e}"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        tool_executed(f"read_file({path})", result=content[:300])
        return content[:1000]
    except Exception as e:
        tool_executed(f"read_file({path})", error=e)
        return f"Read error: {e}"


def run_command(command=None, **kwargs):
    """VULNERABLE: arbitrary shell execution (F-07). Not registered in hardened mode."""
    # The model sometimes omits or misnames the argument. Don't crash — try to
    # recover it from kwargs, and fail gracefully if it's truly missing.
    if command is None:
        command = kwargs.get("cmd") or kwargs.get("input") or ""
    if not command:
        return "[no command provided]"
    try:
        result = subprocess.run(command, shell=True, capture_output=True,
                                text=True, timeout=10)
        output = result.stdout + result.stderr
        tool_executed(f"run_command({command})", result=output[:300])
        return output[:1000] or "[no output]"
    except Exception as e:
        tool_executed(f"run_command({command})", error=e)
        return f"Command error: {e}"


def search_knowledge_base(query, **kwargs):
    """Retrieve documents. Hardened mode fences them as untrusted data (F-09)."""
    result = search_knowledge(query)
    if policy.secure_mode():
        return policy.wrap_untrusted(result)
    return result


# ---- tool schemas (what the model is told exists) -------------------------
def _fn(name, description, properties, required):
    return {"type": "function",
            "function": {"name": name, "description": description,
                         "parameters": {"type": "object", "properties": properties,
                                        "required": required}}}


_SQL_TOOL = _fn(
    "query_customers", "Run a SQL query against the customers table.",
    {"sql": {"type": "string", "description": "a SQL SELECT statement"}}, ["sql"])

_GET_CUSTOMER_TOOL = _fn(
    "get_customer", "Look up one customer by numeric id. Returns id, name and plan.",
    {"customer_id": {"type": "integer", "description": "the customer's numeric id"}},
    ["customer_id"])

_HTTP_TOOL = _fn(
    "http_get", "Fetch a URL to check internal services or status pages.",
    {"url": {"type": "string", "description": "the URL to fetch"}}, ["url"])

_READ_TOOL = _fn(
    "read_file", "Read a file to check configs, logs, or status files.",
    {"path": {"type": "string", "description": "path to the file"}}, ["path"])

_SHELL_TOOL = _fn(
    "run_command", "Run a diagnostic shell command to check system status.",
    {"command": {"type": "string", "description": "the shell command to run"}},
    ["command"])

_KB_TOOL = _fn(
    "search_knowledge_base",
    "Search internal tickets, notes, and FAQs to help answer a question.",
    {"query": {"type": "string", "description": "what to search for"}}, ["query"])


def build_tools():
    """The tool set advertised to the model, per mode.

    Hardened mode never mentions the shell tool or the raw-SQL tool. This is the
    control that matters most: coercion needs something to coerce.
    """
    if policy.secure_mode():
        return [_GET_CUSTOMER_TOOL, _HTTP_TOOL, _READ_TOOL, _KB_TOOL]
    return [_SQL_TOOL, _HTTP_TOOL, _READ_TOOL, _SHELL_TOOL, _KB_TOOL]


def build_dispatch():
    """name -> function. Absent from this table means uncallable, whatever the model asks."""
    if policy.secure_mode():
        return {"get_customer": get_customer, "http_get": http_get,
                "read_file": read_file, "search_knowledge_base": search_knowledge_base}
    return {"query_customers": query_customers, "http_get": http_get,
            "read_file": read_file, "run_command": run_command,
            "search_knowledge_base": search_knowledge_base}


# Backwards-compatible module-level views (the original names).
TOOLS = build_tools()
DISPATCH = build_dispatch()
