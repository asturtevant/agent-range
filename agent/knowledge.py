import chromadb
import requests

from logbook import log

# ---- We use Ollama's embedding model to turn text into vectors -------------
# An "embedding" is a list of numbers representing the MEANING of a piece of
# text. Similar meanings produce similar numbers. nomic-embed-text (which you
# already pulled) is the model that does this conversion.
import os
OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://127.0.0.1:11434")

# How much of an ingested document reaches the evidence log. Must exceed the
# length of the payloads detection rules look for; see F-14.
INGEST_LOG_CHARS = 2000

def embed(text):
    r = requests.post(f"{OLLAMA_BASE}/api/embeddings",
                      json={"model": "nomic-embed-text", "prompt": text})
    return r.json()["embedding"]

# ---- Create the vector database --------------------------------------------
# ChromaDB stores text alongside its embedding and lets us search by meaning.
# We tell it to use OUR embed() function so everything is embedded consistently.
client = chromadb.Client()
collection = client.create_collection(name="acme_knowledge")

# ---- The documents: a small, realistic internal knowledge base -------------
# These are the kinds of docs a DevOps/support bot would search: tickets,
# internal notes, FAQs. All benign for now — we poison one later.
DOCUMENTS = [
    "Ticket #1001: Customer Alice Nguyen reports slow dashboard loading. Resolved by clearing cache.",
    "Ticket #1002: Bob Carter requested a refund for duplicate charge. Refund processed.",
    "Internal note: The billing service restarts nightly at 2am UTC. Do not schedule jobs then.",
    "FAQ: To reset a customer's password, use the admin portal under Users > Reset.",
    "Ticket #1003: Carlos Diaz cannot log in after password change. Escalated to auth team.",
]

# ---- Load the documents into the vector store ------------------------------
# For each document: compute its embedding, then store the text + embedding.
for i, doc in enumerate(DOCUMENTS):
    collection.add(
        ids=[str(i)],                 # a unique id for each doc
        embeddings=[embed(doc)],      # the meaning-vector
        documents=[doc],              # the original text
    )

# ---- The search function: find documents relevant to a query ---------------
def search_knowledge(query, n_results=4):
    # Embed the query, then ask Chroma for the closest-meaning documents.
    results = collection.query(
        query_embeddings=[embed(query)],
        n_results=n_results,
    )
    docs = results["documents"][0]     # the matching document texts
    # Logged to the evidence file, not just stdout: proving a poisoned document
    # was RETRIEVED INTO CONTEXT is half of F-09's ground truth. Without it you
    # cannot distinguish "the injection never got retrieved" from "it was
    # retrieved and the controls held" -- which is exactly the question the
    # hardened-mode assessment turns on.
    log(f"[RAG SEARCH] query={query!r}\n[RAG RESULT]  {docs}")
    return "\n".join(docs)

# ---- Ingest a new ticket into the knowledge base ---------------------------
# In production this is what a ticket-ingestion pipeline does: take submitted
# text, embed it, and add it to the searchable store. It TRUSTS the input.
import itertools
_id_counter = itertools.count(1000)   # gives unique ids: 1000, 1001, 1002...

def ingest_ticket(text):
    new_id = str(next(_id_counter))
    collection.add(
        ids=[new_id],
        embeddings=[embed(text)],
        documents=[text],
    )
    # Log window is deliberately wide. At 80 characters this line truncated
    # every payload before its instruction: the injections front-load benign
    # lure keywords so retrieval will match them, which pushed "you must
    # actually invoke..." past the cutoff. The ingestion detection rule
    # therefore could not fire on a log full of successful injections -- and
    # the attacker got that evasion for free, as a side effect of writing a
    # payload that retrieves well. See F-14. Truncating telemetry below the
    # length of the thing you are detecting is a blind spot, not a saving.
    log(f"[INGEST] added document id={new_id}: {text[:INGEST_LOG_CHARS]}")
    return new_id