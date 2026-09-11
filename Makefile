# Agentic Attack Range — verification entry points.
#
#   make check     fast, offline. No model, no network. What CI runs.
#   make assess    the full scored assessment. Needs Ollama; takes ~20 minutes.
#   make verify    check + assess + re-verify the claims against the new results.
#
# The split matters. `check` guards everything that can be checked without an
# LLM in the loop — redaction, detection rules, and whether the documentation
# still matches the committed evidence. Those are exactly the things that rot
# quietly between runs, so they belong in CI where nobody has to remember them.

PY := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
REPEAT ?= 3
RESULTS := evidence/harness-results.json

.PHONY: help check test rules claims assess detect verify redact clean-evidence

help:
	@echo "make check    fast offline gate: tests, rules, claims (what CI runs)"
	@echo "make assess   full harness run, both builds, REPEAT=$(REPEAT) (needs Ollama)"
	@echo "make verify   check, then assess, then re-verify claims against results"
	@echo "make detect   replay committed evidence logs through the Sigma rules"
	@echo "make redact   strip host identifiers from evidence before committing"

check: test rules claims
	@echo ""
	@echo "  offline gate passed"

test:
	@echo "== unit tests =="
	$(PY) -m unittest harness.test_redact detection.test_sigma_eval -v

rules:
	@echo "== detection rules execute against committed evidence =="
	@$(PY) detection/sigma_eval.py evidence/*.log

claims:
	@echo "== documented claims match committed evidence =="
	@$(PY) harness/verify_claims.py

redact:
	@echo "== redaction =="
	$(PY) harness/redact.py
	$(PY) harness/redact.py --check

# The real thing. Not in CI: it needs a local model, and a GitHub runner has
# neither the GPU nor the patience.
assess:
	@echo "== full assessment, both builds, repeat=$(REPEAT) =="
	$(PY) harness/run.py --mode both --repeat $(REPEAT) --detect --json $(RESULTS)

detect:
	@$(PY) detection/sigma_eval.py evidence/*.log

# assess writes new results, so the claims are re-checked against them
# afterwards rather than before. Running claims first would only confirm that
# the OLD numbers were consistent, which is not the question.
verify: check assess redact claims
	@echo ""
	@echo "  full verification passed: the documented claims match a fresh run."

clean-evidence:
	@echo "This deletes captured evidence logs. Ctrl-C to abort."
	@sleep 3
	rm -f evidence/harness-*.log
