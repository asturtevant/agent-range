"""Tests for the evidence redactor.

An earlier version of this redactor built a regex with one optional group per
letter of the account name. Every group being optional meant the whole pattern
could match the EMPTY STRING, so it matched at every word boundary and inserted
the placeholder throughout the file, corrupting captured evidence before it
hung on backtracking. These tests exist because that failure is silent: the
output still looks like a log until you read it closely.

The fixture name below is synthetic on purpose. An earlier version used the
real host account, which meant the tests for the redaction tool contained
exactly the string the tool exists to remove, in a file that gets published.

Run:  python -m unittest harness.test_redact
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from redact import redact_name, has_name, PLACEHOLDER, PLACEHOLDER_TITLE

NAME = "gwendolynfairfax"


class TestRedact(unittest.TestCase):

    def test_exact_name_replaced(self):
        self.assertEqual(redact_name("[TOOL RESULT] gwendolynfairfax", NAME),
                         f"[TOOL RESULT] {PLACEHOLDER}")

    def test_mangled_variants_replaced(self):
        # Shapes of mangling llama3.1 actually produced for a real account
        # name: a space inserted mid-token, a dropped letter, and a
        # capitalised run-on. Reproduced here against the synthetic fixture.
        for variant in ("Gwendoly Nfairfax", "gwendolynfairfx",
                        "GwendolynFairfax", "Gwendolyn Fairfax"):
            with self.subTest(variant=variant):
                out = redact_name(f"the user is {variant}.", NAME)
                self.assertNotIn(variant, out)
                self.assertIn(PLACEHOLDER.lower(), out.lower())

    def test_title_case_preserved(self):
        """F-06 depends on a lowercase token becoming a spaced proper noun."""
        self.assertIn(PLACEHOLDER_TITLE, redact_name("Gwendoly Nfairfax", NAME))
        self.assertIn(PLACEHOLDER, redact_name("gwendolynfairfax", NAME))

    def test_does_not_touch_unrelated_text(self):
        """The regression that corrupted the evidence: matching everywhere."""
        samples = [
            '[TOOL EXECUTED] http_get(http://127.0.0.1:11434/api/tags)',
            '"successes": 2, "attempts": 3',
            '[TOOL EXECUTED] read_file(../../../../etc/passwd)',
            'The quick brown fox jumps over the lazy dog.',
            '{"mode": "vulnerable", "result": "success"}',
            '[RAG SEARCH] query=\'login problems\'',
        ]
        for s in samples:
            with self.subTest(sample=s):
                self.assertEqual(redact_name(s, NAME), s)

    def test_no_empty_string_matches(self):
        """A pattern able to match '' inserts the placeholder everywhere."""
        text = "abc def ghi" * 50
        self.assertEqual(redact_name(text, NAME), text)

    def test_idempotent(self):
        """Re-running must not re-redact its own output."""
        once = redact_name("user gwendolynfairfax here", NAME)
        self.assertEqual(redact_name(once, NAME), once)

    def test_short_unrelated_names_not_matched(self):
        self.assertEqual(redact_name("alice bob carol", NAME), "alice bob carol")

    def test_has_name_detects_and_clears(self):
        self.assertTrue(has_name("run by gwendolynfairfax", NAME))
        self.assertFalse(has_name("run by hostuser", NAME))

    def test_completes_promptly_on_large_input(self):
        """Guards the backtracking hang: 200k chars must not take seconds."""
        import time
        text = ("[TOOL EXECUTED] run_command(whoami)\n"
                "[TOOL RESULT]  gwendolynfairfax\n") * 4000
        start = time.time()
        out = redact_name(text, NAME)
        self.assertLess(time.time() - start, 10.0)
        self.assertNotIn(NAME, out)


if __name__ == "__main__":
    unittest.main()
