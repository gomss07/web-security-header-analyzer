"""
test_analyzer.py
================
Offline unit tests for the Web Security Header Analyzer.

These tests use Python's built-in 'unittest' module — no third-party
libraries needed, and NO network requests are ever made here.

We test the analyze_headers() function by feeding it hand-crafted
(synthetic) header dictionaries and checking the results.

How to run these tests (once you have approved):
    python test_analyzer.py
"""

import unittest

# Import the function and the header list from main.py.
# Because main.py has the `if __name__ == "__main__"` guard at the bottom,
# importing it here will NOT launch the interactive prompt — it just loads
# the functions and data we need.
from main import analyze_headers, SECURITY_HEADERS


class TestAnalyzeHeaders(unittest.TestCase):
    """
    A test class groups related tests together.
    Each method whose name starts with 'test_' is run automatically
    by unittest when you execute this file.
    """

    # ------------------------------------------------------------------
    # Helper: build a dict with ALL six expected headers present.
    # We use the exact names from SECURITY_HEADERS so the test stays in
    # sync even if the header list is updated in the future.
    # ------------------------------------------------------------------
    ALL_HEADERS_PRESENT = {name: "some-value" for name in SECURITY_HEADERS}

    def test_all_headers_present(self):
        """
        Test 1: When all six recommended headers are in the response,
        every result should be marked present=True.

        Why this matters: verifies the happy-path — a well-configured
        server should pass all six checks.
        """
        results = analyze_headers(self.ALL_HEADERS_PRESENT)

        # There should be exactly one result per expected header
        self.assertEqual(len(results), len(SECURITY_HEADERS))

        # Every single result must have present=True
        for item in results:
            self.assertTrue(
                item["present"],
                msg=f"Expected '{item['name']}' to be present but it was marked missing."
            )

    def test_no_headers_present(self):
        """
        Test 2: When the server sends NO security headers at all,
        every result should be marked present=False.

        Why this matters: verifies the tool correctly flags a completely
        unprotected response — the most important failure case.
        """
        results = analyze_headers({})  # empty dict = no headers

        # There should still be one result per expected header
        self.assertEqual(len(results), len(SECURITY_HEADERS))

        # Every single result must have present=False
        for item in results:
            self.assertFalse(
                item["present"],
                msg=f"Expected '{item['name']}' to be missing but it was marked present."
            )

    def test_partial_headers_present(self):
        """
        Test 3: When only some headers are present, the tool should
        correctly identify which are present and which are missing.

        Why this matters: most real-world servers send some but not all
        recommended headers — this is the most common scenario.
        """
        # Provide only the first three headers from SECURITY_HEADERS
        header_names = list(SECURITY_HEADERS.keys())
        present_set = set(header_names[:3])   # first 3 → should be present
        missing_set = set(header_names[3:])   # last 3  → should be missing

        partial_headers = {name: "some-value" for name in present_set}
        results = analyze_headers(partial_headers)

        for item in results:
            if item["name"] in present_set:
                self.assertTrue(
                    item["present"],
                    msg=f"'{item['name']}' should be present but was marked missing."
                )
            else:
                self.assertFalse(
                    item["present"],
                    msg=f"'{item['name']}' should be missing but was marked present."
                )

    def test_case_insensitive_matching(self):
        """
        Test 4: Header names in HTTP responses can arrive in any capitalisation.
        For example, 'content-security-policy' and 'CONTENT-SECURITY-POLICY'
        are both valid ways to send the same header (RFC 7230).

        The analyzer must treat them all as equal — this test verifies that.
        """
        # Send all six headers in ALL LOWERCASE
        lowercase_headers = {name.lower(): "some-value" for name in SECURITY_HEADERS}
        results = analyze_headers(lowercase_headers)

        for item in results:
            self.assertTrue(
                item["present"],
                msg=(
                    f"'{item['name']}' should match its lowercase version "
                    f"but was marked missing."
                )
            )

    def test_empty_dict_returns_all_missing(self):
        """
        Test 5: Explicitly confirm that an empty dictionary produces
        exactly six results and all are marked missing.

        Why this matters: ensures the function always returns a complete
        result list regardless of input — no silent omissions.
        """
        results = analyze_headers({})

        # Must return one entry for every header we check
        self.assertEqual(
            len(results),
            len(SECURITY_HEADERS),
            msg=(
                f"Expected {len(SECURITY_HEADERS)} results for an empty dict "
                f"but got {len(results)}."
            )
        )

        # All must be missing
        for item in results:
            self.assertFalse(
                item["present"],
                msg=f"'{item['name']}' should be missing for an empty dict."
            )


# ---------------------------------------------------------------------------
# Run all tests when this file is executed directly:  python test_analyzer.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # verbosity=2 prints each test name and its result (PASS / FAIL)
    # instead of just a summary dot, which is more readable for beginners.
    unittest.main(verbosity=2)
