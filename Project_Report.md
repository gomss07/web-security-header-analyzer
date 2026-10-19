# Project Report: Web Security Header Analyzer

---

## 1. Project Title

**Web Security Header Analyzer**
A beginner-friendly command-line tool written in Python that inspects the
HTTP security headers returned by a website and reports which recommended
headers are present and which are missing.

---

## 2. Abstract

HTTP security headers are directives that a web server includes in its
responses to instruct browsers on how to behave in ways that reduce common
attack risks. Many websites omit some or all of these headers, leaving users
more vulnerable to attacks such as cross-site scripting, clickjacking, and
man-in-the-middle interception.

This project implements a lightweight Python tool that makes a single HTTPS
GET request to a user-supplied URL and checks the response headers against a
fixed list of six recommended security headers. The result is printed as a
readable terminal report indicating which headers are present and which are
missing, along with a plain-English explanation of what each header does.

The tool is intentionally narrow in scope: it checks only whether headers are
present. It does not evaluate header values, crawl multiple pages, scan ports,
brute-force credentials, or exploit any system. It is designed as an
educational starting point for learners interested in web security.

---

## 3. Problem Statement

Web developers and site administrators do not always configure HTTP security
headers, either because they are unaware of them or because they are not
surfaced clearly by standard development tools. For a learner entering the
cybersecurity field, understanding which headers exist, what they do, and how
to check for them is a foundational skill.

There is no simple, beginner-readable command-line tool in the standard Python
library that performs this check. Third-party online scanners exist but
require a browser and do not help learners understand the underlying mechanism.

This project fills that gap with a well-commented, single-file Python program
that a beginner can read, understand, and extend.

---

## 4. Objectives

1. Implement a Python tool that checks a given HTTPS URL for six recommended
   HTTP security headers.
2. Report each header as present or missing with a plain-English description
   of its security purpose.
3. Handle errors gracefully (invalid URLs, connection failures, timeouts, and
   HTTP error codes) with clear, beginner-friendly messages.
4. Accept only HTTPS URLs and keep TLS certificate verification enabled at all
   times.
5. Make exactly one network request per run with a 10-second timeout.
6. Include a suite of offline unit tests that verify the core logic without
   making any network calls.
7. Keep the codebase readable and thoroughly commented so it can serve as a
   learning resource.

---

## 5. Tools and Technologies Used

| Tool / Technology | Purpose |
|---|---|
| Python 3.8+ | Primary programming language |
| `requests` library | Making the HTTPS GET request and reading response headers |
| `unittest` (standard library) | Writing and running offline unit tests |
| `pip` | Installing the `requests` dependency |
| Git / `.gitignore` | Version control and keeping the repository clean |

**Why `requests`?**
Python's built-in `urllib` can make HTTP requests, but `requests` provides a
cleaner API, a more informative exception hierarchy, and returns headers as a
case-insensitive dictionary — which simplifies the comparison logic. It is also
the most widely recommended HTTP library for beginners.

---

## 6. Methodology and Program Workflow

The program follows a straightforward three-stage pipeline:

```
User enters URL
      │
      ▼
fetch_headers(url)
  • Reject non-HTTPS URLs immediately
  • Send one HTTPS GET request (timeout=10s, verify=True)
  • Return response headers on success, or None on any error
      │
      ▼
analyze_headers(headers)
  • Normalise all header names to lowercase (case-insensitive comparison)
  • For each of the six expected headers, record present=True or False
  • Return a list of result dictionaries
      │
      ▼
print_report(url, results)
  • Print a bordered terminal report
  • Show ✅ PRESENT or ❌ MISSING for each header with its description
  • Print a summary count and a disclaimer that presence ≠ full security
```

**Key implementation decisions:**

- **HTTPS-only enforcement:** The `fetch_headers` function checks that the URL
  starts with `https://` before making any network call. Plain HTTP is rejected
  upfront with an explanatory error message.

- **TLS verification always on:** `requests.get()` is called with `verify=True`
  (the default). Disabling certificate verification (`verify=False`) is never
  done, as it would undermine the security of the connection itself.

- **10-second timeout:** A `timeout=10` argument is passed to every request.
  Without a timeout, a slow or unresponsive server could cause the program to
  hang indefinitely.

- **Case-insensitive header matching:** HTTP headers are case-insensitive by
  specification (RFC 7230). Both the received headers and the expected header
  names are lowercased before comparison, ensuring that `content-security-policy`
  and `Content-Security-Policy` are treated as identical.

- **Single network request:** The tool makes exactly one GET request per run.
  It does not follow links, crawl pages, or make additional requests.

- **`if __name__ == "__main__"` guard:** This standard Python pattern ensures
  the interactive prompt in `main()` does not fire when `main.py` is imported
  by the test file.

---

## 7. Explanation of the Six HTTP Security Headers Checked

### 7.1 Content-Security-Policy (CSP)
Instructs the browser to allow only content (scripts, images, stylesheets,
fonts, etc.) from sources that the site explicitly approves. This significantly
reduces the risk of **Cross-Site Scripting (XSS)** attacks, in which an
attacker injects malicious scripts into a page viewed by other users.

### 7.2 Strict-Transport-Security (HSTS)
Tells browsers that the site must only be accessed over HTTPS, and to
automatically upgrade any future HTTP requests to HTTPS for a specified period.
This helps prevent **man-in-the-middle (MITM) attacks** that exploit
unencrypted connections.

### 7.3 X-Content-Type-Options
When set to `nosniff`, this header instructs the browser not to try to guess
(or "sniff") the MIME type of a response and to use only the declared
`Content-Type`. This prevents **MIME-type sniffing attacks**, in which a
browser misinterprets a file as executable code.

### 7.4 Referrer-Policy
Controls how much information about the originating page URL the browser
includes in the `Referer` header when a user navigates away from the site.
Stricter policies protect user privacy and prevent leaking sensitive URL
parameters to third-party sites.

### 7.5 Permissions-Policy
Allows a site to declare which browser APIs and hardware features (such as
camera, microphone, geolocation, and payment) may be used in the page. By
disabling features the site does not need, the **attack surface** is reduced
if the page is ever compromised.

### 7.6 X-Frame-Options
Controls whether the page may be embedded inside an `<iframe>` on another
site. Setting this to `DENY` or `SAMEORIGIN` prevents **clickjacking attacks**,
in which an attacker tricks a user into clicking on hidden content by overlaying
a transparent iframe.

---

## 8. Implementation Overview

The project consists of the following files:

| File | Description |
|---|---|
| `main.py` | Core program: `SECURITY_HEADERS` dictionary, `analyze_headers()`, `fetch_headers()`, `print_report()`, and `main()` |
| `test_analyzer.py` | Five offline unit tests using Python's `unittest` module |
| `requirements.txt` | Single dependency: `requests` (no version pin) |
| `README.md` | Setup instructions, usage guide, and example output |
| `Project_Report.md` | This document |
| `.gitignore` | Excludes `__pycache__/`, `*.pyc`, `.env`, and `venv/` from version control |

### Core functions in `main.py`

**`analyze_headers(headers)`**
Accepts a dictionary of HTTP response headers. Builds a set of all received
header names lowercased, then iterates over `SECURITY_HEADERS` and checks
membership. Returns a list of dictionaries — one per expected header — each
containing the header name, a `present` boolean, and a description string.

**`fetch_headers(url)`**
Validates that the URL begins with `https://`, then calls
`requests.get(url, timeout=10, verify=True)`. Calls `response.raise_for_status()`
to surface HTTP error codes as exceptions. Catches five specific exception
types (`MissingSchema`, `InvalidURL`, `ConnectionError`, `Timeout`,
`HTTPError`) and prints a tailored error message for each. Returns the response
headers on success, or `None` on any failure.

**`print_report(url, results)`**
Formats and prints the analysis results to the terminal. Displays a disclaimer
reminding the user that header presence alone does not prove a site is secure.
Counts present headers and prints a final summary.

**`main()`**
Entry point. Displays a welcome banner that explicitly states the tool does not
crawl, scan, brute-force, or exploit anything. Prompts the user for a URL,
calls `fetch_headers`, checks for `None`, then calls `analyze_headers` and
`print_report`.

---

## 9. Testing Methodology and Results

### Approach
Testing is performed entirely offline using Python's built-in `unittest`
module. No network requests are made during any test. The tests import
`analyze_headers` and `SECURITY_HEADERS` directly from `main.py`; the
`if __name__ == "__main__"` guard in `main.py` prevents the interactive prompt
from activating during import.

Synthetic (hand-crafted) header dictionaries are passed directly to
`analyze_headers()`, and the returned results are checked with `unittest`
assertions. This approach tests the core analysis logic in complete isolation
from network conditions.

### Test Cases

| Test name | Input | What is asserted |
|---|---|---|
| `test_all_headers_present` | All six expected headers present | All six results have `present=True`; result count equals 6 |
| `test_no_headers_present` | Empty dictionary `{}` | All six results have `present=False`; result count equals 6 |
| `test_partial_headers_present` | First three headers present, last three absent | Correct `True`/`False` assignment for each header individually |
| `test_case_insensitive_matching` | All six headers sent in lowercase | All six results have `present=True` (case-insensitive match confirmed) |
| `test_empty_dict_returns_all_missing` | Empty dictionary `{}` | Result list length equals exactly 6; all have `present=False` |

### Test Status
All five offline unit tests passed in the latest run. The test suite was
executed with `python test_analyzer.py` and produced the following result:
`Ran 5 tests` with a final status of `OK`. No network requests were made
during the test run.

---

## 10. Limitations

1. **Presence only, not values.** The tool records whether each header exists
   in the response, but does not parse or validate the header's value. For
   example, a `Content-Security-Policy: *` header (which allows all sources)
   would be marked ✅ PRESENT even though its value offers no real protection.

2. **Single URL, single request.** Only the URL entered by the user is checked.
   Other pages on the same site, or API endpoints served by the same server,
   may return different headers. The tool makes no additional requests.

3. **No value-level guidance.** The report describes what each header does in
   general terms but does not advise on correct or recommended header values.

4. **No crawling, port scanning, brute-forcing, or exploitation.** These
   activities are entirely outside the scope of this tool and are not
   implemented.

5. **No pinned dependency version.** `requirements.txt` specifies `requests`
   without a version constraint. A future breaking release of `requests` could
   affect the tool. Pinning to a specific version (e.g. `requests==2.32.3`)
   would improve reproducibility.

6. **HTTP-only URLs rejected.** The tool does not attempt to follow an HTTP URL
   to its HTTPS equivalent. The user must supply a correctly formatted
   `https://` URL.

---

## 11. Ethical Considerations and Safe Use

This tool makes a single, read-only HTTPS GET request — the same type of
request a web browser makes when loading a page. No data is written to the
target server, no credentials are submitted, and no vulnerabilities are probed
or exploited.

Nevertheless, the following principles must be observed:

- **Only analyze websites you own or have explicit written permission to
  assess.** Even passive requests can be logged by the target server. Without
  authorization, you may violate the website's terms of service or applicable
  computer misuse laws in your jurisdiction.

- **Do not use this tool as part of a broader unauthorized assessment.** It is
  intended as a standalone educational exercise, not as a reconnaissance step
  in a larger attack chain.

- **Understand what the results mean before sharing them.** A missing header
  does not necessarily mean a site is vulnerable in practice. Context,
  compensating controls, and server configuration all matter.

---

## 12. Conclusion

This project successfully implements a beginner-friendly Python tool that
checks a website's HTTP response headers against a curated list of six
recommended security headers. The implementation demonstrates several
foundational programming and cybersecurity concepts:

- Making HTTPS requests in Python using the `requests` library.
- Defensive input validation (HTTPS-only enforcement, error handling).
- Case-insensitive string comparison as required by the HTTP specification.
- Structured data representation using Python dictionaries and lists.
- Offline unit testing with Python's built-in `unittest` module.
- Clear separation of concerns across well-named functions.
- Ethical framing: the tool is read-only, narrow in scope, and transparent
  about what it does and does not measure.

The project also demonstrates the importance of distinguishing what a security
tool *can* measure (header presence) from what it *cannot* conclude (overall
site security). This distinction is a recurring theme in cybersecurity
practice.

---

## 13. Future Improvements

The following enhancements are proposed but not yet implemented:

1. **Header value analysis.** Beyond checking presence, validate common header
   values. For example, confirm that `X-Content-Type-Options` is set to
   `nosniff`, that `Strict-Transport-Security` includes `max-age` and ideally
   `includeSubDomains`, and that `Content-Security-Policy` is not a wildcard
   (`*`).

2. **Pinned dependency versions.** Add a version constraint to
   `requirements.txt` (e.g. `requests>=2.32.0,<3.0`) to ensure reproducible
   installs across different environments.

3. **JSON or CSV output.** Add an optional `--output` flag so results can be
   saved to a file for further processing or record-keeping.

4. **Multiple URL support.** Accept a list of URLs (from a file or
   command-line arguments) and produce a consolidated report, without
   crawling or following links.

5. **Severity ratings.** Assign a severity level (e.g. High / Medium / Low) to
   each missing header based on its relative importance, to help prioritise
   remediation.

6. **Redirect following with control.** Optionally follow a single HTTP-to-HTTPS
   redirect to make the tool more convenient, while still enforcing that the
   final request is HTTPS.

7. **Command-line argument support.** Use Python's `argparse` module to accept
   the URL as a command-line argument (e.g. `python main.py https://example.com`)
   rather than requiring interactive input, making the tool easier to script.
