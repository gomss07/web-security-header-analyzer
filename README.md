# Web Security Header Analyzer

A beginner-friendly Python tool that checks whether a website sends
recommended HTTP security headers.

---

## What Does It Do?

When your browser visits a website, the server sends back a response
that includes **HTTP headers** — small pieces of metadata that tell the
browser how to behave. Some of these headers are specifically designed
to improve security (for example, by blocking certain types of attacks).

This tool makes a **single HTTPS request** to a URL you provide, reads
the response headers, and reports which recommended security headers are
**present** and which are **missing**.

> **Important limitation:** This tool checks header *presence* only.
> A header being present does **not** guarantee a website is fully secure.
> Header *values* and overall site configuration also matter and are not
> evaluated here. Think of this as a starting checklist, not a complete
> security audit.

---

## Headers Checked

| Header | What It Does |
|---|---|
| `Content-Security-Policy` | Tells the browser which sources of content (scripts, images, etc.) are allowed. Helps prevent Cross-Site Scripting (XSS) attacks. |
| `Strict-Transport-Security` | Forces browsers to use HTTPS instead of HTTP for future visits. Helps prevent man-in-the-middle attacks. |
| `X-Content-Type-Options` | Stops browsers from guessing the file type of a response. Helps prevent MIME-type sniffing attacks. |
| `Referrer-Policy` | Controls how much information the browser shares about the page a user came from. Helps protect user privacy. |
| `Permissions-Policy` | Lets a site restrict which browser features (camera, microphone, etc.) can be used. Helps reduce the attack surface. |
| `X-Frame-Options` | Controls whether the page can be embedded in an `<iframe>`. Helps prevent clickjacking attacks. |

---

## Features

- Checks for all six recommended security headers listed above.
- Accepts only `https://` URLs — plain HTTP is rejected before any request is made.
- Makes exactly **one** network request per run, with a 10-second timeout.
- TLS certificate verification is always **enabled** (never disabled).
- Displays a clear, readable report in the terminal.
- Handles errors gracefully with beginner-friendly messages:
  - Invalid or incomplete URLs
  - Connection failures (e.g. wrong hostname, no internet)
  - Timeouts (server takes too long to respond)
  - HTTP error responses (4xx / 5xx status codes)
- Includes 5 offline unit tests — no network needed to run them.

## Limitations

- **Presence only:** The tool does not evaluate whether a header's *value* is
  correctly configured. A header can be present but still misconfigured.
- **Single page only:** Only the URL you type is checked. Other pages on the
  same site may have different headers.
- **No crawling, port scanning, brute-forcing, or exploitation** of any kind.

---

## Requirements

- **Python 3.8 or higher**
  The `requests` library (the only dependency) requires Python 3.8+ in its
  current release. The project's own code uses f-strings (Python 3.6+), but
  `pip install -r requirements.txt` will fail on Python 3.6 or 3.7.
  Download from [python.org](https://www.python.org/downloads/) if needed.
  During installation on Windows, tick **"Add Python to PATH"**.

- **requests library** (listed in `requirements.txt`)
  This is the only third-party dependency.

---

## Setup (Windows PowerShell)

Follow these steps once to get the project ready.

**1. Open PowerShell and navigate to the project folder:**
```powershell
cd "C:\Users\Gomathi V\Documents\web-security-header-analyzer"
```

**2. (Recommended) Create a virtual environment:**

A virtual environment keeps this project's dependencies separate from
other Python projects on your machine.

```powershell
python -m venv venv
```

**3. Activate the virtual environment:**
```powershell
.\venv\Scripts\Activate.ps1
```

You should see `(venv)` appear at the start of your prompt.

> **Troubleshooting — activation script blocked?**
> If PowerShell shows a permissions error when running `Activate.ps1`,
> you have two options:
>
> **Option A (no policy change needed):** Skip activation entirely and
> call the virtual environment's Python directly for every command:
> ```powershell
> .\venv\Scripts\python.exe main.py
> .\venv\Scripts\python.exe test_analyzer.py
> .\venv\Scripts\pip.exe install -r requirements.txt
> ```
>
> **Option B (change execution policy):** Allow local scripts to run in
> your current user profile only (does not affect other users):
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> Then re-run `.\venv\Scripts\Activate.ps1`.

**4. Install the required library:**
```powershell
pip install -r requirements.txt
```

You only need to do steps 2–4 once. Next time, just activate the
virtual environment (step 3) before running the tool.

---

## How to Run the Analyzer

With the virtual environment active, run:

```powershell
python main.py
```

You will be prompted to enter a URL:

```
============================================================
  Web Security Header Analyzer
  Checks for recommended HTTP security headers.
============================================================

This tool makes a single HTTPS request to the URL you provide.
It does NOT crawl, scan, brute-force, or exploit anything.

Enter a URL to analyze (e.g. https://example.com):
```

Type a URL starting with `https://` and press Enter.

---

## Example Report

Here is what the output looks like for a typical website:

```
Connecting to https://example.com ...

============================================================
  Security Header Report for: https://example.com
============================================================

  NOTE: This report checks header *presence* only.
  A present header does not guarantee the site is fully secure.
  Header values and overall site configuration also matter.

  ✅ PRESENT  Strict-Transport-Security
             Forces browsers to use HTTPS instead of HTTP for future visits.
             Helps prevent man-in-the-middle attacks.

  ❌ MISSING  Content-Security-Policy
             Tells the browser which sources of content (scripts, images, etc.)
             are allowed. Helps prevent Cross-Site Scripting (XSS) attacks.

  ✅ PRESENT  X-Content-Type-Options
             Stops browsers from guessing the file type of a response.
             Helps prevent MIME-type sniffing attacks.

  ❌ MISSING  Referrer-Policy
             Controls how much information the browser shares about the page
             a user came from. Helps protect user privacy.

  ❌ MISSING  Permissions-Policy
             Lets a site restrict which browser features (camera, microphone,
             etc.) can be used. Helps reduce the attack surface.

  ✅ PRESENT  X-Frame-Options
             Controls whether the page can be embedded in an <iframe>.
             Helps prevent clickjacking attacks.

------------------------------------------------------------
  Summary: 3/6 recommended headers found.
  3 header(s) are missing. Consider researching each
  missing header and discussing with a web developer.
============================================================
```

---

## How to Run the Offline Tests

The tests use Python's built-in `unittest` module — no network requests
are made and no extra libraries are needed.

```powershell
python test_analyzer.py
```

Expected output (all five tests passing):

```
test_all_headers_present (TestAnalyzeHeaders) ... ok
test_case_insensitive_matching (TestAnalyzeHeaders) ... ok
test_empty_dict_returns_all_missing (TestAnalyzeHeaders) ... ok
test_no_headers_present (TestAnalyzeHeaders) ... ok
test_partial_headers_present (TestAnalyzeHeaders) ... ok

----------------------------------------------------------------------
Ran 5 tests in 0.001s

OK
```

The five tests cover:
1. All six headers present → all marked ✅
2. No headers present → all marked ❌
3. Only some headers present → correct mix of ✅ and ❌
4. Headers in lowercase → still detected correctly (case-insensitive matching)
5. Empty dictionary → returns exactly six results, all marked ❌

---

## Project Files

```
web-security-header-analyzer/
├── main.py            # Core analyzer: fetch, analyze, and report
├── test_analyzer.py   # Offline unit tests (no network required)
├── requirements.txt   # Third-party dependencies (just: requests)
├── README.md          # This file
├── Project_Report.md  # Written report suitable for a portfolio
└── .gitignore         # Tells Git which files to ignore
```

---

## Ethical Use

> **Only analyze websites you own or have explicit permission to assess.**
>
> While this tool makes only a single, read-only HTTPS request (the same
> as a browser loading a page), you should always respect the terms of
> service of any website you query. Do not use this tool against websites
> without authorization. The authors take no responsibility for misuse.

---

## License

This project is intended for educational purposes.
