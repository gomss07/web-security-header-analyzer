"""
Web Security Header Analyzer
=============================
A beginner-friendly tool that checks whether a website sends
recommended HTTP security headers.

IMPORTANT DISCLAIMER:
    This tool checks only whether certain headers are *present*.
    A header being present does NOT guarantee a website is fully secure.
    Header *values* also matter and are not evaluated here.
    This tool does NOT crawl, scan ports, brute-force, or exploit anything.

Usage:
    Run this file directly:  python main.py
    Then type a URL when prompted (must start with https://).
"""

import requests  # Third-party library for making HTTP requests (install via requirements.txt)


# ---------------------------------------------------------------------------
# 1. The six security headers we check
# ---------------------------------------------------------------------------
# Each entry maps a header name to a plain-English explanation of what it does.
# This dictionary is the single source of truth — add or remove headers here.

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Tells the browser which sources of content (scripts, images, etc.) "
        "are allowed. Helps prevent Cross-Site Scripting (XSS) attacks."
    ),
    "Strict-Transport-Security": (
        "Forces browsers to use HTTPS instead of HTTP for future visits. "
        "Helps prevent man-in-the-middle attacks."
    ),
    "X-Content-Type-Options": (
        "Stops browsers from guessing the file type of a response. "
        "Helps prevent MIME-type sniffing attacks."
    ),
    "Referrer-Policy": (
        "Controls how much information the browser shares about the page "
        "a user came from. Helps protect user privacy."
    ),
    "Permissions-Policy": (
        "Lets a site restrict which browser features (camera, microphone, etc.) "
        "can be used. Helps reduce the attack surface."
    ),
    "X-Frame-Options": (
        "Controls whether the page can be embedded in an <iframe>. "
        "Helps prevent clickjacking attacks."
    ),
}


# ---------------------------------------------------------------------------
# 2. Analyze headers
# ---------------------------------------------------------------------------

def analyze_headers(headers):
    """
    Compare a response's headers against the list of recommended security headers.

    HTTP header names are case-insensitive (RFC 7230), so 'content-security-policy'
    and 'Content-Security-Policy' are the same thing. We normalize both sides to
    lowercase before comparing to handle any capitalization variation.

    Args:
        headers (dict): The HTTP response headers returned by the requests library.

    Returns:
        list of dict: One entry per expected header, each with:
            - "name"    : the header name (original casing from SECURITY_HEADERS)
            - "present" : True if the server sent this header, False otherwise
            - "description": plain-English explanation of what the header does
    """
    # Build a set of header names the server actually sent, all lowercased.
    # Sets allow fast O(1) membership checks.
    received = {key.lower() for key in headers}

    results = []
    for name, description in SECURITY_HEADERS.items():
        results.append({
            "name": name,
            "present": name.lower() in received,  # case-insensitive check
            "description": description,
        })
    return results


# ---------------------------------------------------------------------------
# 3. Fetch headers from a live URL
# ---------------------------------------------------------------------------

def fetch_headers(url):
    """
    Send a single HTTPS GET request and return the response headers.

    Security notes:
        - verify=True  : TLS certificates ARE verified (the safe default).
        - timeout=10   : We wait at most 10 seconds to avoid hanging forever.
        - Only HTTPS URLs are accepted; HTTP is rejected before any request is made.

    Args:
        url (str): The URL to inspect. Must begin with 'https://'.

    Returns:
        dict | None: Response headers on success, or None if anything goes wrong.
                     Error messages are printed directly here so callers stay simple.
    """
    # Guard: only allow HTTPS — plain HTTP sends data in the clear
    if not url.startswith("https://"):
        print("\n[ERROR] Only HTTPS URLs are supported.")
        print("        Please use a URL that starts with 'https://'.")
        print("        Example: https://example.com")
        return None

    print(f"\nConnecting to {url} ...")

    try:
        # Make a single GET request.
        # stream=False (default) means we download the full response body,
        # but we only actually need the headers — this is fine for our purpose.
        response = requests.get(url, timeout=10, verify=True)

        # raise_for_status() turns HTTP error codes (4xx, 5xx) into exceptions
        # so we can handle them in the except block below.
        response.raise_for_status()

        return response.headers  # a case-insensitive dict-like object

    except requests.exceptions.MissingSchema:
        # Raised when the URL has no scheme, e.g. the user typed "example.com"
        print("\n[ERROR] The URL looks incomplete.")
        print("        Make sure it starts with 'https://', e.g. https://example.com")
    except requests.exceptions.InvalidURL:
        # Raised when the URL is structurally invalid
        print("\n[ERROR] The URL you entered is not valid.")
        print("        Please check for typos and try again.")
    except requests.exceptions.ConnectionError:
        # Raised when the network is unreachable or the hostname does not exist
        print("\n[ERROR] Could not connect to the website.")
        print("        Check that the URL is correct and that you are online.")
    except requests.exceptions.Timeout:
        # Raised when the server does not respond within 10 seconds
        print("\n[ERROR] The request timed out after 10 seconds.")
        print("        The website may be slow or unreachable right now.")
    except requests.exceptions.HTTPError as e:
        # Raised by raise_for_status() for 4xx/5xx responses
        print(f"\n[ERROR] The server returned an error: {e}")
        print("        The website is reachable but returned an HTTP error code.")

    return None  # something went wrong — caller checks for None


# ---------------------------------------------------------------------------
# 4. Print a readable report
# ---------------------------------------------------------------------------

def print_report(url, results):
    """
    Print the analysis results to the terminal in a clear, readable format.

    Args:
        url     (str) : The URL that was analyzed.
        results (list): The list of dicts returned by analyze_headers().
    """
    print("\n" + "=" * 60)
    print(f"  Security Header Report for: {url}")
    print("=" * 60)

    # Reminder that presence ≠ full security
    print(
        "\n  NOTE: This report checks header *presence* only.\n"
        "  A present header does not guarantee the site is fully secure.\n"
        "  Header values and overall site configuration also matter.\n"
    )

    present_count = 0

    for item in results:
        status = "✅ PRESENT" if item["present"] else "❌ MISSING"
        if item["present"]:
            present_count += 1
        print(f"  {status}  {item['name']}")
        print(f"           {item['description']}\n")

    total = len(results)
    missing_count = total - present_count

    print("-" * 60)
    print(f"  Summary: {present_count}/{total} recommended headers found.")
    if missing_count > 0:
        print(
            f"  {missing_count} header(s) are missing. Consider researching each\n"
            "  missing header and discussing with a web developer."
        )
    else:
        print("  All recommended headers are present. Good start!")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# 5. Main entry point
# ---------------------------------------------------------------------------

def main():
    """
    Ask the user for a URL, fetch its headers, analyze them, and print the report.
    This is the function that runs when you execute:  python main.py
    """
    print("=" * 60)
    print("  Web Security Header Analyzer")
    print("  Checks for recommended HTTP security headers.")
    print("=" * 60)
    print("\nThis tool makes a single HTTPS request to the URL you provide.")
    print("It does NOT crawl, scan, brute-force, or exploit anything.\n")

    url = input("Enter a URL to analyze (e.g. https://example.com): ").strip()

    headers = fetch_headers(url)

    if headers is None:
        # fetch_headers already printed an error message — nothing more to do
        return

    results = analyze_headers(headers)
    print_report(url, results)


# ---------------------------------------------------------------------------
# Standard Python idiom: only run main() when this file is executed directly.
# If another file imports main.py (e.g. test_analyzer.py), main() won't run.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
