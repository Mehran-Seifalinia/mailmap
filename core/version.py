from re import compile, search, IGNORECASE
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep

VERSION_PATHS = [
    "/mailman/admin",
    "/mailman/admin/info",
    "/mailman/admin/config",
    "/mailman",
    "/mailman3",
    "/mailman3/admin",
    "/cgi-bin/mailman/admin",
    "/cgi-bin/mailman3/admin",
    "/pipermail/",
    "/mailman/listinfo",
    "/cgi-bin/mailman/listinfo",
    "/mailman/private",
    "/mailman3/postorius",
    "/mailman3/hyperkitty",
]

VERSION_PATTERNS = [
    r"Mailman\s+version\s*[:\-]?\s*([\d\.]+)",
    r"GNU Mailman\s*version\s*[:\-]?\s*([\d\.]+)",
    r"Mailman\s*([\d\.]+)",
    r"version\s*[:\-]?\s*([\d]+\.[\d]+\.[\d]+)",
    r"version\s*[:\-]?\s*([\d]+\.[\d]+)",
]

COMPILED_VERSION_PATTERNS = [compile(pattern, flags=IGNORECASE) for pattern in VERSION_PATTERNS]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
]

REQUEST_DELAY = 1  # seconds delay between requests to avoid rate limiting

def is_valid_url(url: str) -> bool:
    """Validate the URL format."""
    parsed = urlparse(url)
    return all([parsed.scheme in ("http", "https"), parsed.netloc])

def extract_version_from_text(text: str):
    """Extract version string from text using predefined regex patterns."""
    for pattern in COMPILED_VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return None

def detect_version(base_url: str, timeout: int = 5):
    """Detect Mailman version by checking multiple paths and extracting version info."""
    base_url = base_url.rstrip("/")

    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must include scheme (http or https) and domain."}

    session = Session()
    found_versions = set()
    user_agent_index = 0

    for path in VERSION_PATHS:
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            # Rotate User-Agent to reduce blocking risk
            session.headers.update({"User-Agent": USER_AGENTS[user_agent_index % len(USER_AGENTS)]})
            user_agent_index += 1

            response = session.get(full_url, timeout=timeout)
            # Check content type to avoid processing binaries
            content_type = response.headers.get("Content-Type", "").lower()
            if "text" not in content_type:
                continue
            if not response.ok:
                continue
            response.raise_for_status()

            # Check headers for version info
            for header_value in response.headers.values():
                version = extract_version_from_text(header_value)
                if version:
                    found_versions.add(version)

            # Check page content, limit size to 100KB
            content = response.text[:100_000]
            version = extract_version_from_text(content)
            if version:
                found_versions.add(version)

        except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError):
            # Ignore errors and continue scanning other paths
            pass

        sleep(REQUEST_DELAY)  # delay to avoid rate limiting

    if not found_versions:
        return {"version": None}

    if len(found_versions) == 1:
        return {"version": found_versions.pop()}

    # Multiple different versions found - conflict
    return {"conflict": True, "versions": list(found_versions)}

if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    result = detect_version(target)
    if "conflict" in result and result["conflict"]:
        print("Version conflict detected! Found versions:", ", ".join(result["versions"]))
    elif result.get("version"):
        print("Detected Mailman version:", result["version"])
    else:
        print("No Mailman version detected.")
