from re import compile, escape, IGNORECASE
from requests import Session, Timeout, ConnectionError, RequestException
from urllib.parse import urljoin, urlparse

COMMON_PATHS = [
    "/mailman/listinfo",
    "/cgi-bin/mailman/listinfo",
    "/cgi-bin/mailman/admin",
    "/cgi-bin/mailman/private",
    "/cgi-bin/mailman/confirm",
    "/cgi-bin/mailman/options",
    "/cgi-bin/mailman/roster",
    "/mailman/admin",
    "/mailman/private",
    "/mailman/confirm",
    "/mailman/options",
    "/mailman/roster",
    "/mailman3/lists/",
    "/mailman3/postorius/lists/",
    "/mailman3/hyperkitty/",
    "/hyperkitty/",
    "/archives/",
    "/archives/private/",
    "/archives/public/",
    "/pipermail/",
    "/lists/",
    "/listinfo",
    "/admin",
    "/mailman",
    "/mailman3",
    "/mm3",
    "/cgi-bin/mailman",
    "/cgi-bin/mailman3",
    "/mailman/listinfo/mailman",
    "/cgi-bin/mailman/listinfo/mailman",
]

FINGERPRINTS = [
    "GNU Mailman",
    "Mailman mailing list overview",
    "List Administrator Interface",
    "overview of mailing lists",
    "The list overview page has been disabled",
    "This page contains a summary of all Mailman mailing lists",
    "Mailman CGI error",
    "List Configuration",
    "General list information page",
    "If you are having trouble using the lists",
    "Editing the public HTML pages",
    "Configuration Categories",
    "Subscription rules",
    "Privacy options",
    "Digest options",
    "Archiving Options",
    "Bounce Processing",
    "Filtering Rules",
    "Membership Management",
    "Tend to pending moderator requests",
    "The Mailman administrator interface",
    "Enter your address and password",
    "Held Messages",
    "Moderator bit",
    "Postorius",
    "HyperKitty",
    "powered by mailman",
    "Powered by GNU Mailman",
    "This site is powered by GNU Mailman",
    "version",
    "Mailman version",
    "mailman3",
]

# Compile combined regex for better performance
COMBINED_FINGERPRINTS_REGEX = compile(
    "|".join(map(escape, FINGERPRINTS)),
    flags=IGNORECASE
)

def is_valid_url(url: str) -> bool:
    """Validate URL scheme and netloc."""
    parsed = urlparse(url)
    return all([parsed.scheme in ("http", "https"), parsed.netloc])

def detect_mailman(base_url: str, timeout: int = 5) -> dict:
    """Detect Mailman installation on target base URL."""
    base_url = base_url.rstrip("/")  # Clean trailing slash

    if not is_valid_url(base_url):
        return {
            "found": False,
            "error": "Invalid URL format. Must include scheme (http or https) and domain."
        }

    session = Session()
    session.headers.update({"User-Agent": "MailmapScanner/1.0"})

    for path in COMMON_PATHS:
        full_url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            response = session.get(full_url, timeout=timeout)
            if not response.ok:
                continue

            response.raise_for_status()

            content = response.text[:100_000]  # Limit content size to 100KB

            match = COMBINED_FINGERPRINTS_REGEX.search(content)
            if match:
                return {
                    "found": True,
                    "url": full_url,
                    "status_code": response.status_code,
                    "evidence": match.group(),
                }

        except (Timeout, ConnectionError, RequestException):
            continue

    return {
        "found": False,
        "reason": "No known Mailman path responded with recognizable content."
    }

if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    result = detect_mailman(target)
    print(result)
