from re import compile, IGNORECASE
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from logging import getLogger, basicConfig, INFO, DEBUG
import argparse

logger = getLogger(__name__)

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

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
]

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

def detect_version(base_url: str, settings: dict):
    """Detect Mailman version by checking multiple paths and extracting version info.

    Args:
        base_url (str): Target base URL.
        settings (dict): Scanner settings including timeout, proxy, user_agent, delay.

    Returns:
        dict: Contains 'version' key or 'conflict' with versions or 'error'.
    """
    base_url = base_url.rstrip("/")

    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must include scheme (http or https) and domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agents = [settings.get("user_agent")] if settings.get("user_agent") else DEFAULT_USER_AGENTS
    delay = settings.get("delay", 1)

    session = Session()

    if proxy:
        session.proxies.update({
            "http": proxy,
            "https": proxy,
        })

    found_versions = set()
    user_agent_index = 0

    for path in VERSION_PATHS:
        full_url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            session.headers.update({"User-Agent": user_agents[user_agent_index % len(user_agents)]})
            user_agent_index += 1

            response = session.get(full_url, timeout=timeout)
            content_type = response.headers.get("Content-Type", "").lower()

            if "text" not in content_type:
                logger.debug(f"Skipped non-text content at {full_url}")
                continue

            if not response.ok:
                logger.debug(f"Non-OK response ({response.status_code}) at {full_url}")
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

        except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError) as e:
            logger.debug(f"Request error at {full_url}: {e}")

        sleep(delay)

    if not found_versions:
        return {"version": None}

    if len(found_versions) == 1:
        return {"version": found_versions.pop()}

    return {"conflict": True, "versions": list(found_versions)}

def get_version(base_url: str, settings: dict):
    """Wrapper function to keep compatibility with mailmap.py."""
    return detect_version(base_url, settings)

if __name__ == "__main__":
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(description="Mailman Version Detector")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP request timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", help="Custom User-Agent header")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests in seconds")

    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "delay": args.delay,
    }

    result = get_version(args.target, settings)

    if "conflict" in result and result["conflict"]:
        print("Version conflict detected! Found versions:", ", ".join(result["versions"]))
    elif result.get("version"):
        print("Detected Mailman version:", result["version"])
    else:
        print("No Mailman version detected.")
