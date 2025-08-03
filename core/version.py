from re import compile as re_compile, IGNORECASE
from urllib.parse import urljoin, urlparse
from time import sleep
from typing import Optional, Dict, Set, List, Union
from json import load as json_load
from logging import getLogger, basicConfig, INFO, DEBUG
from argparse import ArgumentParser
from sys import exit as sys_exit, stderr
from requests.exceptions import (
    Timeout,
    ConnectionError,
    RequestException,
    TooManyRedirects,
    HTTPError
)
from core.utils import create_session
from rich.console import Console
from rich.theme import Theme

logger = getLogger(__name__)
console = Console(theme=Theme({
    "error": "bold red",
    "success": "bold green",
    "warning": "bold yellow",
    "info": "bold cyan"
}))

def load_fingerprints(filepath: str) -> List[Dict]:
    """Load fingerprint patterns from JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        logger.info(f"Loaded {len(data)} fingerprints from {filepath}")
        return data
    except Exception as e:
        logger.error(f"Failed to load fingerprints file '{filepath}': {e}")
        return []

def is_valid_url(url: str) -> bool:
    """Check if URL has valid scheme and netloc."""
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL format. URL must start with http:// or https:// and include a domain.")
    return valid

def extract_version_from_text(text: str, pattern: re_compile) -> Optional[str]:
    """Extract version string using regex pattern from given text."""
    match = pattern.search(text)
    if match:
        try:
            return match.group(1).strip()
        except IndexError:
            return match.group(0).strip()
    return None

def detect_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprints: List[Dict]
) -> Dict[str, Union[str, bool, List[str], None]]:
    """Detect Mailman version by applying fingerprints on target URLs/headers/body."""

    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. URL must start with http:// or https:// and include a domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agent = settings.get("user_agent")
    delay = settings.get("delay", 1)

    user_agents = [user_agent] if user_agent else [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    ]

    found_versions: Set[str] = set()
    user_agent_index = 0

    with create_session(user_agent=user_agent) as session:
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        for fp in fingerprints:
            method = fp.get("method")
            location = fp.get("location")
            pattern_str = fp.get("pattern")
            version_label = fp.get("version")

            pattern = re_compile(pattern_str, IGNORECASE) if pattern_str else None

            # Rotate User-Agent for each request to reduce chance of blocking
            current_ua = user_agents[user_agent_index % len(user_agents)]
            session.headers.update({"User-Agent": current_ua})
            user_agent_index += 1

            url_to_check = None  # امن‌سازی متغیر

            try:
                if method == "url":
                    url_to_check = urljoin(base_url + "/", location.lstrip("/"))
                    response = session.get(url_to_check, timeout=timeout)
                    if response.status_code == 200:
                        if not pattern:
                            found_versions.add(version_label)
                            logger.debug(f"Fingerprint matched by URL presence: {url_to_check} -> {version_label}")
                        else:
                            ver = extract_version_from_text(response.text, pattern)
                            if ver:
                                found_versions.add(ver)
                                logger.debug(f"Fingerprint matched by URL body regex: {url_to_check} -> {ver}")

                elif method == "header":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    found_in_header = False
                    for u in urls_to_try:
                        url_to_check = u
                        response = session.get(u, timeout=timeout)
                        if not response.ok:
                            continue
                        header_val = response.headers.get(location)
                        if header_val and pattern:
                            ver = extract_version_from_text(header_val, pattern)
                            if ver:
                                found_versions.add(ver)
                                found_in_header = True
                                logger.debug(f"Fingerprint matched in header '{location}': {u} -> {ver}")
                                break
                    if found_in_header:
                        continue

                elif method == "body":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    for u in urls_to_try:
                        url_to_check = u
                        response = session.get(u, timeout=timeout)
                        content_type = response.headers.get("Content-Type", "").lower()
                        if not response.ok or "text" not in content_type:
                            continue
                        content = response.text[:100_000]
                        if pattern:
                            ver = extract_version_from_text(content, pattern)
                            if ver:
                                found_versions.add(ver)
                                logger.debug(f"Fingerprint matched in body content: {u} -> {ver}")
                                break

            except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError) as e:
                logger.debug(f"Request error at {location} or {url_to_check if url_to_check else 'N/A'}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during fingerprint scan: {e}")

            # Delay between requests to avoid triggering protections
            sleep(delay)

    if not found_versions:
        logger.info("No Mailman version detected.")
        return {"version": None}
    if len(found_versions) == 1:
        ver = found_versions.pop()
        logger.info(f"Detected Mailman version: {ver}")
        return {"version": ver}

    # Multiple conflicting versions found
    logger.warning(f"Version conflict detected. Found versions: {found_versions}")
    return {"conflict": True, "versions": list(found_versions)}

def get_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprint_file: str = "data/fingerprints.json"
) -> Dict:
    """Load fingerprints and run version detection."""
    fingerprints = load_fingerprints(fingerprint_file)
    if not fingerprints:
        logger.error("No fingerprints loaded, aborting version detection.")
        return {"error": "No fingerprints loaded."}
    return detect_version(base_url, settings, fingerprints)


# CLI Support
if __name__ == "__main__":
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

    parser = ArgumentParser(description="Mailman Version Detector with Fingerprints")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout (seconds)")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests (seconds)")
    parser.add_argument("--fingerprints", default="data/fingerprints.json", help="Path to fingerprints JSON file")

    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "delay": args.delay,
    }

    try:
        result = get_version(args.target, settings, args.fingerprints)
    except KeyboardInterrupt:
        console.print("\n[error]Process interrupted by user (Ctrl+C). Exiting...[/error]")
        sys_exit(130)  # 128 + 2 for SIGINT

    if "error" in result:
        console.print(f"[error]Error: {result['error']}[/error]")
        sys_exit(1)

    if result.get("conflict"):
        console.print(f"[warning]Version conflict detected! Found versions: {', '.join(result['versions'])}[/warning]")
        sys_exit(2)
    elif result.get("version"):
        console.print(f"[success]Detected Mailman version: {result['version']}[/success]")
        sys_exit(0)
    else:
        console.print("[info]No Mailman version detected.[/info]")
        sys_exit(3)
