# core/version.py

from re import compile as re_compile, Pattern, IGNORECASE
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Set, List, Union
from json import load as json_load
from logging import getLogger
from asyncio import sleep
from core.utils import create_session  # async context manager returning aiohttp.ClientSession

# --------------------------------------------------------------------
# Shared project-wide logger
# NOTE:
# - Configured globally (e.g., in utils.py or main entrypoint) with RichHandler.
# - Do NOT add handlers here to avoid duplicate log lines.
# --------------------------------------------------------------------
logger = getLogger("mailmap")


# --------------------------------------------------------------------
# Load version fingerprints from JSON file
# --------------------------------------------------------------------
def load_fingerprints(filepath: str) -> List[Dict]:
    """
    Load fingerprint patterns from a JSON file.
    Returns a list of fingerprint dictionaries.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        logger.info(f"Loaded {len(data)} fingerprints from {filepath}")
        return data
    except Exception as e:
        logger.error(f"Failed to load fingerprints file '{filepath}': {e}")
        return []


# --------------------------------------------------------------------
# Validate target URL format
# --------------------------------------------------------------------
def is_valid_url(url: str) -> bool:
    """
    Validate URL format - must have http or https scheme and a network location.
    """
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL format. Must start with http:// or https:// and include a domain.")
    return valid


# --------------------------------------------------------------------
# Extract version string from regex match
# --------------------------------------------------------------------
def extract_version_from_text(text: str, pattern: Pattern) -> Optional[str]:
    """
    Extract version string by searching the text with a compiled regex pattern.
    Returns the first matching group or the whole match if groups not present.
    """
    match = pattern.search(text)
    if match:
        try:
            return match.group(1).strip()
        except IndexError:
            return match.group(0).strip()
    return None


# --------------------------------------------------------------------
# Core asynchronous version detection logic
# --------------------------------------------------------------------
async def detect_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprints: List[Dict]
) -> Dict[str, Union[str, bool, List[str], None]]:
    """
    Detect Mailman version asynchronously by applying fingerprint regexes
    on target URLs, headers, or body. Filters out generic or invalid version strings.
    """
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must start with http:// or https:// and include a domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agent = settings.get("user_agent")
    delay = settings.get("delay", 1)

    # Default user-agent list to rotate through if none specified
    user_agents = [user_agent] if user_agent else [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    ]

    found_versions: Set[str] = set()
    user_agent_index = 0

    async with create_session(user_agent=user_agent, proxy=proxy, timeout=timeout) as session:
        for fp in fingerprints:
            method = fp.get("method")
            location = fp.get("location")
            pattern_str = fp.get("pattern")
            version_label = fp.get("version")

            pattern = re_compile(pattern_str, IGNORECASE) if pattern_str else None

            # Rotate User-Agent header for each request
            current_ua = user_agents[user_agent_index % len(user_agents)]
            session.headers.update({"User-Agent": current_ua})
            user_agent_index += 1

            url_to_check = None

            try:
                # ------------------------------------------------
                # Method: URL → check specific path content
                # ------------------------------------------------
                if method == "url":
                    url_to_check = urljoin(base_url + "/", location.lstrip("/"))
                    async with session.get(url_to_check) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not pattern:
                                if version_label.lower() != "generic":
                                    found_versions.add(version_label)
                                else:
                                    logger.debug(f"Ignored generic version label for URL presence: {url_to_check}")
                            else:
                                ver = extract_version_from_text(text, pattern)
                                if ver and ver.lower() != "generic":
                                    found_versions.add(ver)
                                    logger.debug(f"Matched version via URL body regex: {url_to_check} -> {ver}")
                                else:
                                    logger.debug(f"No version found or generic ignored at URL: {url_to_check}")

                # ------------------------------------------------
                # Method: HEADER → check HTTP headers for version
                # ------------------------------------------------
                elif method == "header":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    found_in_header = False
                    for u in urls_to_try:
                        url_to_check = u
                        async with session.get(u) as response:
                            if 200 <= response.status < 300:
                                header_val = response.headers.get(location)
                                if header_val and pattern:
                                    ver = extract_version_from_text(header_val, pattern)
                                    if ver and ver.lower() != "generic":
                                        found_versions.add(ver)
                                        found_in_header = True
                                        logger.debug(f"Matched version in header '{location}' at {u}: {ver}")
                                        break
                                    else:
                                        logger.debug(f"No version found or generic ignored in header '{location}' at {u}")
                    if found_in_header:
                        continue

                # ------------------------------------------------
                # Method: BODY → check HTML/text content for version
                # ------------------------------------------------
                elif method == "body":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    for u in urls_to_try:
                        url_to_check = u
                        async with session.get(u) as response:
                            if 200 <= response.status < 300:
                                content_type = response.headers.get("Content-Type", "").lower()
                                if "text" in content_type:
                                    content = await response.text()
                                    content = content[:100_000]  # Limit body size for performance
                                    if pattern:
                                        ver = extract_version_from_text(content, pattern)
                                        if ver and ver.lower() != "generic":
                                            found_versions.add(ver)
                                            logger.debug(f"Matched version in body content at {u}: {ver}")
                                            break
                                        else:
                                            logger.debug(f"No version found or generic ignored in body content at {u}")

            except Exception as e:
                logger.error(f"Error during fingerprint scan at {url_to_check or 'N/A'}: {e}")

            await sleep(delay)  # polite delay between requests

    # ------------------------------------------------
    # Final version detection results
    # ------------------------------------------------
    if not found_versions:
        logger.info("No valid Mailman version detected (only generic or none found).")
        return {"version": None}

    if len(found_versions) == 1:
        ver = found_versions.pop()
        logger.info(f"Detected Mailman version: {ver}")
        return {"version": ver}

    logger.warning(f"Version conflict detected. Multiple versions found: {found_versions}")
    return {"conflict": True, "versions": list(found_versions)}


# --------------------------------------------------------------------
# API function for external usage
# --------------------------------------------------------------------
async def get_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprint_file: str = "data/fingerprints_version.json"
) -> Dict:
    """
    Load fingerprints from file and run version detection asynchronously.
    """
    fingerprints = load_fingerprints(fingerprint_file)
    if not fingerprints:
        logger.error("No fingerprints loaded. Aborting version detection.")
        return {"error": "No fingerprints loaded."}
    return await detect_version(base_url, settings, fingerprints)


# --------------------------------------------------------------------
# Standalone entrypoint for manual testing
# --------------------------------------------------------------------
if __name__ == "__main__":
    from argparse import ArgumentParser
    from logging import basicConfig, INFO
    from asyncio import run

    # Minimal logger setup for direct runs
    basicConfig(level=INFO, format="[%(levelname)s] %(message)s")

    parser = ArgumentParser(description="Mailman Version Detector with Fingerprints")
    parser.add_argument("target", help="Target base URL (e.g., https://example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL (optional)")
    parser.add_argument("--user-agent", help="Custom User-Agent string (optional)")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests in seconds")
    parser.add_argument("--fingerprints", default="data/fingerprints_version.json",
                        help="Path to fingerprints JSON file")

    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "delay": args.delay,
    }

    try:
        result = run(get_version(args.target, settings, args.fingerprints))
        logger.info(f"Version detection result: {result}")
    except KeyboardInterrupt:
        logger.warning("Interrupted by user (Ctrl+C). Exiting...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
