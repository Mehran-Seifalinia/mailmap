# core/version.py

from re import compile as re_compile, Pattern, IGNORECASE, MULTILINE, DOTALL
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Set, List, Union
from json import load as json_load
from logging import getLogger
from asyncio import sleep
from core.utils import create_session  # async context manager returning aiohttp.ClientSession
from packaging.version import Version, InvalidVersion

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
# Regex helpers
# --------------------------------------------------------------------
def _compile_regex(pattern_str: str, flags_str: Optional[str]) -> Pattern:
    """
    Compile regex with optional flags from JSON ("ims").
    Pattern may also contain inline flags like (?i); both will effectively work.
    """
    flags = 0
    if flags_str:
        for ch in flags_str.lower():
            if ch == "i":
                flags |= IGNORECASE
            elif ch == "m":
                flags |= MULTILINE
            elif ch == "s":
                flags |= DOTALL
    # default IGNORECASE for robustness
    flags |= IGNORECASE
    return re_compile(pattern_str, flags)


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
# URL candidate builder
# --------------------------------------------------------------------
def _build_candidate_urls(base_url: str) -> List[str]:
    """
    Build a list of plausible URLs where Mailman version strings are commonly found.
    Includes /mailman, /mailman/admin, /mailman/listinfo and legacy cgi-bin paths.
    Deduplicates while preserving order.
    """
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")

    candidates: List[str] = []

    def _push(u: str):
        if u and u not in candidates:
            candidates.append(u)

    _push(base_url.rstrip("/"))
    if path:
        _push(root)

    if "/mailman" in path:
        mailman_base = path[: path.find("/mailman")] + "/mailman"
    else:
        mailman_base = "/mailman"

    _push(urljoin(root + "/", mailman_base.lstrip("/")))
    for suffix in ("admin", "listinfo", "admindb"):
        _push(urljoin(root + "/", f"{mailman_base.strip('/')}/{suffix}"))

    _push(urljoin(root + "/", "cgi-bin/mailman/listinfo"))

    return candidates


def _normalize_header_location(location: str) -> str:
    """
    Accept both 'X-Mailman-Version' and 'headers.X-Mailman-Version' from JSON.
    Returns normalized HTTP header name.
    """
    loc = location.strip()
    if loc.lower().startswith("headers."):
        return loc.split(".", 1)[1]
    return loc


# --------------------------------------------------------------------
# Clean and normalize version strings
# --------------------------------------------------------------------
def _clean_and_normalize(versions: Set[str]) -> Set[str]:
    """
    Remove invalid entries (like '.' or empty strings) and normalize semantic versions.
    Converts versions like '2.2' to '2.2.0' using packaging.version.Version.
    Keeps non-standard versions if they are meaningful (like 'Mailman 3.x').
    """
    cleaned = set()
    for v in versions:
        v = v.strip()
        if not v or v == ".":
            continue
        try:
            # Normalize semantic versions (e.g., 2.2 -> 2.2.0)
            cleaned.add(str(Version(v)))
        except InvalidVersion:
            # Keep non-semantic versions if not generic/unknown
            if v.lower() not in {"generic", "unknown"}:
                cleaned.add(v)
    return cleaned


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
    on target URLs, headers, or body. Filters out invalid/empty strings
    and normalizes versions to prevent conflicts.
    """
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must start with http:// or https:// and include a domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    custom_user_agent = settings.get("user_agent")
    delay = settings.get("delay", 1)

    user_agents = [custom_user_agent] if custom_user_agent else [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    ]

    candidate_urls = _build_candidate_urls(base_url)
    found_versions: Set[str] = set()
    ua_index = 0

    async with create_session(user_agent=custom_user_agent, proxy=proxy, timeout=timeout) as session:
        for fp in fingerprints:
            method = (fp.get("method") or "").lower()
            location = fp.get("location") or ""
            pattern_str = fp.get("pattern")
            version_label = fp.get("version")
            flags_str = fp.get("flags")
            pattern: Optional[Pattern] = _compile_regex(pattern_str, flags_str) if pattern_str else None
            current_ua = user_agents[ua_index % len(user_agents)]
            ua_index += 1
            req_headers = {
                "User-Agent": current_ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }

            url_to_check = None
            try:
                if method == "url":
                    url_to_check = urljoin(base_url + "/", location.lstrip("/"))
                    async with session.get(url_to_check, headers=req_headers) as response:
                        if response.status == 200:
                            text = await response.text()
                            if pattern:
                                ver = extract_version_from_text(text, pattern)
                                if ver:
                                    found_versions.add(ver)
                                    logger.debug(f"[version:url] {url_to_check} -> {ver}")
                            elif version_label and version_label.strip().lower() != "generic":
                                found_versions.add(version_label.strip())

                elif method == "header":
                    header_name = _normalize_header_location(location)
                    matched = False
                    for u in candidate_urls:
                        url_to_check = u
                        async with session.get(u, headers=req_headers) as response:
                            if 200 <= response.status < 400:
                                header_val = response.headers.get(header_name)
                                if not header_val:
                                    continue
                                if pattern:
                                    ver = extract_version_from_text(header_val, pattern)
                                    if ver:
                                        found_versions.add(ver)
                                        matched = True
                                        break
                                else:
                                    hv = header_val.strip()
                                    if hv and (not version_label or version_label.strip().lower() == "generic"):
                                        found_versions.add(hv)
                                        matched = True
                                        break
                                    elif version_label and version_label.strip().lower() != "generic":
                                        found_versions.add(version_label.strip())
                                        matched = True
                                        break
                    if not matched:
                        logger.debug(f"[version:header] No header match for '{header_name}' on candidates")

                elif method == "body":
                    if not pattern:
                        logger.debug("[version:body] Skipping entry without pattern.")
                    else:
                        matched = False
                        for u in candidate_urls:
                            url_to_check = u
                            async with session.get(u, headers=req_headers) as response:
                                if 200 <= response.status < 400:
                                    content_type = response.headers.get("Content-Type", "").lower()
                                    if ("text" in content_type) or (content_type == ""):
                                        content = await response.text()
                                        content = content[:100_000]
                                        ver = extract_version_from_text(content, pattern)
                                        if ver:
                                            found_versions.add(ver)
                                            matched = True
                                            break
                        if not matched:
                            logger.debug("[version:body] No match across candidate URLs")

                else:
                    logger.debug(f"[version] Unknown method '{method}' in fingerprint; skipping.")

            except Exception as e:
                logger.error(f"Error during fingerprint scan at {url_to_check or 'N/A'}: {e}")

            await sleep(delay)

    # ----------------------------------------------------------------
    # Clean and normalize collected versions before returning
    # ----------------------------------------------------------------
    found_versions = _clean_and_normalize(found_versions)

    if not found_versions:
        logger.info("No valid Mailman version detected.")
        return {"version": None}

    if len(found_versions) == 1:
        ver = next(iter(found_versions))
        logger.info(f"Detected Mailman version: {ver}")
        return {"version": ver}

    logger.warning(f"Version conflict detected. Multiple versions found: {found_versions}")
    return {"conflict": True, "versions": sorted(found_versions)}


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

    basicConfig(level=INFO, format="[%(levelname)s] %(message)s")

    parser = ArgumentParser(description="Mailman Version Detector with Fingerprints")
    parser.add_argument("target", help="Target base URL (e.g., https://example.com or https://example.com/mailman/admin)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL (optional)")
    parser.add_argument("--user-agent", help="Custom User-Agent string (optional)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
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
