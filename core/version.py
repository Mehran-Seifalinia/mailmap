# core/version.py

from re import compile as re_compile, Pattern, IGNORECASE, MULTILINE, DOTALL
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Set, List, Union
from json import load as json_load
from logging import getLogger
from aiohttp import TCPConnector, ClientTimeout, ClientSession
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
    flags |= IGNORECASE  # default IGNORECASE for robustness
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
# Build candidate URLs for version checking
# --------------------------------------------------------------------
def _build_candidate_urls(base_url: str) -> List[str]:
    """
    Build a list of plausible URLs where Mailman version strings are commonly found.
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
    Remove invalid entries and normalize semantic versions.
    Converts versions like '2.2' to '2.2.0'.
    Keeps non-standard versions if meaningful.
    """
    cleaned = set()
    for v in versions:
        v = v.strip()
        if not v or v == ".":
            continue
        try:
            ver_obj = Version(v)
            major = ver_obj.release[0]
            minor = ver_obj.release[1] if len(ver_obj.release) > 1 else 0
            patch = ver_obj.release[2] if len(ver_obj.release) > 2 else 0
            normalized = f"{major}.{minor}.{patch}"
            cleaned.add(normalized)
        except InvalidVersion:
            if v.lower() not in {"generic", "unknown"}:
                cleaned.add(v)
    return cleaned


# --------------------------------------------------------------------
# Async HTTP fetch with caching
# --------------------------------------------------------------------
async def _fetch_url(session, url: str, headers: Dict[str, str], cache: Dict[str, str]) -> Optional[str]:
    """
    Fetch the content of a URL using aiohttp session.
    Use cache to avoid multiple requests for same URL.
    """
    if url in cache:
        return cache[url]
    try:
        async with session.get(url, headers=headers) as resp:
            if 200 <= resp.status < 400:
                text = await resp.text()
                cache[url] = text
                return text
    except Exception as e:
        logger.debug(f"Request failed for {url}: {e}")
    return None


# --------------------------------------------------------------------
# Core asynchronous version detection logic (parallelized)
# --------------------------------------------------------------------
async def detect_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprints: List[Dict]
) -> Dict[str, Union[str, bool, List[str], None]]:
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format"}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agent = settings.get("user_agent", "MailmapScanner/2.0")

    candidate_urls = _build_candidate_urls(base_url)
    found_versions = set()
    connector = None
    proxy_param = None
    if proxy:
        proxy_lower = proxy.lower()
        if proxy_lower.startswith(("socks5://", "socks4://", "socks5h://")):
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(proxy)
        elif proxy_lower.startswith(("http://", "https://")):
            proxy_param = proxy
            connector = TCPConnector()
        else:
            connector = TCPConnector()
    else:
        connector = TCPConnector()

    headers = {"User-Agent": user_agent}
    timeout_obj = ClientTimeout(total=timeout)

    async with ClientSession(headers=headers, connector=connector, timeout=timeout_obj) as session:
        responses = []
        for url in candidate_urls:
            try:
                async with session.get(url, timeout=timeout, proxy=proxy_param) as resp:
                    if 200 <= resp.status < 400:
                        text = await resp.text()
                        headers = dict(resp.headers)
                        responses.append((url, text, headers))
                    else:
                        logger.debug(f"Non-OK status {resp.status} for {url}")
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")

        for fp in fingerprints:
            method = fp.get("method", "").lower()
            location = fp.get("location", "")
            pattern_str = fp.get("pattern")
            version_label = fp.get("version")
            flags_str = fp.get("flags")
            pattern = _compile_regex(pattern_str, flags_str) if pattern_str else None

            if method == "url":
                for url, _, _ in responses:
                    if location in url:
                        found_versions.add(version_label.strip() if version_label else "Unknown")
                        break

            elif method == "header":
                header_key = _normalize_header_location(location)
                for _, _, headers in responses:
                    header_val = headers.get(header_key)
                    if header_val:
                        if pattern:
                            ver = extract_version_from_text(header_val, pattern)
                            if ver:
                                found_versions.add(ver)
                        else:
                            found_versions.add(header_val.strip())
                        break

            elif method == "body":
                for _, text, _ in responses:
                    if pattern:
                        ver = extract_version_from_text(text[:100_000], pattern)
                        if ver:
                            found_versions.add(ver)
                            break
                    else:
                        if version_label and version_label.lower() != "generic":
                            found_versions.add(version_label.strip())
                            break

    found_versions = _clean_and_normalize(found_versions)

    if not found_versions:
        logger.info("No valid Mailman version detected.")
        return {"version": None}
    if len(found_versions) == 1:
        ver = next(iter(found_versions))
        logger.info(f"Detected Mailman version: {ver}")
        return {"version": ver}
    # Version conflict: pick the highest version using packaging.version
    from packaging.version import Version, InvalidVersion
    valid_versions = []
    for v in found_versions:
        try:
            valid_versions.append((Version(v), v))
        except InvalidVersion:
            # Keep non-semver as fallback, but lower priority
            valid_versions.append((Version("0"), v))
    valid_versions.sort(key=lambda x: x[0])
    highest = valid_versions[-1][1]
    logger.warning(f"Version conflict: {found_versions}. Using highest: {highest}")
    return {"version": highest, "conflict_detected": True, "all_versions": sorted(found_versions)}


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
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (minimal recommended)")
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
