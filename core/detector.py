from asyncio import create_task, wait, FIRST_COMPLETED, Semaphore, TimeoutError, wait_for, run
from json import load
from logging import getLogger, INFO, basicConfig
from re import compile as re_compile, IGNORECASE, Pattern, Match, search
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout
from rich.console import Console
from rich.logging import RichHandler
from argparse import ArgumentParser

console = Console()
logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(
        level=INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console)]
    )

# ------------- Utility Functions ------------- #

def load_json_file(filepath: str) -> Optional[Dict]:
    """
    Load and parse a JSON file.
    Return the dictionary on success, None on failure.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON file {filepath}: {e}")
    return None

def is_valid_url(url: str) -> bool:
    """
    Validate if the input string is a valid HTTP or HTTPS URL.
    """
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def compile_fingerprints(fingerprints: List[Dict]) -> List[Tuple[Dict, Optional[Pattern]]]:
    """
    Compile regex patterns in fingerprints list for faster matching.
    Each element in returned list is a tuple of (fingerprint dict, compiled pattern or None).
    """
    compiled = []
    for fp in fingerprints:
        pattern = fp.get("pattern", "")
        compiled_pattern = re_compile(pattern, IGNORECASE) if pattern else None
        compiled.append((fp, compiled_pattern))
    return compiled

def extract_version_from_match(match: Optional[Match]) -> Optional[str]:
    """
    Extract version string from regex match groups.
    Return None if extraction fails or version is trivial/invalid.
    """
    if not match:
        return None

    # Try to get the first captured group, else full match
    if match.lastindex and match.lastindex >= 1:
        version_candidate = match.group(1)
    else:
        version_candidate = match.group(0)

    if not version_candidate:
        return None

    # Clean version string
    version_candidate = version_candidate.strip()

    # Reject trivial or generic values that are meaningless
    lower_version = version_candidate.lower()
    if lower_version in ("version", "generic", ""):
        return None

    # Ensure version contains at least one digit and a dot (common version format)
    if not search(r"\d", version_candidate):
        return None
    if '.' not in version_candidate:
        return None

    return version_candidate

def match_fingerprint(
    response_text: str,
    response_headers: Dict[str, str],
    url: str,
    status_code: int,
    fingerprint: Dict,
    compiled_pattern: Optional[Pattern],
    verbose: bool = False
) -> Optional[Dict]:
    """
    Match a single fingerprint against the response content (headers, body, or url).
    Return a dict with match details if matched, otherwise None.
    """
    method = fingerprint.get("method", "").lower()
    location = fingerprint.get("location", "")
    version = fingerprint.get("version", "Unknown")
    pattern = fingerprint.get("pattern", "")
    is_status_ok = 200 <= status_code < 300

    # Match based on URL pattern
    if method == "url":
        if is_status_ok and ((not pattern and location in url) or (compiled_pattern and compiled_pattern.search(url))):
            if verbose:
                logger.info(f"URL matched: {url}")
            return {
                "found": True,
                "url": url,
                "status_code": status_code,
                "version": version,
                "evidence": f"URL matched pattern: {pattern or location}"
            }

    # Match based on HTTP headers
    elif method == "header" and compiled_pattern:
        # Extract header key from location like "headers.X-Mailman-Version"
        header_key = location.split(".", 1)[-1].lower()
        header_value = ""
        # Case-insensitive search for header key
        for hk, hv in response_headers.items():
            if hk.lower() == header_key:
                header_value = hv
                break

        if header_value:
            match_obj = compiled_pattern.search(header_value)
            if match_obj:
                extracted_version = extract_version_from_match(match_obj)
                if not extracted_version:
                    extracted_version = version  # fallback to fingerprint version
                if verbose:
                    logger.info(f"Header matched at {url}: {header_key} = {header_value}")
                return {
                    "found": True,
                    "url": url,
                    "status_code": status_code,
                    "version": extracted_version,
                    "evidence": f"Header {header_key}: {header_value}"
                }

    # Match based on response body content
    elif method == "body" and compiled_pattern:
        if is_status_ok:
            # Limit body size to 100k chars for performance
            match_obj = compiled_pattern.search(response_text[:100_000])
            if match_obj:
                extracted_version = extract_version_from_match(match_obj)
                if not extracted_version:
                    extracted_version = version
                if verbose:
                    logger.info(f"Body matched at {url}")
                return {
                    "found": True,
                    "url": url,
                    "status_code": status_code,
                    "version": extracted_version,
                    "evidence": f"Body matched pattern: {pattern}"
                }

    return None

# ------------- Main Async Logic ------------- #

async def fetch_and_check(
    session: ClientSession,
    base_url: str,
    path: str,
    compiled_fingerprints: List[Tuple[Dict, Optional[Pattern]]],
    timeout: int,
    verbose: bool,
    semaphore: Semaphore
) -> Optional[Dict]:
    """
    Fetch a URL (base_url + path) and check all fingerprints against the response.
    Return the first matched fingerprint dict or None.
    """
    url = urljoin(base_url + "/", path.lstrip("/"))
    if verbose:
        logger.info(f"Checking URL: {url}")

    try:
        async with semaphore:
            async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                if verbose:
                    logger.info(f"Got status {resp.status} from {url}")

                if not (200 <= resp.status < 300):
                    if verbose:
                        logger.info(f"Skipping {url} due to non-2xx status code")
                    return None

                text = await resp.text()
                headers = dict(resp.headers)

                for fp, compiled_pattern in compiled_fingerprints:
                    result = match_fingerprint(text, headers, url, resp.status, fp, compiled_pattern, verbose)
                    if result:
                        if verbose:
                            logger.info(f"Fingerprint matched at {url}: {result['evidence']}")
                        return result
    except Exception as e:
        if verbose:
            logger.warning(f"Error fetching {url}: {e}")
    return None

async def detect_mailman_async(
    base_url: str,
    paths: List[str],
    fingerprints: List[Dict],
    timeout: int = 5,
    verbose: bool = False
) -> Dict:
    """
    Asynchronously check multiple paths to detect Mailman installation by matching fingerprints.
    Return a dict with detection info or failure reason.
    """
    if not is_valid_url(base_url):
        return {"found": False, "error": "Invalid URL"}

    compiled_fps = compile_fingerprints(fingerprints)
    headers = {"User-Agent": "MailmapScanner/2.0"}
    timeout_obj = ClientTimeout(total=timeout)
    semaphore = Semaphore(10)  # Limit concurrency to 10 requests at a time

    async with ClientSession(headers=headers, timeout=timeout_obj) as session:
        tasks = [
            create_task(fetch_and_check(session, base_url, path, compiled_fps, timeout, verbose, semaphore))
            for path in paths
        ]

        # Wait for any task to complete successfully
        while tasks:
            done, pending = await wait(tasks, return_when=FIRST_COMPLETED)

            for task in done:
                result = task.result()
                if result:
                    # Cancel other pending tasks
                    for p in pending:
                        p.cancel()
                    try:
                        await wait_for(run(gather(*pending, return_exceptions=True)), timeout=3)
                    except TimeoutError:
                        logger.warning("Timeout while cancelling pending tasks")
                    return result

            tasks = list(pending)

    return {"found": False, "reason": "No known Mailman path responded with recognizable content."}

# ------------- Synchronous Wrapper ------------- #

def check_mailman(base_url: str, settings: Dict) -> Dict:
    """
    Synchronous wrapper to detect Mailman by loading paths and fingerprints from files,
    then running the async detection function.
    """
    paths_file = settings.get("paths", "data/common_paths.json")
    fingerprints_file = settings.get("fingerprints", "data/fingerprints.json")

    common_paths_data = load_json_file(paths_file)
    fingerprints = load_json_file(fingerprints_file)

    if common_paths_data is None or fingerprints is None:
        return {"found": False, "error": "Failed to load required data files."}

    common_paths = []
    for key in ["v2_paths", "v3_paths"]:
        common_paths.extend([item["path"] for item in common_paths_data.get(key, [])])

    # Run the async detection function synchronously using asyncio.run
    result = run(detect_mailman_async(
        base_url,
        common_paths,
        fingerprints,
        timeout=settings.get("timeout", 5),
        verbose=settings.get("verbose", False)
    ))

    return result

# ------------- CLI Entry Point ------------- #

if __name__ == "__main__":
    parser = ArgumentParser(description="Mailmap - Mailman Detection Tool")
    parser.add_argument("--target", required=True, help="Target base URL, e.g. https://example.com")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for HTTP requests")
    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "paths": "data/common_paths.json",
        "fingerprints": "data/fingerprints.json",
        "verbose": args.verbose,
    }

    try:
        result = check_mailman(args.target, settings)
        if result.get("found"):
            console.print(f"[+] Mailman detected: {result}", style="bold green")
        else:
            console.print(f"[!] Mailman not found: {result}", style="bold red")

        # Additional check for invalid version format
        version = result.get("version")
        if version is None or version.lower() in ("generic", "version", ""):
            console.print("[!] Invalid version info format received.", style="bold yellow")

    except KeyboardInterrupt:
        console.print("\n[!] Scan interrupted by user (Ctrl+C)", style="bold yellow")
