from asyncio import (
    create_task,
    wait,
    FIRST_COMPLETED,
    Semaphore,
    TimeoutError,
    wait_for,
    run,
    gather,
    CancelledError,
)
from json import load, JSONDecodeError
from logging import getLogger, Logger
from re import compile as re_compile, IGNORECASE, Pattern, Match, search
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout, ClientResponseError
from rich.console import Console
from rich.logging import RichHandler
from argparse import ArgumentParser

# Setup console for pretty output
console = Console()

# Setup logger with RichHandler and prevent propagation to avoid duplicate logs
logger: Logger = getLogger(__name__)
if not logger.hasHandlers():
    from logging import basicConfig

    basicConfig(
        level="INFO",
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
logger.propagate = False


def load_json_file(filepath: str) -> Optional[Dict]:
    """
    Load and parse a JSON file.

    Args:
        filepath: Path to the JSON file.

    Returns:
        Parsed JSON as dictionary if successful, else None.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except FileNotFoundError:
        logger.error(f"JSON file not found: {filepath}")
    except JSONDecodeError as e:
        logger.error(f"Failed to decode JSON file {filepath}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error loading JSON file {filepath}: {e}")
    return None


def is_valid_url(url: str) -> bool:
    """
    Validate if the input string is a valid HTTP or HTTPS URL.

    Args:
        url: URL string to validate.

    Returns:
        True if valid HTTP/HTTPS URL, False otherwise.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True


def compile_fingerprints(
    fingerprints: List[Dict],
) -> List[Tuple[Dict, Optional[Pattern]]]:
    """
    Compile regex patterns in fingerprints for efficient matching.

    Args:
        fingerprints: List of fingerprint dictionaries, each with optional 'pattern'.

    Returns:
        List of tuples: (original fingerprint dict, compiled regex pattern or None).
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

    Args:
        match: Regex match object.

    Returns:
        Extracted version string if valid, else None.
    """
    if not match:
        return None

    # Use first captured group if available, else whole match
    if match.lastindex and match.lastindex >= 1:
        version_candidate = match.group(1)
    else:
        version_candidate = match.group(0)

    if not version_candidate:
        return None

    version_candidate = version_candidate.strip()

    # Reject generic or trivial values
    lower_version = version_candidate.lower()
    if lower_version in ("version", "generic", ""):
        return None

    # Require at least one digit; dot optional to allow versions like '2021' or 'v1'
    if not search(r"\d", version_candidate):
        return None

    return version_candidate


def match_fingerprint(
    response_text: str,
    response_headers: Dict[str, str],
    url: str,
    status_code: int,
    fingerprint: Dict,
    compiled_pattern: Optional[Pattern],
    verbose: bool = False,
) -> Optional[Dict]:
    """
    Match a single fingerprint against HTTP response data.

    Args:
        response_text: Response body text.
        response_headers: HTTP response headers dictionary.
        url: Full URL requested.
        status_code: HTTP response status code.
        fingerprint: Fingerprint dict containing matching info.
        compiled_pattern: Pre-compiled regex pattern or None.
        verbose: If True, log detailed matching info.

    Returns:
        Dictionary with match details if matched, else None.
    """
    method = fingerprint.get("method", "").lower()
    location = fingerprint.get("location", "")
    default_version = fingerprint.get("version", "Unknown")
    pattern = fingerprint.get("pattern", "")
    is_status_ok = 200 <= status_code < 300

    # Match based on URL
    if method == "url":
        if is_status_ok:
            if (not pattern and location in url) or (
                compiled_pattern and compiled_pattern.search(url)
            ):
                if verbose:
                    logger.info(f"URL matched: {url}")
                return {
                    "found": True,
                    "url": url,
                    "status_code": status_code,
                    "version": default_version,
                    "evidence": f"URL matched pattern: {pattern or location}",
                }

    # Match based on headers
    elif method == "header" and compiled_pattern:
        # Extract header key after "headers."
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
                extracted_version = extract_version_from_match(match_obj) or default_version
                if verbose:
                    logger.info(f"Header matched at {url}: {header_key} = {header_value}")
                return {
                    "found": True,
                    "url": url,
                    "status_code": status_code,
                    "version": extracted_version,
                    "evidence": f"Header {header_key}: {header_value}",
                }

    # Match based on body content
    elif method == "body" and compiled_pattern:
        if is_status_ok:
            # Limit to first 100k characters for performance
            match_obj = compiled_pattern.search(response_text[:100_000])
            if match_obj:
                extracted_version = extract_version_from_match(match_obj) or default_version
                if verbose:
                    logger.info(f"Body matched at {url}")
                return {
                    "found": True,
                    "url": url,
                    "status_code": status_code,
                    "version": extracted_version,
                    "evidence": f"Body matched pattern: {pattern}",
                }

    return None


async def fetch_and_check(
    session: ClientSession,
    base_url: str,
    path: str,
    compiled_fingerprints: List[Tuple[Dict, Optional[Pattern]]],
    timeout: int,
    verbose: bool,
    semaphore: Semaphore,
) -> Optional[Dict]:
    """
    Fetch URL (base_url + path) and check all fingerprints against the response.

    Args:
        session: aiohttp ClientSession object.
        base_url: Base URL string.
        path: Path string to append to base_url.
        compiled_fingerprints: List of compiled fingerprints tuples.
        timeout: Request timeout in seconds.
        verbose: If True, enable detailed logging.
        semaphore: asyncio.Semaphore to limit concurrency.

    Returns:
        First matched fingerprint dict if found, else None.
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
                    result = match_fingerprint(
                        text, headers, url, resp.status, fp, compiled_pattern, verbose
                    )
                    if result:
                        if verbose:
                            logger.info(f"Fingerprint matched at {url}: {result['evidence']}")
                        return result

    except CancelledError:
        # Task was cancelled, likely because another match was found
        if verbose:
            logger.info(f"Fetch cancelled for {url}")
    except TimeoutError:
        logger.warning(f"Timeout fetching {url}")
    except ClientResponseError as e:
        logger.warning(f"HTTP error fetching {url}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching {url}: {e}")

    return None


async def detect_mailman_async(
    base_url: str,
    paths: List[str],
    fingerprints: List[Dict],
    timeout: int = 5,
    verbose: bool = False,
) -> Dict:
    """
    Asynchronously detect Mailman installation by checking multiple paths with fingerprints.

    Args:
        base_url: Target base URL.
        paths: List of URL paths to check.
        fingerprints: List of fingerprint dicts.
        timeout: Timeout for each HTTP request in seconds.
        verbose: Enable verbose logging.

    Returns:
        Dict with detection result or failure reason.
    """
    if not is_valid_url(base_url):
        return {"found": False, "error": "Invalid URL"}

    compiled_fps = compile_fingerprints(fingerprints)
    headers = {"User-Agent": "MailmapScanner/2.0"}
    timeout_obj = ClientTimeout(total=timeout)
    semaphore = Semaphore(10)  # Limit concurrency

    async with ClientSession(headers=headers, timeout=timeout_obj) as session:
        tasks = [
            create_task(fetch_and_check(session, base_url, path, compiled_fps, timeout, verbose, semaphore))
            for path in paths
        ]

        while tasks:
            done, pending = await wait(tasks, return_when=FIRST_COMPLETED)

            for task in done:
                result = task.result()
                if result:
                    # Cancel pending tasks to save resources
                    for p in pending:
                        p.cancel()
                    try:
                        await wait_for(gather(*pending, return_exceptions=True), timeout=3)
                    except TimeoutError:
                        logger.warning("Timeout while cancelling pending tasks")
                    return result

            tasks = list(pending)

    return {"found": False, "reason": "No known Mailman path responded with recognizable content."}


async def check_mailman(base_url: str, settings: Dict) -> Dict:
    """
    Async wrapper to detect Mailman using paths and fingerprints from JSON files.

    Args:
        base_url: Target base URL.
        settings: Dict containing keys:
            - paths: file path for paths JSON.
            - fingerprints: file path for fingerprints JSON.
            - timeout: request timeout.
            - verbose: verbose flag.

    Returns:
        Detection result dict.
    """
    paths_file = settings.get("paths", "data/common_paths.json")
    fingerprints_file = settings.get("fingerprints", "data/fingerprints_detection.json")

    common_paths_data = load_json_file(paths_file)
    fingerprints = load_json_file(fingerprints_file)

    if common_paths_data is None or fingerprints is None:
        return {"found": False, "error": "Failed to load required data files."}

    common_paths = []
    for key in ["v2_paths", "v3_paths"]:
        common_paths.extend([item["path"] for item in common_paths_data.get(key, [])])

    result = await detect_mailman_async(
        base_url,
        common_paths,
        fingerprints,
        timeout=settings.get("timeout", 5),
        verbose=settings.get("verbose", False),
    )

    return result


def main():
    """
    CLI entry point for Mailmap detection tool.
    """
    parser = ArgumentParser(description="Mailmap - Mailman Detection Tool")
    parser.add_argument("--target", required=True, help="Target base URL, e.g. https://example.com")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for HTTP requests (seconds)")
    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "paths": "data/common_paths.json",
        "fingerprints": "data/fingerprints_detection.json",
        "verbose": args.verbose,
    }

    try:
        result = run(check_mailman(args.target, settings))
        if result.get("found"):
            console.print(f"[+] Mailman detected: {result}", style="bold green")
        else:
            console.print(f"[!] Mailman not found: {result}", style="bold red")

        # Check for invalid version format in result
        version = result.get("version")
        if version is None or version.lower() in ("generic", "version", ""):
            console.print("[!] Invalid version info format received.", style="bold yellow")

    except KeyboardInterrupt:
        console.print("\n[!] Scan interrupted by user (Ctrl+C)", style="bold yellow")


if __name__ == "__main__":
    main()
