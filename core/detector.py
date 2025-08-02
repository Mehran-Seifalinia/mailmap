from asyncio import run, wait, create_task, gather, FIRST_COMPLETED, CancelledError
from json import load, JSONDecodeError
from logging import getLogger, INFO
from re import compile as re_compile, IGNORECASE, Pattern
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from aiohttp import ClientSession
from rich.console import Console
from rich.logging import RichHandler
from logging import basicConfig

console = Console()
logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(
        level=INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console)]
    )


def load_json_file(filepath: str) -> Optional[Dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON file {filepath}: {e}")
    return None


def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def compile_fingerprints(fingerprints: List[Dict]) -> List[Tuple[Dict, Optional[Pattern]]]:
    compiled = []
    for fp in fingerprints:
        pattern = fp.get("pattern", "")
        compiled_pattern = re_compile(pattern, IGNORECASE) if pattern else None
        compiled.append((fp, compiled_pattern))
    return compiled


def match_fingerprint(
    response_text: str,
    response_headers: Dict[str, str],
    url: str,
    status_code: int,
    fingerprint: Dict,
    compiled_pattern: Optional[Pattern],
    verbose: bool = False
) -> Optional[Dict]:
    method = fingerprint.get("method", "").lower()
    location = fingerprint.get("location", "")
    version = fingerprint.get("version", "Unknown")
    pattern = fingerprint.get("pattern", "")

    is_status_ok = 200 <= status_code < 300

    if method == "url":
        if (not pattern and location in url) or (compiled_pattern and compiled_pattern.search(url)):
            if verbose:
                logger.info(f"URL matched: {url}")
            return {
                "found": True,
                "url": url,
                "status_code": status_code,
                "version": version,
                "evidence": f"URL matched pattern: {pattern or location}"
            }
    elif method == "header" and compiled_pattern:
        header_key = location.split(".", 1)[1] if location.startswith("headers.") else location
        header_value = response_headers.get(header_key, "")
        if header_value and compiled_pattern.search(header_value):
            if verbose:
                logger.info(f"Header matched at {url}: {header_key} = {header_value}")
            return {
                "found": True,
                "url": url,
                "status_code": status_code,
                "version": version,
                "evidence": f"Header {header_key}: {header_value}"
            }
    elif method == "body" and compiled_pattern:
        if is_status_ok and compiled_pattern.search(response_text[:100_000]):
            if verbose:
                logger.info(f"Body matched at {url}")
            return {
                "found": True,
                "url": url,
                "status_code": status_code,
                "version": version,
                "evidence": f"Body matched pattern: {pattern}"
            }

    return None


async def fetch_and_check(
    session: ClientSession,
    base_url: str,
    path: str,
    compiled_fingerprints: List[Tuple[Dict, Optional[Pattern]]],
    timeout: int,
    verbose: bool
) -> Optional[Dict]:
    url = urljoin(base_url + "/", path.lstrip("/"))
    if verbose:
        logger.info(f"Checking URL: {url}")

    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            if verbose:
                logger.info(f"Got status {resp.status} from {url}")
            text = await resp.text()
            headers = dict(resp.headers)
            for fp, compiled_pattern in compiled_fingerprints:
                result = match_fingerprint(text, headers, url, resp.status, fp, compiled_pattern, verbose)
                if result:
                    if verbose:
                        logger.info(f"Fingerprint matched at {url}: {result['evidence']}")
                    return result
    except CancelledError:
        pass
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
    if not is_valid_url(base_url):
        return {"found": False, "error": "Invalid URL"}

    compiled_fps = compile_fingerprints(fingerprints)
    headers = {"User-Agent": "MailmapScanner/2.0"}

    async with ClientSession(headers=headers) as session:
        tasks = [create_task(fetch_and_check(session, base_url, path, compiled_fps, timeout, verbose)) for path in paths]

        while tasks:
            done, pending = await wait(tasks, return_when=FIRST_COMPLETED)

            for task in done:
                result = task.result()
                if result:
                    for p in pending:
                        p.cancel()
                    await gather(*pending, return_exceptions=True)
                    return result

            tasks = list(pending)

    return {"found": False, "reason": "No known Mailman path responded with recognizable content."}


def check_mailman(base_url: str, settings: Dict) -> Tuple[bool, Dict]:
    paths_file = settings.get("paths", "data/common_paths.json")
    fingerprints_file = settings.get("fingerprints", "data/fingerprints.json")

    common_paths_data = load_json_file(paths_file)
    fingerprints = load_json_file(fingerprints_file)

    if common_paths_data is None or fingerprints is None:
        return False, {"error": "Failed to load required data files."}

    common_paths = []
    for key in ["v2_paths", "v3_paths"]:
        common_paths.extend([item["path"] for item in common_paths_data.get(key, [])])

    result = run(detect_mailman_async(
        base_url,
        common_paths,
        fingerprints,
        timeout=settings.get("timeout", 5),
        verbose=settings.get("verbose", False)
    ))

    return result.get("found", False), result


if __name__ == "__main__":
    from argparse import ArgumentParser

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
        found, result = check_mailman(args.target, settings)
        if found:
            console.print("[+] Mailman detected", style="bold green")
        else:
            console.print("[!] Mailman not found", style="bold red")
        console.print(result)
    except KeyboardInterrupt:
        console.print("\n[!] Scan interrupted by user (Ctrl+C)", style="bold yellow")
