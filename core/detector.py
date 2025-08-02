from re import compile as re_compile, IGNORECASE, Pattern
from urllib.parse import urljoin, urlparse
from json import load, JSONDecodeError
from logging import getLogger, basicConfig, INFO
from typing import List, Dict, Optional, Tuple
from aiohttp import ClientSession
from asyncio import run, wait, create_task, FIRST_COMPLETED
from asyncio.exceptions import CancelledError

# --------------------------
# Logging
# --------------------------

logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

# --------------------------
# Utilities
# --------------------------

def load_json_file(filepath: str) -> Optional[Dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except FileNotFoundError:
        logger.error(f"JSON file not found: {filepath}")
    except JSONDecodeError:
        logger.error(f"Invalid JSON format in file: {filepath}")
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

# --------------------------
# Fingerprint Matcher
# --------------------------

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
        if compiled_pattern.search(response_text[:100_000]):
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

# --------------------------
# Async Request Logic
# --------------------------

async def fetch_and_check(
    session: ClientSession,
    base_url: str,
    path: str,
    compiled_fingerprints: List[Tuple[Dict, Optional[Pattern]]],
    timeout: int,
    verbose: bool
) -> Optional[Dict]:
    url = urljoin(base_url + "/", path.lstrip("/"))
    try:
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            headers = dict(resp.headers)
            for fp, compiled_pattern in compiled_fingerprints:
                result = match_fingerprint(text, headers, url, resp.status, fp, compiled_pattern, verbose)
                if result:
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
        done, pending = await wait(tasks, return_when=FIRST_COMPLETED)

        for task in pending:
            task.cancel()

        for task in done:
            result = task.result()
            if result:
                return result

    return {"found": False, "reason": "No known Mailman path responded with recognizable content."}

# --------------------------
# External Interface
# --------------------------

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

# --------------------------
# CLI Runner
# --------------------------

if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    settings = {
        "timeout": 5,
        "paths": "data/common_paths.json",
        "fingerprints": "data/fingerprints.json",
        "verbose": True
    }

    found, result = check_mailman(target, settings)
    print("[+] Mailman Detected" if found else "[!] Mailman Not Found")
    print(result)
