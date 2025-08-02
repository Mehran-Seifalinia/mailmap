from re import compile, IGNORECASE, Pattern
from requests import Session, Timeout, ConnectionError, RequestException, Response
from urllib.parse import urljoin, urlparse
from json import load, JSONDecodeError
from logging import getLogger, basicConfig, INFO
from typing import List, Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

# --------------------------
# Utility Functions
# --------------------------

def load_json_file(filepath: str) -> Optional[Dict]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
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
    return all([parsed.scheme in ("http", "https"), parsed.netloc])

# --------------------------
# Fingerprint Matcher
# --------------------------

def match_fingerprint(
    response: Response,
    full_url: str,
    fingerprint: Dict,
    compiled_pattern: Optional[Pattern],
    verbose: bool = False
) -> Optional[Dict]:

    method = fingerprint.get("method", "").lower()
    location = fingerprint.get("location", "")
    version = fingerprint.get("version", "Unknown")
    pattern = fingerprint.get("pattern", "")

    if method == "url":
        if not pattern and location in full_url:
            if verbose:
                logger.info(f"URL fingerprint matched: {location} at {full_url}")
            return {
                "found": True,
                "url": full_url,
                "status_code": response.status_code,
                "version": version,
                "evidence": f"URL path matched: {location}"
            }
        elif compiled_pattern and compiled_pattern.search(full_url):
            if verbose:
                logger.info(f"URL regex fingerprint matched: {pattern} at {full_url}")
            return {
                "found": True,
                "url": full_url,
                "status_code": response.status_code,
                "version": version,
                "evidence": f"URL matched pattern: {pattern}"
            }

    elif method == "header" and compiled_pattern:
        header_key = location.split(".", 1)[1] if location.startswith("headers.") else location
        header_value = response.headers.get(header_key, "")
        if header_value and compiled_pattern.search(header_value):
            if verbose:
                logger.info(f"Header fingerprint matched: {header_key} = {header_value} at {full_url}")
            return {
                "found": True,
                "url": full_url,
                "status_code": response.status_code,
                "version": version,
                "evidence": f"Header {header_key}: {header_value}"
            }

    elif method == "body" and compiled_pattern:
        body = response.text[:100_000]
        if compiled_pattern.search(body):
            if verbose:
                logger.info(f"Body fingerprint matched pattern: {pattern} at {full_url}")
            return {
                "found": True,
                "url": full_url,
                "status_code": response.status_code,
                "version": version,
                "evidence": f"Body content matched pattern: {pattern}"
            }

    return None

# --------------------------
# Main Detection Logic
# --------------------------

def fetch_and_check_url(
    session: Session,
    base_url: str,
    path: str,
    fingerprints: List[Dict],
    compiled_patterns: List[Tuple[Dict, Optional[Pattern]]],
    timeout: int,
    verbose: bool
) -> Optional[Dict]:

    full_url = urljoin(base_url + "/", path.lstrip("/"))
    if verbose:
        logger.info(f"Trying path: {full_url}")

    try:
        response = session.get(full_url, timeout=timeout)
        if verbose:
            logger.info(f"Status code for {full_url}: {response.status_code}")

        if not response.ok:
            return None

        for fp, compiled_pattern in compiled_patterns:
            result = match_fingerprint(response, full_url, fp, compiled_pattern, verbose)
            if result:
                return result

    except (Timeout, ConnectionError, RequestException) as e:
        if verbose:
            logger.warning(f"Request error for {full_url}: {e}")

    return None

def detect_mailman(
    base_url: str,
    common_paths: List[str],
    fingerprints: List[Dict],
    timeout: int = 3,
    verbose: bool = False,
    max_threads: int = 10
) -> Dict:

    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {
            "found": False,
            "error": "Invalid URL format. Must include scheme (http or https) and domain."
        }

    session = Session()
    session.headers.update({"User-Agent": "MailmapScanner/1.0"})

    # Compile regex patterns once
    compiled_fingerprints: List[Tuple[Dict, Optional[Pattern]]] = []
    for fp in fingerprints:
        pattern = fp.get("pattern", "")
        compiled = compile(pattern, flags=IGNORECASE) if pattern else None
        compiled_fingerprints.append((fp, compiled))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(
                fetch_and_check_url,
                session,
                base_url,
                path,
                fingerprints,
                compiled_fingerprints,
                timeout,
                verbose
            ): path for path in common_paths
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                return result

    return {
        "found": False,
        "reason": "No known Mailman path responded with recognizable content."
    }

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

    result = detect_mailman(
        base_url,
        common_paths,
        fingerprints,
        timeout=settings.get("timeout", 3),
        verbose=settings.get("verbose", False),
        max_threads=settings.get("max_threads", 10)
    )

    return result.get("found", False), result

# --------------------------
# CLI Runner
# --------------------------

if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    settings = {
        "timeout": 3,
        "paths": "data/common_paths.json",
        "fingerprints": "data/fingerprints.json",
        "verbose": True,
        "max_threads": 10
    }

    found, result = check_mailman(target, settings)
    print("[+] Mailman Detected" if found else "[!] Mailman Not Found")
    print(result)
