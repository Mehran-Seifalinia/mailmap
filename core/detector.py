from re import compile, IGNORECASE
from requests import Session, Timeout, ConnectionError, RequestException
from urllib.parse import urljoin, urlparse
from json import load, JSONDecodeError
from logging import getLogger, basicConfig, INFO
from typing import List, Dict, Optional, Tuple

logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')


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


def detect_mailman(
    base_url: str,
    common_paths: List[str],
    fingerprints: List[Dict],
    timeout: int = 5,
    verbose: bool = False
) -> Dict:
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {
            "found": False,
            "error": "Invalid URL format. Must include scheme (http or https) and domain."
        }

    session = Session()
    session.headers.update({"User-Agent": "MailmapScanner/1.0"})

    for path in common_paths:
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        if verbose:
            logger.info(f"Trying path: {full_url}")
        try:
            response = session.get(full_url, timeout=timeout)
            if verbose:
                logger.info(f"Status code for {full_url}: {response.status_code}")
            if not response.ok:
                continue

            headers = response.headers
            body = response.text[:100_000]

            for fp in fingerprints:
                method = fp.get("method", "").lower()
                location = fp.get("location", "")
                pattern = fp.get("pattern", "")
                version = fp.get("version", "Unknown")

                if method == "url":
                    if not pattern:
                        if location and location in full_url:
                            if verbose:
                                logger.info(f"URL fingerprint matched: {location} at {full_url}")
                            return {
                                "found": True,
                                "url": full_url,
                                "status_code": response.status_code,
                                "version": version,
                                "evidence": f"URL path matched: {location}"
                            }
                    else:
                        regex = compile(pattern, flags=IGNORECASE)
                        if regex.search(full_url):
                            if verbose:
                                logger.info(f"URL regex fingerprint matched: {pattern} at {full_url}")
                            return {
                                "found": True,
                                "url": full_url,
                                "status_code": response.status_code,
                                "version": version,
                                "evidence": f"URL matched pattern: {pattern}"
                            }
                    continue

                if not pattern:
                    continue

                regex = compile(pattern, flags=IGNORECASE)

                if method == "header":
                    header_key = location.split(".", 1)[1] if location.startswith("headers.") else location
                    header_value = headers.get(header_key, "")
                    if header_value and regex.search(header_value):
                        if verbose:
                            logger.info(f"Header fingerprint matched: {header_key} = {header_value} at {full_url}")
                        return {
                            "found": True,
                            "url": full_url,
                            "status_code": response.status_code,
                            "version": version,
                            "evidence": f"Header {header_key}: {header_value}"
                        }

                elif method == "body":
                    if regex.search(body):
                        if verbose:
                            logger.info(f"Body fingerprint matched pattern: {pattern} at {full_url}")
                        return {
                            "found": True,
                            "url": full_url,
                            "status_code": response.status_code,
                            "version": version,
                            "evidence": f"Body content matched pattern: {pattern}"
                        }

        except (Timeout, ConnectionError, RequestException) as e:
            if verbose:
                logger.warning(f"Request error for {full_url}: {e}")
            continue

    return {
        "found": False,
        "reason": "No known Mailman path responded with recognizable content."
    }


def check_mailman(base_url: str, settings: Dict) -> Tuple[bool, Dict]:
    paths_file = settings.get("paths", "data/common_paths.json")
    common_paths_data = load_json_file(paths_file)
    fingerprints = load_json_file(settings.get("fingerprints", "data/fingerprints.json"))

    if common_paths_data is None or fingerprints is None:
        return False, {"error": "Failed to load required data files."}

    common_paths = []
    for key in ["v2_paths", "v3_paths"]:
        common_paths.extend([item["path"] for item in common_paths_data.get(key, [])])

    result = detect_mailman(
        base_url,
        common_paths,
        fingerprints,
        timeout=settings.get("timeout", 5),
        verbose=settings.get("verbose", False)
    )

    return result.get("found", False), result


if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    settings = {
        "timeout": 5,
        "paths": "data/common_paths.json",
        "fingerprints": "data/fingerprints.json"
    }

    found, result = check_mailman(target, settings)
    print("[+] Mailman Detected" if found else "[!] Mailman Not Found")
    print(result)
