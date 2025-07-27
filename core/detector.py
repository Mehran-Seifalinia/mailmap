from re import compile, escape, IGNORECASE
from requests import Session, Timeout, ConnectionError, RequestException
from urllib.parse import urljoin, urlparse
from json import load, JSONDecodeError
from logging import getLogger, basicConfig, INFO, error
from typing import List

# Setup logger
logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

def load_json_file(filepath: str):
    """Load JSON data from a file."""
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
    """Validate URL scheme and netloc."""
    parsed = urlparse(url)
    return all([parsed.scheme in ("http", "https"), parsed.netloc])

def detect_mailman(base_url: str, common_paths: List[str], fingerprints: List[str], timeout: int = 5) -> dict:
    """Detect Mailman installation on target base URL using given paths and fingerprints."""
    base_url = base_url.rstrip("/")

    if not is_valid_url(base_url):
        return {
            "found": False,
            "error": "Invalid URL format. Must include scheme (http or https) and domain."
        }

    session = Session()
    session.headers.update({"User-Agent": "MailmapScanner/1.0"})

    # Compile fingerprints regex once for performance
    combined_fingerprint_regex = compile("|".join(map(escape, fingerprints)), flags=IGNORECASE)

    for path in common_paths:
        full_url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            response = session.get(full_url, timeout=timeout)
            if not response.ok:
                continue

            response.raise_for_status()

            content = response.text[:100_000]  # Limit content size to 100KB

            match = combined_fingerprint_regex.search(content)
            if match:
                return {
                    "found": True,
                    "url": full_url,
                    "status_code": response.status_code,
                    "evidence": match.group(),
                }

        except (Timeout, ConnectionError, RequestException):
            continue

    return {
        "found": False,
        "reason": "No known Mailman path responded with recognizable content."
    }

if __name__ == "__main__":
    import sys

    # Load data files
    common_paths = load_json_file("data/common_paths.json")
    fingerprints = load_json_file("data/fingerprints.json")

    if common_paths is None or fingerprints is None:
        logger.error("Failed to load required data files. Exiting.")
        sys.exit(1)

    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    result = detect_mailman(target, common_paths, fingerprints)
    print(result)
