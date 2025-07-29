from re import compile as re_compile, IGNORECASE
from requests import Session
from requests.exceptions import (
    Timeout,
    ConnectionError,
    RequestException,
    TooManyRedirects,
    HTTPError
)
from urllib.parse import urljoin, urlparse
from time import sleep
from logging import getLogger, basicConfig, INFO, DEBUG
from argparse import ArgumentParser
from sys import exit as sys_exit
from typing import Optional, Dict, Set, List, Union
from json import load as json_load

logger = getLogger(__name__)

# Load fingerprints data from JSON file
def load_fingerprints(filepath: str) -> List[Dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        return data
    except Exception as e:
        logger.error(f"Failed to load fingerprints file: {e}")
        return []

def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def extract_version_from_text(text: str, pattern: re_compile) -> Optional[str]:
    match = pattern.search(text)
    if match:
        # Try to find group 1 or the entire match
        try:
            return match.group(1).strip()
        except IndexError:
            return match.group(0).strip()
    return None

def detect_version(base_url: str, settings: Dict[str, Union[str, int, float]], fingerprints: List[Dict]) -> Dict[str, Union[str, bool, List[str], None]]:
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must include scheme (http or https) and domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agents = [settings.get("user_agent")] if settings.get("user_agent") else [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    ]
    delay = settings.get("delay", 1)

    session = Session()
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    found_versions: Set[str] = set()
    user_agent_index = 0

    for fp in fingerprints:
        method = fp.get("method")
        location = fp.get("location")
        pattern_str = fp.get("pattern")
        version = fp.get("version")

        pattern = re_compile(pattern_str, IGNORECASE) if pattern_str else None

        # Determine URL to check based on method
        if method == "url":
            # location here is the path to check existence
            url_to_check = urljoin(base_url + "/", location.lstrip("/"))
            try:
                session.headers.update({
                    "User-Agent": user_agents[user_agent_index % len(user_agents)]
                })
                user_agent_index += 1

                response = session.get(url_to_check, timeout=timeout)
                if response.status_code == 200:
                    # If there's no pattern, just presence is enough to confirm version
                    if not pattern:
                        found_versions.add(version)
                    else:
                        # If pattern present, check in body
                        if pattern.search(response.text):
                            found_versions.add(version)
            except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError) as e:
                logger.debug(f"Request error at {url_to_check}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error at {url_to_check}: {e}")

        elif method == "header":
            # location is header name, so try multiple URLs if needed
            # We'll check some common paths (root + /mailman)
            urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
            found_in_header = False
            for u in urls_to_try:
                try:
                    session.headers.update({
                        "User-Agent": user_agents[user_agent_index % len(user_agents)]
                    })
                    user_agent_index += 1

                    response = session.get(u, timeout=timeout)
                    if not response.ok:
                        continue

                    header_val = response.headers.get(location)
                    if header_val and pattern:
                        ver_found = extract_version_from_text(header_val, pattern)
                        if ver_found:
                            found_versions.add(ver_found)
                            found_in_header = True
                            break
                except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError) as e:
                    logger.debug(f"Request error at {u}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error at {u}: {e}")

            if found_in_header:
                # Don't try further for this fingerprint
                continue

        elif method == "body":
            # location is ignored, we just try to find pattern in response body for certain URLs
            urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
            for u in urls_to_try:
                try:
                    session.headers.update({
                        "User-Agent": user_agents[user_agent_index % len(user_agents)]
                    })
                    user_agent_index += 1

                    response = session.get(u, timeout=timeout)
                    if not response.ok or "text" not in response.headers.get("Content-Type", "").lower():
                        continue

                    content = response.text[:100_000]
                    if pattern:
                        ver_found = extract_version_from_text(content, pattern)
                        if ver_found:
                            found_versions.add(ver_found)
                            break
                except (Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError) as e:
                    logger.debug(f"Request error at {u}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error at {u}: {e}")

    sleep(delay)

    if not found_versions:
        return {"version": None}
    if len(found_versions) == 1:
        return {"version": found_versions.pop()}
    return {"conflict": True, "versions": list(found_versions)}

def get_version(base_url: str, settings: Dict[str, Union[str, int, float]], fingerprint_file: str = "data/fingerprints.json") -> Dict:
    fingerprints = load_fingerprints(fingerprint_file)
    return detect_version(base_url, settings, fingerprints)

# CLI support
if __name__ == "__main__":
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

    parser = ArgumentParser(description="Mailman Version Detector with Fingerprints")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout (seconds)")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests (seconds)")
    parser.add_argument("--fingerprints", default="data/fingerprints.json", help="Path to fingerprints JSON file")

    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "delay": args.delay,
    }

    result = get_version(args.target, settings, args.fingerprints)

    if result.get("conflict"):
        print("Version conflict detected! Found versions:", ", ".join(result["versions"]))
    elif result.get("version"):
        print("Detected Mailman version:", result["version"])
    else:
        print("No Mailman version detected.")
