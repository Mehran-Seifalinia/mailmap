from json import load
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from random import choice
from typing import List, Dict
from urllib3 import disable_warnings, exceptions as urllib3_exceptions
from re import compile as re_compile
from sys import exit as sys_exit

# Disable SSL warnings (since verify=False is used)
disable_warnings(urllib3_exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]

REQUEST_DELAY = 1  # Delay between requests

# Precompiled pattern for detecting Mailman-related content
MAILMAN_PATTERN = re_compile(
    r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)",
    flags=2  # re.IGNORECASE
)

def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = load(f)
        if version == "v2":
            return data.get("v2_paths", [])
        elif version == "v3":
            return data.get("v3_paths", [])
        else:
            print(f"[!] Unknown version '{version}', defaulting to 'v2'")
            return data.get("v2_paths", [])
    except (FileNotFoundError, OSError) as e:
        print(f"[!] Error loading common paths file: {e}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error loading common paths file: {e}")
        return []

def check_paths(base_url: str, paths: List[Dict], timeout: int = 5) -> List[Dict]:
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return [{"error": "Invalid URL format. Must include scheme (http or https) and domain."}]

    session = Session()
    session.headers.update({"User-Agent": choice(USER_AGENTS)})

    accessible_paths = []

    for item in paths:
        path = item.get("path")
        if not path:
            continue

        full_url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            response = session.get(full_url, timeout=timeout, verify=False)
            if response.status_code == 200 and MAILMAN_PATTERN.search(response.text):
                accessible_paths.append({
                    "path": path,
                    "status_code": response.status_code,
                    "description": item.get("description", ""),
                    "access_level": item.get("access_level", "unknown")
                })
        except (Timeout, ConnectionError) as e:
            print(f"[!] Connection error at {full_url}: {e}")
        except (TooManyRedirects, HTTPError, RequestException) as e:
            print(f"[!] Request failed at {full_url}: {e}")
        except Exception as e:
            print(f"[!] Unexpected error at {full_url}: {e}")

        sleep(REQUEST_DELAY)

    return accessible_paths

# Test block for standalone execution
if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    version = input("Enter Mailman version to scan (v2 or v3): ").strip().lower()

    if version not in ["v2", "v3"]:
        print("[!] Invalid version specified. Defaulting to v2.")
        version = "v2"

    paths = load_common_paths("data/common_paths.json", version)
    if not paths:
        print("[!] No paths loaded. Exiting.")
        sys_exit(1)

    results = check_paths(target, paths)
    if results and isinstance(results[0], dict) and "error" in results[0]:
        print("Error:", results[0]["error"])
    elif results:
        print("\nAccessible Mailman paths:")
        for item in results:
            print(f"{item['path']} - HTTP {item['status_code']} - {item['description']} - Access level: {item['access_level']}")
    else:
        print("No accessible Mailman paths found.")
