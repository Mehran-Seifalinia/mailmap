from json import load
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from random import choice
from typing import List, Dict, Union, Optional
from urllib3 import disable_warnings, exceptions as urllib3_exceptions
from re import compile as re_compile, IGNORECASE
from sys import exit as sys_exit
from signal import signal, SIGINT
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Disable SSL warnings (since verify=False is used)
disable_warnings(urllib3_exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]

REQUEST_DELAY = 1  # seconds delay between requests

# Precompiled pattern for Mailman-related content detection (case-insensitive)
MAILMAN_PATTERN = re_compile(
    r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)",
    flags=IGNORECASE
)

def handle_sigint(signum, frame):
    """Handle Ctrl+C (SIGINT) signal to exit gracefully."""
    print(f"\n{Fore.RED}[!] Interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
    sys_exit(0)

signal(SIGINT, handle_sigint)

def ensure_scheme(url: str) -> str:
    """
    Ensure the URL has an HTTP or HTTPS scheme.
    If missing, add 'http://' by default.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    """
    Validate if the given URL has valid scheme and netloc.
    """
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict]:
    """
    Load common Mailman paths from a JSON file for the specified version.

    Args:
        filepath (str): Path to the JSON file.
        version (str): Mailman version ('v2' or 'v3').

    Returns:
        List[Dict]: List of path dictionaries.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = load(f)
        if version == "v2":
            return data.get("v2_paths", [])
        elif version == "v3":
            return data.get("v3_paths", [])
        else:
            print(f"{Fore.YELLOW}[!] Unknown version '{version}', defaulting to 'v2'{Style.RESET_ALL}")
            return data.get("v2_paths", [])
    except (FileNotFoundError, OSError) as e:
        print(f"{Fore.RED}[!] Error loading common paths file: {e}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error loading common paths file: {e}{Style.RESET_ALL}")
        return []

def check_paths(
    base_url: str,
    paths: List[Dict],
    timeout: int = 5,
    request_delay: int = REQUEST_DELAY
) -> Union[List[Dict], List[Dict[str, str]]]:
    """
    Check accessibility of common Mailman paths under the given base URL.

    Args:
        base_url (str): The base URL to scan.
        paths (List[Dict]): List of paths to check.
        timeout (int): Request timeout in seconds.
        request_delay (int): Delay between requests in seconds.

    Returns:
        List[Dict]: List of accessible paths with details or error dictionary.
    """
    base_url = base_url.rstrip("/")
    base_url = ensure_scheme(base_url)
    
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
            status = response.status_code

            # Accept 200 OK and 3xx redirects as accessible for scanning purposes
            if status == 200:
                content_matches = MAILMAN_PATTERN.search(response.text)
                if content_matches:
                    accessible_paths.append({
                        "path": path,
                        "status_code": status,
                        "description": item.get("description", ""),
                        "access_level": item.get("access_level", "unknown")
                    })
            elif 300 <= status < 400:
                print(f"{Fore.BLUE}[i] Redirect detected at {full_url} - HTTP {status}{Style.RESET_ALL}")
                accessible_paths.append({
                    "path": path,
                    "status_code": status,
                    "description": item.get("description", "") + " (Redirect)",
                    "access_level": item.get("access_level", "unknown")
                })
            else:
                print(f"{Fore.YELLOW}[!] Non-200/3xx status at {full_url}: HTTP {status}{Style.RESET_ALL}")

        except (Timeout, ConnectionError) as e:
            print(f"{Fore.YELLOW}[!] Connection error at {full_url}: {e}{Style.RESET_ALL}")
        except (TooManyRedirects, HTTPError, RequestException) as e:
            print(f"{Fore.YELLOW}[!] Request failed at {full_url}: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error at {full_url}: {e}{Style.RESET_ALL}")

        sleep(request_delay)

    return accessible_paths

def main():
    """Main interactive function to run the path check."""
    try:
        target = input("Enter target base URL (e.g., https://example.com): ").strip()
        target = ensure_scheme(target)

        version = input("Enter Mailman version to scan (v2 or v3): ").strip().lower()
        if version not in ["v2", "v3"]:
            print(f"{Fore.YELLOW}[!] Invalid version specified. Defaulting to v2.{Style.RESET_ALL}")
            version = "v2"

        paths = load_common_paths("data/common_paths.json", version)
        if not paths:
            print(f"{Fore.RED}[!] No paths loaded. Exiting.{Style.RESET_ALL}")
            sys_exit(1)

        results = check_paths(target, paths)
        if results and isinstance(results[0], dict) and "error" in results[0]:
            print(f"{Fore.RED}Error: {results[0]['error']}{Style.RESET_ALL}")
        elif results:
            print(f"\n{Fore.GREEN}Accessible Mailman paths:{Style.RESET_ALL}")
            for item in results:
                print(f"{Fore.CYAN}{item['path']} - HTTP {item['status_code']} - {item['description']} - Access level: {item['access_level']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No accessible Mailman paths found.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
        sys_exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys_exit(1)

if __name__ == "__main__":
    main()
