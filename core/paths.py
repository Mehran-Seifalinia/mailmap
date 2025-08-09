from json import load as json_load
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from random import choice
from typing import List, Dict, Union
from urllib3 import disable_warnings, exceptions as urllib3_exceptions
from re import compile as re_compile, IGNORECASE
from sys import exit as sys_exit
from signal import signal, SIGINT
from logging import getLogger, StreamHandler, Formatter, DEBUG
from colorama import Fore, Style, init as colorama_init

# Initialize colorama for colored output
colorama_init(autoreset=True)

# Disable SSL warnings (since verify=False is used)
disable_warnings(urllib3_exceptions.InsecureRequestWarning)

# Setup logger with color support and formatting
logger = getLogger("mailmap_path")
logger.setLevel(DEBUG)
handler = StreamHandler()
formatter = Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]

REQUEST_DELAY = 1  # seconds delay between requests

# Precompiled regex for Mailman-related content detection (case-insensitive)
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
    If missing, prepend 'http://'.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        logger.debug(f"Scheme missing in URL '{url}', prepending 'http://'")
        return "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    """
    Validate URL has valid HTTP/HTTPS scheme and a network location.
    """
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL format. URL must start with http:// or https:// and include a domain.")
    return valid

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict]:
    """
    Load common Mailman paths from JSON file for the specified version.

    Args:
        filepath (str): JSON file path.
        version (str): Mailman version ('v2' or 'v3').

    Returns:
        List[Dict]: List of path entries.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        if version == "v2":
            return data.get("v2_paths", [])
        elif version == "v3":
            return data.get("v3_paths", [])
        else:
            logger.warning(f"Unknown version '{version}', defaulting to 'v2'")
            return data.get("v2_paths", [])
    except (FileNotFoundError, OSError) as e:
        logger.error(f"Error loading common paths file: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading common paths file: {e}")
        return []

def check_paths(
    base_url: str,
    paths: List[Dict],
    timeout: int = 5,
    request_delay: int = REQUEST_DELAY
) -> List[Dict]:
    """
    Check accessibility of common Mailman paths under base_url.

    Args:
        base_url (str): Base URL to scan.
        paths (List[Dict]): List of paths to check.
        timeout (int): HTTP request timeout in seconds.
        request_delay (int): Delay between requests in seconds.

    Returns:
        List[Dict]: Accessible paths info or empty list.
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

            if status == 200:
                if MAILMAN_PATTERN.search(response.text):
                    accessible_paths.append({
                        "path": path,
                        "status_code": status,
                        "description": item.get("description", ""),
                        "access_level": item.get("access_level", "unknown")
                    })
                    logger.info(f"{Fore.GREEN}Accessible path found: {full_url} - HTTP {status}{Style.RESET_ALL}")
                else:
                    logger.debug(f"Path {full_url} responded 200 but content did not match Mailman pattern.")
            elif 300 <= status < 400:
                logger.info(f"{Fore.BLUE}Redirect at {full_url} - HTTP {status}{Style.RESET_ALL}")
                accessible_paths.append({
                    "path": path,
                    "status_code": status,
                    "description": item.get("description", "") + " (Redirect)",
                    "access_level": item.get("access_level", "unknown")
                })
            else:
                logger.warning(f"{Fore.YELLOW}Non-200/3xx status at {full_url}: HTTP {status}{Style.RESET_ALL}")

        except (Timeout, ConnectionError) as e:
            logger.warning(f"{Fore.YELLOW}Connection error at {full_url}: {e}{Style.RESET_ALL}")
        except (TooManyRedirects, HTTPError, RequestException) as e:
            logger.warning(f"{Fore.YELLOW}Request failed at {full_url}: {e}{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"{Fore.RED}Unexpected error at {full_url}: {e}{Style.RESET_ALL}")

        sleep(request_delay)

    return accessible_paths

def main():
    """
    Main function to run path accessibility checks interactively.
    """
    try:
        target = input("Enter target base URL (e.g., https://example.com): ").strip()
        target = ensure_scheme(target)

        version = input("Enter Mailman version to scan (v2 or v3): ").strip().lower()
        if version not in ["v2", "v3"]:
            logger.warning(f"Invalid version specified. Defaulting to v2.")
            version = "v2"

        paths = load_common_paths("data/common_paths.json", version)
        if not paths:
            logger.error("No paths loaded. Exiting.")
            sys_exit(1)

        results = check_paths(target, paths)
        if results and isinstance(results[0], dict) and "error" in results[0]:
            logger.error(f"Error: {results[0]['error']}")
        elif results:
            print(f"\n{Fore.GREEN}Accessible Mailman paths:{Style.RESET_ALL}")
            for item in results:
                print(f"{Fore.CYAN}{item['path']} - HTTP {item['status_code']} - "
                      f"{item['description']} - Access level: {item['access_level']}{Style.RESET_ALL}")
        else:
            logger.warning("No accessible Mailman paths found.")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
        sys_exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys_exit(1)

if __name__ == "__main__":
    main()
