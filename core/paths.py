from json import load as json_load
from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from random import choice
from typing import List, Dict
from urllib3 import disable_warnings
from urllib3 import exceptions as urllib3_exceptions
from re import compile as re_compile, IGNORECASE
from sys import exit as sys_exit
from signal import signal, SIGINT
from logging import getLogger, StreamHandler, Formatter, DEBUG, INFO
from colorama import Fore, Style, init as colorama_init

# -----------------------------
# Color and SSL warning setup
# -----------------------------
# Initialize colorama for colored terminal output
colorama_init(autoreset=True)

# Suppress SSL warnings because verify=False is used intentionally here
disable_warnings(urllib3_exceptions.InsecureRequestWarning)

# -----------------------------
# Logger setup
# -----------------------------
logger = getLogger("mailmap_path")

# Prevent duplicate handlers if module is imported multiple times
if not logger.handlers:
    handler = StreamHandler()
    handler.setFormatter(Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)

# Default to INFO: only essential messages (200 OK) will be printed.
# When verbose=True, we will bump to DEBUG at runtime to show extras.
logger.setLevel(INFO)

# -----------------------------
# HTTP settings
# -----------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]
REQUEST_DELAY = 1  # seconds between requests

# Precompiled regex for detecting Mailman-related content (case-insensitive)
MAILMAN_PATTERN = re_compile(
    r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)",
    flags=IGNORECASE
)

# -----------------------------
# Signal handling
# -----------------------------
def handle_sigint(signum, frame) -> None:
    """Gracefully exit on Ctrl+C (SIGINT)."""
    print(f"\n{Fore.RED}[!] Interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
    sys_exit(0)

signal(SIGINT, handle_sigint)

# -----------------------------
# Helpers
# -----------------------------
def configure_logger(verbose: bool) -> None:
    """
    Configure logger level based on verbosity.
    - verbose=False: INFO → only essential, success messages (HTTP 200 + matched content)
    - verbose=True:  DEBUG → include redirects, non-200/3xx statuses, and network issues
    """
    logger.setLevel(DEBUG if verbose else INFO)

def ensure_scheme(url: str) -> str:
    """
    Ensure URL includes an HTTP/HTTPS scheme; prepend 'http://' if missing.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        logger.debug(f"Scheme missing in URL '{url}', prepending 'http://'")
        return "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    """
    Validate that URL has a valid HTTP/HTTPS scheme and a network location.
    """
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        # Keep as ERROR: input is invalid and should always be shown.
        logger.error("Invalid URL format. URL must start with http:// or https:// and include a domain.")
    return valid

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict]:
    """
    Load common Mailman paths from a JSON file for a given version.

    Args:
        filepath: Path to JSON file.
        version:  'v2' or 'v3'.

    Returns:
        List of path dicts (may be empty if file missing or invalid).
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        if version == "v2":
            return data.get("v2_paths", [])
        if version == "v3":
            return data.get("v3_paths", [])
        logger.debug(f"Unknown version '{version}', defaulting to 'v2'")
        return data.get("v2_paths", [])
    except (FileNotFoundError, OSError) as e:
        # Keep as ERROR: this is critical for program flow.
        logger.error(f"Error loading common paths file: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading common paths file: {e}")
        return []

# -----------------------------
# Core scanning
# -----------------------------
def check_paths(
    base_url: str,
    paths: List[Dict],
    timeout: int = 5,
    request_delay: int = REQUEST_DELAY,
    verbose: bool = False
) -> List[Dict]:
    """
    Check accessibility of common Mailman paths under a base URL.

    Printing policy (controlled by `verbose`):
      - verbose=False → Only log HTTP 200 + content-matched paths (green).
      - verbose=True  → Additionally log redirects (3xx), non-200/3xx statuses (e.g., 404/403/500),
                        network issues, and 200s without Mailman content (as debug).

    Args:
        base_url: Base URL to scan.
        paths:    List of dict entries; each must contain a 'path'.
        timeout:  Per-request timeout in seconds.
        request_delay: Delay between requests to be polite.
        verbose:  Toggle extended logging.

    Returns:
        A list of dicts describing discovered paths (includes 3xx entries in data regardless of verbosity).
    """
    configure_logger(verbose)

    base_url = ensure_scheme(base_url.rstrip("/"))

    if not is_valid_url(base_url):
        return [{"error": "Invalid URL format. Must include scheme (http or https) and domain."}]

    session = Session()
    session.headers.update({"User-Agent": choice(USER_AGENTS)})

    accessible_paths: List[Dict] = []

    for item in paths:
        path = item.get("path")
        if not path:
            logger.debug("Skipping an entry without 'path' key.")
            continue

        full_url = urljoin(base_url + "/", path.lstrip("/"))

        try:
            response = session.get(full_url, timeout=timeout, verify=False)
            status = response.status_code
            text = response.text if status == 200 else ""

            # Case 1: 200 OK + content looks like Mailman → always informative
            if status == 200 and MAILMAN_PATTERN.search(text):
                accessible_paths.append({
                    "path": path,
                    "status_code": status,
                    "description": item.get("description", ""),
                    "access_level": item.get("access_level", "unknown")
                })
                logger.info(f"{Fore.GREEN}Accessible path found: {full_url} - HTTP {status}{Style.RESET_ALL}")

            # Case 2: 200 OK but content does not look like Mailman → debug only
            elif status == 200:
                logger.debug(
                    f"Path {full_url} responded 200 but content did not match Mailman pattern."
                )

            # Case 3: Redirects (3xx) → include in data, print only in verbose
            elif 300 <= status < 400:
                accessible_paths.append({
                    "path": path,
                    "status_code": status,
                    "description": item.get("description", "") + " (Redirect)",
                    "access_level": item.get("access_level", "unknown")
                })
                logger.debug(f"{Fore.BLUE}Redirect at {full_url} - HTTP {status}{Style.RESET_ALL}")

            # Case 4: Non-200/3xx statuses (e.g., 404/403/500) → debug only
            else:
                logger.debug(f"Non-200/3xx status at {full_url}: HTTP {status}")

        except (Timeout, ConnectionError) as e:
            # Network issues: only show in verbose
            logger.debug(f"Connection error at {full_url}: {e}")
        except (TooManyRedirects, HTTPError, RequestException) as e:
            logger.debug(f"Request failed at {full_url}: {e}")
        except Exception as e:
            # Unexpected exceptions should always be visible
            logger.error(f"{Fore.RED}Unexpected error at {full_url}: {e}{Style.RESET_ALL}")

        sleep(request_delay)

    return accessible_paths

# -----------------------------
# Interactive entrypoint
# -----------------------------
def main() -> None:
    """
    Interactive runner. Keeps printing policy consistent with `verbose`.
    In non-verbose mode, only 200+matched entries are printed.
    In verbose mode, redirects and other details are printed via DEBUG logs.
    """
    try:
        target = input("Enter target base URL (e.g., https://example.com): ").strip()
        version = input("Enter Mailman version to scan (v2 or v3): ").strip().lower()
        verbose_input = input("Verbose output? (y/N): ").strip().lower()
        verbose = verbose_input in ("y", "yes", "true", "1")

        configure_logger(verbose)
        target = ensure_scheme(target)

        if version not in ["v2", "v3"]:
            logger.debug(f"Invalid version '{version}', defaulting to v2.")
            version = "v2"

        paths = load_common_paths("data/common_paths.json", version)
        if not paths:
            logger.error("No paths loaded. Exiting.")
            sys_exit(1)

        results = check_paths(target, paths, verbose=verbose)
        if results and isinstance(results[0], dict) and "error" in results[0]:
            logger.error(f"Error: {results[0]['error']}")
        elif results:
            # In non-verbose mode, print only 200 OK + matched entries
            printable = results if verbose else [r for r in results if r.get("status_code") == 200]

            if printable:
                print(f"\n{Fore.GREEN}Accessible Mailman paths:{Style.RESET_ALL}")
                for item in printable:
                    print(
                        f"{Fore.CYAN}{item['path']} - HTTP {item['status_code']} - "
                        f"{item.get('description','')} - Access level: {item.get('access_level','unknown')}{Style.RESET_ALL}"
                    )
            else:
                # Keep quiet if nothing matched in non-verbose; still show a single line to inform.
                logger.info("No accessible Mailman paths (HTTP 200 + matched content) found.")
        else:
            logger.info("No accessible Mailman paths found.")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
        sys_exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys_exit(1)

if __name__ == "__main__":
    main()
