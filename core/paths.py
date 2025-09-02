from json import load as json_load
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests import Session, RequestException, head, get
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin, urlparse
from time import sleep
from random import choice, uniform
from typing import List, Dict, Any
from urllib3 import disable_warnings, exceptions as urllib3_exceptions
from re import compile as re_compile, IGNORECASE
from sys import exit as sys_exit
from signal import signal, SIGINT
from logging import getLogger, DEBUG, INFO
from threading import local, Lock

# -----------------------------------------------------------
# Suppress insecure request warnings and urllib3 retry warnings
# -----------------------------------------------------------
disable_warnings(urllib3_exceptions.InsecureRequestWarning)
logging_logger = getLogger("urllib3")
logging_logger.setLevel(INFO)  # hide detailed retry warnings

# -----------------------------------------------------------
# Shared logger (configured globally)
# -----------------------------------------------------------
logger = getLogger("mailmap")

# -----------------------------------------------------------
# HTTP / scanning defaults
# -----------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]

DEFAULT_TIMEOUT = 3
DEFAULT_REQUEST_DELAY = 0.12
DEFAULT_MAX_WORKERS = 10
DEFAULT_MAX_CONTENT_BYTES = 100 * 1024
DEFAULT_RETRIES = 0  # disable retries

MAILMAN_PATTERN = re_compile(
    r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)",
    flags=IGNORECASE
)

_thread_local = local()  # thread-local session storage
print_lock = Lock()      # lock for printing safely in threads

# -----------------------------------------------------------
# Handle Ctrl+C interruption
# -----------------------------------------------------------
def handle_sigint(signum, frame) -> None:
    logger.warning("Interrupted by user (Ctrl+C). Exiting...")
    sys_exit(0)

signal(SIGINT, handle_sigint)

# -----------------------------------------------------------
# Helper functions
# -----------------------------------------------------------
def configure_logger(verbose: bool) -> None:
    """Configure global logger level based on verbose flag."""
    logger.setLevel(DEBUG if verbose else INFO)

def ensure_scheme(url: str) -> str:
    """Ensure URL has http/https scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        logger.debug(f"Scheme missing in URL '{url}', prepending 'http://'")
        return "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    """Check if URL has valid scheme and host."""
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL. Must start with http:// or https:// and include a domain.")
    return valid

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict[str, Any]]:
    """Load common paths from JSON file based on Mailman version."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        if version == "v2":
            return data.get("v2_paths", [])
        if version == "v3":
            return data.get("v3_paths", [])
        logger.debug(f"Unknown version '{version}' requested; defaulting to v2 paths.")
        return data.get("v2_paths", [])
    except (FileNotFoundError, OSError) as e:
        logger.error(f"Error loading common paths file: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading common paths file: {e}")
        return []

# -----------------------------------------------------------
# Create per-thread HTTP session
# -----------------------------------------------------------
def _get_thread_session(timeout: int = DEFAULT_TIMEOUT) -> Session:
    """Return a thread-local session with retries disabled."""
    if getattr(_thread_local, "session", None) is None:
        s = Session()
        retry = Retry(
            total=DEFAULT_RETRIES,  # disable retries
            backoff_factor=0,
            status_forcelist=[]
        )
        # Set allowed methods for retry object (for older urllib3)
        try:
            retry.allowed_methods = frozenset(["HEAD", "GET", "OPTIONS"])
        except Exception:
            try:
                retry.method_whitelist = frozenset(["HEAD", "GET", "OPTIONS"])
            except Exception:
                pass
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers.update({"User-Agent": choice(USER_AGENTS)})
        _thread_local.session = s
    return _thread_local.session

# -----------------------------------------------------------
# Check a single path
# -----------------------------------------------------------
def _check_single_path(
    base_url: str,
    item: Dict[str, Any],
    timeout: float,
    request_delay: float,
    max_content_bytes: int
) -> Dict[str, Any]:
    """Check a single URL path for Mailman presence and return result dict."""
    path = item.get("path")
    if not path:
        return {"error": "missing_path_key", "detail": "Entry did not include 'path' key."}

    full_url = urljoin(base_url + "/", path.lstrip("/"))
    session = _get_thread_session()
    sleep(uniform(0, request_delay))  # random delay to avoid detection

    try:
        # Try HEAD request first
        try:
            head_resp = session.head(full_url, timeout=timeout, allow_redirects=True, verify=False)
            status = head_resp.status_code
        except RequestException:
            status = None

        # GET request only if HEAD failed or status != 200
        text = ""
        if status != 200:
            try:
                get_resp = session.get(full_url, timeout=timeout, allow_redirects=True, stream=True, verify=False)
                status = get_resp.status_code
                if status == 200:
                    content_chunks = []
                    bytes_read = 0
                    for chunk in get_resp.iter_content(chunk_size=4096):
                        if not chunk:
                            break
                        content_chunks.append(chunk)
                        bytes_read += len(chunk)
                        if bytes_read >= max_content_bytes:
                            break
                    encoding = get_resp.encoding or "utf-8"
                    text = b"".join(content_chunks).decode(encoding, errors="replace")
            except RequestException:
                pass

        # Pattern matching for Mailman
        matched = False
        evidence = ""
        if status == 200 and text:
            m = MAILMAN_PATTERN.search(text)
            if m:
                matched = True
                evidence = f"Body matched pattern: {m.group(0)}"

        # Heuristic path checks
        path_lower = path.lower()
        if not matched and ("/mailman/admin" in path_lower or "/mailman/listinfo" in path_lower or "/archives/" in path_lower):
            matched = True
            evidence = "Path name indicates Mailman-related endpoint (heuristic)."

        result = {
            "path": path,
            "full_url": full_url,
            "status_code": status,
            "description": item.get("description", ""),
            "severity": item.get("severity", "low"),
            "access_level": item.get("access_level", "unknown"),
            "found": bool(matched),
            "evidence": evidence,
        }
        return result

    except Exception as e:
        return {
            "path": path,
            "full_url": full_url,
            "status_code": None,
            "description": item.get("description", ""),
            "severity": item.get("severity", "low"),
            "access_level": item.get("access_level", "unknown"),
            "found": False,
            "error": f"unexpected_error: {e}",
        }

# -----------------------------------------------------------
# Concurrently scan multiple paths
# -----------------------------------------------------------
def check_paths(
    base_url: str,
    paths: List[Dict[str, Any]],
    timeout: float = DEFAULT_TIMEOUT,
    request_delay: float = DEFAULT_REQUEST_DELAY,
    verbose: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES
) -> List[Dict[str, Any]]:
    """Scan a list of paths concurrently and return results."""
    configure_logger(verbose)
    base_url = ensure_scheme(base_url.rstrip("/"))
    if not is_valid_url(base_url):
        return [{"error": "Invalid URL format. Must include scheme (http or https) and domain."}]

    # Remove duplicates and invalid items
    sanitized_paths: List[Dict[str, Any]] = []
    seen = set()
    for item in paths:
        if not isinstance(item, dict):
            continue
        p = item.get("path")
        if not p or p in seen:
            continue
        seen.add(p)
        sanitized_paths.append(item)

    if not sanitized_paths:
        logger.info("No paths to scan (after sanitization).")
        return []

    # Set number of workers
    workers = max(1, min(max_workers, len(sanitized_paths)))
    accessible_results: List[Dict[str, Any]] = []

    # Scan concurrently
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item = {
            executor.submit(
                _check_single_path,
                base_url,
                item,
                timeout,
                request_delay,
                max_content_bytes
            ): item for item in sanitized_paths
        }
        for future in as_completed(future_to_item):
            try:
                res = future.result()
            except Exception:
                continue
            accessible_results.append(res)

    return accessible_results
