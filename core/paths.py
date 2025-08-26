from json import load as json_load
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests import Session, RequestException, head, get
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin, urlparse
from time import sleep, time
from random import choice, uniform
from typing import List, Dict, Optional, Any
from urllib3 import disable_warnings
from urllib3 import exceptions as urllib3_exceptions
from re import compile as re_compile, IGNORECASE
from sys import exit as sys_exit
from signal import signal, SIGINT
from logging import getLogger, DEBUG, INFO
from threading import local, Lock  # updated import

# -----------------------------------------------------------
# Suppress insecure request warnings because we sometimes
# intentionally use verify=False for scanning.
# -----------------------------------------------------------
disable_warnings(urllib3_exceptions.InsecureRequestWarning)

# -----------------------------------------------------------
# Shared logger (do not add handlers here; configured globally)
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
DEFAULT_RETRIES = 2

MAILMAN_PATTERN = re_compile(
    r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)",
    flags=IGNORECASE
)

# thread-local storage for per-thread sessions
_thread_local = local()
print_lock = Lock()  # for printing/logging safely in threads

# -----------------------------------------------------------
# Signal handling
# -----------------------------------------------------------
def handle_sigint(signum, frame) -> None:
    logger.warning("Interrupted by user (Ctrl+C). Exiting...")
    sys_exit(0)

signal(SIGINT, handle_sigint)

# -----------------------------------------------------------
# Helper utilities
# -----------------------------------------------------------
def configure_logger(verbose: bool) -> None:
    logger.setLevel(DEBUG if verbose else INFO)

def ensure_scheme(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        logger.debug(f"Scheme missing in URL '{url}', prepending 'http://'")
        return "http://" + url
    return url

def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL. It must start with http:// or https:// and include a domain.")
    return valid

def load_common_paths(filepath: str, version: str = "v2") -> List[Dict[str, Any]]:
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
# Session factory (per-thread)
# -----------------------------------------------------------
def _get_thread_session(
    retries: int = DEFAULT_RETRIES,
    backoff_factor: float = 0.5,
    pool_maxsize: int = 20
) -> Session:
    if getattr(_thread_local, "session", None) is None:
        s = Session()
        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        try:
            retry.allowed_methods = frozenset(["HEAD", "GET", "OPTIONS"])
        except Exception:
            try:
                retry.method_whitelist = frozenset(["HEAD", "GET", "OPTIONS"])
            except Exception:
                pass
        adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_maxsize, pool_maxsize=pool_maxsize)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers.update({"User-Agent": choice(USER_AGENTS)})
        _thread_local.session = s
    return _thread_local.session

# -----------------------------------------------------------
# Single path check
# -----------------------------------------------------------
def _check_single_path(
    base_url: str,
    item: Dict[str, Any],
    timeout: float,
    request_delay: float,
    max_content_bytes: int
) -> Dict[str, Any]:
    path = item.get("path")
    if not path:
        return {"error": "missing_path_key", "detail": "Entry did not include 'path' key."}

    full_url = urljoin(base_url + "/", path.lstrip("/"))
    session = _get_thread_session()
    sleep(uniform(0, request_delay))

    try:
        # HEAD request
        head_resp = None
        try:
            head_resp = session.head(full_url, timeout=timeout, allow_redirects=True, verify=False)
        except RequestException:
            head_resp = None

        # GET request to inspect content
        get_resp = session.get(full_url, timeout=timeout, allow_redirects=True, stream=True, verify=False)
        status = get_resp.status_code
        text = ""
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

        matched = False
        evidence = ""
        if status == 200 and text:
            m = MAILMAN_PATTERN.search(text)
            if m:
                matched = True
                evidence = f"Body matched pattern: {m.group(0)}"
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
        if hasattr(get_resp, "url") and get_resp.url != full_url:
            result["redirected_to"] = get_resp.url

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
# Concurrent path scanning
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
    configure_logger(verbose)
    base_url = ensure_scheme(base_url.rstrip("/"))
    if not is_valid_url(base_url):
        return [{"error": "Invalid URL format. Must include scheme (http or https) and domain."}]

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

    workers = max(1, min(max_workers, len(sanitized_paths)))
    accessible_results: List[Dict[str, Any]] = []

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
            except Exception as e:
                continue
            accessible_results.append(res)

    return accessible_results

# -----------------------------------------------------------
# CLI entrypoint
# -----------------------------------------------------------
def main() -> None:
    try:
        target = input("Enter target base URL (e.g., https://example.com): ").strip()
        version = input("Enter Mailman version to scan (v2 or v3) [v2]: ").strip().lower() or "v2"
        verbose_input = input("Verbose output? (y/N): ").strip().lower()
        verbose = verbose_input in ("y", "yes", "true", "1")
        worker_input = input(f"Max workers? [{DEFAULT_MAX_WORKERS}]: ").strip()
        workers = int(worker_input) if worker_input else DEFAULT_MAX_WORKERS

        configure_logger(verbose)
        target = ensure_scheme(target)
        paths = load_common_paths("data/common_paths.json", version)
        if not paths:
            logger.error("No paths loaded. Exiting.")
            sys_exit(1)

        results = check_paths(target, paths, timeout=DEFAULT_TIMEOUT,
                              request_delay=DEFAULT_REQUEST_DELAY, verbose=verbose,
                              max_workers=workers, max_content_bytes=DEFAULT_MAX_CONTENT_BYTES)
        if results and isinstance(results[0], dict) and "error" in results[0]:
            logger.error(f"Error: {results[0]['error']}")
        elif results:
            ok_200 = sum(1 for r in results if r.get("status_code") == 200 and r.get("found"))
            redir = sum(1 for r in results if r.get("status_code") and 300 <= int(r.get("status_code")) < 400)
            logger.info(f"Scan finished. ✅ {ok_200} accessible (200 matched), ↪️ {redir} redirects. Total reported entries: {len(results)}")
        else:
            logger.info("No accessible Mailman paths found.")
    except KeyboardInterrupt:
        logger.warning("Interrupted by user (Ctrl+C). Exiting...")
        sys_exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys_exit(1)

if __name__ == "__main__":
    main()
