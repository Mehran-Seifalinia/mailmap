from os import makedirs, path
from asyncio import TimeoutError as AsyncTimeoutError
from typing import Optional, Dict, Any, Union
from json import load, dump, JSONDecodeError
from logging import getLogger, Logger, basicConfig, INFO, DEBUG, WARNING, ERROR
from contextlib import asynccontextmanager

from rich.logging import RichHandler

from aiohttp import (
    ClientSession,
    ClientTimeout,
    TCPConnector,
    ClientConnectionError,
    ClientResponseError,
)
from aiohttp_socks import ProxyConnector  # SOCKS proxy support


# ============================================================
# Logging setup (pretty console logs via RichHandler)
# ============================================================

# Module-wide verbosity flag. Use set_verbose(True/False) to toggle.
VERBOSE: bool = False

# Configure root logger only if no handlers exist (avoid duplicates).
# This keeps compatibility when the app configures logging elsewhere.
if not getLogger().handlers:
    basicConfig(
        level=INFO,                          # default level (quiet)
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )

logger: Logger = getLogger("mailmap")
logger.propagate = False  # avoid double logging if root is configured


def set_verbose(verbose: bool) -> None:
    """
    Globally toggle verbose behavior for this module.
    - verbose=False: keep output minimal (INFO only, no DEBUG noise)
    - verbose=True:  show detailed logs (DEBUG for network and non-critical issues)
    """
    global VERBOSE
    VERBOSE = bool(verbose)
    logger.setLevel(DEBUG if VERBOSE else INFO)


# Initialize logger level at import time (default: quiet)
set_verbose(False)


# ============================================================
# HTTP connector / proxy helpers
# ============================================================

def _create_connector(proxy: Optional[str]) -> Optional[object]:
    """
    Create an aiohttp connector based on proxy scheme.

    Behavior:
      - SOCKS proxies → returns ProxyConnector (handled at connector-level).
      - HTTP/HTTPS proxies → return None; pass `proxy=` per-request (aiohttp native).
      - None or unsupported scheme → return None and (optionally) log in verbose.

    This keeps behavior explicit and predictable across methods.
    """
    if not proxy:
        logger.debug("No proxy provided; using default TCPConnector.") if VERBOSE else None
        return None

    proxy_lower = proxy.lower()
    try:
        if proxy_lower.startswith(("socks5://", "socks4://", "socks5h://")):
            logger.debug(f"Using SOCKS proxy via connector: {proxy}") if VERBOSE else None
            return ProxyConnector.from_url(proxy)

        if proxy_lower.startswith(("http://", "https://")):
            # aiohttp expects HTTP/HTTPS proxies per-request via `proxy=` parameter
            logger.debug("HTTP/HTTPS proxy detected; will pass via request 'proxy=' param.") if VERBOSE else None
            return None

        # Unsupported scheme
        msg = f"Unsupported proxy scheme: {proxy}"
        logger.warning(msg) if VERBOSE else logger.debug(msg)
        return None

    except Exception as e:
        # Connector build failure is noteworthy even in quiet mode
        logger.error(f"Failed to create proxy connector for {proxy}: {e}")
        return None


# ============================================================
# Session factory (async)
# ============================================================

@asynccontextmanager
async def create_session(
    headers: Optional[Dict[str, str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
) -> ClientSession:
    """
    Async context manager that creates and cleans up an aiohttp ClientSession.

    Args:
        headers:     Optional default headers for the session.
        user_agent:  Optional User-Agent override (added into headers).
        proxy:       Optional proxy URL. SOCKS via connector; HTTP/HTTPS passed per-request.
        timeout:     Total session timeout (seconds).
        verify_ssl:  Whether to verify SSL certificates (passed to TCPConnector).

    Notes:
        - For HTTP/HTTPS proxies, pass `proxy=` per request (aiohttp-native).
        - For SOCKS proxies, `ProxyConnector` is used at session level.
    """
    session_headers = headers.copy() if headers else {}
    session_headers["User-Agent"] = user_agent or session_headers.get("User-Agent", "MailmapScanner/1.0")

    connector = _create_connector(proxy) or TCPConnector(ssl=verify_ssl)
    timeout_obj = ClientTimeout(total=timeout)

    session: Optional[ClientSession] = None
    try:
        session = ClientSession(headers=session_headers, connector=connector, timeout=timeout_obj)
        logger.debug("ClientSession created successfully.") if VERBOSE else None
        yield session
    except Exception as e:
        # Session creation failure is critical; always log as error
        logger.error(f"Failed to create ClientSession: {e}")
        if session:
            await session.close()
        raise
    finally:
        if session and not session.closed:
            await session.close()
            logger.debug("ClientSession closed.") if VERBOSE else None


# ============================================================
# HTTP request helpers (async)
# ============================================================

async def _parse_response(
    response,
    return_json: bool,
) -> Union[dict, str]:
    """
    Parse aiohttp response into JSON or text.
    Falls back to text if JSON parsing fails.
    """
    if return_json:
        try:
            return await response.json(content_type=None)
        except Exception:
            logger.debug("Response is not JSON; returning raw text.") if VERBOSE else None
            return await response.text()
    return await response.text()


async def send_request(
    session: ClientSession,
    method: str,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict[str, Any]] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """
    Send a general HTTP request (GET/POST) using an existing aiohttp ClientSession.

    Quiet vs Verbose policy:
      - Quiet (default): suppress non-critical network chatter (timeouts, 4xx/5xx) to keep output clean.
      - Verbose: show detailed info about redirects, timeouts, response errors, etc.

    Args:
        session:      Existing aiohttp ClientSession.
        method:       HTTP method: "GET" or "POST".
        url:          Target URL.
        timeout:      Per-request total timeout (seconds).
        headers:      Optional per-request headers.
        json_payload: Optional JSON payload for POST.
        return_json:  If True, try JSON first and fallback to text.
        proxy:        Optional HTTP/HTTPS proxy (per request).

    Returns:
        JSON dict or text string on success; None on failure.
    """
    method = method.upper()
    timeout_obj = ClientTimeout(total=timeout)

    try:
        if method == "GET":
            async with session.get(url, timeout=timeout_obj, headers=headers, proxy=proxy) as response:
                response.raise_for_status()
                return await _parse_response(response, return_json)

        if method == "POST":
            async with session.post(url, timeout=timeout_obj, headers=headers, json=json_payload, proxy=proxy) as response:
                response.raise_for_status()
                return await _parse_response(response, return_json)

        # Unsupported method
        msg = f"Unsupported HTTP method: {method}"
        logger.error(msg)  # programming error → always log
        return None

    except AsyncTimeoutError:
        msg = f"{method} request to {url} timed out."
        logger.warning(msg) if VERBOSE else logger.debug(msg)
    except ClientConnectionError as e:
        msg = f"Connection error during {method} request to {url}: {e}"
        logger.warning(msg) if VERBOSE else logger.debug(msg)
    except ClientResponseError as e:
        # Includes 4xx/5xx after raise_for_status()
        msg = f"{method} request to {url} failed: {e.status} {e.message or ''}".strip()
        logger.warning(msg) if VERBOSE else logger.debug(msg)
    except Exception as e:
        # Unexpected exceptions are important—always surface them
        logger.error(f"Unexpected error on {method} request to {url}: {e}")

    return None


# Convenience wrappers
async def send_get_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """Send async GET request."""
    return await send_request(
        session=session,
        method="GET",
        url=url,
        timeout=timeout,
        headers=headers,
        json_payload=None,
        return_json=return_json,
        proxy=proxy,
    )


async def send_post_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict[str, Any]] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """Send async POST request."""
    return await send_request(
        session=session,
        method="POST",
        url=url,
        timeout=timeout,
        headers=headers,
        json_payload=json_payload,
        return_json=return_json,
        proxy=proxy,
    )


# ============================================================
# Logging convenience wrappers (consistent API)
# ============================================================

def log_info(message: str) -> None:
    """Log an info-level message (always visible)."""
    logger.info(message)


def log_error(message: str) -> None:
    """Log an error-level message (always visible)."""
    logger.error(message)


def log_debug(message: str) -> None:
    """Log a debug-level message (visible only in verbose mode)."""
    logger.debug(message)


def log_warning(message: str) -> None:
    """
    Log a warning-level message.
    In quiet mode, degrade to DEBUG to avoid noise.
    """
    logger.warning(message) if VERBOSE else logger.debug(message)


# ============================================================
# JSON file helpers
# ============================================================

def read_json_file(filepath: str) -> Optional[Any]:
    """
    Read and parse a JSON file.

    Returns:
        Parsed data or None on failure.
    """
    if not path.isfile(filepath):
        # Missing config/data is important enough to always show
        logger.error(f"JSON file not found: {filepath}")
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except JSONDecodeError as e:
        logger.error(f"Failed to decode JSON file {filepath}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error reading JSON file {filepath}: {e}")
    return None


def write_json_file(filepath: str, data: Any) -> bool:
    """
    Serialize data into a JSON file, creating parent folders as needed.

    Returns:
        True on success; False on failure.
    """
    try:
        makedirs(path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        logger.debug(f"Wrote JSON file: {filepath}") if VERBOSE else None
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON file {filepath}: {e}")
        return False
