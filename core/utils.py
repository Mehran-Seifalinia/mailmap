# core/utils.py

from os import makedirs, path
from asyncio import TimeoutError as AsyncTimeoutError
from typing import Optional, Dict, Any, Union
from json import load, dump, JSONDecodeError
from logging import getLogger, Logger, basicConfig, INFO, DEBUG, WARNING

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
# Logging setup
# ============================================================

VERBOSE: bool = False  # Global verbosity flag

if not getLogger().handlers:
    basicConfig(
        level=INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )

logger: Logger = getLogger("mailmap")
logger.propagate = False  # avoid duplicate logging

def set_verbose(verbose: bool) -> None:
    """
    Toggle verbose mode globally.
    - verbose=False: minimal output (INFO only)
    - verbose=True: detailed DEBUG logs for networking and errors
    """
    global VERBOSE
    VERBOSE = bool(verbose)
    logger.setLevel(DEBUG if VERBOSE else INFO)

set_verbose(False)

# ============================================================
# Connector helpers
# ============================================================

def _create_connector(proxy: Optional[str]) -> Optional[object]:
    """
    Create aiohttp connector for SOCKS proxies.
    HTTP/HTTPS proxies are passed per-request, not at connector level.
    """
    if not proxy:
        return None

    try:
        lower = proxy.lower()
        if lower.startswith(("socks5://", "socks4://", "socks5h://")):
            return ProxyConnector.from_url(proxy)
        # HTTP/HTTPS proxies handled per-request
        return None
    except Exception as e:
        logger.error(f"Failed to create proxy connector for {proxy}: {e}")
        return None

# ============================================================
# Async session factory
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
    Async context manager to create a ClientSession with timeout and optional proxy.
    Args:
        headers: default headers
        user_agent: optional User-Agent override
        proxy: SOCKS proxy via connector; HTTP/HTTPS passed per-request
        timeout: session timeout in seconds
        verify_ssl: whether to verify SSL certificates
    """
    session_headers = headers.copy() if headers else {}
    session_headers["User-Agent"] = user_agent or session_headers.get("User-Agent", "MailmapScanner/1.0")

    connector = _create_connector(proxy) or TCPConnector(ssl=verify_ssl)
    timeout_obj = ClientTimeout(total=timeout)

    session: Optional[ClientSession] = None
    try:
        session = ClientSession(headers=session_headers, connector=connector, timeout=timeout_obj)
        yield session
    except Exception as e:
        logger.error(f"Failed to create ClientSession: {e}")
        if session:
            await session.close()
        raise
    finally:
        if session and not session.closed:
            await session.close()

# ============================================================
# HTTP request helpers
# ============================================================

async def _parse_response(response, return_json: bool) -> Union[dict, str]:
    """
    Parse aiohttp response into JSON or text. Fallback to text if JSON parsing fails.
    """
    if return_json:
        try:
            return await response.json(content_type=None)
        except Exception:
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
    Send async HTTP request (GET or POST) with controlled timeout and optional proxy.
    Returns JSON or text; None on failure.
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

        logger.error(f"Unsupported HTTP method: {method}")
        return None

    except AsyncTimeoutError:
        msg = f"{method} request to {url} timed out."
        logger.debug(msg)  # suppress verbose warnings in quiet mode
    except ClientConnectionError as e:
        msg = f"Connection error during {method} request to {url}: {e}"
        logger.debug(msg)
    except ClientResponseError as e:
        msg = f"{method} request to {url} failed: {e.status}"
        logger.debug(msg)
    except Exception as e:
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
    """Async GET request wrapper."""
    return await send_request(session, "GET", url, timeout, headers, None, return_json, proxy)

async def send_post_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict[str, Any]] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """Async POST request wrapper."""
    return await send_request(session, "POST", url, timeout, headers, json_payload, return_json, proxy)

# ============================================================
# JSON file helpers
# ============================================================

def read_json_file(filepath: str) -> Optional[Any]:
    """Read and parse JSON file. Returns None on failure."""
    if not path.isfile(filepath):
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
    """Write JSON file, creating parent directories if needed. Returns True on success."""
    try:
        makedirs(path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON file {filepath}: {e}")
        return False
