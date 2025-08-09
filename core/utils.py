from os import makedirs, path
from asyncio import TimeoutError
from typing import Optional, Dict, Any, Union
from json import load, dump, JSONDecodeError
from logging import getLogger, Logger, basicConfig
from rich.logging import RichHandler
from contextlib import asynccontextmanager

from aiohttp import (
    ClientSession,
    ClientTimeout,
    TCPConnector,
    ClientConnectionError,
    ClientResponseError,
)
from aiohttp_socks import ProxyConnector  # For SOCKS proxy support

# Setup logger with RichHandler for pretty console logs
basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
logger: Logger = getLogger("mailmap")
logger.propagate = False  # Prevent double logging if root logger configured elsewhere


def _create_connector(proxy: Optional[str]) -> Optional[object]:
    """
    Create appropriate aiohttp connector based on proxy scheme.
    Supports SOCKS proxies via aiohttp_socks, HTTP/HTTPS proxies with TCPConnector.
    Returns None if no proxy.
    """
    if not proxy:
        return None

    proxy_lower = proxy.lower()
    try:
        if proxy_lower.startswith(("socks5://", "socks4://", "socks5h://")):
            return ProxyConnector.from_url(proxy)
        elif proxy_lower.startswith(("http://", "https://")):
            # HTTP/HTTPS proxies should be passed as 'proxy' param in request,
            # aiohttp does not support HTTP proxy in connector
            logger.warning(
                "HTTP/HTTPS proxy detected. Pass 'proxy' parameter in request methods."
            )
            return None
        else:
            logger.error(f"Unsupported proxy scheme: {proxy}")
            return None
    except Exception as e:
        logger.error(f"Failed to create proxy connector for {proxy}: {e}")
        return None


@asynccontextmanager
async def create_session(
    headers: Optional[Dict[str, str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    timeout: int = 10,
):
    """
    Async context manager to create and close aiohttp ClientSession.
    Supports custom User-Agent, optional SOCKS proxy, and timeout settings.

    Note:
    - For HTTP/HTTPS proxies, pass 'proxy' parameter directly to request methods.
    - SOCKS proxies are supported via ProxyConnector.
    """
    session_headers = headers.copy() if headers else {}
    if user_agent:
        session_headers["User-Agent"] = user_agent
    else:
        session_headers.setdefault("User-Agent", "MailmapScanner/1.0")

    connector = _create_connector(proxy)

    timeout_obj = ClientTimeout(total=timeout)
    session = None
    try:
        session = ClientSession(
            headers=session_headers, connector=connector, timeout=timeout_obj
        )
        yield session
    except Exception as e:
        logger.error(f"Failed to create ClientSession: {e}")
        if session:
            await session.close()
        raise
    finally:
        if session and not session.closed:
            await session.close()


async def send_request(
    session: ClientSession,
    method: str,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """
    General async HTTP request sender (GET/POST supported).

    Args:
        session: aiohttp ClientSession to use.
        method: "GET" or "POST".
        url: Target URL.
        timeout: Request timeout in seconds.
        headers: Optional headers for the request.
        json_payload: JSON data for POST requests.
        return_json: If True, parse response as JSON, else return text.
        proxy: Optional HTTP/HTTPS proxy URL (used per request).

    Returns:
        Parsed JSON dict or raw text string on success, None on failure.
    """
    method = method.upper()
    timeout_obj = ClientTimeout(total=timeout)

    try:
        if method == "GET":
            async with session.get(
                url, timeout=timeout_obj, headers=headers, proxy=proxy
            ) as response:
                response.raise_for_status()
                if return_json:
                    try:
                        return await response.json(content_type=None)
                    except Exception:
                        logger.warning(f"Response from {url} is not JSON, returning raw text.")
                        return await response.text()
                else:
                    return await response.text()

        elif method == "POST":
            async with session.post(
                url, timeout=timeout_obj, headers=headers, json=json_payload, proxy=proxy
            ) as response:
                response.raise_for_status()
                if return_json:
                    try:
                        return await response.json(content_type=None)
                    except Exception:
                        logger.warning(f"Response from {url} is not JSON, returning raw text.")
                        return await response.text()
                else:
                    return await response.text()
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return None

    except TimeoutError:
        logger.error(f"{method} request to {url} timed out.")
    except ClientConnectionError:
        logger.error(f"Connection error during {method} request to {url}.")
    except ClientResponseError as e:
        logger.error(f"{method} request to {url} failed: {e}")
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
    """Send async GET request."""
    return await send_request(session, "GET", url, timeout, headers, None, return_json, proxy)


async def send_post_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict] = None,
    return_json: bool = True,
    proxy: Optional[str] = None,
) -> Optional[Union[dict, str]]:
    """Send async POST request."""
    return await send_request(session, "POST", url, timeout, headers, json_payload, return_json, proxy)


def log_info(message: str) -> None:
    """Log an info-level message."""
    logger.info(message)


def log_error(message: str) -> None:
    """Log an error-level message."""
    logger.error(message)


def read_json_file(filepath: str) -> Optional[Any]:
    """
    Read JSON data from a file.

    Args:
        filepath: Path to JSON file.

    Returns:
        Parsed JSON data or None on failure.
    """
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
    """
    Write data as JSON to a file.

    Args:
        filepath: Target file path.
        data: Data to serialize as JSON.

    Returns:
        True if successful, False otherwise.
    """
    try:
        makedirs(path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON file {filepath}: {e}")
        return False
