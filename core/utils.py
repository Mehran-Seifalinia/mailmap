from aiohttp import ClientSession, ClientConnectionError, ClientResponseError, ClientTimeout
from asyncio import TimeoutError
from typing import Optional, Dict, Any, Union
from json import load, dump, JSONDecodeError
from logging import getLogger, Logger, basicConfig
from rich.logging import RichHandler
from contextlib import asynccontextmanager

# Setup logger with RichHandler for pretty logs
basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger: Logger = getLogger("mailmap")

@asynccontextmanager
async def create_session(
    headers: Optional[Dict[str, str]] = None,
    user_agent: Optional[str] = None
):
    """
    Async context manager to create and close aiohttp ClientSession.
    Adds custom User-Agent header if provided.
    """
    session_headers = headers.copy() if headers else {}
    if user_agent:
        session_headers["User-Agent"] = user_agent
    else:
        session_headers.setdefault("User-Agent", "MailmapScanner/1.0")

    session = ClientSession(headers=session_headers)
    try:
        yield session
    finally:
        await session.close()

async def send_get_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    return_json: bool = True
) -> Optional[Union[dict, str]]:
    """
    Send an asynchronous GET request using the provided session.
    Returns JSON or raw text based on return_json flag.
    """
    try:
        timeout_obj = ClientTimeout(total=timeout)
        async with session.get(url, timeout=timeout_obj, headers=headers) as response:
            response.raise_for_status()
            if return_json:
                return await response.json(content_type=None)  # content_type=None for flexible parsing
            else:
                return await response.text()
    except TimeoutError:
        logger.error(f"GET request to {url} timed out.")
    except ClientConnectionError:
        logger.error(f"Connection error during GET request to {url}.")
    except ClientResponseError as e:
        logger.error(f"Request to {url} failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error on GET request to {url}: {e}")
    return None

async def send_post_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict] = None,
    return_json: bool = True
) -> Optional[Union[dict, str]]:
    """
    Send an asynchronous POST request using the provided session.
    Returns JSON or raw text based on return_json flag.
    """
    try:
        timeout_obj = ClientTimeout(total=timeout)
        async with session.post(url, timeout=timeout_obj, headers=headers, json=json_payload) as response:
            response.raise_for_status()
            if return_json:
                return await response.json(content_type=None)
            else:
                return await response.text()
    except TimeoutError:
        logger.error(f"POST request to {url} timed out.")
    except ClientConnectionError:
        logger.error(f"Connection error during POST request to {url}.")
    except ClientResponseError as e:
        logger.error(f"Request to {url} failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error on POST request to {url}: {e}")
    return None

def log_info(message: str) -> None:
    """Log info message."""
    logger.info(message)

def log_error(message: str) -> None:
    """Log error message."""
    logger.error(message)

def read_json_file(filepath: str) -> Optional[Any]:
    """
    Read JSON data from a file.
    Returns parsed JSON or None on error.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except FileNotFoundError:
        logger.error(f"JSON file not found: {filepath}")
    except JSONDecodeError as e:
        logger.error(f"Failed to decode JSON file {filepath}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error reading JSON file {filepath}: {e}")
    return None

def write_json_file(filepath: str, data: Any) -> bool:
    """
    Write data as JSON to a file.
    Returns True on success, False on failure.
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON file {filepath}: {e}")
        return False
