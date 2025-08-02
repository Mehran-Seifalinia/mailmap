from aiohttp import ClientSession, ClientConnectionError, ClientResponseError
from asyncio import TimeoutError
from typing import Optional, Dict, Any
from json import load, dump, JSONDecodeError
from logging import getLogger, Logger, basicConfig
from rich.logging import RichHandler

# راه‌اندازی logger با rich
basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger: Logger = getLogger("mailmap")

# ---- بخش HTTP async با aiohttp ----

async def create_session(headers: Optional[Dict[str, str]] = None, user_agent: Optional[str] = None) -> ClientSession:
    session_headers = headers or {}
    if user_agent:
        session_headers["User-Agent"] = user_agent
    else:
        session_headers["User-Agent"] = "MailmapScanner/1.0"
    return ClientSession(headers=session_headers)

async def send_get_request(session: ClientSession, url: str, timeout: int = 5, headers: Optional[Dict[str, str]] = None) -> Optional[ClientSession]:
    try:
        async with session.get(url, timeout=timeout, headers=headers) as response:
            response.raise_for_status()
            return response
    except TimeoutError:
        logger.error(f"[red]GET request to {url} timed out.[/red]")
    except ClientConnectionError:
        logger.error(f"[red]Connection error during GET request to {url}.[/red]")
    except ClientResponseError as e:
        logger.error(f"[red]Request to {url} failed: {e}[/red]")
    except Exception as e:
        logger.error(f"[red]Unexpected error on GET request to {url}: {e}[/red]")
    return None

async def send_post_request(
    session: ClientSession,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict] = None,
) -> Optional[ClientSession]:
    try:
        async with session.post(url, timeout=timeout, headers=headers, json=json_payload) as response:
            response.raise_for_status()
            return response
    except TimeoutError:
        logger.error(f"[red]POST request to {url} timed out.[/red]")
    except ClientConnectionError:
        logger.error(f"[red]Connection error during POST request to {url}.[/red]")
    except ClientResponseError as e:
        logger.error(f"[red]Request to {url} failed: {e}[/red]")
    except Exception as e:
        logger.error(f"[red]Unexpected error on POST request to {url}: {e}[/red]")
    return None

# ---- لاگ‌های رنگی و استاندارد ----

def log_info(message: str) -> None:
    logger.info(f"[green]{message}[/green]")

def log_error(message: str) -> None:
    logger.error(f"[red]{message}[/red]")

# ---- توابع sync برای خواندن و نوشتن JSON ----

def read_json_file(filepath: str) -> Optional[Any]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except FileNotFoundError:
        logger.error(f"[red]JSON file not found: {filepath}[/red]")
    except JSONDecodeError as e:
        logger.error(f"[red]Failed to decode JSON file {filepath}: {e}[/red]")
    except Exception as e:
        logger.error(f"[red]Unexpected error reading JSON file {filepath}: {e}[/red]")
    return None

def write_json_file(filepath: str, data: Any) -> bool:
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"[red]Failed to write JSON file {filepath}: {e}[/red]")
        return False
