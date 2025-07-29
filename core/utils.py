from requests import Session, RequestException, Response
from requests.exceptions import Timeout, ConnectionError
from typing import Optional, Dict, Any
from json import load, dump, JSONDecodeError
from logging import getLogger, basicConfig, INFO

basicConfig(
    level=INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = getLogger(__name__)


def create_session(headers: Optional[Dict[str, str]] = None, user_agent: Optional[str] = None) -> Session:
    """
    Create and return a requests Session with optional headers and User-Agent.
    If user_agent is not provided, a default User-Agent will be set.
    """
    session = Session()
    if headers:
        session.headers.update(headers)
    if user_agent:
        session.headers.update({"User-Agent": user_agent})
    else:
        session.headers.update({"User-Agent": "MailmapScanner/1.0"})
    return session


def send_get_request(session: Session, url: str, timeout: int = 5, headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
    """
    Send a GET request using the given session to the specified URL with timeout and optional headers.
    Returns the Response object if successful, otherwise None.
    """
    try:
        response = session.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        return response
    except Timeout:
        logger.error(f"GET request to {url} timed out.")
    except ConnectionError:
        logger.error(f"Connection error during GET request to {url}.")
    except RequestException as e:
        logger.error(f"Request to {url} failed: {e}")
    return None


def send_post_request(
    session: Session,
    url: str,
    timeout: int = 5,
    headers: Optional[Dict[str, str]] = None,
    json_payload: Optional[Dict] = None,
) -> Optional[Response]:
    """
    Send a POST request using the given session to the specified URL with timeout, optional headers, and JSON payload.
    Returns the Response object if successful, otherwise None.
    """
    try:
        response = session.post(url, timeout=timeout, headers=headers, json=json_payload)
        response.raise_for_status()
        return response
    except Timeout:
        logger.error(f"POST request to {url} timed out.")
    except ConnectionError:
        logger.error(f"Connection error during POST request to {url}.")
    except RequestException as e:
        logger.error(f"Request to {url} failed: {e}")
    return None


def log_info(message: str) -> None:
    """
    Log an informational message.
    """
    logger.info(message)


def log_error(message: str) -> None:
    """
    Log an error message.
    """
    logger.error(message)


def read_json_file(filepath: str) -> Optional[Any]:
    """
    Read and parse a JSON file from the given filepath.
    Returns the parsed data or None if error occurs.
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
    Write data as JSON to the given filepath.
    Returns True if successful, False otherwise.
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON file {filepath}: {e}")
        return False
