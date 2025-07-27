from requests import Session, RequestException, Response
from typing import Optional, Dict, Any
from json import load, dump, JSONDecodeError
from logging import basicConfig, info, error, INFO

basicConfig(
    level=INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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

def send_get_request(session: Session, url: str, timeout: int = 5) -> Optional[Response]:
    """
    Send a GET request using the given session to the specified URL with timeout.
    Returns the Response object if successful, otherwise None.
    """
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response
    except RequestException as e:
        error(f"Request to {url} failed: {e}")
        return None

def log_info(message: str) -> None:
    """
    Log an informational message.
    """
    info(message)

def log_error(message: str) -> None:
    """
    Log an error message.
    """
    error(message)

def read_json_file(filepath: str) -> Optional[Any]:
    """
    Read and parse a JSON file from the given filepath.
    Returns the parsed data or None if error occurs.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return load(f)
    except (FileNotFoundError, JSONDecodeError) as e:
        error(f"Failed to read JSON file {filepath}: {e}")
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
        error(f"Failed to write JSON file {filepath}: {e}")
        return False
