from re import compile as re_compile, Pattern, IGNORECASE
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Set, List, Union
from json import load as json_load
from logging import getLogger
from argparse import ArgumentParser
from sys import exit as sys_exit
from asyncio import sleep, run
from core.utils import create_session  # async context manager returning aiohttp.ClientSession
from rich.console import Console
from rich.theme import Theme

logger = getLogger(__name__)
console = Console(theme=Theme({
    "error": "bold red",
    "success": "bold green",
    "warning": "bold yellow",
    "info": "bold cyan"
}))

def load_fingerprints(filepath: str) -> List[Dict]:
    """Load fingerprint patterns from JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json_load(f)
        logger.info(f"Loaded {len(data)} fingerprints from {filepath}")
        return data
    except Exception as e:
        logger.error(f"Failed to load fingerprints file '{filepath}': {e}")
        return []

def is_valid_url(url: str) -> bool:
    """Check if URL has valid scheme and netloc."""
    parsed = urlparse(url)
    valid = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if not valid:
        logger.error("Invalid URL format. URL must start with http:// or https:// and include a domain.")
    return valid

def extract_version_from_text(text: str, pattern: Pattern) -> Optional[str]:
    """Extract version string using regex pattern from given text."""
    match = pattern.search(text)
    if match:
        try:
            return match.group(1).strip()
        except IndexError:
            return match.group(0).strip()
    return None

async def detect_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprints: List[Dict]
) -> Dict[str, Union[str, bool, List[str], None]]:
    """
    Detect Mailman version by applying fingerprints on target URLs/headers/body asynchronously.
    Filters out generic or invalid version strings.
    """

    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. URL must start with http:// or https:// and include a domain."}

    timeout = settings.get("timeout", 5)
    proxy = settings.get("proxy")
    user_agent = settings.get("user_agent")
    delay = settings.get("delay", 1)

    user_agents = [user_agent] if user_agent else [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    ]

    found_versions: Set[str] = set()
    user_agent_index = 0

    async with create_session(user_agent=user_agent, proxy=proxy, timeout=timeout) as session:

        for fp in fingerprints:
            method = fp.get("method")
            location = fp.get("location")
            pattern_str = fp.get("pattern")
            version_label = fp.get("version")

            pattern = re_compile(pattern_str, IGNORECASE) if pattern_str else None

            # Rotate User-Agent for each request
            current_ua = user_agents[user_agent_index % len(user_agents)]
            session.headers.update({"User-Agent": current_ua})
            user_agent_index += 1

            url_to_check = None

            try:
                if method == "url":
                    url_to_check = urljoin(base_url + "/", location.lstrip("/"))
                    async with session.get(url_to_check) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not pattern:
                                # No pattern means just presence check; add version_label only if meaningful
                                if version_label.lower() != "generic":
                                    found_versions.add(version_label)
                                else:
                                    logger.debug(f"Ignored generic version label for URL presence: {url_to_check}")
                            else:
                                ver = extract_version_from_text(text, pattern)
                                if ver and ver.lower() != "generic":
                                    found_versions.add(ver)
                                    logger.debug(f"Fingerprint matched by URL body regex: {url_to_check} -> {ver}")
                                else:
                                    logger.debug(f"Ignored generic or empty version from {url_to_check}")

                elif method == "header":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    found_in_header = False
                    for u in urls_to_try:
                        url_to_check = u
                        async with session.get(u) as response:
                            if response.status < 200 or response.status >= 300:
                                continue
                            header_val = response.headers.get(location)
                            if header_val and pattern:
                                ver = extract_version_from_text(header_val, pattern)
                                if ver and ver.lower() != "generic":
                                    found_versions.add(ver)
                                    found_in_header = True
                                    logger.debug(f"Fingerprint matched in header '{location}': {u} -> {ver}")
                                    break
                                else:
                                    logger.debug(f"Ignored generic or empty version from header '{location}' at {u}")
                    if found_in_header:
                        continue

                elif method == "body":
                    urls_to_try = [base_url, urljoin(base_url + "/", "mailman")]
                    for u in urls_to_try:
                        url_to_check = u
                        async with session.get(u) as response:
                            if response.status < 200 or response.status >= 300:
                                continue
                            content_type = response.headers.get("Content-Type", "").lower()
                            if "text" not in content_type:
                                continue
                            content = await response.text()
                            content = content[:100_000]
                            if pattern:
                                ver = extract_version_from_text(content, pattern)
                                if ver and ver.lower() != "generic":
                                    found_versions.add(ver)
                                    logger.debug(f"Fingerprint matched in body content: {u} -> {ver}")
                                    break
                                else:
                                    logger.debug(f"Ignored generic or empty version from body content at {u}")

            except Exception as e:
                logger.error(f"Unexpected error during fingerprint scan at {url_to_check if url_to_check else 'N/A'}: {e}")

            await sleep(delay)

    if not found_versions:
        logger.info("No Mailman version detected.")
        return {"version": None}

    if len(found_versions) == 1:
        ver = found_versions.pop()
        logger.info(f"Detected Mailman version: {ver}")
        return {"version": ver}

    logger.warning(f"Version conflict detected. Found versions: {found_versions}")
    return {"conflict": True, "versions": list(found_versions)}

async def get_version(
    base_url: str,
    settings: Dict[str, Union[str, int, float]],
    fingerprint_file: str = "data/fingerprints.json"
) -> Dict:
    """Load fingerprints and run version detection asynchronously."""
    fingerprints = load_fingerprints(fingerprint_file)
    if not fingerprints:
        logger.error("No fingerprints loaded, aborting version detection.")
        return {"error": "No fingerprints loaded."}
    return await detect_version(base_url, settings, fingerprints)


if __name__ == "__main__":
    from logging import basicConfig
    from sys import exit as sys_exit
    from asyncio import run

    basicConfig(level=20, format='[%(levelname)s] %(message)s')

    parser = ArgumentParser(description="Mailman Version Detector with Fingerprints")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout (seconds)")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--delay", type=float, default=1, help="Delay between requests (seconds)")
    parser.add_argument("--fingerprints", default="data/fingerprints.json", help="Path to fingerprints JSON file")

    args = parser.parse_args()

    settings = {
        "timeout": args.timeout,
        "proxy": args.proxy,
        "user_agent": args.user_agent,
        "delay": args.delay,
    }

    async def main():
        try:
            result = await get_version(args.target, settings, args.fingerprints)
        except KeyboardInterrupt:
            console.print("\n[error]Process interrupted by user (Ctrl+C). Exiting...[/error]")
            sys_exit(130)  # 128 + 2 for SIGINT

        if "error" in result:
            console.print(f"[error]Error: {result['error']}[/error]")
            sys_exit(1)

        if result.get("conflict"):
            console.print(f"[warning]Version conflict detected! Found versions: {', '.join(result['versions'])}[/warning]")
            sys_exit(2)
        elif result.get("version"):
            console.print(f"[success]Detected Mailman version: {result['version']}[/success]")
            sys_exit(0)
        else:
            console.print("[info]No Mailman version detected.[/info]")
            sys_exit(3)

    run(main())
