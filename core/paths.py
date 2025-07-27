from requests import Session, Timeout, ConnectionError, RequestException, TooManyRedirects, HTTPError
from urllib.parse import urljoin, urlparse
from time import sleep
from re import search
from random import choice

# Common paths where Mailman installations might be exposed
MAILMAN_PATHS = [
    "/mailman/admin",
    "/mailman/admin/info",
    "/mailman/admin/config",
    "/mailman/admin/listinfo",
    "/mailman",
    "/mailman3",
    "/mailman3/admin",
    "/mailman3/api/",
    "/mailman3/postorius",
    "/mailman3/hyperkitty",
    "/mailman3/static",
    "/mailman3/templates",
    "/cgi-bin/mailman/admin",
    "/cgi-bin/mailman3/admin",
    "/pipermail/",
    "/mailman/listinfo",
    "/cgi-bin/mailman/listinfo",
    "/mailman/private",
    "/mailman/archives/public",
    "/mailman/archives/private",
    "/mailman/cron",
    "/mailman/mailman.cfg",
    "/mailman/config.py",
    "/mailman/secretkey",
    "/mailman/data",
    "/mailman/db",
    "/mailman/logs",
    "/mailman/log/mailman.log",
    "/mailman/tmp",
    "/mailman/static",
    "/mailman/templates",
    "/cgi-bin/mailman/admindb",
    "/cgi-bin/mailman/member",
    "/cgi-bin/mailman/subscribe",
    "/cgi-bin/mailman/unsubscribe",
    "/cgi-bin/mailman/approve",
    "/cgi-bin/mailman/deny",
]

# Random User-Agent pool to avoid being blocked
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
]

# Delay between requests to avoid detection or rate limiting
REQUEST_DELAY = 1


def is_valid_url(url: str) -> bool:
    """Validate the URL format (must include scheme and netloc)."""
    parsed = urlparse(url)
    return all([parsed.scheme in ("http", "https"), parsed.netloc])


def check_paths(base_url: str, timeout: int = 5):
    """Check accessibility of important Mailman paths on the target."""
    base_url = base_url.rstrip("/")
    if not is_valid_url(base_url):
        return {"error": "Invalid URL format. Must include scheme (http or https) and domain."}

    session = Session()
    session.headers.update({"User-Agent": choice(USER_AGENTS)})

    accessible_paths = []

    for path in MAILMAN_PATHS:
        full_url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            response = session.get(full_url, timeout=timeout, verify=False)

            if response.ok:
                # Look for keywords that indicate a Mailman page
                if search(r"(mailman|gnu|listinfo|hyperkitty|postorius|mailing list|admin)", response.text, flags=2):
                    accessible_paths.append({
                        "path": path,
                        "status_code": response.status_code
                    })

        except (Timeout, ConnectionError) as e:
            print(f"[!] Connection error at {full_url}: {e}")

        except (TooManyRedirects, HTTPError, RequestException) as e:
            print(f"[!] Request failed at {full_url}: {e}")

        except Exception as e:
            print(f"[!] Unexpected error at {full_url}: {e}")

        sleep(REQUEST_DELAY)

    return accessible_paths


if __name__ == "__main__":
    target = input("Enter target base URL (e.g., https://example.com): ").strip()
    results = check_paths(target)
    if isinstance(results, dict) and "error" in results:
        print("Error:", results["error"])
    elif results:
        print("\nAccessible Mailman paths:")
        for item in results:
            print(f"{item['path']} - HTTP {item['status_code']}")
    else:
        print("No accessible Mailman paths found.")
