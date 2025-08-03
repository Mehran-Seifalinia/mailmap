from typing import List, Dict, Optional, Tuple, Any
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from re import search, IGNORECASE
from logging import getLogger
from colorama import init as colorama_init, Fore, Style
from asyncio import gather
from aiohttp import ClientSession, ClientConnectorError
from urllib.parse import urljoin

from core.utils import read_json_file, log_error

colorama_init(autoreset=True)
logger = getLogger(__name__)


def print_error(message: str):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")


def print_warning(message: str):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")


def print_info(message: str):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")


def get_cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "None"


class CVEScannerException(Exception):
    pass


class CVEScanner:
    def __init__(self, cve_data_path: str = "data/cves.json"):
        self.cves: List[Dict[str, Any]] = self.load_cves(cve_data_path)

    def load_cves(self, path: str) -> List[Dict[str, Any]]:
        data = read_json_file(path)
        if not data or not isinstance(data, list):
            print_warning(f"Empty, invalid, or malformed CVE data file: {path}")
            return []
        return data

    async def perform_test(
        self,
        session: ClientSession,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[Dict] = None,
        evidence_regex: Optional[str] = None,
        timeout: int = 10,
    ) -> Tuple[bool, str]:
        try:
            headers = headers or {}
            payload = payload or {}
            method = method.upper()

            async with session.request(
                method,
                url,
                headers=headers,
                json=payload if method == "POST" else None,
                timeout=timeout
            ) as response:

                if response.status != 200:
                    try:
                        text = await response.text()
                        snippet = text[:100]
                    except Exception:
                        snippet = "Unable to read response body"
                    return False, f"Unexpected status code {response.status}: {snippet}"

                try:
                    text = await response.text()
                except Exception:
                    return False, "Failed to decode response as text"

                if evidence_regex:
                    if search(evidence_regex, text, flags=IGNORECASE):
                        return True, f"Evidence matched: {evidence_regex}"
                    else:
                        return False, "Evidence not found in response"

                return True, "Expected response received"

        except Exception as e:
            log_error(f"Exception during test request to {url}: {e}")
            print_error(f"Exception during test request to {url}: {e}")
            return False, f"Exception during test: {e}"

    async def scan_single(
        self,
        session: ClientSession,
        cve: Dict[str, Any],
        detected_version: Optional[str],
        base_url: Optional[str],
        timeout: int
    ) -> Dict[str, Any]:
        cve_id = cve.get("id", "UNKNOWN")
        description = cve.get("description", "")
        cvss_raw = cve.get("cvss", "0.0")
        test_info = cve.get("test", {})

        if not isinstance(test_info, dict):
            return {
                "id": cve_id,
                "description": description,
                "cvss": 0.0,
                "severity": "None",
                "status": "error",
                "reason": "Invalid test configuration",
            }

        affected_versions = cve.get("affected_versions", [])
        affected_versions_str = ",".join(affected_versions) if isinstance(affected_versions, list) else str(affected_versions)

        try:
            cvss = float(cvss_raw)
        except (ValueError, TypeError):
            cvss = 0.0
            print_warning(f"Invalid CVSS format in CVE {cve_id}: {cvss_raw}")

        severity = get_cvss_severity(cvss)

        if detected_version:
            if not affected_versions:
                return {
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "skipped",
                    "reason": "No affected versions specified",
                }
            try:
                ver = Version(detected_version)
                spec_set = SpecifierSet(affected_versions_str)
                if ver not in spec_set:
                    return {
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "severity": severity,
                        "status": "skipped",
                        "reason": "Version not affected",
                    }
            except (InvalidVersion, InvalidSpecifier) as e:
                log_error(f"Version check failed for CVE {cve_id}: {e}")
                return {
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "skipped",
                    "reason": f"Invalid version specifier: {e}",
                }

        method = test_info.get("method", "GET")
        path = test_info.get("path", "")
        url = test_info.get("url", None)
        headers = test_info.get("headers", None)
        payload = test_info.get("data", None)
        evidence_regex = test_info.get("evidence_regex") or test_info.get("evidence")

        if not url and path:
            if not base_url:
                return {
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "not_tested",
                    "reason": "Invalid base URL",
                }
            url = urljoin(base_url, path)

        if url:
            test_passed, reason = await self.perform_test(session, method, url, headers, payload, evidence_regex, timeout)
            return {
                "id": cve_id,
                "description": description,
                "cvss": cvss,
                "severity": severity,
                "status": "vulnerable" if test_passed else "not_vulnerable",
                "reason": reason,
            }
        else:
            return {
                "id": cve_id,
                "description": description,
                "cvss": cvss,
                "severity": severity,
                "status": "not_tested",
                "reason": "No test URL or path provided",
            }

    async def scan(
        self,
        detected_version: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 10
    ) -> List[Dict[str, Any]]:
        try:
            async with ClientSession() as session:
                tasks = [
                    self.scan_single(session, cve, detected_version, base_url, timeout)
                    for cve in self.cves
                ]
                return await gather(*tasks)

        except KeyboardInterrupt:
            print_error("Scan interrupted by user (Ctrl+C). Exiting gracefully.")
            raise SystemExit(1)
        except ClientConnectorError as e:
            print_error(f"Network connection error: {e}")
            log_error(f"Network connection error: {e}")
            raise CVEScannerException("Unable to connect to target.")
        except Exception as e:
            print_error(f"Unexpected error during scan: {e}")
            log_error(f"Unexpected error during scan: {e}")
            raise CVEScannerException(str(e))
