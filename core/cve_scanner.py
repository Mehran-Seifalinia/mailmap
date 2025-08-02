from typing import List, Dict, Optional, Tuple, Any
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from requests import Session, Response
from re import search, IGNORECASE
from logging import getLogger

from colorama import init as colorama_init, Fore, Style

from core.utils import (
    create_session,
    send_get_request,
    send_post_request,
    read_json_file,
    log_error,
)

colorama_init(autoreset=True)
logger = getLogger(__name__)


def print_error(message: str):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")


def print_warning(message: str):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")


def print_info(message: str):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")


def get_cvss_severity(score: float) -> str:
    """Convert CVSS numeric score to severity string."""
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
    """Custom exception for CVE Scanner errors."""
    pass


class CVEScanner:
    def __init__(self, cve_data_path: str = "data/cves.json"):
        """Initialize CVE scanner by loading CVE definitions and creating HTTP session."""
        self.session: Session = create_session()
        self.cves: List[Dict[str, Any]] = self.load_cves(cve_data_path)

    def load_cves(self, path: str) -> List[Dict[str, Any]]:
        """Load CVE definitions from a JSON file."""
        data = read_json_file(path)
        if not data or not isinstance(data, list):
            print_warning(f"Empty, invalid, or malformed CVE data file: {path}")
            return []
        return data

    def perform_test(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[Dict] = None,
        evidence_regex: Optional[str] = None,
        timeout: int = 10,
    ) -> Tuple[Optional[bool], str]:
        """
        Perform an HTTP test with optional headers and payload.
        Checks the response content against evidence_regex if provided.
        Returns a tuple (test_passed: bool|None, reason: str).
        """
        try:
            method = method.upper()
            response: Optional[Response] = None

            headers = headers or {}
            payload = payload or {}

            if method == "GET":
                response = send_get_request(self.session, url, headers=headers, timeout=timeout)
            elif method == "POST":
                response = send_post_request(self.session, url, headers=headers, json=payload, timeout=timeout)
            else:
                return None, f"Unsupported HTTP method: {method}"

            if not response:
                return False, "No response or request failed"

            if response.status_code != 200:
                return False, f"Unexpected status code: {response.status_code}"

            if evidence_regex:
                response_text = response.text or ""
                if search(evidence_regex, response_text, flags=IGNORECASE):
                    return True, f"Evidence matched: {evidence_regex}"
                else:
                    return False, "Evidence not found in response"

            return True, "Expected response received"

        except Exception as e:
            log_error(f"Exception during test request to {url}: {e}")
            print_error(f"Exception during test request to {url}: {e}")
            return False, f"Exception during test: {e}"

    def scan(
        self,
        detected_version: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 10,  # اضافه کردم timeout به پارامترهای scan
    ) -> List[Dict[str, Any]]:
        """
        Scan loaded CVEs against the detected software version.
        Combines base_url and test paths if needed.
        Returns list of CVE scan results with statuses and reasons.
        """
        results = []
        try:
            for cve in self.cves:
                if not all(k in cve for k in ("id", "description", "test")):
                    print_warning(f"Malformed CVE entry skipped: {cve}")
                    continue

                cve_id = cve.get("id", "UNKNOWN")
                description = cve.get("description", "")
                cvss_raw = cve.get("cvss", "0.0")
                test_info = cve.get("test", {})

                # بررسی نوع test_info
                if not isinstance(test_info, dict):
                    print_warning(f"Invalid test info for CVE {cve_id}, skipping.")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": 0.0,
                        "severity": "None",
                        "status": "error",
                        "reason": "Invalid test configuration",
                    })
                    continue

                affected_versions = cve.get("affected_versions", [])

                if isinstance(affected_versions, list):
                    affected_versions_str = ",".join(affected_versions)
                else:
                    affected_versions_str = str(affected_versions)

                try:
                    cvss = float(cvss_raw)
                except (ValueError, TypeError):
                    cvss = 0.0
                    print_warning(f"Invalid CVSS format in CVE {cve_id}: {cvss_raw}")

                severity = get_cvss_severity(cvss)

                if detected_version and affected_versions_str:
                    try:
                        ver = Version(detected_version)
                    except InvalidVersion:
                        print_warning(f"Invalid detected version '{detected_version}' for CVE {cve_id}")
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "severity": severity,
                            "status": "skipped",
                            "reason": "Invalid detected version format",
                        })
                        continue

                    try:
                        spec_set = SpecifierSet(affected_versions_str)
                    except (InvalidSpecifier, Exception) as e:
                        print_warning(f"Invalid version specifier in CVE {cve_id}: {affected_versions_str} - {e}")
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "severity": severity,
                            "status": "skipped",
                            "reason": "Invalid version specifier",
                        })
                        continue

                    if ver not in spec_set:
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "severity": severity,
                            "status": "skipped",
                            "reason": "Version not affected",
                        })
                        continue
                elif detected_version and not affected_versions_str:
                    print_info(f"No affected version info for CVE {cve_id}, testing anyway.")

                method = test_info.get("method", "GET").upper()
                path = test_info.get("path", "")
                url = test_info.get("url", None)
                headers = test_info.get("headers", None)
                payload = test_info.get("data", None)
                evidence_regex = test_info.get("evidence_regex") or test_info.get("evidence")

                # اعتبارسنجی base_url
                if not url and path:
                    if not base_url or not isinstance(base_url, str) or base_url.strip() == "":
                        print_info(f"Invalid base URL for CVE {cve_id}, skipping.")
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "severity": severity,
                            "status": "not_tested",
                            "reason": "Invalid base URL",
                        })
                        continue
                    # ساخت URL صحیح
                    if base_url.endswith("/") and path.startswith("/"):
                        url = base_url[:-1] + path
                    elif not base_url.endswith("/") and not path.startswith("/"):
                        url = base_url + "/" + path
                    else:
                        url = base_url + path

                if url:
                    test_passed, reason = self.perform_test(
                        method,
                        url,
                        headers=headers,
                        payload=payload,
                        evidence_regex=evidence_regex,
                        timeout=timeout,  # پاس دادن timeout به perform_test
                    )
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "severity": severity,
                        "status": "vulnerable" if test_passed else "not_vulnerable" if test_passed is False else "error",
                        "reason": reason,
                    })
                else:
                    print_info(f"No URL or path provided for test in CVE {cve_id}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "severity": severity,
                        "status": "not_tested",
                        "reason": "No test URL or path provided",
                    })

            return results

        except KeyboardInterrupt:
            print_error("Scan interrupted by user (Ctrl+C). Exiting gracefully.")
            raise SystemExit(1)
        except Exception as e:
            print_error(f"Unexpected error during scan: {e}")
            log_error(f"Unexpected error during scan: {e}")
            raise CVEScannerException(str(e))
