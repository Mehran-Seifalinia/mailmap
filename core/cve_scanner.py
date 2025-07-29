from logging import getLogger
from typing import List, Dict, Optional, Tuple, Any
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from requests import Session, Response
from re import search, IGNORECASE

from core.utils import (
    create_session,
    send_get_request,
    send_post_request,
    read_json_file,
    log_error,
)

logger = getLogger(__name__)


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


class CVEScanner:
    def __init__(self, cve_data_path: str = "data/cves.json"):
        """Initialize CVE scanner by loading CVE definitions and creating HTTP session."""
        self.session: Session = create_session()
        self.cves: List[Dict[str, Any]] = self.load_cves(cve_data_path)

    def load_cves(self, path: str) -> List[Dict[str, Any]]:
        """Load CVE definitions from a JSON file."""
        data = read_json_file(path)
        if not data or not isinstance(data, list):
            logger.warning(f"Empty, invalid, or malformed CVE data file: {path}")
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
                # Search evidence regex in response text case-insensitively
                if search(evidence_regex, response.text, flags=IGNORECASE):
                    return True, f"Evidence matched: {evidence_regex}"
                else:
                    return False, "Evidence not found in response"

            # If no evidence regex to check, success is based on status code only
            return True, "Expected response received"

        except Exception as e:
            log_error(f"Exception during test request to {url}: {e}")
            return False, f"Exception during test: {e}"

    def scan(
        self,
        detected_version: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan loaded CVEs against the detected software version.
        Combines base_url and test paths if needed.
        Returns list of CVE scan results with statuses and reasons.
        """
        results = []

        for cve in self.cves:
            # Check essential fields exist
            if not all(k in cve for k in ("id", "description", "test")):
                logger.warning(f"Malformed CVE entry skipped: {cve}")
                continue

            cve_id = cve.get("id", "UNKNOWN")
            description = cve.get("description", "")
            cvss_raw = cve.get("cvss", "0.0")
            test_info = cve.get("test", {})
            affected_versions = cve.get("affected_versions", [])

            # Convert affected_versions list to string for SpecifierSet
            if isinstance(affected_versions, list):
                affected_versions_str = ",".join(affected_versions)
            else:
                affected_versions_str = str(affected_versions)

            # Parse CVSS score safely
            try:
                cvss = float(cvss_raw)
            except (ValueError, TypeError):
                cvss = 0.0
                logger.warning(f"Invalid CVSS format in CVE {cve_id}: {cvss_raw}")

            severity = get_cvss_severity(cvss)

            # Check if detected version is affected
            if detected_version and affected_versions_str:
                try:
                    ver = Version(detected_version)
                    spec_set = SpecifierSet(affected_versions_str)
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
                except InvalidVersion:
                    logger.warning(f"Invalid detected version format '{detected_version}' for CVE {cve_id}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "severity": severity,
                        "status": "skipped",
                        "reason": "Invalid detected version format",
                    })
                    continue
            elif detected_version and not affected_versions_str:
                logger.debug(f"No affected version info for CVE {cve_id}, testing anyway.")

            # Prepare test parameters
            method = test_info.get("method", "GET").upper()
            path = test_info.get("path", "")
            url = test_info.get("url", None)
            headers = test_info.get("headers", None)
            payload = test_info.get("data", None)  # data key in JSON used as payload
            evidence_regex = test_info.get("evidence_regex") or test_info.get("evidence")

            # Construct full URL if needed
            if not url and path and base_url:
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
                logger.info(f"No URL or path provided for test in CVE {cve_id}")
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "not_tested",
                    "reason": "No test URL or path provided",
                })

        return results
