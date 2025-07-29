from logging import getLogger
from typing import List, Dict, Optional, Tuple, Any
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from requests import Session, Response

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
        self.session: Session = create_session()
        self.cves: List[Dict[str, Any]] = self.load_cves(cve_data_path)

    def load_cves(self, path: str) -> List[Dict[str, Any]]:
        """Load CVE definitions from JSON file."""
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
        timeout: int = 10,
    ) -> Tuple[Optional[bool], str]:
        """Performs an HTTP-based vulnerability test with optional headers/payload."""
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

            if response.status_code == 200:
                return True, "Expected response received"
            else:
                return False, f"Unexpected status code: {response.status_code}"

        except Exception as e:
            log_error(f"Exception during test request to {url}: {e}")
            return False, f"Exception during test: {e}"

    def scan(self, detected_version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan loaded CVEs against the detected Mailman version.
        Returns a list of CVE scan results with test outcomes.
        """
        results = []

        for cve in self.cves:
            # Validate essential fields exist
            if not all(k in cve for k in ("id", "description", "test")):
                logger.warning(f"Malformed CVE entry skipped: {cve}")
                continue

            cve_id = cve.get("id", "UNKNOWN")
            description = cve.get("description", "")
            cvss_raw = cve.get("cvss", "0.0")
            test_info = cve.get("test", {})
            affected_versions = cve.get("version_affected", "").strip()

            # Parse CVSS score safely
            try:
                cvss = float(cvss_raw)
            except (ValueError, TypeError):
                cvss = 0.0
                logger.warning(f"Invalid CVSS format in CVE {cve_id}: {cvss_raw}")

            severity = get_cvss_severity(cvss)

            # Version filtering
            if detected_version and affected_versions:
                try:
                    ver = Version(detected_version)
                    spec_set = SpecifierSet(affected_versions)
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
                    logger.warning(f"Invalid version format '{detected_version}' for CVE {cve_id}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "severity": severity,
                        "status": "skipped",
                        "reason": "Invalid detected version format",
                    })
                    continue
            elif detected_version and not affected_versions:
                logger.debug(f"No affected version info provided for CVE {cve_id}, test will proceed anyway.")

            # Prepare HTTP test parameters
            method = test_info.get("method", "GET").upper()
            url = test_info.get("url")
            headers = test_info.get("headers")
            payload = test_info.get("payload")

            if url:
                test_passed, reason = self.perform_test(method, url, headers=headers, payload=payload)
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "vulnerable" if test_passed else "not_vulnerable" if test_passed is False else "error",
                    "reason": reason,
                })
            else:
                logger.info(f"No URL provided for test in CVE {cve_id}")
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "severity": severity,
                    "status": "not_tested",
                    "reason": "No test URL or test data provided",
                })

        return results
