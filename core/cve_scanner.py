from logging import getLogger
from typing import List, Dict, Optional, Tuple
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from requests import Session, Response

from core.utils import create_session, send_get_request, send_post_request, read_json_file, log_error

logger = getLogger(__name__)


class CVEScanner:
    def __init__(self, cve_data_path: str = "data/cves.json"):
        self.session: Session = create_session()
        self.cves: List[Dict] = self.load_cves(cve_data_path)

    def load_cves(self, path: str) -> List[Dict]:
        """Load CVE definitions from JSON file."""
        data = read_json_file(path)
        if not data:
            logger.warning(f"Empty or invalid CVE data file: {path}")
            return []
        return data

    def perform_test(self, method: str, url: str) -> Tuple[Optional[bool], str]:
        """Performs an HTTP-based vulnerability test based on method and URL."""
        try:
            method = method.upper()
            if method == "GET":
                response: Optional[Response] = send_get_request(self.session, url)
            elif method == "POST":
                response: Optional[Response] = send_post_request(self.session, url)
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

    def scan(self, detected_version: Optional[str] = None) -> List[Dict]:
        """
        Scan loaded CVEs against the detected Mailman version.
        Returns a list of CVE scan results with test outcomes.
        """
        results = []

        for cve in self.cves:
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
                            "test_passed": None,
                            "reason": "Version not affected",
                        })
                        continue
                except InvalidVersion:
                    logger.warning(f"Invalid version format '{detected_version}' for CVE {cve_id}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "test_passed": None,
                        "reason": "Invalid detected version format",
                    })
                    continue
            elif detected_version and not affected_versions:
                logger.debug(f"No affected version info provided for CVE {cve_id}, test will proceed anyway.")

            # Perform test if test info is present
            method = test_info.get("method", "GET").upper()
            url = test_info.get("url")

            if url:
                test_passed, reason = self.perform_test(method, url)
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "test_passed": test_passed,
                    "reason": reason,
                })
            else:
                logger.info(f"No URL provided for test in CVE {cve_id}")
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "test_passed": None,
                    "reason": "No test URL or test data provided",
                })

        return results
