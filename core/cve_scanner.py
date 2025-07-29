from logging import getLogger, warning
from typing import List, Dict, Optional
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from requests import Session, Response

from core.utils import create_session, send_get_request, read_json_file, log_error, log_info

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

    def scan(self, detected_version: Optional[str] = None) -> List[Dict]:
        """
        Scan loaded CVEs against the detected Mailman version.
        If detected_version is None, it skips version filtering and attempts all tests.
        Returns a list of CVE scan results with test outcomes.
        """
        results = []

        for cve in self.cves:
            cve_id = cve.get("id", "UNKNOWN")
            description = cve.get("description", "")
            cvss = cve.get("cvss", "N/A")
            affected_versions = cve.get("version_affected", "")
            test_info = cve.get("test", {})

            # Check version compatibility if version is given
            if detected_version and affected_versions:
                try:
                    spec_set = SpecifierSet(affected_versions)
                    ver = Version(detected_version)
                    if ver not in spec_set:
                        # Version not affected
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "test_passed": None,
                            "reason": "Version not affected",
                        })
                        continue
                except InvalidVersion:
                    warning(f"Invalid version format '{detected_version}' for CVE {cve_id}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "test_passed": None,
                        "reason": "Invalid detected version format",
                    })
                    continue

            # Perform the vulnerability test if test info is present
            method = test_info.get("method", "GET").upper()
            url = test_info.get("url")

            if method == "GET" and url:
                try:
                    response: Optional[Response] = send_get_request(self.session, url)
                    if response:
                        status_code = response.status_code
                        if status_code == 200:
                            results.append({
                                "id": cve_id,
                                "description": description,
                                "cvss": cvss,
                                "test_passed": True,
                                "reason": "Expected response received",
                            })
                        else:
                            results.append({
                                "id": cve_id,
                                "description": description,
                                "cvss": cvss,
                                "test_passed": False,
                                "reason": f"Unexpected status code: {status_code}",
                            })
                    else:
                        results.append({
                            "id": cve_id,
                            "description": description,
                            "cvss": cvss,
                            "test_passed": False,
                            "reason": "No response or request failed",
                        })
                except Exception as e:
                    log_error(f"Error performing GET request for CVE {cve_id}: {e}")
                    results.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss,
                        "test_passed": False,
                        "reason": f"Exception during test: {e}",
                    })
            else:
                # If no test or unsupported method, just report CVE info without test
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "test_passed": None,
                    "reason": "No test or unsupported test method",
                })

        return results
