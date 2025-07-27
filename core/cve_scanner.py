from logging import getLogger, warning
from typing import List, Dict, Optional
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from requests import Response

from core.utils import create_session, read_json_file, send_get_request, log_info, log_error

logger = getLogger(__name__)


class CVEScanner:
    def __init__(self, path_to_cves: str):
        self.session = create_session()
        self.cves = self.load_cves(path_to_cves)

    def load_cves(self, path_to_cves: str) -> List[Dict]:
        """
        Load CVE definitions from a JSON file.
        """
        data = read_json_file(path_to_cves)
        return data if data else []

    def scan(self, detected_version: Optional[str] = None) -> List[Dict]:
        """
        Scan CVEs against the detected version.
        If version is affected or not specified, perform the vulnerability test.
        """
        results = []
        for cve in self.cves:
            try:
                affected_versions = cve.get('version_affected')
                skip_test = False

                # Check if the detected version is within the affected range
                if affected_versions and detected_version:
                    try:
                        spec_set = SpecifierSet(affected_versions)
                        if Version(detected_version) not in spec_set:
                            skip_test = True
                    except InvalidVersion:
                        warning(f"Invalid version format: {detected_version}")
                        skip_test = True

                if skip_test:
                    results.append({
                        "id": cve.get("id"),
                        "description": cve.get("description"),
                        "cvss": cve.get("cvss"),
                        "test_passed": None,
                        "reason": "Version not affected",
                    })
                    continue

                # Perform the vulnerability test
                test_info = cve.get("test", {})
                method = test_info.get("method", "GET").upper()
                url = test_info.get("url")

                if method == "GET" and url:
                    response: Optional[Response] = send_get_request(self.session, url)
                    if response:
                        status_code = response.status_code
                        if status_code == 200:
                            results.append({
                                "id": cve.get("id"),
                                "description": cve.get("description"),
                                "cvss": cve.get("cvss"),
                                "test_passed": True,
                                "reason": "Expected response received",
                            })
                        else:
                            results.append({
                                "id": cve.get("id"),
                                "description": cve.get("description"),
                                "cvss": cve.get("cvss"),
                                "test_passed": False,
                                "reason": f"Unexpected status code: {status_code}",
                            })
                    else:
                        results.append({
                            "id": cve.get("id"),
                            "description": cve.get("description"),
                            "cvss": cve.get("cvss"),
                            "test_passed": False,
                            "reason": "No response or request failed",
                        })

            except Exception as e:
                log_error(f"Error scanning CVE {cve.get('id')}: {e}")
                results.append({
                    "id": cve.get("id"),
                    "description": cve.get("description"),
                    "cvss": cve.get("cvss"),
                    "test_passed": False,
                    "reason": f"Exception occurred: {e}",
                })

        return results
