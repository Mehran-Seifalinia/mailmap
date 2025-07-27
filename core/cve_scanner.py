from re import compile, error as RegexError
from json import load, JSONDecodeError
from logging import getLogger, basicConfig, INFO, error, warning
from requests import Session, RequestException
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from os import path
from typing import List, Dict, Tuple, Optional, Union

# Setup logger with check to avoid duplicate handlers
logger = getLogger(__name__)
if not logger.hasHandlers():
    basicConfig(level=INFO, format='[%(levelname)s] %(message)s')

class CVEScanner:
    """
    A class to scan known CVEs against a target Mailman installation.
    """

    def __init__(self, base_url: str, mailman_version: Optional[str] = None, timeout: Tuple[int, int] = (5, 10)) -> None:
        """
        Initialize the scanner with target base URL and Mailman version.

        Args:
            base_url (str): The base URL of the target Mailman instance.
            mailman_version (str, optional): The detected Mailman version (e.g., '2.1.39').
            timeout (tuple): (connect_timeout, read_timeout) for HTTP requests.
        """
        self.base_url = base_url.rstrip('/')
        self.mailman_version = mailman_version
        self.timeout = timeout
        self.session = Session()
        self.cves: List[Dict[str, Union[str, float, List[str]]]] = []

    def load_cves(self, path_to_cves: str) -> List[Dict]:
        """
        Load CVE data from a JSON file.

        Args:
            path_to_cves (str): Path to cves.json file.

        Returns:
            List of CVE dictionaries.
        """
        try:
            with open(path_to_cves, 'r', encoding='utf-8') as f:
                return load(f)
        except FileNotFoundError:
            error(f"CVEs JSON file not found: {path_to_cves}")
        except JSONDecodeError:
            error(f"Invalid JSON format in CVEs file: {path_to_cves}")
        except Exception as e:
            error(f"Failed to load CVEs JSON file: {e}")
        return []

    def is_version_affected(self, cve: Dict) -> bool:
        """
        Check if the Mailman version is affected by the given CVE.

        Args:
            cve (dict): A dictionary containing CVE details, including 'affected_versions'.

        Returns:
            bool: True if the version is affected, False otherwise.
        """
        if not self.mailman_version or not isinstance(self.mailman_version, str):
            logger.error("Invalid Mailman version: must be a non-empty string")
            return False

        affected_versions = cve.get('affected_versions')
        if not affected_versions or not isinstance(affected_versions, list):
            logger.warning(f"Invalid or missing affected_versions in CVE {cve.get('id')}")
            return False

        try:
            current_version = Version(self.mailman_version)
        except InvalidVersion:
            logger.error(f"Invalid Mailman version format: {self.mailman_version}")
            return False

        # Use SpecifierSet for all version specs
        for spec in affected_versions:
            try:
                # If spec starts with comparison operators, treat as SpecifierSet
                if any(spec.startswith(op) for op in ('<', '>', '=', '!', '~')):
                    spec_set = SpecifierSet(spec)
                    if current_version in spec_set:
                        return True
                else:
                    # Exact version match
                    if current_version == Version(spec):
                        return True
            except InvalidVersion:
                logger.warning(f"Invalid version specifier '{spec}' in CVE {cve.get('id')}")
                continue
            except Exception as e:
                logger.warning(f"Error processing version spec '{spec}': {e}")
                continue

        return False

    def run_test(self, test: Dict) -> Tuple[bool, Optional[str]]:
        """
        Run a single CVE test against the target.

        Args:
            test (dict): Test dictionary with keys like method, path, data, headers, expected_status, evidence_regex, evidence.

        Returns:
            Tuple[bool, Optional[str]]: (test_passed, error_or_reason)
        """
        method = test.get('method', 'GET').upper()
        url = self.base_url + test.get('path', '')
        data = test.get('data')
        headers = test.get('headers')
        expected_status = test.get('expected_status')
        evidence_regex = test.get('evidence_regex')
        evidence_text = test.get('evidence')

        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=self.timeout)
            elif method == 'POST':
                response = self.session.post(url, headers=headers, data=data, timeout=self.timeout)
            else:
                # For simplicity, not implementing other methods currently
                return False, f"HTTP method {method} not supported."

        except RequestException as e:
            logger.error(f"Request error during CVE test at {url}: {e}")
            return False, f"Request failed: {e}"

        # Validate expected_status if provided
        if expected_status is not None and response.status_code != expected_status:
            return False, f"Unexpected status code: {response.status_code}"

        content = response.text if response.text else ""

        # Validate evidence_regex if present
        if evidence_regex:
            try:
                pattern = compile(evidence_regex, flags=0)
            except RegexError as e:
                warning(f"Invalid regex pattern '{evidence_regex}': {e}")
                return False, "Invalid regex pattern"

            if not pattern.search(content):
                return False, "Evidence regex not matched"

        # Validate evidence text if present
        if evidence_text and evidence_text not in content:
            return False, "Evidence text not found"

        return True, None

    def scan(self) -> List[Dict[str, Union[str, bool, Optional[str]]]]:
        """
        Scan all loaded CVEs against the target.

        Returns:
            List of dictionaries with scan results for each CVE.
        """
        if not self.cves:
            error("No CVE data loaded. Scan aborted.")
            return []

        results = []
        for cve in self.cves:
            cve_id = cve.get('id', 'UNKNOWN')
            title = cve.get('title', '')
            description = cve.get('description', '')
            cvss = cve.get('cvss', 'N/A')

            if not self.is_version_affected(cve):
                continue

            test = cve.get('test', {})
            passed, reason = self.run_test(test)

            result = {
                'id': cve_id,
                'title': title,
                'description': description,
                'cvss': cvss,
                'test_passed': passed,
            }
            if not passed:
                # Add debug info for failures
                result['reason'] = reason

            results.append(result)

        return results


if __name__ == '__main__':
    # Example usage
    scanner = CVEScanner(base_url="http://localhost/mailman", mailman_version="2.1.39")
    scanner.cves = scanner.load_cves("data/cves.json")
    results = scanner.scan()
    for r in results:
        print(r)
