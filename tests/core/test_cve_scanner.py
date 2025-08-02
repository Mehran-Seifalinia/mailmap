import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from packaging.version import Version

# اضافه کردن مسیر ریشه پروژه به PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from core.cve_scanner import CVEScanner, get_cvss_severity, CVEScannerException


class TestCVEScanner(unittest.TestCase):

    def setUp(self):
        patcher_session = patch('core.cve_scanner.create_session', return_value=MagicMock())
        self.mock_create_session = patcher_session.start()
        self.addCleanup(patcher_session.stop)

    @patch('core.cve_scanner.read_json_file')
    def test_load_cves_valid_and_invalid(self, mock_read_json):
        # valid data
        mock_read_json.return_value = [{"id": "CVE-1", "description": "desc", "test": {}}]
        scanner = CVEScanner()
        self.assertEqual(len(scanner.cves), 1)

        # invalid data (empty list)
        mock_read_json.return_value = []
        with patch('core.cve_scanner.print_warning') as mock_warn:
            scanner = CVEScanner()
            self.assertEqual(scanner.cves, [])
            mock_warn.assert_called()

        # invalid data (not a list)
        mock_read_json.return_value = {"not": "a list"}
        with patch('core.cve_scanner.print_warning') as mock_warn:
            scanner = CVEScanner()
            self.assertEqual(scanner.cves, [])
            mock_warn.assert_called()

    def test_get_cvss_severity(self):
        self.assertEqual(get_cvss_severity(9.5), "Critical")
        self.assertEqual(get_cvss_severity(7.5), "High")
        self.assertEqual(get_cvss_severity(5.0), "Medium")
        self.assertEqual(get_cvss_severity(1.0), "Low")
        self.assertEqual(get_cvss_severity(0), "None")
        self.assertEqual(get_cvss_severity(-1), "None")

    @patch('core.cve_scanner.send_get_request')
    @patch('core.cve_scanner.send_post_request')
    def test_perform_test_get_post(self, mock_post, mock_get):
        scanner = CVEScanner()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "some Evidence here"
        mock_get.return_value = mock_response

        passed, reason = scanner.perform_test(
            method="GET",
            url="http://test.url",
            evidence_regex="Evidence"
        )
        self.assertTrue(passed)
        self.assertIn("Evidence matched", reason)

        mock_post.return_value = mock_response
        passed, reason = scanner.perform_test(
            method="POST",
            url="http://test.url"
        )
        self.assertTrue(passed)
        self.assertEqual(reason, "Expected response received")

        passed, reason = scanner.perform_test("PUT", "http://test.url")
        self.assertIsNone(passed)
        self.assertIn("Unsupported HTTP method", reason)

        mock_get.return_value = None
        passed, reason = scanner.perform_test("GET", "http://test.url")
        self.assertFalse(passed)
        self.assertIn("No response", reason)

        mock_response.status_code = 404
        mock_get.return_value = mock_response
        passed, reason = scanner.perform_test("GET", "http://test.url")
        self.assertFalse(passed)
        self.assertIn("Unexpected status code", reason)

        mock_response.status_code = 200
        mock_response.text = "no match"
        mock_get.return_value = mock_response
        passed, reason = scanner.perform_test("GET", "http://test.url", evidence_regex="abc")
        self.assertFalse(passed)
        self.assertIn("Evidence not found", reason)

        mock_get.side_effect = Exception("Test exception")
        with patch('core.cve_scanner.log_error') as mock_log_error, \
             patch('core.cve_scanner.print_error') as mock_print_error:
            passed, reason = scanner.perform_test("GET", "http://test.url")
            self.assertFalse(passed)
            self.assertIn("Exception during test", reason)
            mock_log_error.assert_called()
            mock_print_error.assert_called()

    @patch('core.cve_scanner.CVEScanner.perform_test')
    @patch('core.cve_scanner.read_json_file')
    def test_scan_basic(self, mock_read_json, mock_perform_test):
        mock_read_json.return_value = [{
            "id": "CVE-2023-1234",
            "description": "Test vulnerability",
            "cvss": "9.8",
            "affected_versions": [">=1.0,<2.0"],
            "test": {
                "method": "GET",
                "path": "/test",
                "evidence_regex": "vuln"
            }
        }]

        mock_perform_test.return_value = (True, "Evidence matched")

        scanner = CVEScanner()
        results = scanner.scan(detected_version="1.5", base_url="http://example.com")
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res['id'], "CVE-2023-1234")
        self.assertEqual(res['severity'], "Critical")
        self.assertEqual(res['status'], "vulnerable")
        self.assertIn("Evidence matched", res['reason'])

        results = scanner.scan(detected_version="2.5", base_url="http://example.com")
        self.assertEqual(results[0]['status'], "skipped")
        self.assertIn("Version not affected", results[0]['reason'])

        mock_read_json.return_value[0]['cvss'] = "invalid"
        with patch('core.cve_scanner.print_warning') as mock_warn:
            scanner = CVEScanner()
            results = scanner.scan(detected_version="1.5", base_url="http://example.com")
            mock_warn.assert_called()

        mock_read_json.return_value = [{}]
        with patch('core.cve_scanner.print_warning') as mock_warn:
            scanner = CVEScanner()
            results = scanner.scan()
            self.assertEqual(results, [])
            mock_warn.assert_called()

    @patch('core.cve_scanner.CVEScanner.perform_test')
    @patch('core.cve_scanner.read_json_file')
    def test_scan_with_invalid_test_info(self, mock_read_json, mock_perform_test):
        mock_read_json.return_value = [{
            "id": "CVE-0000",
            "description": "desc",
            "cvss": "5.0",
            "affected_versions": [">=1.0"],
            "test": "invalid"
        }]

        scanner = CVEScanner()
        results = scanner.scan(detected_version="1.2", base_url="http://base.url")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], "error")
        self.assertIn("Invalid test configuration", results[0]['reason'])

    @patch('core.cve_scanner.CVEScanner.perform_test')
    @patch('core.cve_scanner.read_json_file')
    def test_scan_with_missing_url_and_path(self, mock_read_json, mock_perform_test):
        mock_read_json.return_value = [{
            "id": "CVE-123",
            "description": "desc",
            "cvss": "7.0",
            "test": {}
        }]
        scanner = CVEScanner()
        with patch('core.cve_scanner.print_info') as mock_info:
            results = scanner.scan(detected_version="1.0", base_url="http://base.url")
            self.assertEqual(results[0]['status'], "not_tested")
            self.assertIn("No test URL or path", results[0]['reason'])
            mock_info.assert_called()

    @patch('core.cve_scanner.CVEScanner.perform_test')
    @patch('core.cve_scanner.read_json_file')
    def test_scan_with_invalid_base_url(self, mock_read_json, mock_perform_test):
        mock_read_json.return_value = [{
            "id": "CVE-1234",
            "description": "desc",
            "cvss": "4.0",
            "test": {"method": "GET", "path": "/testpath"}
        }]
        scanner = CVEScanner()
        with patch('core.cve_scanner.print_info') as mock_info:
            results = scanner.scan(detected_version="1.0", base_url="")
            self.assertEqual(results[0]['status'], "not_tested")
            self.assertIn("Invalid base URL", results[0]['reason'])
            mock_info.assert_called()

    def test_scan_keyboard_interrupt(self):
        scanner = CVEScanner()
        with patch('core.cve_scanner.read_json_file', return_value=[{
            "id": "CVE-INT",
            "description": "desc",
            "cvss": "4.0",
            "test": {"method": "GET", "url": "http://test"}
        }]), \
             patch.object(scanner, 'perform_test', side_effect=KeyboardInterrupt), \
             patch('core.cve_scanner.print_error') as mock_print_error:
            with self.assertRaises(SystemExit):
                scanner.scan()
            mock_print_error.assert_called_with("Scan interrupted by user (Ctrl+C). Exiting gracefully.")

    def test_scan_unexpected_exception(self):
        scanner = CVEScanner()
        with patch('core.cve_scanner.read_json_file', return_value=[{
            "id": "CVE-EX",
            "description": "desc",
            "cvss": "4.0",
            "test": {"method": "GET", "url": "http://test"}
        }]), \
             patch.object(scanner, 'perform_test', side_effect=Exception("Boom")), \
             patch('core.cve_scanner.print_error') as mock_print_error, \
             patch('core.cve_scanner.log_error') as mock_log_error:
            with self.assertRaises(CVEScannerException):
                scanner.scan()
            mock_print_error.assert_called()
            mock_log_error.assert_called()


if __name__ == "__main__":
    unittest.main()
