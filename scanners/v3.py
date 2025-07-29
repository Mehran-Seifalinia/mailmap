from json import load
from re import search

class MailmanV3Scanner:
    """
    Mailman v3.x scanner.
    Detects Mailman 3 version using fingerprints loaded from JSON file.
    """

    def __init__(self, fingerprints_path='data/fingerprints.json'):
        self.fingerprints = self._load_json(fingerprints_path)

    def _load_json(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return load(f)

    def _get_header_value(self, headers, header_name):
        """
        Case-insensitive header retrieval.
        """
        for k, v in headers.items():
            if k.lower() == header_name.lower():
                return v
        return None

    def detect_version(self, response):
        """
        Detect Mailman 3 version from response dict.
        Args:
            response: dict with keys 'headers', 'body', 'url_path'
        Returns:
            version string or None if not found.
        """
        headers = response.get('headers', {})
        body = response.get('body', '')
        url_path = response.get('url_path', '')

        for fp in self.fingerprints:
            if fp.get('version', '').startswith('Mailman 3'):
                method = fp.get('method')
                location = fp.get('location')
                pattern = fp.get('pattern')
                version = fp.get('version')

                if method == 'header' and location.startswith('headers.'):
                    header_name = location[len('headers.'):]
                    val = self._get_header_value(headers, header_name)
                    if val and search(pattern, val):
                        return version

                elif method == 'body':
                    if search(pattern, body):
                        return version

                elif method == 'url':
                    if location in url_path:
                        return version

        return None


# Example usage
if __name__ == "__main__":
    sample_response = {
        'headers': {
            'X-Mailman-Version': '3.3.1',
            'Server': 'Mailman/3.3.1'
        },
        'body': '<html><body>Powered by Mailman 3</body></html>',
        'url_path': '/mailman/api/lists'
    }

    scanner = MailmanV3Scanner()
    detected_version = scanner.detect_version(sample_response)
    print(f"Detected Mailman 3 version: {detected_version}")
