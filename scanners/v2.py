from json import load
from re import search

class MailmanV2Scanner:
    """
    Mailman v2.x scanner: detect version based on HTTP response
    and fingerprints loaded from JSON.
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
        Detect Mailman version from response dict:
        - headers: dict
        - body: string
        - url_path: string
        Returns version string or None.
        """
        headers = response.get('headers', {})
        body = response.get('body', '')
        url_path = response.get('url_path', '')

        for fp in self.fingerprints:
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


# Example usage:
if __name__ == "__main__":
    sample_response = {
        'headers': {
            'X-Mailman-Version': '2.1.39',
            'Server': 'Mailman/2.1.39'
        },
        'body': '<html><body>Powered by Mailman 2</body></html>',
        'url_path': '/mailman/private/mailman'
    }

    scanner = MailmanV2Scanner()
    detected_version = scanner.detect_version(sample_response)
    print(f"Detected Mailman version: {detected_version}")
