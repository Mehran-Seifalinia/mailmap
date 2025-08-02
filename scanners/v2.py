from json import load
from re import search
from rich import print
from rich.console import Console

console = Console()

class MailmanV2Scanner:
    """
    Mailman v2.x scanner: detect version based on HTTP response
    and fingerprints loaded from JSON.
    """

    _fingerprints_cache = None

    def __init__(self, fingerprints_path='data/fingerprints.json'):
        if MailmanV2Scanner._fingerprints_cache is None:
            MailmanV2Scanner._fingerprints_cache = self._load_json(fingerprints_path)
        self.fingerprints = MailmanV2Scanner._fingerprints_cache

    def _load_json(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = load(f)
            console.print(f"[green][+] Loaded fingerprints from '{filepath}'[/green]")
            return data
        except Exception as e:
            console.print(f"[red][!] Error loading fingerprints file '{filepath}': {e}[/red]")
            return []

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
        try:
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

        except KeyboardInterrupt:
            console.print("[yellow]\n[!] Scan interrupted by user (Ctrl+C)[/yellow]")
            raise  # به بالا پاس میده که بتونی مدیریت کنی
        except Exception as e:
            console.print(f"[red][!] Unexpected error in detect_version: {e}[/red]")
            return None


if __name__ == "__main__":
    import sys

    sample_response = {
        'headers': {
            'X-Mailman-Version': '2.1.39',
            'Server': 'Mailman/2.1.39'
        },
        'body': '<html><body>Powered by Mailman 2</body></html>',
        'url_path': '/mailman/private/mailman'
    }

    scanner = MailmanV2Scanner()

    try:
        detected_version = scanner.detect_version(sample_response)
        if detected_version:
            console.print(f"[bold green]Detected Mailman version:[/] {detected_version}")
        else:
            console.print("[bold yellow]Mailman version not detected[/bold yellow]")
    except KeyboardInterrupt:
        console.print("[yellow]Scan stopped by user.[/yellow]")
        sys.exit(0)
