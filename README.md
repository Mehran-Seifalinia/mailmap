# Mailmap - Mailman Security Scanner

Mailmap is a reconnaissance and vulnerability scanner for websites using GNU Mailman. It detects Mailman presence, extracts the version, scans sensitive paths, and checks for known CVEs.

---

## Features

- **Mailman detection** – Identifies Mailman using URL patterns, HTTP headers, and body fingerprints
- **Version extraction** – Detects exact version via `X-Mailman-Version`, `X-Mailman-Release`, and body regex
- **Sensitive path scanning** – Checks for admin interfaces, archives, config files, logs, and more
- **CVE scanning** – Matches detected version against a database of vulnerabilities with optional active tests
- **Asynchronous scanning** – Uses `aiohttp` for high‑performance concurrent requests
- **Proxy support** – HTTP/HTTPS and SOCKS proxies
- **Multiple output formats** – JSON, HTML, Markdown
- **Verbose logging** – Debug output for troubleshooting
- **Modular architecture** – Separate modules for detection, version, paths, CVEs

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/mailmap.git
cd mailmap
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Required packages:  
`aiohttp`, `aiohttp-socks`, `packaging`, `colorama`, `rich`, `nest_asyncio`

---

## Usage

### Basic scan (full)

```bash
python mailmap.py --target https://example.com
```

### Run specific scan parts

```bash
# Detection only
python mailmap.py --target https://example.com --scan-part detector

# Version detection only
python mailmap.py --target https://example.com --scan-part version

# Path scanning only
python mailmap.py --target https://example.com --scan-part paths

# CVE scanning only (requires version detection first)
python mailmap.py --target https://example.com --scan-part cve
```

### With proxy and custom User-Agent

```bash
python mailmap.py --target https://example.com --proxy socks5://127.0.0.1:9050 --user-agent "CustomUA/1.0" --timeout 15
```

### Save report

```bash
python mailmap.py --target https://example.com --output report.json --format json --verbose
```

---

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--target` | Target URL (e.g., `https://example.com`) |
| `--scan-part` | Scan part: `detector`, `version`, `paths`, `cve`, `full` (default: `full`) |
| `--paths` | Custom paths JSON file (default: `data/common_paths.json`) |
| `--proxy` | Proxy URL (e.g., `http://user:pass@host:port` or `socks5://127.0.0.1:9050`) |
| `--user-agent` | Custom User-Agent string |
| `--timeout` | HTTP request timeout in seconds (default: `10`) |
| `--delay` | Delay between requests in seconds (default: `0`) |
| `--output` | Output file path for report |
| `--format` | Report format: `json`, `html`, `md` (default: `json`) |
| `--verbose` | Enable verbose logging (debug level) |
| `--max-retries` | Maximum retries for failed requests (default: `3`) |
| `--version` | Show version and exit |

---

## Project Structure

```
mailmap/
├── mailmap.py                 # Main CLI entry point
├── runner.py                  # Orchestrates scan phases
├── core/
│   ├── detector.py            # Mailman presence detection (async)
│   ├── version.py             # Version fingerprinting
│   ├── paths.py               # Sensitive path scanner (threaded)
│   ├── cve_scanner.py         # CVE checking against detected version
│   └── utils.py               # Shared utilities (HTTP, JSON, logging)
├── data/
│   ├── common_paths.json      # Mailman path definitions (v2 and v3)
│   ├── cves.json              # CVE database with test configurations
│   ├── fingerprints_detection.json  # Fingerprints for Mailman detection
│   └── fingerprints_version.json     # Fingerprints for version extraction
├── output/
│   └── report_generator.py    # Report generation (JSON/HTML/Markdown)
├── scanners/                  # Legacy version-specific scanners (v2, v3)
├── requirements.txt
└── README.md
```

---

## Scan Components

### 1. Detector (`--scan-part detector`)
Checks for Mailman presence using:
- URL patterns (`/mailman/`, `/postorius/`, `/hyperkitty/`)
- HTTP headers (`Server: Mailman`)
- Body patterns (`"Powered by Mailman"`, `"GNU Mailman"`)

### 2. Version (`--scan-part version`)
Extracts version from:
- `X-Mailman-Version` or `X-Mailman-Release` headers
- Body text using regex patterns (e.g., `Mailman version \d+\.\d+\.\d+`)
- URL patterns (e.g., `/mailman/api/` for Mailman 3)

### 3. Paths (`--scan-part paths`)
Scans for sensitive endpoints:
- Admin interfaces (`/mailman/admin`, `/postorius/`)
- Archives (`/pipermail/`, `/archives/`)
- Configuration files (`mm_cfg.py`, `config.py`)
- Log directories, cron scripts, temporary files

### 4. CVE (`--scan-part cve`)
Matches detected version against `cves.json` and performs optional active tests (HTTP requests with payloads) to confirm vulnerability.

---

## Output Format

The tool generates reports containing:

```json
{
  "mailman_found": true,
  "details": { "found": true, "version": "Generic", "url": "...", "evidence": "..." },
  "version": { "version": "2.1.39" },
  "paths": [
    { "path": "/mailman/admin", "status_code": 200, "severity": "high", "found": true }
  ],
  "cves": [
    { "id": "CVE-2025-43919", "cvss": 7.5, "severity": "High", "status": "vulnerable" }
  ]
}
```

HTML and Markdown reports are also supported.

---

## Troubleshooting

### Connection errors
- Verify the target URL is reachable
- Use `--proxy` if behind a firewall
- Increase `--timeout` for slow sites

### "No valid Mailman version detected"
- The target may not be Mailman, or the version is hidden
- Use `--verbose` to see which fingerprints were attempted
- Consider updating `fingerprints_version.json`

### CVE scan returns no results
- Ensure `cves.json` contains entries for the detected version
- Run `--scan-part version` first to obtain a concrete version string

### Missing `data/` files
All JSON files must be present in the `data/` directory. The tool expects:
- `common_paths.json`
- `cves.json`
- `fingerprints_detection.json`
- `fingerprints_version.json`

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

- [GNU Mailman](https://www.list.org/) – The open source mailing list manager
- `aiohttp` – Async HTTP client
- `packaging` – Version parsing and specifiers
- `rich` – Beautiful console output
