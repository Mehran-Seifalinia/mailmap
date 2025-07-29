from argparse import ArgumentParser
from sys import exit, stderr
from traceback import print_exc

from core import detector, version, paths, cve_scanner
from output import report_generator


def main():
    parser = ArgumentParser(description="Mailman Security Scanner CLI")
    parser.add_argument('--target', required=True, help="Target URL for scanning")
    parser.add_argument('--paths', default='data/common_paths.json', help="Custom paths file")
    parser.add_argument('--proxy', help="Proxy URL (e.g. http://user:pass@host:port)")
    parser.add_argument('--user-agent', help="Custom User-Agent string for HTTP requests")
    parser.add_argument('--timeout', type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument('--delay', type=float, default=0, help="Delay between HTTP requests in seconds")
    parser.add_argument('--output', help="Output file path")
    parser.add_argument('--format', choices=['json', 'html', 'md'], default='json', help="Output format")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('--scan-part', choices=['detector', 'version', 'paths', 'cve', 'full'], default='full', help="Select scan part")
    parser.add_argument('--max-retries', type=int, default=3, help="Max retries for HTTP requests")
    parser.add_argument('--version', action='version', version='Mailmap Scanner 1.0')

    args = parser.parse_args()

    try:
        # Setup connection settings (proxy, user-agent, timeout, etc.)
        settings = {
            'proxy': args.proxy,
            'user_agent': args.user_agent,
            'timeout': args.timeout,
            'delay': args.delay,
            'max_retries': args.max_retries,
            'verbose': args.verbose,
            'paths': args.paths
        }

        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Detect Mailman installation
        if args.scan_part in ['detector', 'full']:
            mailman_exists, details = detector.check_mailman(args.target, settings)
            if not mailman_exists:
                print(f"[!] Mailman not found on {args.target}.")
                exit(0)
            print(f"[+] Mailman detected: {details}")

        # Step 2: Extract Mailman version
        if args.scan_part in ['version', 'full']:
            version_info = version.get_version(args.target, settings)
            if 'conflict' in version_info:
                print(f"[!] Multiple versions found: {version_info['versions']}")
            elif version_info.get('version'):
                print(f"[+] Mailman version: {version_info['version']}")
            else:
                print("[!] No Mailman version detected.")

        # Step 3: Scan important paths and sensitive files
        if args.scan_part in ['paths', 'full']:
            path_results = paths.scan_paths(args.target, args.paths, settings)
            for item in path_results:
                print(f"[!] Found: {item['type']} - {item['path']} - Severity: {item['severity']}")

        # Step 4: Check for CVEs
        if args.scan_part in ['cve', 'full']:
            # Pass version string or None to CVE scanner
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                print(f"[!] CVE found: {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # Final output saving
        if args.output:
            report_generator.save_report(args.output, args.format, {
                'mailman_found': mailman_exists,
                'version': version_info,
                'paths': path_results,
                'cves': cve_results,
            })
            print(f"[+] Report saved to {args.output}")

    except Exception as e:
        print(f"[!] Error: {str(e)}", file=stderr)
        if args.verbose:
            print_exc()
        exit(1)


if __name__ == "__main__":
    main()
