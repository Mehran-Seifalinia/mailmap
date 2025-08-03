from core import detector, version, paths, cve_scanner
from output import report_generator
from colorama import Fore, Style, init
from json import load

# Initialize colorama for Windows and terminals with auto-reset after each print
init(autoreset=True)

def severity_color(severity: str) -> str:
    """
    Return appropriate console color code based on severity level.

    Args:
        severity (str): Severity level ('high', 'medium', 'low', etc.)

    Returns:
        str: Colorama color code string.
    """
    return {
        'high': Fore.RED,
        'medium': Fore.YELLOW,
        'low': Fore.CYAN
    }.get(severity.lower(), Fore.WHITE)

def load_common_paths(filepath: str) -> list:
    """
    Load common sensitive paths from a JSON file.

    Args:
        filepath (str): Path to the JSON file containing paths.

    Returns:
        list: Combined list of paths from both v2 and v3 keys or empty list on error.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = load(f)
        # Combine paths for Mailman v2 and v3 into a single list
        paths_list = []
        for key in ["v2_paths", "v3_paths"]:
            if key in data:
                paths_list.extend(data[key])
        return paths_list
    except Exception as e:
        print(Fore.RED + f"[!] Failed to load common paths file: {e}")
        return []

def run_scan(target: str, scan_part: str, settings: dict, output_file: str = None, output_format: str = "json") -> None:
    """
    Run the scan process on the specified target.

    Args:
        target (str): The target URL or domain to scan.
        scan_part (str): Part of the scan to run ('detector', 'version', 'paths', 'cve', 'full').
        settings (dict): Settings and configuration for scanning (timeouts, proxies, etc.).
        output_file (str, optional): Path to save the report file. Defaults to None.
        output_format (str, optional): Output file format ('json', 'html', 'md', etc.). Defaults to 'json'.

    Prints results to the console and saves a report if requested.
    """
    try:
        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Detect Mailman installation presence
        if scan_part in ['detector', 'full']:
            result = detector.check_mailman(target, settings)
            mailman_exists = result.get("found", False)
            details = result
            if not mailman_exists:
                print(Fore.RED + f"[!] Mailman not found on {target}.")
                return  # Early exit if Mailman not found
            print(Fore.GREEN + f"[+] Mailman detected: {details}")

        # Step 2: Detect Mailman version
        if scan_part in ['version', 'full']:
            version_info = version.get_version(target, settings)
            if isinstance(version_info, dict):
                if 'conflict' in version_info:
                    print(Fore.YELLOW + f"[!] Multiple versions found: {version_info['versions']}")
                # Ignore 'Generic' version label as it is not a valid version string
                elif version_info.get('version') and version_info.get('version').lower() != "generic":
                    print(Fore.GREEN + f"[+] Mailman version: {version_info['version']}")
                else:
                    print(Fore.RED + "[!] No Mailman version detected.")
            else:
                print(Fore.RED + "[!] Invalid version info format received.")

        # Step 3: Scan sensitive paths if requested
        if scan_part in ['paths', 'full']:
            common_paths = load_common_paths(settings.get('paths', 'data/common_paths.json'))
            if not common_paths:
                print(Fore.RED + "[!] No paths loaded, skipping path scan.")
            else:
                # Run path checks using the loaded paths
                path_results = paths.check_paths(target, common_paths, timeout=settings.get('timeout', 5))
                for item in path_results:
                    severity = item.get('severity', 'unknown')
                    item_type = item.get('type', 'Unknown')
                    print(severity_color(severity) + f"[!] Found: {item_type} - {item.get('path', 'N/A')} - Severity: {severity}")

        # Step 4: Scan known CVEs based on detected version
        if scan_part in ['cve', 'full']:
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                print(severity_color(cve['severity']) + f"[!] CVE found: {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # Step 5: Save the full report if an output file is specified
        if output_file:
            report_data = {
                'mailman_found': mailman_exists,
                'details': details,
                'version': version_info,
                'paths': path_results,
                'cves': cve_results,
            }
            report_generator.save_report(output_file, output_format, report_data)
            print(Fore.GREEN + f"[+] Report saved to {output_file}")

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user (Ctrl+C).")
    except Exception as e:
        import traceback
        print(Fore.RED + f"[!] Unexpected error: {e}")
        print(Fore.RED + traceback.format_exc())
