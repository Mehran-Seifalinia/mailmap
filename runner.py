from core import detector, version, paths, cve_scanner
from output import report_generator
from rich.console import Console
from rich.traceback import install
from json import load
from sys import exit as sys_exit  # import exit with alias

# Enable rich traceback globally for better error display
install(show_locals=False)

console = Console()

def severity_color(severity: str) -> str:
    """
    Return appropriate console style based on severity level.

    Args:
        severity (str): Severity level ('high', 'medium', 'low', etc.)

    Returns:
        str: Rich style string.
    """
    return {
        'high': "bold red",
        'medium': "yellow",
        'low': "cyan"
    }.get(severity.lower(), "white")

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
        paths_list = []
        for key in ["v2_paths", "v3_paths"]:
            if key in data:
                paths_list.extend(data[key])
        return paths_list
    except Exception as e:
        console.print(f"[bold red][!] Failed to load common paths file:[/bold red] {e}")
        return []

def handle_error(exc: Exception, verbose: bool = False) -> int:
    """
    Unified error handler to print errors and return appropriate exit code.

    Args:
        exc (Exception): The caught exception.
        verbose (bool): Whether to print detailed traceback.

    Returns:
        int: Exit code (130 for KeyboardInterrupt, 1 for others).
    """
    if isinstance(exc, KeyboardInterrupt):
        console.print("[bold yellow]\n[!] Scan interrupted by user (KeyboardInterrupt).[/bold yellow]")
        return 130
    else:
        console.print(f"[bold red][!] Unexpected error:[/bold red] {exc}")
        if verbose:
            console.print_exception()
        return 1

def run_scan(target: str, scan_part: str, settings: dict, output_file: str = None,
             output_format: str = "json", verbose: bool = False) -> None:
    """
    Run the scan process on the specified target.

    Args:
        target (str): The target URL or domain to scan.
        scan_part (str): Part of the scan to run ('detector', 'version', 'paths', 'cve', 'full').
        settings (dict): Settings and configuration for scanning (timeouts, proxies, etc.).
        output_file (str, optional): Path to save the report file. Defaults to None.
        output_format (str, optional): Output file format ('json', 'html', 'md', etc.). Defaults to 'json'.
        verbose (bool, optional): Whether to print detailed errors and traceback. Defaults to False.

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
                console.print(f"[bold red][!] Mailman not found on {target}.[/bold red]")
                return  # Early exit if Mailman not found
            console.print(f"[bold green][+] Mailman detected:[/bold green] {details}")

        # Step 2: Detect Mailman version
        if scan_part in ['version', 'full']:
            version_info = version.get_version(target, settings)
            if isinstance(version_info, dict):
                if 'conflict' in version_info:
                    console.print(f"[bold yellow][!] Multiple versions found:[/bold yellow] {version_info['versions']}")
                elif version_info.get('version') and version_info.get('version').lower() != "generic":
                    console.print(f"[bold green][+] Mailman version:[/bold green] {version_info['version']}")
                else:
                    console.print("[bold red][!] No Mailman version detected.[/bold red]")
            else:
                console.print("[bold red][!] Invalid version info format received.[/bold red]")

        # Step 3: Scan sensitive paths if requested
        if scan_part in ['paths', 'full']:
            common_paths = load_common_paths(settings.get('paths', 'data/common_paths.json'))
            if not common_paths:
                console.print("[bold red][!] No paths loaded, skipping path scan.[/bold red]")
            else:
                path_results = paths.check_paths(target, common_paths, timeout=settings.get('timeout', 5))
                for item in path_results:
                    severity = item.get('severity', 'unknown')
                    item_type = item.get('type', 'Unknown')
                    console.print(f"[{severity_color(severity)}][!] Found:[/] {item_type} - {item.get('path', 'N/A')} - Severity: {severity}")

        # Step 4: Scan known CVEs based on detected version
        if scan_part in ['cve', 'full']:
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                console.print(f"[{severity_color(cve['severity'])}][!] CVE found:[/] {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

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
            console.print(f"[bold green][+] Report saved to {output_file}[/bold green]")

    except Exception as e:
        exit_code = handle_error(e, verbose)
        sys_exit(exit_code)
