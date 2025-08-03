from core import detector, version, paths, cve_scanner
from output import report_generator
from rich.console import Console
from rich.traceback import install
from json import load
from sys import exit as sys_exit  # Use alias for exit to avoid name clashes

# Enable rich traceback globally for improved error visibility
install(show_locals=False)

console = Console()

def severity_color(severity: str) -> str:
    """
    Map severity levels to console colors/styles.

    Args:
        severity (str): Severity level string (e.g., 'high', 'medium', 'low')

    Returns:
        str: Corresponding rich style string for printing
    """
    return {
        'high': "bold red",
        'medium': "yellow",
        'low': "cyan"
    }.get(severity.lower(), "white")


def is_valid_version(version: str) -> bool:
    """
    Validate Mailman version string to filter out generic or invalid values.

    Args:
        version (str): Version string to validate

    Returns:
        bool: True if version is valid, False otherwise
    """
    if not version:
        return False
    invalid_versions = {"generic", "version", "unknown", "none", ""}
    return version.lower() not in invalid_versions


def load_common_paths(filepath: str) -> list:
    """
    Load common sensitive paths from a JSON file.

    The JSON is expected to have keys like 'v2_paths' and 'v3_paths' containing lists.

    Args:
        filepath (str): Path to JSON file containing common paths

    Returns:
        list: Combined list of paths from both Mailman v2 and v3

    Raises:
        SystemExit: Exits the program if the file is missing, unreadable, or contains no paths.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = load(f)
        paths_list = []
        for key in ["v2_paths", "v3_paths"]:
            if key in data and isinstance(data[key], list):
                paths_list.extend(data[key])
        if not paths_list:
            console.print(f"[bold red][!] The sensitive paths file '{filepath}' is empty or invalid.[/bold red]")
            sys_exit(1)
        return paths_list
    except Exception as e:
        console.print(f"[bold red][!] Failed to load sensitive paths file '{filepath}': {e}[/bold red]")
        sys_exit(1)


def handle_error(exc: Exception, verbose: bool = False) -> int:
    """
    Unified error handler to display error messages and return exit code.

    Args:
        exc (Exception): The exception caught during scanning
        verbose (bool): Flag to indicate whether to print full traceback

    Returns:
        int: Exit code for the program (130 if interrupted, 1 otherwise)
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
    Main scan runner function that orchestrates the full scanning workflow.

    Steps:
    1. Detect if Mailman is installed on the target.
    2. Extract Mailman version.
    3. Scan for sensitive paths if requested.
    4. Scan for CVEs based on detected version.
    5. Generate and save report if requested.

    Args:
        target (str): URL or domain to scan.
        scan_part (str): Part of the scan to execute ('detector', 'version', 'paths', 'cve', 'full').
        settings (dict): Dictionary of scan settings (timeouts, proxy, user agent, etc.).
        output_file (str, optional): Path to output file for saving the report.
        output_format (str, optional): Format of the output report ('json', 'html', 'md').
        verbose (bool, optional): Flag to enable verbose error output.

    Returns:
        None
    """

    # Set default delay to 0 if not provided in settings
    delay = settings.get('delay')
    if delay is None:
        delay = 0
    settings['delay'] = delay

    try:
        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Detect Mailman presence
        if scan_part in ['detector', 'full']:
            result = detector.check_mailman(target, settings)
            mailman_exists = result.get("found", False)
            details = result
            if not mailman_exists:
                console.print(f"[bold red][!] Mailman not found on {target}.[/bold red]")
                return  # Stop scanning if Mailman is not present
            console.print(f"[bold green][+] Mailman detected:[/bold green] {details}")

        # Step 2: Get Mailman version
        if scan_part in ['version', 'full']:
            version_info = version.get_version(target, settings)
            if isinstance(version_info, dict):
                if 'conflict' in version_info:
                    console.print(f"[bold yellow][!] Multiple versions found:[/bold yellow] {version_info['versions']}")
                else:
                    version_str = version_info.get('version')
                    if is_valid_version(version_str):
                        console.print(f"[bold green][+] Mailman version:[/bold green] {version_str}")
                    else:
                        console.print("[bold red][!] No valid Mailman version detected.[/bold red]")
            else:
                console.print("[bold red][!] Invalid version info format received.[/bold red]")

        # Step 3: Scan sensitive paths
        if scan_part in ['paths', 'full']:
            common_paths = load_common_paths(settings.get('paths', 'data/common_paths.json'))
            # Since load_common_paths exits on error or empty, we can safely continue here
            path_results = paths.check_paths(target, common_paths, timeout=settings.get('timeout', 5))
            for item in path_results:
                severity = item.get('severity', 'unknown')
                item_type = item.get('type', 'Unknown')
                console.print(f"[{severity_color(severity)}][!] Found:[/] {item_type} - {item.get('path', 'N/A')} - Severity: {severity}")

        # Step 4: Scan known CVEs based on version
        if scan_part in ['cve', 'full']:
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                console.print(f"[{severity_color(cve['severity'])}][!] CVE found:[/] {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # Step 5: Save report if output file specified
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
