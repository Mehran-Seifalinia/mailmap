from asyncio import run
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

async def run_scan(
    target: str,
    scan_part: str,
    settings: dict,
    output_file: str = None,
    output_format: str = "json",
    verbose: bool = False
) -> None:
    """
    Main async scan runner function that orchestrates the full scanning workflow.

    Steps:
    1. Detect if Mailman is installed on the target.
    2. Extract Mailman version asynchronously.
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

    delay = settings.get('delay', 0)
    settings['delay'] = delay

    try:
        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Detect Mailman presence synchronously
        if scan_part in ['detector', 'full']:
            result = detector.check_mailman(target, settings)
            mailman_exists = result.get("found", False)
            details = result
            if not mailman_exists:
                console.print(f"[bold red][!] Mailman not found on {target}.[/bold red]")
                # Prepare minimal report indicating Mailman not found
                report_data = {
                    'mailman_found': False,
                    'details': details,
                    'version': None,
                    'paths': [],
                    'cves': [],
                    'message': 'Mailman not found on target.'
                }
                # Save report if output file is specified
                if output_file:
                    report_generator.save_report(output_file, output_format, report_data)
                    console.print(f"[bold green][+] Report saved to {output_file}[/bold green]")
                return  # Stop further scanning after saving report
            console.print(f"[bold green][+] Mailman detected:[/bold green] {details}")

        # Step 2: Get Mailman version asynchronously
        if scan_part in ['version', 'full']:
            version_info = await version.get_version(target, settings)
            
            # Check the type of version_info and handle possible outcomes
            if not isinstance(version_info, dict):
                console.print("[bold red][!] Invalid version info format received.[/bold red]")
            elif 'error' in version_info:
                console.print(f"[bold red][!] Error: {version_info['error']}[/bold red]")
            elif version_info.get('conflict'):
                console.print(f"[bold yellow][!] Multiple versions found:[/bold yellow] {version_info['versions']}")
            else:
                version_str = version_info.get('version')
                if is_valid_version(version_str):
                    console.print(f"[bold green][+] Mailman version:[/bold green] {version_str}")
                else:
                    console.print("[bold cyan][*] No valid Mailman version detected.[/bold cyan]")
        else:
            version_info = {}

        # Step 3: Scan sensitive paths
        if scan_part in ['paths', 'full']:
            common_paths = load_common_paths(settings.get('paths', 'data/common_paths.json'))
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

def main():
    """
    Main entry point to run the async scan from a synchronous context.
    Uses asyncio.run to execute async run_scan.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Mailmap Security Scanner CLI")
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

    settings = {
        'timeout': args.timeout,
        'delay': args.delay,
        'max_retries': args.max_retries,
        'verbose': args.verbose,
        'paths': args.paths,
    }
    if args.proxy:
        settings['proxy'] = args.proxy
    if args.user_agent:
        settings['user_agent'] = args.user_agent

    try:
        run(
            run_scan(
                target=args.target,
                scan_part=args.scan_part,
                settings=settings,
                output_file=args.output,
                output_format=args.format,
                verbose=args.verbose
            )
        )
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan cancelled by user (Ctrl+C)[/bold red]")
        sys_exit(130)
    except Exception as e:
        console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
        if args.verbose:
            console.print_exception()
        sys_exit(1)

if __name__ == "__main__":
    main()
