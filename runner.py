from asyncio import run as asyncio_run
from json import load
from sys import exit as sys_exit
from rich.console import Console
from rich.traceback import install
from core import detector, version, paths, cve_scanner
from output import report_generator

install(show_locals=False)

console = Console()

def severity_color(severity: str) -> str:
    """
    Map severity string to rich console color style.

    Args:
        severity (str): Severity level ('high', 'medium', 'low', etc.)

    Returns:
        str: Corresponding rich style string
    """
    return {
        'high': "bold red",
        'medium': "yellow",
        'low': "cyan"
    }.get(severity.lower(), "white")

def is_valid_version(version_str: str) -> bool:
    """
    Validate Mailman version string, ignoring generic or invalid entries.

    Args:
        version_str (str): Version string to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not version_str:
        return False
    invalid = {"generic", "version", "unknown", "none", ""}
    return version_str.lower() not in invalid

def load_common_paths(filepath: str) -> list:
    """
    Load common sensitive paths from JSON file.

    Args:
        filepath (str): Path to JSON file containing common paths.

    Returns:
        list: Combined list of paths from different Mailman versions.

    Raises:
        SystemExit: If file cannot be read or paths are missing.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = load(f)
        paths_list = []
        for key in ("v2_paths", "v3_paths"):
            if key in data and isinstance(data[key], list):
                paths_list.extend(data[key])
        if not paths_list:
            console.print(f"[bold red][!] Sensitive paths file '{filepath}' is empty or invalid.[/bold red]")
            sys_exit(1)
        return paths_list
    except Exception as e:
        console.print(f"[bold red][!] Failed to load sensitive paths file '{filepath}': {e}[/bold red]")
        sys_exit(1)

def handle_error(exc: Exception, verbose: bool = False) -> int:
    """
    Unified error handler printing error and returning proper exit code.

    Args:
        exc (Exception): Exception object
        verbose (bool): Whether to print full traceback

    Returns:
        int: Exit code (130 for KeyboardInterrupt, 1 otherwise)
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
    verbose: bool = False,
) -> None:
    """
    Main asynchronous scan runner handling scanning phases and report generation.

    Args:
        target (str): Target URL or domain to scan.
        scan_part (str): Which part of scan to execute ('detector', 'version', 'paths', 'cve', 'full').
        settings (dict): Settings dict including timeout, proxy, paths file, etc.
        output_file (str, optional): Path to save report.
        output_format (str, optional): Format of the report ('json', 'html', 'md').
        verbose (bool, optional): Enable verbose error output.

    Returns:
        None
    """
    delay = settings.get('delay', 0)
    settings['delay'] = delay

    try:
        mailman_found = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Mailman detection (sync)
        if scan_part in ("detector", "full"):
            result = detector.check_mailman(target, settings)
            mailman_found = result.get("found", False)
            details = result
            if not mailman_found:
                console.print(f"[bold red][!] Mailman not found on {target}.[/bold red]")
                report_data = {
                    'mailman_found': False,
                    'details': details,
                    'version': None,
                    'paths': [],
                    'cves': [],
                    'message': 'Mailman not found on target.'
                }
                if output_file:
                    report_generator.save_report(output_file, output_format, report_data)
                    console.print(f"[bold green][+] Report saved to {output_file}[/bold green]")
                return

            console.print(f"[bold green][+] Mailman detected:[/bold green] {details}")

        # Step 2: Mailman version extraction (async)
        if scan_part in ("version", "full"):
            version_info = await version.get_version(target, settings)
            if not isinstance(version_info, dict):
                console.print("[bold red][!] Invalid version info format received.[/bold red]")
            elif "error" in version_info:
                console.print(f"[bold red][!] Error: {version_info['error']}[/bold red]")
            elif version_info.get("conflict"):
                console.print(f"[bold yellow][!] Multiple versions found:[/bold yellow] {version_info['versions']}")
            else:
                ver_str = version_info.get("version")
                if is_valid_version(ver_str):
                    console.print(f"[bold green][+] Mailman version: {ver_str}[/bold green]")
                else:
                    console.print("[bold cyan][*] No valid Mailman version detected.[/bold cyan]")
        else:
            version_info = {}

        # Step 3: Sensitive paths scanning (sync)
        if scan_part in ("paths", "full"):
            common_paths = load_common_paths(settings.get('paths', 'data/common_paths.json'))
            path_results = paths.check_paths(target, common_paths, timeout=settings.get('timeout', 5))
            for item in path_results:
                sev = item.get("severity", "unknown")
                typ = item.get("type", "Unknown")
                console.print(f"[{severity_color(sev)}][!] Found:[/] {typ} - {item.get('path', 'N/A')} - Severity: {sev}")

        # Step 4: CVE scanning (sync)
        if scan_part in ("cve", "full"):
            ver_str = version_info.get("version") if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(ver_str, settings)
            for cve in cve_results:
                console.print(f"[{severity_color(cve['severity'])}][!] CVE found:[/] {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # Step 5: Save report
        if output_file:
            report_data = {
                'mailman_found': mailman_found,
                'details': details,
                'version': version_info,
                'paths': path_results,
                'cves': cve_results,
            }
            report_generator.save_report(output_file, output_format, report_data)
            console.print(f"[bold green][+] Report saved to {output_file}[/bold green]")

    except Exception as exc:
        exit_code = handle_error(exc, verbose)
        sys_exit(exit_code)
