from os import path
from json import load
from sys import exit as sys_exit
from rich.console import Console
from rich.traceback import install
from core import detector, version, paths
from core.cve_scanner import CVEScanner
from output.report_generator import ReportGenerator

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

        # Step 1: Mailman detection (async)
        if scan_part in ("detector", "full"):
            result = await detector.check_mailman(target, settings)
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
                    ReportGenerator.save_report(output_file, output_format, report_data)
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
            path_results = paths.check_paths(
                target,
                common_paths,
                timeout=settings.get('timeout', 5),
                request_delay=settings.get('delay', 0),
                proxy=settings.get('proxy'),
                verbose=settings.get('verbose', False)
            )
            # Count and filter
            high_med = []
            low_count = 0
            for item in path_results:
                sev = item.get("severity", "unknown")
                if sev in ("high", "medium"):
                    high_med.append(item)
                else:
                    low_count += 1
            # Print high/medium
            for item in high_med:
                sev = item.get("severity", "unknown")
                desc = item.get("description", "Unknown")
                console.print(f"[{severity_color(sev)}][!] Found:[/] {desc} - {item.get('path', 'N/A')} - Severity: {sev}")
            if low_count:
                console.print(f"[dim][!] Plus {low_count} low-severity paths (use --verbose to see all)[/dim]")

        # Step 4: CVE scanning (sync)
        if scan_part in ("cve", "full"):
            ver_str = version_info.get("version") if isinstance(version_info, dict) else None
            cve_scanner_obj = CVEScanner(cve_data_path="data/cves.json")
            cve_results = await cve_scanner_obj.scan(
                detected_version=ver_str if is_valid_version(ver_str) else None,
                base_url=target,
                timeout=settings.get('timeout', 10)
            )
            for cve in cve_results:
                if cve.get('status') != 'vulnerable':
                    if settings.get('verbose', False):
                        console.print(f"[dim][*] Skipped {cve['id']}: {cve.get('reason', '')}[/dim]")
                    continue
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
            rg = ReportGenerator(output_dir=path.dirname(output_file) if output_file else "output")
            if output_format == 'json':
                rg.generate_json(report_data, filename=path.basename(output_file))
            elif output_format == 'html':
                rg.generate_html(report_data, filename=path.basename(output_file))
            elif output_format == 'md':
                rg.generate_markdown(report_data, filename=path.basename(output_file))
            else:
                console.print(f"[yellow]Unsupported format: {output_format}[/yellow]")

    except Exception as exc:
        exit_code = handle_error(exc, verbose)
        sys_exit(exit_code)
