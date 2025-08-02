from core import detector, version, paths, cve_scanner
from output import report_generator
from colorama import Fore, Style, init

# مقداردهی اولیه colorama برای ویندوز و ترمینال‌ها
init(autoreset=True)

def run_scan(target, scan_part, settings, output_file=None, output_format="json"):
    try:
        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # Step 1: Mailman Detection
        if scan_part in ['detector', 'full']:
            mailman_exists, details = detector.check_mailman(target, settings)
            if not mailman_exists:
                print(Fore.RED + f"[!] Mailman not found on {target}.")
                return
            print(Fore.GREEN + f"[+] Mailman detected: {details}")

        # Step 2: Version Detection
        if scan_part in ['version', 'full']:
            version_info = version.get_version(target, settings)
            if 'conflict' in version_info:
                print(Fore.YELLOW + f"[!] Multiple versions found: {version_info['versions']}")
            elif version_info.get('version'):
                print(Fore.GREEN + f"[+] Mailman version: {version_info['version']}")
            else:
                print(Fore.RED + "[!] No Mailman version detected.")

        # Step 3: Sensitive Path Scanning
        if scan_part in ['paths', 'full']:
            path_results = paths.scan_paths(target, settings.get('paths', []), settings)
            for item in path_results:
                severity_color = {
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.CYAN
                }.get(item['severity'].lower(), Fore.WHITE)
                print(severity_color + f"[!] Found: {item['type']} - {item['path']} - Severity: {item['severity']}")

        # Step 4: CVE Scan
        if scan_part in ['cve', 'full']:
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                severity_color = {
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.CYAN
                }.get(cve['severity'].lower(), Fore.WHITE)
                print(severity_color + f"[!] CVE found: {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # Step 5: Save Report
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
        print(Fore.RED + "\n[!] اسکن توسط کاربر متوقف شد (Ctrl+C).")
    except Exception as e:
        print(Fore.RED + f"[!] خطای ناگهانی: {e}")
