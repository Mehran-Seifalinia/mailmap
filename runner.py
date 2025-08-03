from core import detector, version, paths, cve_scanner
from output import report_generator
from colorama import Fore, Style, init

# مقداردهی اولیه colorama برای ویندوز و ترمینال‌ها
init(autoreset=True)

def severity_color(severity: str) -> str:
    """بر اساس شدت، رنگ مناسب را برمی‌گرداند."""
    return {
        'high': Fore.RED,
        'medium': Fore.YELLOW,
        'low': Fore.CYAN
    }.get(severity.lower(), Fore.WHITE)

def run_scan(target: str, scan_part: str, settings: dict, output_file: str = None, output_format: str = "json") -> None:
    """
    اجرای فرایند اسکن روی هدف مشخص.

    پارامترها:
    - target: آدرس یا دامنه مورد هدف اسکن
    - scan_part: بخشی از اسکن که باید اجرا شود ('detector', 'version', 'paths', 'cve', 'full')
    - settings: تنظیمات و داده‌های مورد نیاز برای اسکن
    - output_file: مسیر فایل خروجی برای ذخیره گزارش (اختیاری)
    - output_format: فرمت فایل خروجی ('json', 'html', 'md', ...)

    این تابع خروجی‌ای برنمی‌گرداند و نتایج را روی ترمینال نمایش می‌دهد و در صورت درخواست گزارش را ذخیره می‌کند.
    """
    try:
        mailman_exists = False
        details = {}
        version_info = {}
        path_results = []
        cve_results = []

        # مرحله 1: شناسایی نصب Mailman
        if scan_part in ['detector', 'full']:
            mailman_exists, details = detector.check_mailman(target, settings)
            if not mailman_exists:
                print(Fore.RED + f"[!] Mailman not found on {target}.")
                return  # خروج زودهنگام اگر Mailman پیدا نشد
            print(Fore.GREEN + f"[+] Mailman detected: {details}")

        # مرحله 2: تشخیص نسخه Mailman
        if scan_part in ['version', 'full']:
            version_info = version.get_version(target, settings)
            if isinstance(version_info, dict):
                if 'conflict' in version_info:
                    print(Fore.YELLOW + f"[!] Multiple versions found: {version_info['versions']}")
                elif version_info.get('version'):
                    print(Fore.GREEN + f"[+] Mailman version: {version_info['version']}")
                else:
                    print(Fore.RED + "[!] No Mailman version detected.")
            else:
                print(Fore.RED + "[!] Invalid version info format received.")

        # مرحله 3: اسکن مسیرهای حساس
        if scan_part in ['paths', 'full']:
            # توجه: فرض بر این است که settings['paths'] لیست مسیرها را دارد، اگر نه لیست خالی فرستاده می‌شود
            path_results = paths.scan_paths(target, settings.get('paths', []), settings)
            for item in path_results:
                print(severity_color(item['severity']) + f"[!] Found: {item['type']} - {item['path']} - Severity: {item['severity']}")

        # مرحله 4: اسکن CVEها
        if scan_part in ['cve', 'full']:
            version_str = version_info.get('version') if isinstance(version_info, dict) else None
            cve_results = cve_scanner.scan_cves(version_str, settings)
            for cve in cve_results:
                print(severity_color(cve['severity']) + f"[!] CVE found: {cve['id']} - {cve['description']} - Severity: {cve['severity']}")

        # مرحله 5: ذخیره گزارش در فایل در صورت درخواست
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
        import traceback
        print(Fore.RED + f"[!] خطای ناگهانی: {e}")
        print(Fore.RED + traceback.format_exc())
