from argparse import ArgumentParser
from sys import exit, stderr
from traceback import print_exc
from rich.console import Console

from runner import run_scan

console = Console()

def parse_args():
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
    return parser.parse_args()


def main():
    args = parse_args()

    settings = {
        'proxy': args.proxy,
        'user_agent': args.user_agent,
        'timeout': args.timeout,
        'delay': args.delay,
        'max_retries': args.max_retries,
        'verbose': args.verbose,
        'paths': args.paths
    }

    try:
        run_scan(
            target=args.target,
            scan_part=args.scan_part,
            settings=settings,
            output_file=args.output,
            output_format=args.format
        )
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan cancelled by user (Ctrl+C)[/bold red]")
        exit(130)
    except Exception as e:
        console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
        if args.verbose:
            console.print_exception()
        exit(1)


if __name__ == "__main__":
    main()
