from nest_asyncio import apply  
apply()  # Patch asyncio to allow nested event loops (e.g. in Jupyter or IDEs)

from argparse import ArgumentParser, Namespace
from sys import exit as sys_exit
from asyncio import run as asyncio_run, get_running_loop
from rich.console import Console
from runner import run_scan

console = Console()


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Mailmap Security Scanner CLI")
    parser.add_argument('--target', required=True, help="Target URL for scanning")
    parser.add_argument('--paths', default='data/common_paths.json', help="Custom paths file")
    parser.add_argument('--proxy', help="Proxy URL (e.g. http://user:pass@host:port)")
    parser.add_argument('--user-agent', help="Custom User-Agent string for HTTP requests")
    parser.add_argument('--timeout', type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument('--delay', type=float, default=0, help="Delay between HTTP requests in seconds")
    parser.add_argument('--output', help="Output file path")
    parser.add_argument('--format', choices=['json', 'html', 'md'], default='json', help="Output format")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('--scan-part', choices=['detector', 'version', 'paths', 'cve', 'full'], default='full',
                        help="Select scan part to run")
    parser.add_argument('--max-retries', type=int, default=3, help="Max retries for HTTP requests")
    parser.add_argument('--version', action='version', version='Mailmap Scanner 1.0')
    return parser.parse_args()


async def async_runner(args):

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

    await run_scan(
        target=args.target,
        scan_part=args.scan_part,
        settings=settings,
        output_file=args.output,
        output_format=args.format,
        verbose=args.verbose,
    )
def main() -> None:
    args = parse_args()

    # Check if an asyncio event loop is already running
    try:
        loop = get_running_loop()
        if loop.is_running():
            console.print("[bold yellow][!] Detected running event loop. Using nest_asyncio to patch and allow nested loops.[/bold yellow]")
    except RuntimeError:
        # No running event loop detected
        pass

    try:
        # Use asyncio.run safely even if event loop is already running because of nest_asyncio patch
        asyncio_run(async_runner(args))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan cancelled by user (Ctrl+C)[/bold red]")
        sys_exit(130)
    except Exception as e:
        console.print(f"[bold red][!] Unexpected error: {e}[/bold red]")
        if args.verbose:
            console.print_exception()
        sys_exit(1)


if __name__ == "__main__":
    main()
