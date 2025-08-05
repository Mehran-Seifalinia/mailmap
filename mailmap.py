from argparse import ArgumentParser, Namespace
from sys import exit as sys_exit
from rich.console import Console
from asyncio import get_running_loop, run
from runner import run_scan

console = Console()

def parse_args() -> Namespace:
    """
    Parse CLI arguments for the Mailmap scanner.
    
    Returns:
        Namespace: Parsed arguments
    """
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
    parser.add_argument('--scan-part', choices=['detector', 'version', 'paths', 'cve', 'full'], default='full', help="Select scan part")
    parser.add_argument('--max-retries', type=int, default=3, help="Max retries for HTTP requests")
    parser.add_argument('--version', action='version', version='Mailmap Scanner 1.0')
    return parser.parse_args()

def main() -> None:
    """
    Main entry point to run the async scan from a synchronous context.
    Checks if an event loop is already running and runs the async function accordingly.
    """
    args = parse_args()

    # Prepare settings dictionary from parsed CLI arguments
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

    async def runner():
        """
        Async runner function that calls the main async scan function.
        """
        await run_scan(
            target=args.target,
            scan_part=args.scan_part,
            settings=settings,
            output_file=args.output,
            output_format=args.format,
            verbose=args.verbose
        )

    try:
        # Attempt to get the currently running event loop
        try:
            loop = get_running_loop()
        except RuntimeError:
            # No event loop is running
            loop = None

        if loop and loop.is_running():
            # If an event loop is already running (e.g. in an interactive environment),
            # create a task and wait for it to complete
            task = loop.create_task(runner())
            loop.run_until_complete(task)  # This can sometimes cause errors in some environments
            # Alternative: await task (but this requires the context to be async)
        else:
            # No event loop is running, safe to use asyncio.run()
            run(runner())

    except KeyboardInterrupt:
        # Handle Ctrl+C interruption gracefully
        console.print("\n[bold red][!] Scan cancelled by user (Ctrl+C)[/bold red]")
        sys_exit(130)
    except Exception as e:
        # Print any other exceptions and optionally print traceback if verbose
        console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
        if args.verbose:
            console.print_exception()
        sys_exit(1)

if __name__ == "__main__":
    main()
