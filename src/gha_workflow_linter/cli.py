# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Command-line interface for gha-workflow-linter."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import json
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
import typer

from ._version import __version__
from .auto_fix import AutoFixer
from .cache import ValidationCache
from .config import ConfigManager
from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .github_auth import get_github_token_with_fallback
from .models import (
    CLIOptions,
    Config,
    LogLevel,
    ValidationMethod,
)
from .scanner import WorkflowScanner
from .system_utils import get_default_workers
from .utils import has_test_comment
from .validator import ActionCallValidator


def _get_relative_path(file_path: Path, base_path: Path) -> Path:
    """
    Safely compute relative path from base_path to file_path.

    Args:
        file_path: The file path to make relative
        base_path: The base path to compute relative to

    Returns:
        Relative path if possible, otherwise the original file_path
    """
    try:
        return file_path.relative_to(base_path)
    except ValueError:
        # If relative path can't be computed, use the original path
        return file_path


def help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def main_app_help_callback(
    ctx: typer.Context, _param: Any, value: bool
) -> None:
    """Show main app help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def cache_help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show cache command help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


console = Console()


def _print_version() -> None:
    """Print version string with consistent formatting."""
    # Two spaces fixes rendering issues in terminal applications
    console.print(f"🏷️  gha-workflow-linter version {__version__}")


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        _print_version()
        raise typer.Exit()


def _preprocess_args_for_default_command(args: list[str] | None = None) -> list[str]:
    """
    Preprocess CLI arguments to inject 'lint' command if no subcommand is provided.

    This allows the CLI to work like other linters where you can just run:
        gha-workflow-linter /path --verbose
    instead of requiring:
        gha-workflow-linter lint /path --verbose

    Args:
        args: Arguments to preprocess. If None, uses sys.argv[1:]

    Returns:
        Preprocessed argument list
    """
    import sys

    if args is None:
        args = sys.argv[1:]
    else:
        # Make a copy to avoid modifying the original
        args = list(args)

    # Known subcommands
    known_commands = {"lint", "cache"}

    # Skip if we have no arguments, or if help/version is requested
    if not args:
        args.append("lint")
        return args

    # Check for eager options that should be handled at the app level
    for arg in args:
        if arg in ("--help", "--version"):
            return args

    # Check if first non-option argument is a known command
    for i, arg in enumerate(args):
        # Skip options and their values
        if arg.startswith("-"):
            # Check if this is a flag that takes a value
            if arg in ("--config", "-c", "--github-token", "--workers", "-j",
                      "--exclude", "-e", "--cache-ttl", "--validation-method",
                      "--log-level", "--format", "-f", "--files"):
                # Skip the next argument (the value) if it exists
                continue
            continue

        # Found a non-option argument
        if arg in known_commands:
            # Already has a subcommand
            return args
        else:
            # No subcommand found, inject 'lint' before this argument
            args.insert(i, "lint")
            return args

    # No positional arguments found, add 'lint' at the end
    args.append("lint")
    return args


app = typer.Typer(
    name="gha-workflow-linter",
    help="GitHub Actions workflow linter for validating action and workflow calls",
    add_completion=False,
    rich_markup_mode="rich",
)


# Add custom help option to main app
@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    _help: bool = typer.Option(
        False,
        "--help",
        callback=main_app_help_callback,
        is_eager=True,
        help="Show this message and exit",
        expose_value=False,
    ),
    _version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
        expose_value=False,
    ),
) -> None:
    """GitHub Actions workflow linter for validating action and workflow calls"""
    # The preprocessing of args happens before this callback is invoked
    # This callback exists primarily for --help and --version handling
    pass


def run() -> None:
    """Main entry point that preprocesses arguments and runs the app."""
    import sys

    # Preprocess arguments to inject 'lint' if needed
    processed_args = _preprocess_args_for_default_command()

    # Update sys.argv with processed arguments
    sys.argv[1:] = processed_args

    # Run the app normally (it will read from sys.argv)
    app()


def setup_logging(log_level: LogLevel, quiet: bool = False) -> None:
    """
    Setup logging configuration.

    Args:
        log_level: Logging level
        quiet: Suppress all output except errors
    """
    level = logging.ERROR if quiet else getattr(logging, log_level.value)

    # Get root logger and set its level explicitly
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers to avoid duplicates in tests
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our handler
    rich_handler = RichHandler(
        console=console,
        show_time=False,
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(level)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(rich_handler)

    # Set httpx logging to WARNING to suppress verbose HTTP request logs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
    logging.getLogger("httpcore.http11").setLevel(logging.WARNING)


@app.command()
def lint(
    path: Path | None = typer.Argument(
        None,
        help="Path to scan for workflows (default: current directory)",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    github_token: str | None = typer.Option(
        None,
        "--github-token",
        help="GitHub API token (or set GITHUB_TOKEN environment variable)",
        hide_input=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all output except errors",
    ),
    log_level: LogLevel = typer.Option(
        LogLevel.INFO,
        "--log-level",
        help="Set logging level",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format (text, json)",
    ),
    fail_on_error: bool = typer.Option(
        True,
        "--fail-on-error/--no-fail-on-error",
        help="Exit with error code if validation failures found",
    ),
    parallel: bool = typer.Option(
        True,
        "--parallel/--no-parallel",
        help="Enable parallel processing",
    ),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-j",
        help="Number of parallel workers (default: auto-detect performance cores)",
        min=1,
        max=32,
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Patterns to exclude (multiples accepted)",
    ),
    require_pinned_sha: bool = typer.Option(
        True,
        "--require-pinned-sha/--no-require-pinned-sha",
        help="Require action calls to be pinned to commit SHAs (default: enabled)",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass local cache and always validate against remote repositories",
    ),

    cache_ttl: int | None = typer.Option(
        None,
        "--cache-ttl",
        help="Override default cache TTL in seconds",
        min=60,  # minimum 1 minute
    ),
    validation_method: ValidationMethod | None = typer.Option(
        None,
        "--validation-method",
        help="Validation method: github-api or git (auto-detected if not specified)",
    ),
    auto_fix: bool | None = typer.Option(
        None,
        "--auto-fix/--no-auto-fix",
        help="Automatically fix broken/invalid SHA pins, versions, and branches (default: enabled unless overridden in config)",
    ),
    auto_latest: bool | None = typer.Option(
        None,
        "--auto-latest/--no-auto-latest",
        help="When auto-fixing, use the latest version of actions (default: disabled unless overridden in config)",
    ),
    allow_prerelease: bool | None = typer.Option(
        None,
        "--allow-prerelease/--no-allow-prerelease",
        help="Allow prerelease versions when finding latest versions (default: disabled unless overridden in config)",
    ),
    two_space_comments: bool | None = typer.Option(
        None,
        "--two-space-comments/--no-two-space-comments",
        help="Use two spaces before inline comments when fixing (default: disabled unless overridden in config)",
    ),
    skip_actions: bool | None = typer.Option(
        None,
        "--skip-actions/--no-skip-actions",
        help="Skip scanning action.yaml/action.yml files (default: disabled unless overridden in config, actions ARE scanned)",
    ),
    fix_test_calls: bool | None = typer.Option(
        None,
        "--fix-test-calls",
        help="Enable auto-fixing action calls with 'test' in comments (default: disabled unless overridden in config, test actions are skipped)",
    ),
    files: list[str] | None = typer.Option(
        None,
        "--files",
        help="Specific files to scan (supports wildcards, can be specified multiple times)",
    ),

    _help: bool = typer.Option(
        False,
        "--help",
        callback=help_callback,
        is_eager=True,
        help="Show this message and exit",
    ),
) -> None:
    """
    Scan GitHub Actions workflows and action definitions for invalid action and workflow calls.

    This tool scans for .github/workflows directories and action.yaml/action.yml files,
    validating that all 'uses' statements reference valid repositories, branches, tags,
    or commit SHAs.

    Validation Methods:
        github-api: Uses GitHub GraphQL API (requires token, faster)
        git: Uses Git operations (no token required, works with SSH keys)

        If --validation-method is not specified, the tool automatically selects:
        - 'github-api' if a GitHub token is available
        - 'git' if no token is found (automatic fallback)

    Cache Options:
        --no-cache: Bypass cache and always validate against remote repositories
        --cache-ttl: Override default cache TTL (7 days) in seconds

    GitHub API Authentication (for github-api method):

        # Using environment variable (recommended)
        export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
        gha-workflow-linter lint

        # Using CLI flag
        gha-workflow-linter lint --github-token ghp_xxxxxxxxxxxxxxxxxxxx

        # Using GitHub CLI (automatic fallback)
        gh auth login
        gha-workflow-linter lint

    Git Authentication (for git method):

        # Uses your existing Git configuration, SSH keys, or ssh-agent
        # No additional setup required if you can already clone GitHub repos

    Examples:

        # Scan current directory (auto-detects validation method)
        gha-workflow-linter lint

        # Force Git validation method
        gha-workflow-linter lint --validation-method git

        # Force GitHub API method
        gha-workflow-linter lint --validation-method github-api

        # Scan specific path with custom workers
        gha-workflow-linter lint /path/to/project --workers 8

        # Use custom config and output JSON
        gha-workflow-linter lint --config config.yaml --format json

        # Verbose output with 8 workers and token
        gha-workflow-linter lint --verbose --workers 8 --github-token ghp_xxx

        # Disable SHA pinning requirement
        gha-workflow-linter lint --no-require-pinned-sha

        # Auto-fix issues without using latest versions
        gha-workflow-linter lint --auto-fix --no-auto-latest

        # Auto-fix with two-space comment formatting
        gha-workflow-linter lint --auto-fix --two-space-comments

        # Enable auto-fixing for actions with 'test' in comments (default is to skip them)
        gha-workflow-linter lint --auto-fix --fix-test-calls

        # Scan only specific files
        gha-workflow-linter lint --files .github/workflows/ci.yml

        # Scan multiple files with wildcards
        gha-workflow-linter lint --files ".github/workflows/*.yml" --files "action.yml"

        # Auto-fix only specific files
        gha-workflow-linter lint --auto-fix --files .github/workflows/release.yml
    """
    # Handle mutually exclusive options
    if verbose and quiet:
        console.print(
            "[red]Error: --verbose and --quiet cannot be used together[/red]"
        )
        raise typer.Exit(1)

    # JSON format implies quiet mode (suppress console output)
    if output_format == "json":
        quiet = True

    if verbose:
        log_level = LogLevel.DEBUG

    # Setup logging
    setup_logging(log_level, quiet)
    logger = logging.getLogger(__name__)

    # Force set logger level to ERROR in quiet mode as safety measure
    # (ensures AutoFixer can detect quiet mode via logger.getEffectiveLevel())
    if quiet:
        logging.getLogger("gha_workflow_linter").setLevel(logging.ERROR)

    # Set default path
    if path is None:
        path = Path.cwd()

    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config(config_file)

        # Override config with CLI options
        cli_options = CLIOptions(
            path=path,
            config_file=config_file,
            verbose=verbose,
            quiet=quiet,
            output_format=output_format,
            fail_on_error=fail_on_error,
            parallel=parallel,
            exclude=exclude,
            require_pinned_sha=require_pinned_sha,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            validation_method=validation_method,
            auto_fix=auto_fix,
            auto_latest=auto_latest,
            allow_prerelease=allow_prerelease,
            two_space_comments=two_space_comments,
            skip_actions=skip_actions,
            fix_test_calls=fix_test_calls,
            files=files,
        )

        # Apply CLI overrides to config
        if workers is not None:
            config.parallel_workers = workers
        else:
            # Auto-detect performance cores if not specified
            config.parallel_workers = get_default_workers()
        if exclude is not None:
            config.exclude_patterns = exclude
        if not parallel:
            config.parallel_workers = 1
        config.require_pinned_sha = require_pinned_sha

        # Apply auto-fix overrides (only if explicitly provided)
        if auto_fix is not None:
            config.auto_fix = auto_fix
        if auto_latest is not None:
            config.auto_latest = auto_latest
        if allow_prerelease is not None:
            config.allow_prerelease = allow_prerelease
        if two_space_comments is not None:
            config.two_space_comments = two_space_comments
        if skip_actions is not None:
            config.skip_actions = skip_actions
        if fix_test_calls is not None:
            config.fix_test_calls = fix_test_calls

        # Apply validation method override if specified
        if validation_method is not None:
            config.validation_method = validation_method

        # Handle cache options
        if no_cache:
            config.cache.enabled = False
            logger.debug("Cache disabled via --no-cache")

        if cache_ttl is not None:
            config.cache.default_ttl_seconds = cache_ttl
            logger.debug(f"Cache TTL overridden to {cache_ttl} seconds")

        logger.debug(f"Starting gha-workflow-linter {__version__}")

        # Skip GitHub token operations if Git method is explicitly chosen
        effective_token = None
        if config.validation_method != ValidationMethod.GIT:
            # Resolve GitHub token with CLI fallback
            effective_token = get_github_token_with_fallback(
                explicit_token=github_token or config.github_api.token,
                console=console,
                quiet=quiet,
            )

            # Update config with resolved token
            if effective_token:
                config.github_api.token = effective_token

        # Determine validation method based on token availability and user preference
        if not config.validation_method:
            if effective_token:
                config.validation_method = ValidationMethod.GITHUB_API
            else:
                config.validation_method = ValidationMethod.GIT
                if not quiet:
                    console.print(
                        "[yellow]ℹ️ No GitHub token available, using Git validation method[/yellow]"
                    )

        # Display validation method being used (suppress for JSON output)
        if not quiet and output_format != "json":
            if config.validation_method == ValidationMethod.GITHUB_API:
                console.print("[blue]🔍 Using validation method: [GraphQL][/blue]")
            else:
                console.print("[blue]🔍 Using validation method: [Git/SSH][/blue]")

            # Display number of parallel workers
            worker_source = "auto-detected" if workers is None else "configured"
            console.print(f"[blue]⚙️  Using {config.parallel_workers} parallel worker(s) ({worker_source})[/blue]")

        # Only check rate limits if using GitHub API
        if config.validation_method == ValidationMethod.GITHUB_API:
            from .github_api import GitHubGraphQLClient

            github_client = GitHubGraphQLClient(config.github_api)

            try:
                github_client.check_rate_limit_and_exit_if_needed()
                # If we get here, we're not rate limited
                if not effective_token and not quiet:
                    logger.warning(
                        "⚠️ No GitHub token available; API requests may be rate-limited"
                    )
            except SystemExit:
                # Rate limit check triggered exit, re-raise to exit cleanly
                raise

        # Only show scanning path if we're actually going to proceed
        logger.debug(f"Scanning path: {path}")

        # Run the linting process
        exit_code = run_linter(config, cli_options)

    except typer.Exit:
        # Re-raise typer.Exit to avoid catching it as a general exception
        raise
    except ValidationAbortedError as e:
        # These errors should already be handled in run_linter, but catch here as fallback
        logger.error(f"Validation aborted: {e.message}")
        raise typer.Exit(1) from None
    except (ValueError, ConfigurationError) as e:
        logger.error(f"Configuration error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(1) from None
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(1) from None

    raise typer.Exit(exit_code)


@app.command()
def cache(
    info: bool = typer.Option(False, "--info", help="Show cache information"),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Remove expired cache entries"
    ),
    purge: bool = typer.Option(
        False, "--purge", help="Clear all cache entries"
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    _help: bool = typer.Option(
        False,
        "--help",
        callback=cache_help_callback,
        is_eager=True,
        help="Show this message and exit",
        expose_value=False,
    ),
) -> None:
    """Manage local validation cache."""
    # Load configuration
    from .config import ConfigManager

    config_manager = ConfigManager()
    config = config_manager.load_config(config_file)

    cache_instance = ValidationCache(config.cache)

    if purge:
        removed_count = cache_instance.purge()
        console.print(f"[green]✅ Purged {removed_count} cache entries[/green]")
        return

    if cleanup:
        removed_count = cache_instance.cleanup()
        console.print(
            f"[green]✅ Removed {removed_count} expired cache entries[/green]"
        )
        return

    if info:
        cache_info = cache_instance.get_cache_info()

        table = Table(title="Cache Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Enabled", str(cache_info["enabled"]))
        table.add_row("Cache File", cache_info["cache_file"])
        table.add_row(
            "File Exists", str(cache_info.get("cache_file_exists", False))
        )
        table.add_row("Total Entries", str(cache_info["entries"]))

        if cache_info["entries"] > 0:
            table.add_row(
                "Expired Entries", str(cache_info.get("expired_entries", 0))
            )
            if cache_info.get("oldest_entry_age"):
                table.add_row(
                    "Oldest Entry Age",
                    f"{cache_info['oldest_entry_age']:.1f} seconds",
                )
            if cache_info.get("newest_entry_age"):
                table.add_row(
                    "Newest Entry Age",
                    f"{cache_info['newest_entry_age']:.1f} seconds",
                )

        table.add_row("Max Cache Size", str(cache_info["max_cache_size"]))
        table.add_row("TTL (seconds)", str(cache_info["ttl_seconds"]))

        console.print(table)

        # Show stats if available
        stats = cache_info["stats"]
        if stats["hits"] > 0 or stats["misses"] > 0:
            console.print()
            stats_table = Table(title="Cache Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="green")

            stats_table.add_row("Cache Hits", str(stats["hits"]))
            stats_table.add_row("Cache Misses", str(stats["misses"]))
            stats_table.add_row(
                "Hit Rate", f"{cache_instance.stats.hit_rate:.1f}%"
            )
            stats_table.add_row("Cache Writes", str(stats["writes"]))
            stats_table.add_row("Purges", str(stats["purges"]))
            stats_table.add_row(
                "Cleanup Removed", str(stats["cleanup_removed"])
            )

            console.print(stats_table)
        return

    # Default: show basic cache info
    cache_info = cache_instance.get_cache_info()
    console.print(f"Cache enabled: {cache_info['enabled']}")
    console.print(f"Cache entries: {cache_info['entries']}")
    console.print(f"Cache file: {cache_info['cache_file']}")


def run_linter(config: Config, options: CLIOptions) -> int:
    """
    Run the main linting process.

    Args:
        config: Configuration object
        options: CLI options

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    logger = logging.getLogger(__name__)

    # Initialize scanner and validator
    scanner = WorkflowScanner(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        disable=options.quiet,
    ) as progress:
        # Scan for workflows
        scan_task = progress.add_task("Scanning workflows...", total=None)

        try:
            workflow_calls = scanner.scan_directory(
                options.path, progress, scan_task, specific_files=options.files
            )
        except Exception as e:
            logger.error(f"Error scanning workflows: {e}")
            return 1

        if not workflow_calls:
            if not options.quiet:
                console.print("[yellow]No workflows found to validate[/yellow]")
            return 0

        # Count total calls for progress tracking
        total_calls = sum(len(calls) for calls in workflow_calls.values())

        # Validate action calls
        validate_task = progress.add_task(
            "Validating action calls...", total=total_calls
        )

        try:
            validator = ActionCallValidator(config)
            validation_errors = validator.validate_action_calls(
                workflow_calls, progress, validate_task
            )
        except ValidationAbortedError as e:
            logger.error(f"Validation aborted: {e.message}")

            # Provide specific guidance based on the error type
            if isinstance(e.original_error, NetworkError):
                console.print(
                    "\n[yellow]❌ Network connectivity issue detected[/yellow]"
                )
                console.print("[dim]• Check your internet connection")
                console.print("[dim]• Verify DNS resolution is working")
                console.print("[dim]• Try again in a few moments[/dim]")
            elif isinstance(e.original_error, AuthenticationError):
                console.print(
                    "\n[yellow]❌ GitHub API authentication failed[/yellow]"
                )
                from .github_auth import get_github_cli_suggestions

                suggestions = get_github_cli_suggestions()
                for suggestion in suggestions:
                    console.print(f"[dim]• {suggestion}")
                console.print(
                    "[dim]• Ensure token has 'public_repo' scope[/dim]"
                )
            elif isinstance(e.original_error, RateLimitError):
                console.print(
                    "\n[yellow]❌ GitHub API rate limit exceeded[/yellow]"
                )
                console.print("[dim]• Wait for rate limit to reset")
                from .github_auth import get_github_cli_suggestions

                suggestions = get_github_cli_suggestions()
                for suggestion in suggestions:
                    console.print(f"[dim]• {suggestion}")
                console.print("[dim]• Try again later[/dim]")
            elif isinstance(
                e.original_error, (GitHubAPIError, TemporaryAPIError)
            ):
                console.print("\n[yellow]❌ GitHub API error[/yellow]")
                console.print(
                    "[dim]• This may be a temporary GitHub service issue"
                )
                console.print("[dim]• Try again in a few minutes")
                console.print(
                    "[dim]• Check GitHub status at https://status.github.com/[/dim]"
                )
            else:
                console.print(
                    "\n[yellow]❌ Validation could not be completed[/yellow]"
                )
                console.print(f"[dim]• {e.reason}[/dim]")

            console.print(
                "\n[red]Cannot determine if action calls are valid or invalid.[/red]"
            )
            console.print(
                "[red]Validation was not performed due to the above issue.[/red]"
            )
            return 1
        except Exception as e:
            logger.error(f"Unexpected error validating action calls: {e}")
            return 1

    # Auto-fix validation errors if enabled, or collect skipped testing items
    fixed_files: dict[Path, list[dict[str, str]]] = {}
    redirect_stats: dict[str, int] = {"actions_moved": 0, "calls_updated": 0}
    stale_actions_summary: dict[str, list[dict[str, Any]]] = {}

    # Determine if we should run auto-fix:
    # - If auto_fix is enabled, fix validation errors and check for outdated versions
    # - If auto_latest is also enabled, update to latest versions
    should_run_auto_fix = (config.auto_fix or not config.fix_test_calls) and (validation_errors or config.auto_fix)
    if should_run_auto_fix:
        try:
            async def run_auto_fix() -> tuple[dict[Path, list[dict[str, str]]], dict[str, int], dict[str, list[dict[str, Any]]]]:
                async with AutoFixer(config, base_path=options.path) as auto_fixer:
                    # When auto_fix is enabled, always pass all action calls to check
                    # check_for_updates=True only when auto_latest is enabled (update to latest versions)
                    # check_for_updates=False means: fix validation errors, report outdated versions
                    all_calls = workflow_calls if config.auto_fix else {}
                    check_for_updates = config.auto_latest
                    return await auto_fixer.fix_validation_errors(validation_errors, all_calls, check_for_updates=check_for_updates)

            fixed_files, redirect_stats, stale_actions_summary = asyncio.run(run_auto_fix())

            if fixed_files and not options.quiet:
                # Separate skipped items from actual fixes
                files_with_fixes = {}
                files_with_skipped = {}

                for file_path, changes in fixed_files.items():
                    has_fixes = False
                    has_skipped = False

                    for change in changes:
                        if change.get("skipped") == "true":
                            has_skipped = True
                        else:
                            has_fixes = True

                    if has_fixes:
                        files_with_fixes[file_path] = [c for c in changes if c.get("skipped") != "true"]
                    if has_skipped:
                        files_with_skipped[file_path] = [c for c in changes if c.get("skipped") == "true"]

                # Display skipped testing items first
                if files_with_skipped:
                    console.print(f"\n[cyan]⏩ Skipped {sum(len(v) for v in files_with_skipped.values())} testing action(s) in {len(files_with_skipped)} file(s):[/cyan]")
                    for file_path, changes in files_with_skipped.items():
                        console.print(f"\n[bold]📄 {_get_relative_path(file_path, options.path)}[/bold]")
                        for change in changes:
                            # Extract just the uses: part from the raw line
                            line = change["old_line"].strip()
                            # Remove leading "- " if present
                            if line.startswith("- "):
                                line = line[2:]
                            console.print(f"  ⏩ {line}")

                # Display actual fixes
                if files_with_fixes:
                    total_workflow_calls_updated = sum(len(changes) for changes in files_with_fixes.values())
                    console.print(f"\n[yellow]🔧 Updated {total_workflow_calls_updated} workflow call(s) in {len(files_with_fixes)} file(s):[/yellow]")
                    for file_path, changes in files_with_fixes.items():
                        console.print(f"\n[bold]📄 {_get_relative_path(file_path, options.path)}[/bold]")
                        for change in changes:
                            console.print(f"[red]  - {change['old_line'].strip()}[/red]")
                            console.print(f"[green]  + {change['new_line'].strip()}[/green]")
                    console.print()  # Add blank line after changes



        except Exception as e:
            logger.warning(f"Auto-fix failed: {e}")
            if not options.quiet:
                console.print(f"[yellow]⚠️ Auto-fix failed: {e}[/yellow]")

    # Generate and display results
    scan_summary = scanner.get_scan_summary(workflow_calls)

    # Calculate unique calls for statistics
    unique_calls = set()
    for calls in workflow_calls.values():
        for call in calls.values():
            call_key = f"{call.organization}/{call.repository}@{call.reference}"
            unique_calls.add(call_key)

    validation_summary = validator.get_validation_summary(
        validation_errors, total_calls, len(unique_calls)
    )

    if options.output_format == "json":
        output_json_results(
            scan_summary, validation_summary, validation_errors, options.path
        )
    else:
        output_text_results(
            scan_summary,
            validation_summary,
            validation_errors,
            options.path,
            options.quiet,
            fixed_files,
            redirect_stats,
            stale_actions_summary,
        )

    # When auto_fix is enabled but auto_latest is not, display outdated actions report
    # (validation errors were fixed, but version updates are only reported)
    if stale_actions_summary and not config.auto_latest and not options.quiet:
        _display_stale_actions_from_summary(stale_actions_summary, options)
        return 0

    # Determine exit code
    # If we auto-fixed files (not just skipped testing items), always exit with error to indicate changes were made
    if fixed_files:
        # Check if there are any actual fixes (not just skipped items)
        has_actual_fixes = False
        for changes in fixed_files.values():
            for change in changes:
                if change.get("skipped") != "true":
                    has_actual_fixes = True
                    break
            if has_actual_fixes:
                break

        if has_actual_fixes:
            return 1

    # Otherwise, exit with error only if there are validation errors (excluding test references) and fail_on_error is enabled
    if options.fail_on_error:
        # Count actual errors (excluding test references)
        actual_errors = [e for e in validation_errors if not has_test_comment(e.action_call)]
        if actual_errors:
            return 1

    return 0


def _create_scan_summary_table(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    total_fixes: int = 0,
    redirect_stats: dict[str, int] | None = None
) -> Table:
    """Create the scan summary table.

    This table is always displayed with the same structure regardless of CLI flags.
    """
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="magenta")

    # Core metrics - always displayed
    table.add_row("Workflow files", str(scan_summary["total_files"]))
    table.add_row("Total action calls", str(scan_summary["total_calls"]))
    table.add_row("Action calls", str(scan_summary["action_calls"]))
    table.add_row("Workflow calls", str(scan_summary["workflow_calls"]))
    table.add_row("SHA references", str(scan_summary["sha_references"]))
    table.add_row("Tag references", str(scan_summary["tag_references"]))
    table.add_row("Branch references", str(scan_summary["branch_references"]))

    # Validation efficiency metrics - always displayed when available
    if validation_summary.get("unique_calls_validated", 0) > 0:
        table.add_row(
            "Unique calls validated",
            str(validation_summary["unique_calls_validated"]),
        )
        table.add_row(
            "Duplicate calls avoided",
            str(validation_summary["duplicate_calls_avoided"]),
        )
        efficiency = (
            1
            - validation_summary["unique_calls_validated"]
            / validation_summary["total_calls"]
        ) * 100
        table.add_row("Validation efficiency", f"{efficiency:.1f}%")

    # Update statistics - always displayed when checking for updates
    if total_fixes > 0:
        table.add_row("Action calls updated", str(total_fixes))

    # Redirect statistics - always displayed when redirects are found
    if redirect_stats and redirect_stats.get("actions_moved", 0) > 0:
        table.add_row("Actions moved/relocated", str(redirect_stats["actions_moved"]))
        table.add_row("Calls updated (relocated)", str(redirect_stats["calls_updated"]))

    return table


def _create_api_stats_table(validation_summary: dict[str, Any]) -> Table | None:
    """Create the API statistics table if there are API calls."""
    if validation_summary.get("api_calls_total", 0) == 0:
        return None

    api_table = Table(title="API Call Statistics")
    api_table.add_column("Metric", style="cyan")
    api_table.add_column("Count", justify="right", style="magenta")

    api_table.add_row(
        "Total API calls", str(validation_summary["api_calls_total"])
    )
    api_table.add_row(
        "GraphQL calls", str(validation_summary["api_calls_graphql"])
    )
    api_table.add_row(
        "REST API calls", str(validation_summary["api_calls_rest"])
    )
    api_table.add_row(
        "Git operations", str(validation_summary["api_calls_git"])
    )
    api_table.add_row("Cache hits", str(validation_summary["cache_hits"]))

    if validation_summary.get("rate_limit_delays", 0) > 0:
        api_table.add_row(
            "Rate limit delays", str(validation_summary["rate_limit_delays"])
        )
    if validation_summary.get("failed_api_calls", 0) > 0:
        api_table.add_row(
            "Failed API calls", str(validation_summary["failed_api_calls"])
        )

    return api_table


def _display_validation_summary(validation_summary: dict[str, Any], skip_success: bool = False) -> None:
    """Display validation results summary."""
    # Calculate actual errors (excluding test references)
    actual_errors = validation_summary["total_errors"] - validation_summary.get("test_references", 0)
    test_refs = validation_summary.get("test_references", 0)

    if actual_errors == 0 and test_refs == 0:
        if not skip_success:
            console.print("[green]✅ All action calls are valid![/green]")
        return

    # Show actual errors
    if actual_errors > 0:
        console.print(
            f"[red]❌ Found {actual_errors} validation errors[/red]"
        )

        if validation_summary["invalid_repositories"] > 0:
            console.print(
                f"  - {validation_summary['invalid_repositories']} invalid repositories"
            )
        if validation_summary["invalid_references"] > 0:
            console.print(
                f"  - {validation_summary['invalid_references']} invalid references"
            )
        if validation_summary["network_errors"] > 0:
            console.print(
                f"  - {validation_summary['network_errors']} network errors"
            )
        if validation_summary["timeouts"] > 0:
            console.print(f"  - {validation_summary['timeouts']} timeouts")
        if validation_summary["not_pinned_to_sha"] > 0:
            console.print(
                f"  - {validation_summary['not_pinned_to_sha']} actions not pinned to SHA"
            )

    # Show test references as warnings
    if test_refs > 0:
        if actual_errors > 0:
            console.print()  # Add spacing between errors and warnings
        console.print(
            f"[yellow]⚠️  Found {test_refs} test action references[/yellow]"
        )

    # Show deduplication and API efficiency
    if validation_summary.get("duplicate_calls_avoided", 0) > 0:
        console.print(
            f"[dim]Deduplication avoided {validation_summary['duplicate_calls_avoided']} redundant validations[/dim]"
        )

    # Show API efficiency metrics
    if validation_summary.get("api_calls_total", 0) > 0:
        console.print(
            f"[dim]Made {validation_summary['api_calls_total']} API calls "
            f"({validation_summary['api_calls_graphql']} GraphQL, "
            f"{validation_summary['cache_hits']} cache hits)[/dim]"
        )

    if validation_summary.get("rate_limit_delays", 0) > 0:
        console.print(
            f"[yellow]Rate limiting encountered {validation_summary['rate_limit_delays']} times[/yellow]"
        )




def _display_stale_actions_from_summary(
    stale_actions: dict[str, list[dict[str, Any]]],
    _options: CLIOptions,
) -> None:
    """
    Display a report of outdated action calls from a pre-built summary.

    Args:
        stale_actions: Dictionary mapping relative file paths to lists of stale action info
        options: CLI options
    """
    console = Console()

    if not stale_actions:
        console.print("[green]✅ All action calls are up to date![/green]\n")
        return

    # Count incorrect (invalid) and outdated actions separately
    incorrect_count = 0
    outdated_count = 0
    incorrect_files = set()
    outdated_files = set()

    for file_path, actions in stale_actions.items():
        for action_info in actions:
            if action_info.get("is_invalid", False):
                incorrect_count += 1
                incorrect_files.add(file_path)
            else:
                outdated_count += 1
                outdated_files.add(file_path)

    # Display separate counts for incorrect and outdated actions
    if incorrect_count > 0:
        console.print(f"\n[red]Found {incorrect_count} incorrect action call(s) in {len(incorrect_files)} file(s)[/red]")
    if outdated_count > 0:
        console.print(f"[yellow]Found {outdated_count} outdated action call(s) in {len(outdated_files)} file(s)[/yellow]")

    console.print()

    for file_path in sorted(stale_actions.keys()):
        console.print(f"[bold]📄 {file_path}[/bold]")
        for action_info in stale_actions[file_path]:
            current_display = action_info["current_ref"][:12] + "..." if len(action_info["current_ref"]) > 40 else action_info["current_ref"]
            latest_display = action_info["latest_ref"][:12] + "..." if len(action_info["latest_ref"]) > 40 else action_info["latest_ref"]

            # Check if this is an invalid reference (validation error) or just outdated
            is_invalid = action_info.get("is_invalid", False)

            # Show action with redirect indicator if applicable
            action_display = action_info["action"]
            if action_info.get("redirected", False):
                action_display += " [orange3](moved/relocated)[/orange3]"

            # Use different colors and labels based on whether it's invalid or just outdated
            if is_invalid:
                # Invalid reference - entire line in red, correction line in green
                console.print(f"  [red]Line {action_info['line']}:[/red] [red]{action_display}[/red]")
                if action_info["current_comment"]:
                    console.print(f"    [red]Invalid:  @{current_display} # {action_info['current_comment'].lstrip('#').strip()}[/red]")
                else:
                    console.print(f"    [red]Invalid:  @{current_display}[/red]")
                console.print(f"    [green]Correct:  @{latest_display} # {action_info['latest_version']}[/green]")
            else:
                # Just outdated - use yellow for line and current ref
                console.print(f"  [yellow]Line {action_info['line']}:[/yellow] {action_display}")
                console.print(f"    [yellow]Current:[/yellow]  @{current_display}", end="")
                if action_info["current_comment"]:
                    console.print(f" [dim]# {action_info['current_comment'].lstrip('#').strip()}[/dim]")
                else:
                    console.print()
                console.print(f"    [green]Latest:[/green]   @{latest_display} [dim]# {action_info['latest_version']}[/dim]")
        console.print()

    console.print("[cyan]💡 Run with [bold]--auto-fix --auto-latest[/bold] to update these actions[/cyan]\n")


def output_text_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
    quiet: bool = False,
    fixed_files: dict[Path, list[dict[str, str]]] | None = None,
    redirect_stats: dict[str, int] | None = None,
    stale_actions_summary: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """
    Output results in human-readable text format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics summary
        errors: List of validation errors
        scan_path: Base path for computing relative paths
        quiet: Whether to suppress non-error output
        fixed_files: Dictionary of files that were auto-fixed
        redirect_stats: Statistics about redirected/relocated actions
        stale_actions_summary: Dictionary of stale actions to report
    """
    if not quiet:
        # Count total action calls fixed
        total_fixes = 0
        if fixed_files:
            for changes in fixed_files.values():
                for change in changes:
                    if change.get("skipped") != "true":
                        total_fixes += 1

        # Display scan summary (with redirect stats if available)
        table = _create_scan_summary_table(scan_summary, validation_summary, total_fixes, redirect_stats)

        # Display API statistics if available
        api_table = _create_api_stats_table(validation_summary)
        if api_table:
            console.print()  # Add blank line before API table
            console.print(api_table)

        console.print()
        console.print(table)

        # Check if files were modified
        has_actual_fixes = False
        if fixed_files:
            for changes in fixed_files.values():
                for change in changes:
                    if change.get("skipped") != "true":
                        has_actual_fixes = True
                        break
                if has_actual_fixes:
                    break

        # Display validation summary (but skip "all valid" message if files were modified or there are stale actions)
        has_stale_actions = bool(stale_actions_summary and any(stale_actions_summary.values()))
        _display_validation_summary(validation_summary, skip_success=(has_actual_fixes or has_stale_actions))

        # Display modification message after scan summary if files were modified
        if has_actual_fixes:
            console.print("\n[yellow]⚠️ Files have been modified; please review the changes and commit them.[/yellow]")

    # Separate errors by type
    if errors:
        # Group errors by file and type
        actual_errors = defaultdict(list)
        test_warnings = defaultdict(list)

        for error in errors:
            relative_path = _get_relative_path(error.file_path, scan_path)

            # Format action reference without 'uses:'
            action_ref = f"{error.action_call.organization}/{error.action_call.repository}@{error.action_call.reference}"
            if error.action_call.comment:
                action_ref += f"  {error.action_call.comment}"

            error_info = {
                "action_ref": action_ref,
                "line": error.action_call.line_number,
                "result": error.result
            }

            # Check if this is a test reference based on comment
            if has_test_comment(error.action_call):
                test_warnings[relative_path].append(error_info)
            else:
                actual_errors[relative_path].append(error_info)

        # Display actual validation errors
        if actual_errors:
            console.print("\n[red]Validation Errors:[/red]")
            for file_path in sorted(actual_errors.keys()):
                console.print(f"❌ Invalid action call in workflow: [bold]{file_path}[/bold]")
                for error_info in actual_errors[file_path]:
                    console.print(f"   {error_info['action_ref']} [dim][line {error_info['line']}][/dim]")

        # Display test action warnings
        if test_warnings:
            console.print("\n[yellow]Test Action Calls:[/yellow]")
            for file_path in sorted(test_warnings.keys()):
                # Two spaces is deliberate; fixes rendering in terminal output
                console.print(f"⚠️  Test action calls in workflow: [bold]{file_path}[/bold]")
                for warning_info in test_warnings[file_path]:
                    console.print(f"   {warning_info['action_ref']} [dim][line {warning_info['line']}][/dim]")


def output_json_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
) -> None:
    """
    Output results in JSON format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics
        errors: List of validation errors
        scan_path: Base path for computing relative paths
    """
    result = {
        "scan_summary": scan_summary,
        "validation_summary": validation_summary,
        "errors": [
            {
                "file_path": str(
                    _get_relative_path(error.file_path, scan_path)
                ),
                "line_number": error.action_call.line_number,
                "raw_line": error.action_call.raw_line.strip(),
                "organization": error.action_call.organization,
                "repository": error.action_call.repository,
                "reference": error.action_call.reference,
                "call_type": error.action_call.call_type.value,
                "reference_type": error.action_call.reference_type.value,
                "validation_result": error.result.value,
                "error_message": error.error_message,
            }
            for error in errors
        ],
    }

    # Use plain print() to avoid Rich formatting/ANSI codes in JSON output
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
