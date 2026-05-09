#!/usr/bin/env python3
"""
DevSec Vault CLI — layered secret-detection pipeline.

Commands
--------
  scan     Scan files / directories for secrets
  staged   Scan git staged changes (pre-commit gate)
  history  Scan full git history across all branches
  baseline Manage the allowlist baseline
  report   Re-render a saved JSON report in another format
  info     Show loaded patterns and tool metadata

Exit codes
----------
  0  No findings (or all findings suppressed by baseline)
  1  One or more active findings detected
  2  Tool/configuration error
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# ── Make sure src/ is importable whether run as `python src/cli.py` or
#    installed as a package entry-point. ─────────────────────────────────────
_SRC = Path(__file__).parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from baseline import DEFAULT_BASELINE_PATH, diff_baseline, load_baseline, save_baseline
from patterns import PATTERNS, RAW_PATTERNS, SEVERITY_ORDER
from report import build_metrics, write_json_report, write_sarif_report
from scanner import ScanResult, scan_directory, scan_file, scan_git_history, scan_staged

# ─────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────

console = Console(stderr=False)
err_console = Console(stderr=True)

VERSION = "2.0.0"

SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


# ─────────────────────────────────────────────────────────────
# SHARED OPTIONS (reused across commands)
# ─────────────────────────────────────────────────────────────

_baseline_opt = click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(dir_okay=False),
    default=str(DEFAULT_BASELINE_PATH),
    show_default=True,
    help="Path to baseline allowlist file.",
)

_format_opt = click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)

_output_opt = click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write report to file instead of stdout.",
)

_no_entropy_opt = click.option(
    "--no-entropy",
    is_flag=True,
    default=False,
    help="Disable high-entropy heuristic (faster, fewer false positives).",
)

_severity_opt = click.option(
    "--min-severity",
    "min_severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Ignore findings below this severity.",
)


# ─────────────────────────────────────────────────────────────
# RICH RENDERING HELPERS
# ─────────────────────────────────────────────────────────────


def _severity_badge(severity: str) -> Text:
    style = SEVERITY_STYLE.get(severity, "white")
    return Text(f" {severity} ", style=f"bold {style} on default")


def _render_findings_table(
    results: list[ScanResult], min_severity: str = "LOW"
) -> Table:
    min_rank = SEVERITY_ORDER.get(min_severity, 99)

    table = Table(
        title="[bold]Secret Scan Findings[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10, no_wrap=True)
    table.add_column("Rule", style="cyan", width=26, no_wrap=True)
    table.add_column("Target", style="dim", overflow="fold")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Masked Value", overflow="fold")
    table.add_column("Source", width=8)

    row_count = 0
    for r in results:
        for f in r.sorted_findings():
            if SEVERITY_ORDER.get(f.severity, 99) > min_rank:
                continue
            sev_style = SEVERITY_STYLE.get(f.severity, "white")
            table.add_row(
                Text(f.severity, style=f"bold {sev_style}"),
                f.rule,
                r.target,
                str(f.line_number),
                f.masked_value,
                f.source,
            )
            row_count += 1

    return table, row_count


def _render_summary(results: list[ScanResult], min_severity: str = "LOW") -> Panel:
    min_rank = SEVERITY_ORDER.get(min_severity, 99)
    total = sum(
        1
        for r in results
        for f in r.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= min_rank
    )
    by_sev: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            if SEVERITY_ORDER.get(f.severity, 99) <= min_rank:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    targets = len(results)
    clean = sum(1 for r in results if r.clean)

    lines = []
    lines.append(
        f"[bold]Targets scanned:[/bold] {targets}   [bold]Clean:[/bold] {clean}   [bold]With findings:[/bold] {targets - clean}"
    )
    lines.append("")
    if total == 0:
        lines.append("[bold green]✓ No secrets detected[/bold green]")
    else:
        lines.append(f"[bold red]✗ {total} finding(s) detected[/bold red]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_sev.get(sev, 0)
            if count:
                style = SEVERITY_STYLE.get(sev, "white")
                lines.append(f"  [{style}]{sev}[/{style}]: {count}")

    return Panel(
        "\n".join(lines),
        title="[bold]DevSec Vault[/bold] — Scan Summary",
        border_style="blue",
    )


def _print_results(
    results: list[ScanResult],
    output_format: str,
    output_path: str | None,
    min_severity: str,
) -> None:
    out = Path(output_path) if output_path else None

    if output_format == "json":
        payload = write_json_report(results, output_path=out)
        if not out:
            console.print_json(payload)

    elif output_format == "sarif":
        payload = write_sarif_report(results, output_path=out)
        if not out:
            console.print(payload)

    else:  # text / rich
        table, row_count = _render_findings_table(results, min_severity=min_severity)
        summary = _render_summary(results, min_severity=min_severity)

        if row_count > 0:
            console.print(table)
            console.print()
        console.print(summary)

        if out:
            # also write JSON to file when format=text
            write_json_report(results, output_path=out)
            console.print(f"\n[dim]Report written to {out}[/dim]")


def _filter_by_severity(
    results: list[ScanResult], min_severity: str
) -> list[ScanResult]:
    """Return new ScanResult list with findings below min_severity stripped."""
    min_rank = SEVERITY_ORDER.get(min_severity, 99)
    filtered = []
    for r in results:
        kept = [f for f in r.findings if SEVERITY_ORDER.get(f.severity, 99) <= min_rank]
        nr = ScanResult(target=r.target, error=r.error)
        nr.findings = kept
        filtered.append(nr)
    return filtered


# ─────────────────────────────────────────────────────────────
# CLI GROUP
# ─────────────────────────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.version_option(VERSION, prog_name="devsec-vault")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    \b
    ██████╗ ███████╗██╗   ██╗███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝
    ██║  ██║█████╗  ██║   ██║███████╗█████╗  ██║
    ██║  ██║██╔══╝  ╚██╗ ██╔╝╚════██║██╔══╝  ██║
    ██████╔╝███████╗ ╚████╔╝ ███████║███████╗╚██████╗
    ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
                                          VAULT v2.0.0

    Layered secret detection: files · staged · history · CI.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ─────────────────────────────────────────────────────────────
# scan
# ─────────────────────────────────────────────────────────────


@cli.command("scan")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@_baseline_opt
@_format_opt
@_output_opt
@_no_entropy_opt
@_severity_opt
@click.option(
    "--max-file-size",
    "max_file_size_kb",
    default=500,
    show_default=True,
    help="Skip files larger than this (KB).",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["any", "high", "critical", "never"], case_sensitive=False),
    default="any",
    show_default=True,
    help="Exit code 1 only when findings meet this threshold.",
)
@click.option(
    "--exclude",
    "exclude_paths",
    multiple=True,
    help="Paths to exclude (can be repeated). Also reads DEVSEC_EXCLUDE env var (comma-separated).",
)
def cmd_scan(
    targets: tuple[str, ...],
    baseline_path: str,
    output_format: str,
    output_path: str | None,
    no_entropy: bool,
    min_severity: str,
    max_file_size_kb: int,
    fail_on: str,
    exclude_paths: tuple[str, ...],
) -> None:
    """Scan files or directories for secrets.

    \b
    Examples
    --------
      devsec-vault scan src/
      devsec-vault scan . --format json --output report.json
      devsec-vault scan config/ --min-severity HIGH
    """
    allowlist = load_baseline(Path(baseline_path))
    all_results: list[ScanResult] = []

    # Build exclusion set: --exclude flags + DEVSEC_EXCLUDE env var
    env_excludes = [
        p.strip() for p in os.environ.get("DEVSEC_EXCLUDE", "").split(",") if p.strip()
    ]
    excluded: set[Path] = {Path(p).resolve() for p in list(exclude_paths) + env_excludes}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=None)

        for target_str in targets:
            target = Path(target_str)
            if target.is_file():
                if target.resolve() not in excluded:
                    all_results.append(scan_file(target, allowlist=allowlist))
            elif target.is_dir():
                dir_results = scan_directory(
                    target, allowlist=allowlist, max_file_size_kb=max_file_size_kb
                )
                all_results.extend(
                    r for r in dir_results if Path(r.target).resolve() not in excluded
                )

    if no_entropy:
        for r in all_results:
            r.findings = [f for f in r.findings if f.rule != "HIGH_ENTROPY"]

    filtered = _filter_by_severity(all_results, min_severity)
    _print_results(filtered, output_format, output_path, min_severity)

    # ── Exit code logic ─────────────────────────────────────
    total_findings = sum(len(r.findings) for r in filtered)
    if total_findings == 0 or fail_on == "never":
        sys.exit(0)

    fail_severities = {
        "any": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        "high": {"CRITICAL", "HIGH"},
        "critical": {"CRITICAL"},
    }.get(fail_on, {"CRITICAL", "HIGH", "MEDIUM", "LOW"})

    triggered = any(f.severity in fail_severities for r in filtered for f in r.findings)
    sys.exit(1 if triggered else 0)


# ─────────────────────────────────────────────────────────────
# staged
# ─────────────────────────────────────────────────────────────


@cli.command("staged")
@click.option(
    "--repo",
    "repo_root",
    default=".",
    show_default=True,
    type=click.Path(exists=True, file_okay=False),
    help="Git repository root.",
)
@_baseline_opt
@_format_opt
@_output_opt
@_no_entropy_opt
@_severity_opt
def cmd_staged(
    repo_root: str,
    baseline_path: str,
    output_format: str,
    output_path: str | None,
    no_entropy: bool,
    min_severity: str,
) -> None:
    """Scan git staged changes (use as a pre-commit hook gate).

    \b
    Examples
    --------
      devsec-vault staged
      devsec-vault staged --format json
    """
    allowlist = load_baseline(Path(baseline_path))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning staged diff…", total=None)
        result = scan_staged(Path(repo_root), allowlist=allowlist)

    if no_entropy:
        result.findings = [f for f in result.findings if f.rule != "HIGH_ENTROPY"]

    filtered = _filter_by_severity([result], min_severity)
    _print_results(filtered, output_format, output_path, min_severity)

    if any(r.findings for r in filtered):
        err_console.print(
            "\n[bold red]✗ Secret(s) detected in staged changes — commit blocked.[/bold red]"
        )
        sys.exit(1)
    sys.exit(0)


# ─────────────────────────────────────────────────────────────
# history
# ─────────────────────────────────────────────────────────────


@cli.command("history")
@click.option(
    "--repo",
    "repo_root",
    default=".",
    show_default=True,
    type=click.Path(exists=True, file_okay=False),
    help="Git repository root.",
)
@click.option(
    "--max-commits",
    default=500,
    show_default=True,
    help="Maximum number of commits to inspect.",
)
@_baseline_opt
@_format_opt
@_output_opt
@_no_entropy_opt
@_severity_opt
def cmd_history(
    repo_root: str,
    max_commits: int,
    baseline_path: str,
    output_format: str,
    output_path: str | None,
    no_entropy: bool,
    min_severity: str,
) -> None:
    """Scan the full git history for secrets across all branches.

    \b
    Examples
    --------
      devsec-vault history
      devsec-vault history --max-commits 1000 --format sarif --output history.sarif
    """
    allowlist = load_baseline(Path(baseline_path))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task(f"Scanning up to {max_commits} commits…", total=None)
        results = scan_git_history(
            Path(repo_root), allowlist=allowlist, max_commits=max_commits
        )

    if no_entropy:
        for r in results:
            r.findings = [f for f in r.findings if f.rule != "HIGH_ENTROPY"]

    filtered = _filter_by_severity(results, min_severity)
    _print_results(filtered, output_format, output_path, min_severity)

    if any(r.findings for r in filtered):
        err_console.print(
            "\n[bold red]✗ Secret(s) found in git history — rotate affected credentials immediately.[/bold red]"
        )
        sys.exit(1)
    sys.exit(0)


# ─────────────────────────────────────────────────────────────
# baseline
# ─────────────────────────────────────────────────────────────


@cli.group("baseline")
def cmd_baseline() -> None:
    """Manage the allowlist baseline (suppress known / accepted findings)."""


@cmd_baseline.command("generate")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--output",
    "output_path",
    default=str(DEFAULT_BASELINE_PATH),
    show_default=True,
    help="Where to write the baseline file.",
)
def baseline_generate(targets: tuple[str, ...], output_path: str) -> None:
    """Generate a baseline from current scan findings.

    All current findings will be marked as accepted / suppressed in future scans.
    """
    all_results: list[ScanResult] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            all_results.append(scan_file(p))
        elif p.is_dir():
            all_results.extend(scan_directory(p))

    save_baseline(all_results, path=Path(output_path))
    count = sum(len(r.findings) for r in all_results)
    console.print(
        f"[green]✓[/green] Baseline written to [cyan]{output_path}[/cyan] ({count} fingerprint(s) recorded)."
    )


@cmd_baseline.command("diff")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--baseline", "baseline_path", default=str(DEFAULT_BASELINE_PATH), show_default=True
)
def baseline_diff(targets: tuple[str, ...], baseline_path: str) -> None:
    """Show findings that are new (not in baseline) or resolved (fixed since baseline)."""
    old_fps = load_baseline(Path(baseline_path))
    all_results: list[ScanResult] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            all_results.append(scan_file(p))
        elif p.is_dir():
            all_results.extend(scan_directory(p))

    new_findings, resolved_fps = diff_baseline(old_fps, all_results)

    if new_findings:
        table = Table(
            title="[bold red]New Findings (regressions)[/bold red]", box=box.ROUNDED
        )
        table.add_column("Rule")
        table.add_column("Severity")
        table.add_column("Line")
        table.add_column("Masked Value")
        for f in new_findings:
            sev_style = SEVERITY_STYLE.get(f.severity, "white")
            table.add_row(
                f.rule,
                Text(f.severity, style=f"bold {sev_style}"),
                str(f.line_number),
                f.masked_value,
            )
        console.print(table)
    else:
        console.print("[green]✓ No new findings vs baseline.[/green]")

    if resolved_fps:
        console.print(
            f"\n[cyan]{len(resolved_fps)} finding(s) resolved since baseline:[/cyan]"
        )
        for fp in resolved_fps:
            console.print(f"  [dim]{fp}[/dim]")


@cmd_baseline.command("show")
@click.option(
    "--baseline", "baseline_path", default=str(DEFAULT_BASELINE_PATH), show_default=True
)
def baseline_show(baseline_path: str) -> None:
    """Show the contents of the current baseline."""
    p = Path(baseline_path)
    if not p.exists():
        console.print(f"[yellow]No baseline found at {baseline_path}[/yellow]")
        return
    import json as _json

    data = _json.loads(p.read_text())
    console.print_json(_json.dumps(data, indent=2))


# ─────────────────────────────────────────────────────────────
# report (re-render)
# ─────────────────────────────────────────────────────────────


@cli.command("report")
@click.argument("json_report", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "sarif", "metrics"], case_sensitive=False),
    default="text",
    show_default=True,
)
@_output_opt
def cmd_report(json_report: str, output_format: str, output_path: str | None) -> None:
    """Re-render a saved JSON scan report in another format.

    \b
    Examples
    --------
      devsec-vault report report.json --format sarif --output results.sarif
      devsec-vault report report.json --format metrics
    """
    import json as _json

    raw = _json.loads(Path(json_report).read_text())

    # Reconstruct ScanResult objects from saved report
    from scanner import Finding, ScanResult

    results: list[ScanResult] = []
    for item in raw.get("results", []):
        r = ScanResult(target=item["target"], error=item.get("error", ""))
        for fd in item.get("findings", []):
            r.findings.append(
                Finding(
                    rule=fd["rule"],
                    severity=fd["severity"],
                    description=fd["description"],
                    line_number=fd["line_number"],
                    masked_value=fd["masked_value"],
                    fingerprint=fd["fingerprint"],
                    source=fd.get("source", "file"),
                    commit=fd.get("commit", ""),
                )
            )
        results.append(r)

    out = Path(output_path) if output_path else None

    if output_format == "sarif":
        payload = write_sarif_report(results, output_path=out)
        if not out:
            console.print(payload)
    elif output_format == "metrics":
        metrics = build_metrics(results)
        console.print_json(json.dumps(metrics, indent=2))
    else:
        _print_results(results, "text", output_path, "LOW")


# ─────────────────────────────────────────────────────────────
# info
# ─────────────────────────────────────────────────────────────


@cli.command("info")
def cmd_info() -> None:
    """Show loaded patterns, version, and tool metadata."""
    table = Table(
        title=f"[bold]DevSec Vault v{VERSION}[/bold] — Loaded Detection Rules",
        box=box.SIMPLE_HEAD,
        highlight=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", width=10)
    table.add_column("Description")

    for idx, (rule_id, (_, severity, desc)) in enumerate(
        sorted(RAW_PATTERNS.items(), key=lambda kv: SEVERITY_ORDER.get(kv[1][1], 99)),
        start=1,
    ):
        sev_style = SEVERITY_STYLE.get(severity, "white")
        table.add_row(
            str(idx),
            rule_id,
            Text(severity, style=f"bold {sev_style}"),
            desc,
        )

    console.print(table)
    console.print(f"\n[dim]Total patterns loaded: {len(RAW_PATTERNS)}[/dim]")
    console.print(
        "[dim]Entropy heuristic: enabled by default (Shannon entropy ≥ 4.2, min 20 chars)[/dim]"
    )


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
