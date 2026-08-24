"""whatsrisky CLI: point it at a project path, get a prioritized security report."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import __version__, settings
from .core import (
    ALL_TOOLS,
    DEFAULT_TOOLS,
    FAIL_ON_CHOICES,
    ScanOptions,
    probe_tools,
    run_scan,
)
from .models import SEVERITY_ORDER, ScanReport, Severity
from .progress import STATUS_STYLE, ProgressModel
from .util import open_file, truncate, which

console = Console()


# --- doctor -----------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    table = Table(title="whatsrisky prerequisites", show_lines=False)
    table.add_column("Tool")
    table.add_column("Found")
    table.add_column("Version / install hint")
    tools = probe_tools()
    for tool in tools:
        if tool["found"]:
            table.add_row(tool["name"], "[green]yes[/]", tool["version"] or tool["binary"])
        else:
            table.add_row(tool["name"], "[red]no[/]", tool["hint"])
    console.print(table)

    missing = [t for t in tools if not t["found"]]
    if not missing:
        console.print("[green]All scanners present.[/]")
        return 0

    brew_targets = [t["binary"] for t in missing if t["binary"] != "claude"]
    if args.install and brew_targets:
        if not which("brew"):
            console.print("[red]Homebrew not found; install the tools manually.[/]")
            return 1
        console.print(f"[cyan]Installing:[/] {' '.join(brew_targets)}")
        return subprocess.run(["brew", "install", *brew_targets]).returncode
    if brew_targets:
        console.print(f"\nInstall the missing scanners with:\n  brew install {' '.join(brew_targets)}")
    if any(t["binary"] == "claude" for t in missing):
        console.print("  npm install -g @anthropic-ai/claude-code")
    return 1


# --- ui ---------------------------------------------------------------
def cmd_ui(args: argparse.Namespace) -> int:
    try:
        from .ui import launch
    except ImportError as exc:  # textual missing
        console.print(f"[red]The settings UI needs textual:[/] uv pip install textual  ({exc})")
        return 1
    return launch(args.path or "")


# --- scan -------------------------------------------------------------
def _options_from_args(args: argparse.Namespace) -> ScanOptions:
    base = settings.load_profile(args.profile) if args.profile else None
    if args.profile and base is None:
        raise SystemExit(f"no such profile: {args.profile} (have: {', '.join(settings.profile_names()) or 'none'})")
    options = base or ScanOptions()

    options.path = args.path
    if args.tools is not None:
        options.tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    # Naming a Claude setting is an unambiguous request for the AI pass.
    wants_ai = args.ai or args.model is not None or args.claude_mode is not None
    if wants_ai and "claude" not in options.tools:
        options.tools = options.tools + ["claude"]
    skipped = {t.strip() for t in (args.skip or "").split(",") if t.strip()}
    if skipped:
        options.tools = [t for t in options.tools if t not in skipped]
    if args.format is not None:
        options.formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    for name, value in (
        ("out", args.out),
        ("out_dir", args.out_dir),
        ("work_dir", args.work_dir),
        ("model", args.model),
        ("claude_mode", args.claude_mode),
        ("claude_timeout", args.claude_timeout),
        ("claude_max_findings", args.claude_max_findings),
        ("trivy_scanners", args.trivy_scanners),
        ("gitleaks_mode", args.gitleaks_mode),
        ("timeout", args.timeout),
        ("jobs", args.jobs),
        ("min_severity", args.min_severity),
        ("max_per_severity", args.max_per_severity),
        ("fail_on", args.fail_on),
        ("diff", args.diff),
    ):
        if value is not None:
            setattr(options, name, value)
    if args.semgrep_config:
        options.semgrep_configs = args.semgrep_config
    if args.exclude:
        options.exclude = args.exclude
    if args.offline:
        options.offline = True
    if args.no_default_excludes:
        options.use_default_excludes = False
    if args.keep_work:
        options.keep_work = True
    if args.open:
        options.open_report = True

    unknown = [t for t in options.tools if t not in ALL_TOOLS]
    if unknown:
        raise SystemExit(f"unknown tool(s): {', '.join(unknown)}. Known: {', '.join(ALL_TOOLS)}")
    return options


def _summary_table(report: ScanReport) -> Table:
    table = Table(title=f"{report.project_name} — {report.verdict()}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts = report.counts()
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    for severity in SEVERITY_ORDER:
        table.add_row(f"[{colors[severity]}]{severity.value}[/]", str(counts[severity]))
    table.add_row("[bold]TOTAL[/]", f"[bold]{len(report.findings)}[/]")
    return table


class ProgressView:
    """CLI front end for ProgressModel: a live table on a terminal, plain lines otherwise."""

    def __init__(self, target_console: Console):
        self.console = target_console
        self.model = ProgressModel()
        self.live: Live | None = None

    def start(self) -> None:
        if self.console.is_terminal:
            self.live = Live(
                get_renderable=self.model.render_table,
                console=self.console,
                refresh_per_second=8,
                transient=True,
            )
            self.live.start()

    def stop(self) -> None:
        if self.live:
            self.live.stop()
            self.live = None
        for tool in self.model.order:
            row = self.model.rows[tool]
            if row["status"] != "running":
                style = STATUS_STYLE.get(row["status"], "white")
                self.console.print(Text("▪ " + self.model.line(tool), style=style))

    def handle(self, kind: str, payload: dict) -> None:
        if kind == "info":
            self.console.print(f"[bold]whatsrisky {__version__}[/] {payload['message']}")
            line = f"scanners: {', '.join(payload['tools'])}"
            if "claude" in payload["tools"]:
                line += f"  ·  claude: {payload['model']} ({payload['claude_mode']})"
            self.console.print(line)
            return
        if kind == "report":
            return
        self.model.handle(kind, payload)
        if not self.live:
            self._print_plain(kind, payload.get("tool", ""))

    def _print_plain(self, kind: str, tool: str) -> None:
        if kind == "tool_start":
            self.console.print(f"[cyan]▸ {tool}[/] started")
        elif kind == "tool_progress" and tool in self.model.rows:
            self.console.print(
                Text(f"  {tool}: {self.model.rows[tool]['message']}", style="dim"), highlight=False
            )


def _on_event(kind: str, payload: dict) -> None:
    if kind == "info":
        console.print(f"[bold]whatsrisky {__version__}[/] {payload['message']}")
        line = f"scanners: {', '.join(payload['tools'])}"
        if "claude" in payload["tools"]:
            line += f"  ·  claude: {payload['model']} ({payload['claude_mode']})"
        console.print(line)
    elif kind == "tool_start":
        console.print(f"[cyan]▸ {payload['tool']}[/] started")
    elif kind == "tool_done":
        style = STATUS_STYLE.get(payload["status"], "white")
        console.print(
            f"[{style}]▪ {payload['tool']}[/] {payload['status']} · "
            f"{payload['findings']} findings · {payload['duration']:.0f}s"
        )


def cmd_scan(args: argparse.Namespace) -> int:
    options = _options_from_args(args)
    if args.show_excludes:
        patterns = options.effective_excludes()
        console.print(f"[bold]{len(patterns)} exclusion pattern(s)[/] in effect:")
        for pattern in patterns:
            source = "user" if pattern in options.exclude else "default"
            console.print(f"  {pattern}  [dim]({source})[/]")
        return 0
    machine = args.json_stdout
    if machine:
        # stdout belongs to the JSON payload; everything else goes to stderr.
        globals()["console"] = Console(stderr=True)
    quiet = args.quiet or machine
    if not Path(options.path).expanduser().is_dir():
        console.print(f"[red]Not a directory:[/] {options.path}")
        return 1
    normalized = options.normalized()
    if normalized.semgrep_configs != options.semgrep_configs:
        console.print(
            "[yellow]--offline:[/] semgrep `auto` needs network, using "
            f"{','.join(normalized.semgrep_configs)} instead"
        )
    if args.save_profile:
        settings.save_profile(args.save_profile, options)
        console.print(f"[green]saved profile[/] {args.save_profile}")
    settings.save_last(options)

    view = None if quiet else ProgressView(console)
    if view:
        view.start()
    try:
        outcome = run_scan(options, view.handle if view else None)
    except ValueError as exc:
        if view:
            view.stop()
        console.print(f"[red]{exc}[/]")
        return 1
    finally:
        if view:
            view.stop()

    if machine:
        sys.stdout.write(json.dumps(outcome.report.to_dict(), indent=2, ensure_ascii=False) + "\n")
    elif quiet:
        for path in outcome.written:
            print(path)
    else:
        console.print()
        console.print(_summary_table(outcome.report))
        for tool in (t for t in outcome.report.tools if not t.ok):
            console.print(
                f"[{STATUS_STYLE.get(tool.status, 'yellow')}]! {tool.name} {tool.status}[/]: "
                f"{truncate(tool.message, 200)}"
            )
        if outcome.report.excluded_count:
            console.print(
                f"[dim]{outcome.report.excluded_count} finding(s) dropped by exclusions "
                f"({len(outcome.report.excludes)} patterns; --show-excludes to list)[/]"
            )
        for path in outcome.written:
            console.print(f"[green]report[/] {path}")
        if options.keep_work:
            console.print(f"[dim]raw scanner output kept in {outcome.work_dir}[/]")

    if options.open_report:
        docx = next((p for p in outcome.written if p.suffix == ".docx"), None)
        if docx and not open_file(docx):
            console.print("[yellow]could not open the report on this platform[/]")
    return outcome.exit_code


# --- profiles ---------------------------------------------------------
def cmd_profiles(args: argparse.Namespace) -> int:
    names = settings.profile_names()
    if args.delete:
        if settings.delete_profile(args.delete):
            console.print(f"[green]deleted[/] {args.delete}")
            return 0
        console.print(f"[red]no such profile:[/] {args.delete}")
        return 1
    if not names:
        console.print("No saved profiles. Create one in the UI (`whatsrisky ui`) or with --save-profile.")
        return 0
    table = Table(title=f"profiles in {settings.config_path()}")
    table.add_column("Name")
    table.add_column("Equivalent command")
    for name in names:
        options = settings.load_profile(name)
        table.add_row(name, options.command_line() if options else "-")
    console.print(table)
    return 0


# --- argparse ---------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whatsrisky",
        description="Run Semgrep + Trivy + gitleaks + Claude against a project and write a prioritized report.",
    )
    parser.add_argument("--version", action="version", version=f"whatsrisky {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a project path")
    scan.add_argument("path", help="absolute or relative path to the project to scan")
    scan.add_argument("-o", "--out", help="explicit .docx output path")
    scan.add_argument("--out-dir", help="directory for reports (default ./whatsrisky-reports)")
    scan.add_argument("--format", help="comma list: docx,md,json (default all)")
    scan.add_argument("--tools", help=f"comma list of scanners (default {','.join(DEFAULT_TOOLS)})")
    scan.add_argument("--skip", help="comma list of scanners to skip")
    scan.add_argument(
        "--ai",
        action="store_true",
        help="add the Claude review pass (off by default: it spends tokens and needs network)",
    )
    scan.add_argument(
        "--diff",
        help="scope the scan to files changed in a git range, e.g. HEAD~1..HEAD or main...HEAD",
    )
    scan.add_argument("--model", help="Claude model for the AI review (implies --ai; default opus)")
    scan.add_argument(
        "--claude-mode",
        choices=["full", "review", "both"],
        help="full = whole-project audit prompt; review = security-review on the diff; both (implies --ai)",
    )
    scan.add_argument("--claude-timeout", type=int, help="seconds for each claude pass")
    scan.add_argument("--claude-max-findings", type=int, help="cap on AI findings")
    scan.add_argument(
        "--semgrep-config", action="append", help="semgrep --config value, repeatable (default: auto)"
    )
    scan.add_argument(
        "--trivy-scanners", help="trivy --scanners value (add ,secret to duplicate gitleaks coverage)"
    )
    scan.add_argument("--gitleaks-mode", choices=["auto", "dir", "git"])
    scan.add_argument(
        "--exclude",
        action="append",
        help="directory, path or glob to skip, repeatable (e.g. --exclude vendor --exclude '*.min.js')",
    )
    scan.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="also scan node_modules, vendor, dist and the rest of the default skip list",
    )
    scan.add_argument(
        "--show-excludes", action="store_true", help="print the effective skip list and exit"
    )
    scan.add_argument("--offline", action="store_true", help="no network: skip trivy DB update")
    scan.add_argument("--timeout", type=int, help="per-scanner timeout in seconds")
    scan.add_argument("--jobs", type=int, help="scanners to run in parallel (1 = sequential)")
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in SEVERITY_ORDER],
        help="drop findings below this severity",
    )
    scan.add_argument(
        "--max-per-severity",
        type=int,
        help="cap findings rendered per severity in the DOCX (json keeps everything)",
    )
    scan.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        help="exit 2 when a finding at or above this severity exists (for CI)",
    )
    scan.add_argument("--profile", help="start from a saved profile, then apply the flags below it")
    scan.add_argument("--save-profile", help="store these settings under this profile name")
    scan.add_argument("--work-dir", help="where to keep raw scanner output")
    scan.add_argument("--keep-work", action="store_true", help="do not delete raw scanner output")
    scan.add_argument("--open", action="store_true", help="open the DOCX when done")
    scan.add_argument("--quiet", action="store_true", help="print only the written report paths")
    scan.add_argument(
        "--json-stdout",
        action="store_true",
        help="write the full JSON report to stdout and nothing else (for embedding in other tools)",
    )
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.set_defaults(func=cmd_scan)

    ui = sub.add_parser("ui", help="interactive settings UI (default when run with no arguments)")
    ui.add_argument("path", nargs="?", help="project path to preload")
    ui.set_defaults(func=cmd_ui)

    doctor = sub.add_parser("doctor", help="check that the scanners are installed")
    doctor.add_argument("--install", action="store_true", help="brew install what is missing")
    doctor.set_defaults(func=cmd_doctor)

    profiles = sub.add_parser("profiles", help="list or delete saved setting profiles")
    profiles.add_argument("--delete", help="profile name to remove")
    profiles.set_defaults(func=cmd_profiles)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"scan", "doctor", "ui", "profiles"}
    if not argv:
        argv = ["ui"]  # bare `whatsrisky` opens the settings UI
    elif argv[0] not in known and not argv[0].startswith("-"):
        argv.insert(0, "scan")  # allow `whatsrisky /path/to/project`
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
