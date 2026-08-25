"""Interactive settings UI: pick what to scan and how, then run it.

Launch with `whatsrisky ui` (or bare `whatsrisky`). Everything here maps 1:1 onto
ScanOptions, so the TUI and the flags can never drift apart - the right-hand
panel always shows the equivalent command line.
"""

from __future__ import annotations

import re
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Rule,
    Select,
    SelectionList,
    Static,
)
from textual.widgets.selection_list import Selection

from . import __version__, settings
from .util import open_file
from .ai import PROVIDER_CHOICES, make_backend
from .core import (
    ALL_TOOLS,
    DEFAULT_EXCLUDES,
    FAIL_ON_CHOICES,
    FORMAT_CHOICES,
    ScanOptions,
    ScanOutcome,
    probe_tools,
    run_scan,
    validate,
)
from .models import SCHEMA_VERSION, SEVERITY_ORDER
from .progress import ProgressModel
from .util import path_excluded

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}
STATUS_STYLE = {"ok": "green", "missing": "yellow", "error": "red", "skipped": "dim"}


def _csv(value: str) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


# ----------------------------------------------------------------------
# run screen
# ----------------------------------------------------------------------
class RunScreen(Screen):
    """Live scan progress, then the summary and the report paths."""

    BINDINGS = [
        ("escape", "back", "Back to settings"),
        ("v", "view_report", "View report"),
        ("d", "open_docx", "Open DOCX"),
        ("q", "quit_app", "Quit"),
    ]

    def __init__(self, options: ScanOptions):
        super().__init__()
        self.options = options
        self.outcome: ScanOutcome | None = None
        self.progress = ProgressModel()
        self.live_report: str = ""   # readable while the scan runs

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="run-body"):
            yield Static(f"[b]scanning[/] {self.options.path}", id="run-title")
            yield Static(f"[dim]{self.options.command_line()}[/]", id="run-cmd")
            yield Static(id="run-progress")
            yield RichLog(id="run-log", markup=True, wrap=True, highlight=False)
            yield Static("", id="run-summary")
            with Horizontal(id="run-buttons"):
                yield Button("View report", id="view", variant="success", disabled=True)
                yield Button("Open DOCX", id="open", disabled=True)
                yield Button("Back to settings", id="back", variant="primary")
                yield Button("Quit", id="quit", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#run-log", RichLog)
        log.write(f"[b]whatsrisky {__version__}[/]")
        log.write(f"scanners: {', '.join(self.options.tools)}")
        if "claude" in self.options.tools:
            log.write(f"claude: model={self.options.model} mode={self.options.claude_mode}")
        log.write("")
        # Repaint on a timer so elapsed time keeps moving even while a scanner is silent.
        self.set_interval(0.2, self._paint_progress)
        self.execute()

    def _paint_progress(self) -> None:
        if self.progress.order:
            self.query_one("#run-progress", Static).update(self.progress.render_table())

    # --- worker -------------------------------------------------------
    @work(thread=True, exclusive=True)
    def execute(self) -> None:
        def on_event(kind: str, payload: dict) -> None:
            self.app.call_from_thread(self._handle_event, kind, payload)

        try:
            outcome = run_scan(self.options, on_event)
        except Exception as exc:
            self.app.call_from_thread(self._failed, f"{type(exc).__name__}: {exc}")
            return
        self.app.call_from_thread(self._finished, outcome)

    def _handle_event(self, kind: str, payload: dict) -> None:
        self.progress.handle(kind, payload)
        log = self.query_one("#run-log", RichLog)
        if kind == "info":
            log.write(f"[cyan]▸[/] {payload['message']}")
        elif kind == "tool_start":
            log.write(f"[cyan]▸ {payload['tool']}[/] started")
        elif kind == "tool_progress":
            return  # the table shows it; the log would drown in it
        elif kind == "tool_done":
            style = STATUS_STYLE.get(payload["status"], "white")
            line = (
                f"[{style}]▪ {payload['tool']}[/] {payload['status']} · "
                f"{payload['findings']} findings · {payload['duration']:.0f}s"
            )
            log.write(line)
            if payload.get("message") and payload["status"] != "ok":
                log.write(f"  [dim]{payload['message'][:300]}[/]")
        elif kind == "live":
            self.live_report = payload.get("html") or payload.get("json") or ""
            if self.live_report:
                self.query_one("#view", Button).disabled = False
                log.write("[dim]live report ready — press v to open it any time[/]")
        elif kind == "report":
            for path in payload["paths"]:
                log.write(f"[green]report[/] {path}")

    def _failed(self, message: str) -> None:
        self.query_one("#run-log", RichLog).write(f"[bold red]failed:[/] {message}")
        self.query_one("#run-title", Static).update("[bold red]scan failed[/]")

    def _finished(self, outcome: ScanOutcome) -> None:
        self.outcome = outcome
        log = self.query_one("#run-log", RichLog)
        report = outcome.report
        counts = report.counts()
        cells = "   ".join(
            f"[{SEVERITY_STYLE[s.value]}]{s.value} {counts[s]}[/]" for s in SEVERITY_ORDER
        )
        worst = next((s for s in SEVERITY_ORDER if counts[s]), None)
        verdict_style = SEVERITY_STYLE[worst.value] if worst else "green"
        summary = [
            f"[b]{report.project_name}[/]  ·  [{verdict_style}]{report.verdict()}[/]",
            f"risk score [b]{report.risk_score()}/100[/]  ·  {len(report.findings)} findings  "
            f"·  {report.duration_s:.0f}s",
            cells,
        ]
        problems = [t for t in report.tools if not t.ok]
        if problems:
            summary.append(
                "[yellow]coverage gaps:[/] "
                + ", ".join(f"{t.name} ({t.status})" for t in problems)
            )
        if outcome.exit_code:
            summary.append(f"[red]exit code {outcome.exit_code}[/] (--fail-on {self.options.fail_on})")
        self.query_one("#run-summary", Static).update("\n".join(summary))
        self.query_one("#run-title", Static).update(f"[b green]done[/] {self.options.path}")
        if outcome.report.excluded_count:
            log.write(
                f"[dim]{outcome.report.excluded_count} finding(s) dropped by exclusions[/]"
            )
        docx = next((p for p in outcome.written if p.suffix == ".docx"), None)
        if docx:
            self.query_one("#open", Button).disabled = False
        else:
            # Say why instead of leaving a dead button: the DOCX is written once, at
            # the end, and only when the format was asked for.
            log.write("[dim]no DOCX in this run — add docx to the formats to get one[/]")
        self.notify(f"{len(report.findings)} findings · {report.verdict()}", timeout=8)

    # --- actions ------------------------------------------------------
    def action_back(self) -> None:
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit(self.outcome.exit_code if self.outcome else 0)

    def action_view_report(self) -> None:
        """Open the HTML view - available while the scan is still running."""
        target = self.live_report
        if not target and self.outcome:
            html = next((p for p in self.outcome.written if p.suffix == ".html"), None)
            target = str(html) if html else ""
        if not target:
            self.notify("no viewable report in this run (add html to the formats)", severity="warning")
        elif not open_file(target):
            self.notify("could not open the file on this platform", severity="warning")

    def action_open_docx(self) -> None:
        if not self.outcome:
            self.notify("the DOCX is written when the scan finishes", severity="warning")
            return
        docx = next((p for p in self.outcome.written if p.suffix == ".docx"), None)
        if not docx:
            self.notify("no DOCX in this run — add docx to the formats", severity="warning")
        elif not open_file(docx):
            self.notify("could not open the file on this platform", severity="warning")

    @on(Button.Pressed, "#back")
    def _back(self) -> None:
        self.action_back()

    @on(Button.Pressed, "#view")
    def _view(self) -> None:
        self.action_view_report()

    @on(Button.Pressed, "#open")
    def _open(self) -> None:
        self.action_open_docx()

    @on(Button.Pressed, "#quit")
    def _quit(self) -> None:
        self.action_quit_app()


# ----------------------------------------------------------------------
# settings screen
# ----------------------------------------------------------------------
class SettingsScreen(Screen):
    BINDINGS = [
        ("r", "run", "Run scan"),
        ("ctrl+s", "save_profile", "Save profile"),
        ("q", "quit_app", "Quit"),
    ]

    def __init__(self, options: ScanOptions):
        super().__init__()
        self.options = options

    # --- layout -------------------------------------------------------
    def compose(self) -> ComposeResult:
        opts = self.options
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            with VerticalScroll(id="form"):
                yield Label("[b]Project[/]", classes="section")
                yield Input(value=opts.path, placeholder="/path/to/project", id="path")
                yield Label("scope to a git range (blank = whole project)", classes="field")
                yield Input(value=opts.diff, placeholder="HEAD~1..HEAD  ·  main...HEAD", id="diff")

                yield Label("[b]Skip these directories[/]", classes="section")
                yield Label(
                    "click to skip; vendored/build dirs are already skipped below",
                    classes="field",
                )
                yield SelectionList[str](id="skip-dirs")
                yield Checkbox(
                    "also skip the default list (node_modules, vendor, dist, …)",
                    value=opts.use_default_excludes,
                    id="use-default-excludes",
                )
                yield Label("extra patterns, comma separated", classes="field")
                yield Input(
                    value=",".join(opts.exclude),
                    placeholder="*.min.js, src/generated",
                    id="exclude",
                )

                yield Label("[b]Scanners[/]", classes="section")
                with Horizontal(classes="pair"):
                    for name in ALL_TOOLS:
                        yield Checkbox(name, value=name in opts.tools, id=f"tool-{name}")

                yield Label("[b]AI review[/]", classes="section")
                yield Label("provider", classes="field")
                yield Select(
                    [
                        ("claude-cli — reads the repo itself", "claude-cli"),
                        ("openai — api, sees only what we send", "openai"),
                    ],
                    value=opts.ai_provider if opts.ai_provider in PROVIDER_CHOICES else "claude-cli",
                    allow_blank=False,
                    id="ai-provider",
                )
                yield Label("model (blank = the backend's default)", classes="field")
                yield Input(value=opts.model, placeholder="opus · gpt-5 · a full model id", id="model")
                yield Label("mode", classes="field")
                yield Select(
                    [
                        ("full — audit the whole project", "full"),
                        ("review — the branch diff (agentic backends only)", "review"),
                        ("both", "both"),
                    ],
                    value=opts.ai_mode,
                    allow_blank=False,
                    id="ai-mode",
                )
                yield Label("timeout per pass (s) / max findings", classes="field")
                with Horizontal(classes="pair"):
                    yield Input(value=str(opts.ai_timeout), type="integer", id="ai-timeout")
                    yield Input(value=str(opts.ai_max_findings), type="integer", id="ai-max-findings")

                yield Label("[b]Output[/]", classes="section")
                yield Label("formats", classes="field")
                with Horizontal(classes="pair"):
                    for fmt in FORMAT_CHOICES:
                        yield Checkbox(fmt, value=fmt in opts.formats, id=f"fmt-{fmt}")
                yield Label("report directory (blank = ./whatsrisky-reports)", classes="field")
                yield Input(value=opts.out_dir, placeholder="./whatsrisky-reports", id="out-dir")
                yield Label("explicit .docx path (optional)", classes="field")
                yield Input(value=opts.out, placeholder="~/Desktop/audit.docx", id="out")
                yield Checkbox("open the DOCX when done", value=opts.open_report, id="open-report")

                yield Label("[b]Filtering[/]", classes="section")
                yield Label("minimum severity", classes="field")
                yield Select(
                    [(s.value, s.value) for s in SEVERITY_ORDER],
                    value=opts.min_severity,
                    allow_blank=False,
                    id="min-severity",
                )
                yield Label("max findings per severity in the DOCX (blank = all)", classes="field")
                yield Input(
                    value=str(opts.max_per_severity or ""), type="integer", id="max-per-severity"
                )
                yield Label("fail-on (exit 2 at or above, for CI)", classes="field")
                yield Select(
                    [(c, c) for c in FAIL_ON_CHOICES],
                    value=opts.fail_on,
                    allow_blank=False,
                    id="fail-on",
                )
                yield Label("[b]Scanner tuning[/]", classes="section")
                yield Label("semgrep --config (comma separated)", classes="field")
                yield Input(value=",".join(opts.semgrep_configs), id="semgrep-configs")
                yield Label("trivy --scanners", classes="field")
                yield Input(value=opts.trivy_scanners, id="trivy-scanners")
                yield Label("gitleaks mode", classes="field")
                yield Select(
                    [
                        ("auto — tree + history if git", "auto"),
                        ("dir — working tree only", "dir"),
                        ("git — history only", "git"),
                    ],
                    value=opts.gitleaks_mode,
                    allow_blank=False,
                    id="gitleaks-mode",
                )
                yield Label("per-scanner timeout (s) / parallel jobs", classes="field")
                with Horizontal(classes="pair"):
                    yield Input(value=str(opts.timeout), type="integer", id="timeout")
                    yield Input(value=str(opts.jobs), type="integer", id="jobs")
                with Horizontal(classes="pair"):
                    yield Checkbox("offline", value=opts.offline, id="offline")
                    yield Checkbox("keep raw output", value=opts.keep_work, id="keep-work")

            with Vertical(id="side"):
                yield Static("", id="tools-panel")
                yield Rule()
                yield Label("[b]Equivalent command[/]")
                yield Static("", id="cmd-panel")
                yield Rule()
                yield Static("", id="problems-panel")
                yield Rule()
                yield Label("[b]Profiles[/]")
                yield Select([("(none saved)", "")], allow_blank=True, id="profile-load")
                yield Input(placeholder="profile name to save", id="profile-name")
                with Horizontal(classes="pair"):
                    yield Button("Save", id="save-profile", variant="primary")
                    yield Button("Delete", id="delete-profile")
                yield Rule()
                yield Button("▶  Run scan", id="run", variant="success")
                yield Static(
                    f"[dim]whatsrisky {__version__} · report schema {SCHEMA_VERSION}[/]",
                    id="version",
                )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#tools-panel", Static).update("[dim]probing scanners…[/]")
        self._refresh_profiles()
        self._refresh_preview()
        self.probe()
        self.scan_dirs()

    @on(Input.Submitted, "#path")
    @on(Checkbox.Changed, "#use-default-excludes")
    def _path_changed(self) -> None:
        self.scan_dirs()

    def _panel(self, selector: str) -> Static | None:
        """A widget, or None when this screen is no longer mounted."""
        try:
            return self.query_one(selector, Static)
        except NoMatches:
            return None

    # --- directory picker ---------------------------------------------
    def _picked_dirs(self) -> list[str]:
        try:
            return list(self.query_one("#skip-dirs", SelectionList).selected)
        except Exception:
            return []

    def _exclusions(self) -> list[str]:
        """Picked directories plus hand-written patterns, in a stable order."""
        out: list[str] = []
        for pattern in self._picked_dirs() + _csv(self.query_one("#exclude", Input).value):
            if pattern and pattern not in out:
                out.append(pattern)
        return out

    @work(thread=True, exclusive=True, group="dirs")
    def scan_dirs(self) -> None:
        path = Path(self.query_one("#path", Input).value.strip()).expanduser()
        defaults_on = self.query_one("#use-default-excludes", Checkbox).value
        picked = set(self._picked_dirs())
        entries: list[tuple[str, int, bool]] = []
        if path.is_dir():
            try:
                for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
                    if not child.is_dir():
                        continue
                    # Already covered by the default list? Then it is not a choice to make.
                    if defaults_on and path_excluded(child.name, DEFAULT_EXCLUDES):
                        continue
                    try:
                        count = sum(1 for _ in child.rglob("*") if _.is_file())
                    except OSError:
                        count = 0
                    entries.append((child.name, count, child.name in picked))
            except OSError:
                pass
        self.app.call_from_thread(self._show_dirs, entries)

    def _show_dirs(self, entries: list[tuple[str, int, bool]]) -> None:
        try:
            widget = self.query_one("#skip-dirs", SelectionList)
        except NoMatches:
            return  # the screen went away while the directories were being counted
        widget.clear_options()
        if not entries:
            widget.display = False
            return
        widget.display = True
        widget.add_options(
            Selection(f"{name}  ({count} files)" if count else name, name, selected)
            for name, count, selected in entries
        )
        widget.styles.height = min(10, max(3, len(entries) + 1))

    # --- scanner availability -----------------------------------------
    @work(thread=True)
    def probe(self) -> None:
        tools = probe_tools()
        self.app.call_from_thread(self._show_tools, tools)

    def _show_tools(self, tools: list[dict]) -> None:
        # A background probe can land after the user has moved on. Textual tears the
        # widgets down with the screen, so this must be a no-op, not a crash.
        panel = self._panel("#tools-panel")
        if panel is None:
            return
        lines = ["[b]Scanners on this machine[/]"]
        for tool in tools:
            if tool["found"]:
                version = re.sub(r"\s*\(model:[^)]*\)", "", tool["version"])
                version = version.replace(f"{tool['name']} ", "").replace("Version: ", "")
                lines.append(f"[green]✓[/] {tool['name']} [dim]{version[:26]}[/]")
            else:
                lines.append(f"[red]✗[/] {tool['name']} [dim]{tool['hint'][:34]}[/]")
        if any(not t["found"] for t in tools):
            lines.append("")
            lines.append("[yellow]missing → `whatsrisky doctor --install`[/]")
        panel.update("\n".join(lines))

    # --- form <-> options ---------------------------------------------
    def _int(self, widget_id: str, default: int) -> int:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        try:
            return int(raw) if raw else default
        except ValueError:
            return default

    def collect(self) -> ScanOptions:
        max_per = self.query_one("#max-per-severity", Input).value.strip()
        return ScanOptions(
            path=self.query_one("#path", Input).value.strip(),
            tools=[n for n in ALL_TOOLS if self.query_one(f"#tool-{n}", Checkbox).value],
            diff=self.query_one("#diff", Input).value.strip(),
            formats=[f for f in FORMAT_CHOICES if self.query_one(f"#fmt-{f}", Checkbox).value],
            out_dir=self.query_one("#out-dir", Input).value.strip(),
            out=self.query_one("#out", Input).value.strip(),
            ai_provider=str(self.query_one("#ai-provider", Select).value),
            model=self.query_one("#model", Input).value.strip(),
            ai_mode=str(self.query_one("#ai-mode", Select).value),
            ai_timeout=self._int("ai-timeout", 3600),
            ai_max_findings=self._int("ai-max-findings", 40),
            semgrep_configs=_csv(self.query_one("#semgrep-configs", Input).value) or ["auto"],
            trivy_scanners=self.query_one("#trivy-scanners", Input).value.strip() or "vuln,misconfig",
            gitleaks_mode=str(self.query_one("#gitleaks-mode", Select).value),
            exclude=self._exclusions(),
            use_default_excludes=self.query_one("#use-default-excludes", Checkbox).value,
            offline=self.query_one("#offline", Checkbox).value,
            timeout=self._int("timeout", 1800),
            jobs=self._int("jobs", 4),
            min_severity=str(self.query_one("#min-severity", Select).value),
            max_per_severity=int(max_per) if max_per.isdigit() and int(max_per) > 0 else None,
            fail_on=str(self.query_one("#fail-on", Select).value),
            keep_work=self.query_one("#keep-work", Checkbox).value,
            open_report=self.query_one("#open-report", Checkbox).value,
        )

    def apply(self, opts: ScanOptions) -> None:
        """Push a loaded profile back into the widgets."""
        self.query_one("#path", Input).value = opts.path
        for name in ALL_TOOLS:
            self.query_one(f"#tool-{name}", Checkbox).value = name in opts.tools
        self.query_one("#diff", Input).value = opts.diff
        for fmt in FORMAT_CHOICES:
            self.query_one(f"#fmt-{fmt}", Checkbox).value = fmt in opts.formats
        self.query_one("#ai-provider", Select).value = (
            opts.ai_provider if opts.ai_provider in PROVIDER_CHOICES else "claude-cli"
        )
        self.query_one("#model", Input).value = opts.model
        self.query_one("#ai-mode", Select).value = opts.ai_mode
        self.query_one("#ai-timeout", Input).value = str(opts.ai_timeout)
        self.query_one("#ai-max-findings", Input).value = str(opts.ai_max_findings)
        self.query_one("#out-dir", Input).value = opts.out_dir
        self.query_one("#out", Input).value = opts.out
        self.query_one("#open-report", Checkbox).value = opts.open_report
        self.query_one("#min-severity", Select).value = opts.min_severity
        self.query_one("#max-per-severity", Input).value = str(opts.max_per_severity or "")
        self.query_one("#fail-on", Select).value = opts.fail_on
        self.query_one("#exclude", Input).value = ",".join(
            p for p in opts.exclude if p not in self._picked_dirs()
        )
        self.query_one("#use-default-excludes", Checkbox).value = opts.use_default_excludes
        self.query_one("#semgrep-configs", Input).value = ",".join(opts.semgrep_configs)
        self.query_one("#trivy-scanners", Input).value = opts.trivy_scanners
        self.query_one("#gitleaks-mode", Select).value = opts.gitleaks_mode
        self.query_one("#timeout", Input).value = str(opts.timeout)
        self.query_one("#jobs", Input).value = str(opts.jobs)
        self.query_one("#offline", Checkbox).value = opts.offline
        self.query_one("#keep-work", Checkbox).value = opts.keep_work
        self._refresh_preview()

    # --- live preview -------------------------------------------------
    def _refresh_preview(self) -> None:
        try:
            opts = self.collect().normalized()
        except Exception:
            return
        self.query_one("#cmd-panel", Static).update(f"[cyan]{opts.command_line()}[/]")
        problems = validate(opts)
        panel = self.query_one("#problems-panel", Static)
        notes = [f"[red]•[/] {p}" for p in problems]
        if opts.offline and "claude" in opts.tools:
            notes.append("[yellow]•[/] claude needs network even with --offline")
        if opts.offline and self.collect().semgrep_configs == ["auto"]:
            notes.append("[yellow]•[/] offline: semgrep switches to p/security-audit")
        if "ai" in opts.tools:
            notes.append("[yellow]•[/] the ai pass spends tokens on your account")
            backend = make_backend(opts.ai_provider, Path(opts.path or "."), Path("."))
            ready, why = backend.available()
            if not ready:
                notes.append(f"[red]•[/] {why}")
            if not backend.agentic:
                if opts.ai_mode in ("review", "both"):
                    notes.append(f"[red]•[/] {opts.ai_provider} cannot review a diff — use full")
                notes.append("[dim]•[/] this backend sees only the files we send it")
            elif (opts.model or backend.default_model) == "opus":
                notes.append("[dim]•[/] opus is the priciest pass; sonnet is ~5x cheaper")
        if opts.diff and "trivy" in opts.tools:
            notes.append("[dim]•[/] trivy ignores --diff (CVEs are manifest-wide)")
        skipped = len(opts.effective_excludes())
        if skipped:
            notes.append(f"[dim]•[/] skipping {skipped} pattern(s); see the command above")
        self.query_one("#run", Button).disabled = bool(problems)
        panel.update("\n".join(notes) if notes else "[green]ready to run[/]")

    @on(Input.Changed)
    @on(Checkbox.Changed)
    @on(Select.Changed)
    @on(SelectionList.SelectedChanged)
    def _any_change(self) -> None:
        self._refresh_preview()

    # --- profiles -----------------------------------------------------
    def _refresh_profiles(self) -> None:
        names = settings.profile_names()
        select = self.query_one("#profile-load", Select)
        select.set_options([(n, n) for n in names] or [("(none saved)", "")])

    @on(Select.Changed, "#profile-load")
    def _load_profile(self, event: Select.Changed) -> None:
        name = str(event.value or "")
        if not name:
            return
        opts = settings.load_profile(name)
        if opts:
            self.apply(opts)
            self.query_one("#profile-name", Input).value = name
            self.notify(f"loaded profile '{name}'")

    @on(Button.Pressed, "#save-profile")
    def _save_profile(self) -> None:
        self.action_save_profile()

    @on(Button.Pressed, "#delete-profile")
    def _delete_profile(self) -> None:
        name = self.query_one("#profile-name", Input).value.strip()
        if name and settings.delete_profile(name):
            self._refresh_profiles()
            self.notify(f"deleted profile '{name}'")
        else:
            self.notify("no such profile", severity="warning")

    def action_save_profile(self) -> None:
        name = self.query_one("#profile-name", Input).value.strip()
        if not name:
            self.notify("type a profile name first", severity="warning")
            return
        settings.save_profile(name, self.collect())
        self._refresh_profiles()
        self.notify(f"saved profile '{name}'")

    # --- run ----------------------------------------------------------
    @on(Button.Pressed, "#run")
    def _run(self) -> None:
        self.action_run()

    def action_run(self) -> None:
        opts = self.collect()
        problems = validate(opts.normalized())
        if problems:
            self.notify("; ".join(problems), severity="error")
            return
        settings.save_last(opts)
        self.app.push_screen(RunScreen(opts.normalized()))

    def action_quit_app(self) -> None:
        self.app.exit(0)


# ----------------------------------------------------------------------
class WhatsriskyApp(App):
    TITLE = "whatsrisky"
    SUB_TITLE = f"{__version__} · security scan settings"
    CSS = """
    #main { height: 1fr; }
    #form { width: 2fr; padding: 0 2 1 2; }
    #side { width: 1fr; min-width: 40; max-width: 52; padding: 0 1 1 2; border-left: solid $panel; }
    .section { margin: 1 0 0 0; color: $accent; text-style: bold; }
    .field { color: $text-muted; }
    .pair { height: auto; }
    .pair Input { width: 1fr; margin-right: 1; }
    .pair Checkbox { width: auto; margin-right: 2; }
    Input { margin: 0; border: tall $panel; height: 3; }
    Input:focus { border: tall $accent; }
    Checkbox { height: auto; margin: 0; border: none; padding: 0 1 0 0; }
    Select { margin: 0; }
    Rule { margin: 0; }
    #tools-panel, #cmd-panel, #problems-panel { padding: 0; }
    #version { padding: 1 0 0 0; }
    #cmd-panel { color: $text-accent; }
    #run { width: 100%; margin-top: 1; }
    #side Button { width: 1fr; }
    #run-body { padding: 1 2; height: 1fr; }
    #run-log { height: 1fr; border: round $panel; padding: 0 1; }
    #run-progress { padding: 1 0; }
    #skip-dirs { height: auto; max-height: 10; border: tall $panel; }
    #run-summary { padding: 1 0; }
    #run-buttons { height: auto; }
    #run-buttons Button { margin-right: 2; }
    """

    def __init__(self, options: ScanOptions):
        super().__init__()
        self.options = options

    def on_mount(self) -> None:
        self.push_screen(SettingsScreen(self.options))


def launch(path: str = "") -> int:
    """Open the settings UI. `path` (or the last used options) seeds the form."""
    options = settings.load_last() or ScanOptions()
    if path:
        options.path = str(Path(path).expanduser())
    if not options.path:
        options.path = str(Path.cwd())
    app = WhatsriskyApp(options)
    result = app.run()
    return int(result or 0)
