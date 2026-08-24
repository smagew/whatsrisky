"""Scan orchestration, shared by the CLI and the TUI.

Everything the UI can configure lives in ScanOptions; run_scan() reports
progress through a callback so it never assumes a terminal.
"""

from __future__ import annotations

import concurrent.futures
import json
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .models import SEVERITY_ORDER, ScanReport, Severity, ToolResult
from .report import write_docx, write_markdown
from .runners import ALL_RUNNERS, ScanConfig
from .util import changed_files, git_info, slugify, which

ALL_TOOLS = ["semgrep", "trivy", "gitleaks", "claude"]
# claude is NOT a default: it costs the caller money and needs network. Opt in with --ai.
DEFAULT_TOOLS = ["semgrep", "trivy", "gitleaks"]
SCHEMA_VERSION = 1
MODEL_CHOICES = ["opus", "sonnet", "haiku"]
FORMAT_CHOICES = ["docx", "md", "json"]
FAIL_ON_CHOICES = ["none", "critical", "high", "medium", "low", "info"]

TOOL_COVERAGE = {
    "semgrep": "First-party source code (SAST)",
    "trivy": "Dependency CVEs, IaC misconfig",
    "gitleaks": "Secrets in tree and git history",
    "claude": "LLM review of logic and authz",
}


@dataclass
class ScanOptions:
    """Every knob the CLI exposes, in one serializable object."""

    path: str = ""
    tools: list[str] = field(default_factory=lambda: list(DEFAULT_TOOLS))
    diff: str = ""  # git range, e.g. "HEAD~1..HEAD" - scopes the scan to changed files
    formats: list[str] = field(default_factory=lambda: list(FORMAT_CHOICES))
    out_dir: str = ""
    out: str = ""
    model: str = "opus"
    claude_mode: str = "full"
    claude_timeout: int = 3600
    claude_max_findings: int = 40
    semgrep_configs: list[str] = field(default_factory=lambda: ["auto"])
    trivy_scanners: str = "vuln,misconfig"
    gitleaks_mode: str = "auto"
    exclude: list[str] = field(default_factory=list)
    offline: bool = False
    timeout: int = 1800
    jobs: int = 4
    min_severity: str = "INFO"
    max_per_severity: int | None = None
    fail_on: str = "none"
    work_dir: str = ""
    keep_work: bool = False
    open_report: bool = False

    def normalized(self) -> "ScanOptions":
        """Resolve the combinations that cannot work as configured."""
        opts = ScanOptions(**asdict(self))
        opts.tools = [t for t in ALL_TOOLS if t in opts.tools]
        opts.formats = [f for f in FORMAT_CHOICES if f in opts.formats]
        if opts.offline and opts.semgrep_configs == ["auto"]:
            # `--config auto` fetches rules from the registry; offline needs a pack.
            opts.semgrep_configs = ["p/security-audit"]
        opts.jobs = max(1, min(8, opts.jobs))
        return opts

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "ScanOptions":
        known = {f for f in cls().to_json()}
        clean = {k: v for k, v in (data or {}).items() if k in known}
        return cls(**clean)

    def command_line(self) -> str:
        """The equivalent `whatsrisky ...` invocation, for copy/paste and audit."""
        parts = ["whatsrisky", self.path or "."]
        if self.diff:
            parts += ["--diff", self.diff]
        if "claude" in self.tools:
            parts.append("--ai")
        tool_set = [t for t in self.tools if t != "claude"]
        if sorted(tool_set) != sorted(DEFAULT_TOOLS):
            parts += ["--tools", ",".join(tool_set)] if tool_set else ["--tools", "none"]
        if sorted(self.formats) != sorted(FORMAT_CHOICES):
            parts += ["--format", ",".join(self.formats)]
        if self.out_dir:
            parts += ["--out-dir", self.out_dir]
        if self.out:
            parts += ["--out", self.out]
        if "claude" in self.tools:
            if self.model != "opus":
                parts += ["--model", self.model]
            if self.claude_mode != "full":
                parts += ["--claude-mode", self.claude_mode]
            if self.claude_timeout != 3600:
                parts += ["--claude-timeout", str(self.claude_timeout)]
            if self.claude_max_findings != 40:
                parts += ["--claude-max-findings", str(self.claude_max_findings)]
        if self.semgrep_configs != ["auto"]:
            for cfg in self.semgrep_configs:
                parts += ["--semgrep-config", cfg]
        if self.trivy_scanners != "vuln,misconfig":
            parts += ["--trivy-scanners", self.trivy_scanners]
        if self.gitleaks_mode != "auto":
            parts += ["--gitleaks-mode", self.gitleaks_mode]
        for pattern in self.exclude:
            parts += ["--exclude", pattern]
        if self.offline:
            parts.append("--offline")
        if self.timeout != 1800:
            parts += ["--timeout", str(self.timeout)]
        if self.jobs != 4:
            parts += ["--jobs", str(self.jobs)]
        if self.min_severity != "INFO":
            parts += ["--min-severity", self.min_severity]
        if self.max_per_severity:
            parts += ["--max-per-severity", str(self.max_per_severity)]
        if self.fail_on != "none":
            parts += ["--fail-on", self.fail_on]
        if self.keep_work:
            parts.append("--keep-work")
        if self.open_report:
            parts.append("--open")
        return " ".join(parts)


def probe_tools() -> list[dict]:
    """Availability + version of every scanner, for `doctor` and the TUI."""
    config = ScanConfig(target=Path.cwd(), work_dir=Path(tempfile.gettempdir()))
    out: list[dict] = []
    for name in ALL_TOOLS:
        runner = ALL_RUNNERS[name](config)
        path = which(runner.binary)
        out.append(
            {
                "name": name,
                "binary": runner.binary,
                "found": bool(path),
                "version": runner.version() if path else "",
                "hint": runner.install_hint,
                "covers": TOOL_COVERAGE.get(name, ""),
            }
        )
    return out


@dataclass
class ScanOutcome:
    report: ScanReport
    written: list[Path]
    exit_code: int
    work_dir: Path


# on_event(kind, payload) - kind is one of: info, tool_start, tool_done, report
Callback = Callable[[str, dict], None]


def _noop(kind: str, payload: dict) -> None:
    return None


def validate(options: ScanOptions) -> list[str]:
    """Human-readable reasons the scan cannot start. Empty means good to go."""
    problems: list[str] = []
    if not options.path.strip():
        problems.append("Project path is empty.")
    elif not Path(options.path).expanduser().is_dir():
        problems.append(f"Not a directory: {options.path}")
    if not options.tools:
        problems.append("No scanners selected.")
    unknown = [t for t in options.tools if t not in ALL_RUNNERS]
    if unknown:
        problems.append(f"Unknown scanner(s): {', '.join(unknown)}")
    if not options.formats:
        problems.append("No output format selected.")
    return problems


def build_scan_config(
    options: ScanOptions, target: Path, work_dir: Path, scope_paths: list[str] | None = None
) -> ScanConfig:
    return ScanConfig(
        target=target,
        work_dir=work_dir,
        scope_paths=list(scope_paths or []),
        diff_range=options.diff,
        semgrep_configs=options.semgrep_configs or ["auto"],
        semgrep_timeout=options.timeout,
        trivy_scanners=options.trivy_scanners,
        trivy_timeout=options.timeout,
        trivy_offline=options.offline,
        gitleaks_mode=options.gitleaks_mode,
        gitleaks_timeout=min(options.timeout, 900),
        claude_model=options.model,
        claude_mode=options.claude_mode,
        claude_timeout=options.claude_timeout,
        claude_max_findings=options.claude_max_findings,
        exclude=options.exclude or [],
        min_severity=options.min_severity,
    )


def _run_tools(names: list[str], config: ScanConfig, jobs: int, on_event: Callback) -> list[ToolResult]:
    runners = [ALL_RUNNERS[name](config) for name in names]
    results: dict[str, ToolResult] = {}

    def execute(runner):
        on_event("tool_start", {"tool": runner.name})
        started = time.monotonic()
        result = runner.run()
        on_event(
            "tool_done",
            {
                "tool": runner.name,
                "status": result.status,
                "findings": len(result.findings),
                "duration": time.monotonic() - started,
                "message": result.message,
            },
        )
        return result

    if jobs <= 1 or len(runners) == 1:
        for runner in runners:
            results[runner.name] = execute(runner)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {pool.submit(execute, r): r for r in runners}
            for future in concurrent.futures.as_completed(futures):
                runner = futures[future]
                try:
                    results[runner.name] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    results[runner.name] = ToolResult(
                        name=runner.name, status="error", message=f"{type(exc).__name__}: {exc}"
                    )
    return [results[name] for name in names if name in results]


def exit_code_for(report: ScanReport, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity.parse(fail_on, Severity.HIGH)
    counts = report.counts()
    if any(counts[s] for s in SEVERITY_ORDER if s.rank <= threshold.rank):
        return 2
    return 0


def run_scan(options: ScanOptions, on_event: Callback | None = None) -> ScanOutcome:
    on_event = on_event or _noop
    options = options.normalized()
    problems = validate(options)
    if problems:
        raise ValueError("; ".join(problems))

    target = Path(options.path).expanduser().resolve()
    stamp = datetime.now()
    base = f"{slugify(target.name)}-{stamp.strftime('%Y%m%d-%H%M%S')}"
    out_dir = (
        Path(options.out_dir).expanduser().resolve()
        if options.out_dir
        else Path.cwd() / "whatsrisky-reports"
    )
    work_dir = (
        Path(options.work_dir).expanduser().resolve()
        if options.work_dir
        else out_dir / f".work-{base}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    scope_paths: list[str] = []
    if options.diff:
        scope_paths = changed_files(target, options.diff)
        on_event(
            "info",
            {
                "message": f"diff {options.diff}: {len(scope_paths)} changed file(s)",
                "tools": options.tools,
                "model": options.model,
                "claude_mode": options.claude_mode,
            },
        )
        if not scope_paths:
            raise ValueError(f"git range {options.diff!r} touches no existing files")

    config = build_scan_config(options, target, work_dir, scope_paths)
    commit, branch = git_info(target)
    report = ScanReport(
        project_path=str(target),
        project_name=target.name,
        started_at=stamp.strftime("%Y-%m-%d %H:%M:%S"),
        git_commit=commit,
        git_branch=branch,
        diff_range=options.diff,
        scope_paths=scope_paths,
    )
    on_event(
        "info",
        {
            "message": f"scanning {target}",
            "tools": options.tools,
            "model": options.model,
            "claude_mode": options.claude_mode,
        },
    )

    started = time.monotonic()
    report.tools = _run_tools(options.tools, config, options.jobs, on_event)
    report.duration_s = time.monotonic() - started
    report.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    floor = Severity.parse(options.min_severity, Severity.INFO)
    seen: set[str] = set()
    for tool in report.tools:
        for finding in tool.findings:
            if finding.severity.rank > floor.rank or finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            report.findings.append(finding)

    written: list[Path] = []
    if "docx" in options.formats:
        path = Path(options.out).expanduser().resolve() if options.out else out_dir / f"{base}.docx"
        written.append(write_docx(report, path, options.max_per_severity))
    if "md" in options.formats:
        written.append(write_markdown(report, out_dir / f"{base}.md"))
    if "json" in options.formats:
        json_path = out_dir / f"{base}.json"
        json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(json_path)
    on_event("report", {"paths": [str(p) for p in written]})

    if not options.keep_work and work_dir.name.startswith(".work-"):
        shutil.rmtree(work_dir, ignore_errors=True)

    return ScanOutcome(
        report=report,
        written=written,
        exit_code=exit_code_for(report, options.fail_on),
        work_dir=work_dir,
    )
