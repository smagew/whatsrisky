"""Runner contract: one scanner in, normalized findings out."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, ToolResult
from ..util import clean_text, platform_key, tail, which


@dataclass
class ScanConfig:
    target: Path
    work_dir: Path
    # scope: when set, only these paths are scanned (resolved from a git range)
    scope_paths: list[str] = field(default_factory=list)
    diff_range: str = ""
    # semgrep
    semgrep_configs: list[str] = field(default_factory=lambda: ["auto"])
    semgrep_timeout: int = 1800
    # trivy
    trivy_scanners: str = "vuln,misconfig"
    trivy_timeout: int = 1800
    trivy_offline: bool = False
    # gitleaks
    gitleaks_mode: str = "auto"  # auto | dir | git
    gitleaks_timeout: int = 600
    # claude
    claude_model: str = "opus"
    claude_mode: str = "full"  # full | review | both
    claude_timeout: int = 3600
    claude_max_findings: int = 40
    # shared
    exclude: list[str] = field(default_factory=list)
    min_severity: str = "INFO"
    verbose: bool = False

    @property
    def target_str(self) -> str:
        return str(self.target)


class Runner:
    """Base class. Subclasses implement `binary`, `probe_version` and `scan`."""

    name: str = "runner"
    binary: str = ""
    category: str = ""
    # per-platform install instructions; "default" is the fallback
    install_hints: dict[str, str] = {}

    def __init__(self, config: ScanConfig):
        self.config = config

    @property
    def install_hint(self) -> str:
        hints = type(self).install_hints
        return hints.get(platform_key()) or hints.get("default", "")

    # --- availability -------------------------------------------------
    def available(self) -> bool:
        return bool(self.binary) and which(self.binary) is not None

    def version(self) -> str:
        from ..util import tool_version

        return tool_version(self.binary)

    # --- execution ----------------------------------------------------
    def scan(self) -> tuple[list[Finding], str, str]:
        """Return (findings, command_line, stderr_tail). Raise on hard failure."""
        raise NotImplementedError

    def run(self) -> ToolResult:
        result = ToolResult(name=self.name)
        if not self.available():
            result.status = "missing"
            result.message = f"`{self.binary}` not found in PATH. Install: {self.install_hint}"
            return result
        result.version = clean_text(self.version())
        started = time.monotonic()
        try:
            findings, command, stderr = self.scan()
            result.findings = findings
            result.command = command
            result.stderr_tail = tail(stderr)
        except Exception as exc:  # a broken scanner must not kill the whole scan
            result.status = "error"
            result.message = clean_text(f"{type(exc).__name__}: {exc}")
        result.duration_s = time.monotonic() - started
        return result
