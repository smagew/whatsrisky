"""Normalized data model shared by every scanner and every report writer."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    @property
    def weight(self) -> float:
        return _WEIGHTS[self]

    @property
    def color(self) -> str:
        """Hex fill used for badges in the DOCX/MD reports."""
        return _COLORS[self]

    @classmethod
    def parse(cls, value: Any, default: "Severity" = None) -> "Severity":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().upper()
        if text in _ALIASES:
            return _ALIASES[text]
        return default if default is not None else cls.INFO


_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_WEIGHTS = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.1,
}
_COLORS = {
    Severity.CRITICAL: "B00020",
    Severity.HIGH: "E8590C",
    Severity.MEDIUM: "B08900",
    Severity.LOW: "2F6FA8",
    Severity.INFO: "6C757D",
}
_ALIASES = {
    "CRITICAL": Severity.CRITICAL,
    "BLOCKER": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MAJOR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "WARN": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "MINOR": Severity.LOW,
    "NOTE": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
    "UNKNOWN": Severity.INFO,
    "NONE": Severity.INFO,
}

SEVERITY_ORDER = tuple(_ORDER)

# Bump when the JSON report shape changes in a way consumers must notice.
SCHEMA_VERSION = 1


@dataclass
class Finding:
    """One normalized security finding, whatever tool produced it."""

    tool: str
    severity: Severity
    title: str
    description: str = ""
    category: str = ""           # e.g. "SAST", "Dependency", "Secret", "Misconfiguration"
    rule_id: str = ""
    file: str = ""               # path relative to the scanned project
    line: int | None = None
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    package: str = ""            # dependency findings
    installed_version: str = ""
    fixed_version: str = ""
    confidence: str = ""
    snippet: str = ""
    cvss: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        from .util import clean_text

        for field_name in (
            "tool", "title", "description", "category", "rule_id", "file",
            "remediation", "package", "installed_version", "fixed_version",
            "confidence", "snippet", "cvss",
        ):
            setattr(self, field_name, clean_text(getattr(self, field_name)))
        for field_name in ("cwe", "owasp", "references"):
            setattr(self, field_name, [clean_text(v) for v in getattr(self, field_name)])

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        if self.package:
            return self.package
        return "-"

    @property
    def fingerprint(self) -> str:
        key = "|".join(
            [
                self.tool,
                self.rule_id or self.title,
                self.file,
                str(self.line or ""),
                self.package,
                self.installed_version,
            ]
        )
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "references": self.references,
            "remediation": self.remediation,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "confidence": self.confidence,
            "snippet": self.snippet,
            "cvss": self.cvss,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ToolResult:
    """Outcome of a single scanner run."""

    name: str
    status: str = "ok"           # ok | skipped | error | missing
    findings: list[Finding] = field(default_factory=list)
    version: str = ""
    command: str = ""
    duration_s: float = 0.0
    message: str = ""            # error text / skip reason
    stderr_tail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class ScanReport:
    project_path: str
    project_name: str
    started_at: str
    finished_at: str = ""
    duration_s: float = 0.0
    git_commit: str = ""
    git_branch: str = ""
    diff_range: str = ""
    scope_paths: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    excluded_count: int = 0
    tools: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[Severity, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def counts_by_tool(self) -> dict[str, dict[Severity, int]]:
        out: dict[str, dict[Severity, int]] = {}
        for f in self.findings:
            out.setdefault(f.tool, {s: 0 for s in SEVERITY_ORDER})[f.severity] += 1
        return out

    def risk_score(self) -> int:
        """0-100 heuristic: saturating weighted sum of findings."""
        total = sum(f.severity.weight for f in self.findings)
        if total <= 0:
            return 0
        # 100 * (1 - exp(-total/120)) keeps a single critical meaningful (~28)
        import math

        return min(100, round(100 * (1 - math.exp(-total / 120.0))))

    def verdict(self) -> str:
        c = self.counts()
        if c[Severity.CRITICAL]:
            return "CRITICAL - immediate remediation required"
        if c[Severity.HIGH]:
            return "HIGH RISK - fix before release"
        if c[Severity.MEDIUM]:
            return "MODERATE - plan remediation"
        if c[Severity.LOW] or c[Severity.INFO]:
            return "LOW - hygiene issues only"
        return "CLEAN - no findings from the configured scanners"

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.tool, f.file, f.line or 0, f.title),
        )

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "schema_version": SCHEMA_VERSION,
            "generator": {"name": "whatsrisky", "version": __version__},
            "project_path": self.project_path,
            "project_name": self.project_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 2),
            "git_commit": self.git_commit,
            "git_branch": self.git_branch,
            "diff_range": self.diff_range,
            "scope_paths": self.scope_paths,
            "excludes": self.excludes,
            "excluded_findings": self.excluded_count,
            "risk_score": self.risk_score(),
            "verdict": self.verdict(),
            "counts": {s.value: n for s, n in self.counts().items()},
            "tools": [
                {
                    "name": t.name,
                    "status": t.status,
                    "version": t.version,
                    "command": t.command,
                    "duration_s": round(t.duration_s, 2),
                    "findings": len(t.findings),
                    "message": t.message,
                }
                for t in self.tools
            ],
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
