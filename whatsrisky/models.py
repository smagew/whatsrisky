"""Normalized data model shared by every scanner and every report writer."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import categories


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
SCHEMA_VERSION = 2


class Status:
    """Where a finding stands relative to the previous scan."""

    NEW = "new"                    # absent from the baseline
    OPEN = "open"                  # present in both
    RESOLVED = "resolved"          # in the baseline, gone now - carried over so it can be shown
    REINTRODUCED = "reintroduced"  # was resolved in the baseline, back again
    ACCEPTED = "accepted"          # a human decided to live with it

    ALL = (NEW, OPEN, RESOLVED, REINTRODUCED, ACCEPTED)
    # What still counts against the project. A resolved finding is history and an
    # accepted one is a decision already taken: both stay visible in the report,
    # neither inflates the counts, the verdict or the exit code.
    ACTIVE = (NEW, OPEN, REINTRODUCED)


class Source:
    """The kind of artifact a finding lives in - the axis for 'only dependencies'."""

    CODE = "source-code"
    DEPENDENCY = "dependency-manifest"
    GIT_HISTORY = "git-history"
    IAC = "iac"
    CONTAINER = "container"
    CI = "ci-config"

    ALL = (CODE, DEPENDENCY, GIT_HISTORY, IAC, CONTAINER, CI)


_CONTAINER_FILE = re.compile(r"(^|/)(dockerfile|containerfile)|docker-compose|compose\.ya?ml", re.I)
_IAC_FILE = re.compile(r"\.(tf|tfvars|hcl)$|(^|/)(k8s|kubernetes|helm|charts|manifests)/", re.I)
_CI_FILE = re.compile(r"(^|/)\.(github|gitlab|circleci)/|(^|/)(jenkinsfile|\.travis\.yml|azure-pipelines\.ya?ml)", re.I)


def infer_source(tool: str, pass_name: str, file: str) -> str:
    """Which artifact class this finding belongs to."""
    if tool == "gitleaks":
        return Source.GIT_HISTORY if pass_name == "git" else Source.CODE
    if tool == "trivy" and pass_name == "vuln":
        return Source.DEPENDENCY
    path = file or ""
    if _CI_FILE.search(path):
        return Source.CI
    if _CONTAINER_FILE.search(path):
        return Source.CONTAINER
    if _IAC_FILE.search(path):
        return Source.IAC
    if tool == "trivy" and pass_name == "misconfig":
        return Source.IAC
    return Source.CODE


# Evidence as we render it carries a line-number gutter and, for context, the
# neighbouring lines. Neither may enter the content key: the gutter changes when a
# line drifts, and the neighbours change when the code moves - both would make the
# same finding look like a different one.
_SNIPPET_GUTTER = re.compile(r"^[>\s]*\d+\s*\|\s?")
_MARKED_LINE = re.compile(r"^\s*>")


def evidence_of(snippet: str) -> str:
    """The offending code itself, with the gutter and the context stripped.

    A marked snippet (our own reader marks the finding's line with `>`) reduces to
    the marked lines. An unmarked one is already just the match - that is what the
    scanners hand us - so it is kept whole.
    """
    lines = (snippet or "").splitlines()
    marked = [line for line in lines if _MARKED_LINE.match(line)]
    chosen = marked or lines
    return " ".join(" ".join(_SNIPPET_GUTTER.sub("", line).split()) for line in chosen).strip()


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:12]


@dataclass
class Finding:
    """One normalized security finding, whatever tool produced it."""

    tool: str
    severity: Severity
    title: str
    description: str = ""
    category: str = ""           # the scanner's own words, e.g. "Dependency/pip"
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
    # who found it: provider/model are empty for local scanners
    provider: str = ""
    model: str = ""
    pass_name: str = ""
    # derived; set in __post_init__ unless a caller overrides
    norm_category: str = ""
    source: str = ""
    # comparison against the previous scan, filled by compare.correlate()
    status: str = Status.OPEN
    first_seen: str = ""
    last_seen: str = ""
    moved_from: str = ""
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
        if not self.norm_category:
            self.norm_category = categories.classify(
                cwe=self.cwe,
                native_category=self.category,
                rule_id=self.rule_id,
                title=self.title,
            )
        if not self.source:
            self.source = infer_source(self.tool, self.pass_name, self.file)

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
    def is_active(self) -> bool:
        return self.status in Status.ACTIVE

    @property
    def category_label(self) -> str:
        return categories.label(self.norm_category)

    @property
    def fingerprint(self) -> str:
        """Exact identity. Changes when anything about the location changes."""
        return _digest(
            self.tool,
            self.rule_id or self.title,
            self.file,
            str(self.line or ""),
            self.package,
            self.installed_version,
        )

    @property
    def content_key(self) -> str:
        """Identity that survives the code moving - within a file or between files.

        Keyed on the evidence rather than the location. Dependency findings have no
        evidence to hash, so they fall back to the package identity, which is what
        actually identifies them.
        """
        evidence = evidence_of(self.snippet)
        if not evidence:
            evidence = " ".join(filter(None, [self.package, self.installed_version])) or self.title
        return _digest(self.tool, self.rule_id or self.title, evidence)

    @property
    def match_key(self) -> str:
        """Identity that survives a line drifting inside the same file."""
        return _digest(self.tool, self.rule_id or self.title, self.file, self.package)

    @property
    def detector(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "provider": self.provider or None,
            "model": self.model or None,
            "pass": self.pass_name or None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "detector": self.detector,
            "severity": self.severity.value,
            "status": self.status,
            "title": self.title,
            "description": self.description,
            "category": self.norm_category,
            "category_label": self.category_label,
            "source": self.source,
            "scanner_category": self.category,
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
            "content_key": self.content_key,
            "match_key": self.match_key,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "moved_from": self.moved_from,
        }


def finding_from_dict(data: dict[str, Any]) -> Finding:
    """Rebuild a Finding from a report JSON entry (schema 2)."""
    detector = data.get("detector") or {}
    return Finding(
        tool=data.get("tool") or detector.get("tool") or "",
        severity=Severity.parse(data.get("severity"), Severity.INFO),
        title=data.get("title") or "",
        description=data.get("description") or "",
        category=data.get("scanner_category") or "",
        rule_id=data.get("rule_id") or "",
        file=data.get("file") or "",
        line=data.get("line"),
        end_line=data.get("end_line"),
        cwe=list(data.get("cwe") or []),
        owasp=list(data.get("owasp") or []),
        references=list(data.get("references") or []),
        remediation=data.get("remediation") or "",
        package=data.get("package") or "",
        installed_version=data.get("installed_version") or "",
        fixed_version=data.get("fixed_version") or "",
        confidence=data.get("confidence") or "",
        snippet=data.get("snippet") or "",
        cvss=data.get("cvss") or "",
        provider=detector.get("provider") or "",
        model=detector.get("model") or "",
        pass_name=detector.get("pass") or "",
        norm_category=data.get("category") or "",
        source=data.get("source") or "",
        status=data.get("status") or Status.OPEN,
        first_seen=data.get("first_seen") or "",
        last_seen=data.get("last_seen") or "",
        moved_from=data.get("moved_from") or "",
    )


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
    scan_id: str = ""
    finished_at: str = ""
    duration_s: float = 0.0
    git_commit: str = ""
    git_branch: str = ""
    diff_range: str = ""
    scope_paths: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    excluded_count: int = 0
    status: str = "complete"   # running | complete | partial
    comparison: dict[str, Any] | None = None
    tools: list[ToolResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_active]

    def counts(self) -> dict[Severity, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.active_findings():
            out[f.severity] += 1
        return out

    def counts_by_tool(self) -> dict[str, dict[Severity, int]]:
        out: dict[str, dict[Severity, int]] = {}
        for f in self.active_findings():
            out.setdefault(f.tool, {s: 0 for s in SEVERITY_ORDER})[f.severity] += 1
        return out

    def risk_score(self) -> int:
        """0-100 heuristic: saturating weighted sum of the active findings."""
        total = sum(f.severity.weight for f in self.active_findings())
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
        """Priority order, with what no longer counts pushed to the end."""
        return sorted(
            self.findings,
            key=lambda f: (
                0 if f.is_active else 1,
                f.severity.rank,
                f.tool,
                f.file,
                f.line or 0,
                f.title,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        from . import __version__

        return {
            "schema_version": SCHEMA_VERSION,
            "generator": {"name": "whatsrisky", "version": __version__},
            "scan_id": self.scan_id,
            "status": self.status,
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
            "comparison": self.comparison,
            "counts_by_category": {
                cat: sum(1 for f in self.active_findings() if f.norm_category == cat)
                for cat in sorted({f.norm_category for f in self.active_findings()})
            },
            "counts_by_source": {
                src: sum(1 for f in self.active_findings() if f.source == src)
                for src in sorted({f.source for f in self.active_findings()})
            },
            "counts_by_status": {
                status: sum(1 for f in self.findings if f.status == status)
                for status in sorted({f.status for f in self.findings})
            },
            "risk_score": self.risk_score(),
            "verdict": self.verdict(),
            "counts": {s.value: n for s, n in self.counts().items()},
            "total_findings": len(self.findings),
            "active_findings": len(self.active_findings()),
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
