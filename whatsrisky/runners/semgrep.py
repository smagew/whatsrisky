"""Semgrep - static analysis (SAST) of first-party source code."""

from __future__ import annotations

import json

from ..models import Finding, Severity
from ..util import read_snippet, relative, run, truncate
from .base import Runner

# Semgrep speaks ERROR/WARNING/INFO (and CRITICAL/HIGH/... in newer versions).
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


class SemgrepRunner(Runner):
    name = "semgrep"
    binary = "semgrep"
    category = "SAST"
    install_hints = {
        "darwin": "brew install semgrep",
        "linux": "pipx install semgrep  (or: pip install semgrep)",
        "windows": "pipx install semgrep  (WSL recommended)",
        "default": "pipx install semgrep",
    }

    def version(self) -> str:
        from ..util import tool_version

        return f"semgrep {tool_version(self.binary)}"

    def _argv(self) -> list[str]:
        cfg = self.config
        argv = [self.binary, "scan", "--json", "--quiet", "--timeout", "60", "--max-target-bytes", "2000000"]
        uses_auto = any(c == "auto" for c in cfg.semgrep_configs)
        # `--config auto` needs metrics enabled; everything else runs fully offline.
        argv += ["--metrics", "auto" if uses_auto else "off"]
        for conf in cfg.semgrep_configs:
            argv += ["--config", conf]
        for pattern in cfg.exclude:
            argv += ["--exclude", pattern]
        # A diff-scoped run passes the changed files explicitly instead of the tree.
        argv += cfg.scope_paths or ["."]
        return argv

    def scan(self):
        cfg = self.config
        argv = self._argv()
        res = run(argv, cwd=cfg.target, timeout=cfg.semgrep_timeout)
        data = None
        if res.stdout.strip():
            try:
                data = json.loads(res.stdout)
            except ValueError:
                data = None
        if data is None:
            raise RuntimeError(
                f"semgrep produced no parsable JSON (exit {res.returncode}): "
                f"{(res.stderr or res.stdout)[-400:].strip()}"
            )

        findings: list[Finding] = []
        for item in data.get("results", []):
            extra = item.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            severity = _SEV.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
            # A high-impact, high-confidence ERROR rule is a genuine critical.
            if severity is Severity.HIGH and str(meta.get("impact", "")).upper() == "HIGH":
                if str(meta.get("confidence", "")).upper() in ("HIGH", ""):
                    severity = Severity.CRITICAL

            rel = relative(item.get("path", ""), cfg.target)
            line = (item.get("start") or {}).get("line")
            rule_id = item.get("check_id", "")
            message = truncate(extra.get("message", ""), 4000)
            fix = extra.get("fix") or ""
            remediation = f"Suggested fix:\n{fix}" if fix else ""
            if meta.get("shortlink"):
                remediation = (remediation + f"\nRule docs: {meta['shortlink']}").strip()

            snippet = extra.get("lines") or ""
            if not snippet.strip() or snippet.strip() == "requires login":
                snippet = read_snippet(cfg.target, rel, line)

            findings.append(
                Finding(
                    tool=self.name,
                    severity=severity,
                    title=_title(rule_id, message),
                    description=message,
                    category=_category(meta),
                    rule_id=rule_id,
                    file=rel,
                    line=line,
                    end_line=(item.get("end") or {}).get("line"),
                    cwe=_as_list(meta.get("cwe")),
                    owasp=_as_list(meta.get("owasp")),
                    references=_as_list(meta.get("references"))[:5],
                    remediation=remediation,
                    confidence=str(meta.get("confidence", "")),
                    snippet=snippet.strip()[:1500],
                    raw={"technology": _as_list(meta.get("technology"))},
                )
            )
        return findings, res.command, res.stderr


def _title(rule_id: str, message: str) -> str:
    short = rule_id.split(".")[-1].replace("-", " ").replace("_", " ").strip()
    if short:
        return short[:120]
    return truncate(message, 120)


def _category(meta: dict) -> str:
    cat = str(meta.get("category", "")).strip()
    return f"SAST/{cat}" if cat else "SAST"


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]
