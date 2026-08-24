"""Trivy - dependency CVEs, IaC misconfiguration and (optionally) secrets."""

from __future__ import annotations

import json

from ..models import Finding, Severity
from ..util import read_snippet, relative, run_streaming, truncate
from .base import Runner


class TrivyRunner(Runner):
    scope_note = ""
    name = "trivy"
    binary = "trivy"
    category = "Dependency/IaC"
    install_hints = {
        "darwin": "brew install trivy",
        "linux": "see https://trivy.dev/latest/getting-started/installation/",
        "windows": "scoop install trivy  (or winget install AquaSecurity.Trivy)",
        "default": "https://trivy.dev/latest/getting-started/installation/",
    }

    def version(self) -> str:
        from ..util import tool_version

        return tool_version(self.binary, ["--version"])

    def scan(self):
        cfg = self.config
        out_file = cfg.work_dir / "trivy.json"
        argv = [
            self.binary,
            "fs",
            "--scanners",
            cfg.trivy_scanners,
            "--format",
            "json",
            "--output",
            str(out_file),
            "--exit-code",
            "0",
        ]
        if cfg.trivy_offline:
            argv += ["--offline-scan", "--skip-db-update", "--skip-java-db-update"]
        for pattern in cfg.exclude:
            argv += ["--skip-dirs", pattern.rstrip("/")]
        argv.append(".")

        res = run_streaming(
            argv, cwd=cfg.target, timeout=cfg.trivy_timeout, on_stderr=self._report_line
        )
        if cfg.diff_range:
            # A dependency CVE is a property of the manifest, not of the diff: a lockfile
            # untouched by this range can still be vulnerable. Scanning the whole tree is
            # the honest choice, and the report says so.
            self.scope_note = (
                f"trivy ignored --diff {cfg.diff_range}: dependency and IaC findings are "
                "properties of the whole manifest, not of the changed lines."
            )
        if not out_file.exists():
            raise RuntimeError(
                f"trivy wrote no report (exit {res.returncode}): {(res.stderr or res.stdout)[-400:].strip()}"
            )
        try:
            data = json.loads(out_file.read_text(encoding="utf-8", errors="replace") or "{}")
        except ValueError as exc:
            raise RuntimeError(f"trivy report is not valid JSON: {exc}") from exc

        findings: list[Finding] = []
        for result in data.get("Results") or []:
            target = relative(result.get("Target", ""), cfg.target)
            pkg_type = result.get("Type", "")
            findings += self._vulns(result, target, pkg_type)
            findings += self._misconfigs(result, target)
            findings += self._secrets(result, target)
        return findings, res.command, res.stderr

    def run(self):
        result = super().run()
        if result.ok and self.scope_note:
            result.message = self.scope_note
        return result

    # --- sections -----------------------------------------------------
    def _report_line(self, line: str) -> None:
        if any(level in line for level in ("\tINFO\t", "\tWARN\t", "\tERROR\t")):
            self.progress(_trivy_message(line))

    def _vulns(self, result: dict, target: str, pkg_type: str) -> list[Finding]:
        out = []
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            installed = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            remediation = (
                f"Upgrade {pkg} from {installed} to {fixed} or later."
                if fixed
                else f"No fixed version published yet for {pkg} {installed}. "
                "Evaluate mitigations, pin an alternative, or accept the risk explicitly."
            )
            out.append(
                Finding(
                    tool=self.name,
                    severity=Severity.parse(v.get("Severity"), Severity.MEDIUM),
                    title=truncate(v.get("Title") or f"{vid} in {pkg}", 140),
                    description=truncate(v.get("Description", ""), 3000),
                    category=f"Dependency/{pkg_type}" if pkg_type else "Dependency",
                    rule_id=vid,
                    file=relative(v.get("PkgPath") or target, self.config.target),
                    cwe=[str(c) for c in (v.get("CweIDs") or [])],
                    references=[r for r in (v.get("References") or [])][:5],
                    remediation=remediation,
                    package=pkg,
                    installed_version=installed,
                    fixed_version=fixed,
                    cvss=_cvss(v),
                    raw={"primary_url": v.get("PrimaryURL", "")},
                )
            )
        return out

    def _misconfigs(self, result: dict, target: str) -> list[Finding]:
        out = []
        for m in result.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            line = cause.get("StartLine") or None
            out.append(
                Finding(
                    tool=self.name,
                    severity=Severity.parse(m.get("Severity"), Severity.MEDIUM),
                    title=truncate(m.get("Title") or m.get("ID", "Misconfiguration"), 140),
                    description=truncate(
                        (m.get("Description") or "") + "\n\n" + (m.get("Message") or ""), 3000
                    ),
                    category=f"Misconfiguration/{m.get('Type', '')}".rstrip("/"),
                    rule_id=m.get("AVDID") or m.get("ID", ""),
                    file=target,
                    line=line,
                    end_line=cause.get("EndLine") or None,
                    references=[r for r in (m.get("References") or [])][:5],
                    remediation=truncate(m.get("Resolution", ""), 1200),
                    snippet=read_snippet(self.config.target, target, line),
                )
            )
        return out

    def _secrets(self, result: dict, target: str) -> list[Finding]:
        out = []
        for s in result.get("Secrets") or []:
            line = s.get("StartLine") or None
            out.append(
                Finding(
                    tool=self.name,
                    severity=Severity.parse(s.get("Severity"), Severity.CRITICAL),
                    title=truncate(f"Secret: {s.get('Title') or s.get('RuleID', '')}", 140),
                    description=(
                        f"Trivy secret rule `{s.get('RuleID', '')}` "
                        f"({s.get('Category', '')}) matched in {target}."
                    ),
                    category="Secret",
                    rule_id=s.get("RuleID", ""),
                    file=target,
                    line=line,
                    end_line=s.get("EndLine") or None,
                    remediation=(
                        "Revoke and rotate the credential at the provider, purge it from the file "
                        "and from git history, then load it from a secret manager or environment."
                    ),
                    snippet=truncate(s.get("Match", ""), 300),
                )
            )
        return out


def _trivy_message(line: str) -> str:
    """Strip the timestamp and level from a trivy log line, keep the rest."""
    parts = [p.strip() for p in line.split("\t")]
    if len(parts) >= 3:
        return " ".join(p for p in parts[2:] if p)
    return line.strip()


def _cvss(v: dict) -> str:
    cvss = v.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(source) or {}
        score = entry.get("V3Score") or entry.get("V2Score")
        if score:
            return f"{score} ({source.upper()})"
    return ""
