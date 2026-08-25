"""gitleaks - hardcoded secrets in the working tree and in git history."""

from __future__ import annotations

import json
import re

from ..models import Finding, Severity
from ..util import pattern_to_regex, relative, run, run_streaming, truncate
from .base import Runner

TRIPLE = "'" * 3
# gitleaks logs as "11:07PM INF message"; only the message is worth showing.
_LOG_PREFIX = re.compile(r"^\d{1,2}:\d{2}(AM|PM)?\s+(INF|WRN|ERR|DBG|TRC)\s+", re.IGNORECASE)

# Rules that match on shape/entropy alone produce more false positives than
# provider-specific rules, so they land one notch lower.
_GENERIC_RULES = {
    "generic-api-key",
    "generic-api-token",
    "high-entropy-string",
    "jwt",
    "private-key",
}
_NON_PROD_HINT = re.compile(
    r"(^|/)(tests?|spec|specs|fixtures?|examples?|samples?|mocks?|__tests__|testdata)(/|$)"
    r"|\.(example|sample|template|dist|md|mdx|rst|txt)$",
    re.IGNORECASE,
)


class GitleaksRunner(Runner):
    name = "gitleaks"
    binary = "gitleaks"
    category = "Secret"
    install_hints = {
        "darwin": "brew install gitleaks",
        "linux": "download a release from https://github.com/gitleaks/gitleaks/releases",
        "windows": "scoop install gitleaks",
        "default": "https://github.com/gitleaks/gitleaks/releases",
    }

    def version(self) -> str:
        res = run([self.binary, "version"], timeout=30)
        raw = (res.stdout or res.stderr).strip().splitlines()
        return f"gitleaks {raw[0].strip()}" if raw else ""

    def _version_tuple(self) -> tuple[int, ...]:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", self.version())
        return tuple(int(g) for g in match.groups()) if match else (0, 0, 0)

    def _modes(self) -> list[str]:
        """Which gitleaks passes to run: working tree, git history, or both."""
        from ..util import is_git_repo

        if self.config.diff_range:
            return ["git"]  # only the commits in the range matter
        mode = self.config.gitleaks_mode
        if mode == "dir":
            return ["dir"]
        if mode == "git":
            return ["git"]
        return ["dir", "git"] if is_git_repo(self.config.target) else ["dir"]

    def _exclude_config(self) -> str:
        """gitleaks has no --exclude flag: paths are excluded through a config allowlist."""
        patterns = [p for p in (pattern_to_regex(x) for x in self.config.exclude) if p]
        if not patterns:
            return ""
        path = self.config.work_dir / "gitleaks-excludes.toml"
        lines = [
            "[extend]",
            "useDefault = true",
            "",
            "[[allowlists]]",
            'description = "whatsrisky excludes"',
            "paths = [",
        ]
        lines += ["  " + TRIPLE + p + TRIPLE + "," for p in patterns]
        lines.append("]")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def _argv(self, mode: str, report: str) -> list[str]:
        cfg = self.config
        modern = self._version_tuple() >= (8, 19, 0)
        common = [
            "--report-format",
            "json",
            "--report-path",
            report,
            "--exit-code",
            "0",
            "--no-banner",
            "--redact",
        ]
        scoped = ["--log-opts", cfg.diff_range] if (mode == "git" and cfg.diff_range) else []
        config_path = self._exclude_config()
        if config_path:
            scoped += ["--config", config_path]
        if modern:
            return [self.binary, mode, ".", *common, *scoped]
        argv = [self.binary, "detect", "--source", ".", *common, *scoped]
        if mode == "dir":
            argv.append("--no-git")
        return argv

    def scan(self):
        cfg = self.config
        findings: list[Finding] = []
        commands: list[str] = []
        stderr_all: list[str] = []
        seen: set[str] = set()

        for mode in self._modes():
            report = cfg.work_dir / f"gitleaks-{mode}.json"
            if report.exists():
                report.unlink()
            self.progress(f"scanning {'git history' if mode == 'git' else 'working tree'}")
            res = run_streaming(
                self._argv(mode, str(report)),
                cwd=cfg.target,
                timeout=cfg.gitleaks_timeout,
                on_stderr=lambda line: self.progress(_LOG_PREFIX.sub("", line.strip())),
            )
            commands.append(res.command)
            stderr_all.append(res.stderr)
            if not report.exists():
                if res.returncode not in (0, 1):
                    stderr_all.append(f"[whatsrisky] gitleaks {mode} exit {res.returncode}")
                continue
            text = report.read_text(encoding="utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                entries = json.loads(text)
            except ValueError as exc:
                stderr_all.append(f"[whatsrisky] unparsable gitleaks {mode} report: {exc}")
                continue
            for item in entries or []:
                finding = self._to_finding(item, mode)
                key = finding.fingerprint
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        if not commands:
            raise RuntimeError("gitleaks did not run")
        return findings, " && ".join(commands), "\n".join(stderr_all)

    def _to_finding(self, item: dict, mode: str) -> Finding:
        rule = item.get("RuleID", "")
        rel = relative(item.get("File", ""), self.config.target)
        severity = Severity.CRITICAL
        if rule in _GENERIC_RULES:
            severity = Severity.HIGH
        if rel and _NON_PROD_HINT.search(rel):
            severity = Severity.HIGH if severity is Severity.CRITICAL else Severity.MEDIUM

        commit = item.get("Commit", "")
        where = "git history" if commit else "working tree"
        detail = [
            f"gitleaks rule `{rule}` matched a likely credential in the {where}.",
            f"Description: {item.get('Description', '')}",
        ]
        if commit:
            detail.append(
                f"Commit {commit[:12]} by {item.get('Author', '?')} <{item.get('Email', '?')}> "
                f"on {item.get('Date', '?')}"
            )
        if item.get("Entropy"):
            detail.append(f"Entropy: {item['Entropy']}")

        return Finding(
            tool=self.name,
            severity=severity,
            title=truncate(f"Hardcoded secret: {rule or 'unknown rule'}", 140),
            description="\n".join(d for d in detail if d.strip()),
            category="Secret" + ("/git-history" if commit else "/working-tree"),
            rule_id=rule,
            file=rel,
            line=item.get("StartLine") or None,
            end_line=item.get("EndLine") or None,
            cwe=["CWE-798"],
            remediation=(
                "1) Treat the credential as compromised and rotate it at the provider. "
                "2) Remove it from the source and load it from a secret manager/env var. "
                "3) If it is in git history, purge it (git filter-repo / BFG) and force-push. "
                "4) Add a pre-commit gitleaks hook to prevent recurrence."
            ),
            snippet=truncate(item.get("Match", ""), 240),
            pass_name=mode,
            raw={"mode": mode, "commit": commit, "fingerprint": item.get("Fingerprint", "")},
        )
