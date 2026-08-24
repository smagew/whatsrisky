"""Integration tests: each runner against the real scanner binary.

These are the tests that catch a scanner changing its JSON shape. They skip
when the binary is absent, so the unit suite still runs anywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from whatsrisky.core import ScanOptions, build_scan_config, run_scan
from whatsrisky.models import Severity
from whatsrisky.runners import GitleaksRunner, SemgrepRunner, TrivyRunner


def requires(binary: str) -> None:
    import shutil

    if not shutil.which(binary):
        pytest.skip(f"{binary} is not installed")

pytestmark = pytest.mark.integration


def _config(vulnapp: Path, tmp_path: Path, **kwargs):
    options = ScanOptions(path=str(vulnapp), **kwargs)
    return build_scan_config(options, vulnapp, tmp_path, kwargs.get("scope_paths"))


def test_semgrep_finds_injection(vulnapp, tmp_path):
    requires("semgrep")
    result = SemgrepRunner(_config(vulnapp, tmp_path, semgrep_configs=["p/security-audit"])).run()
    assert result.status == "ok", result.message
    assert result.findings, "semgrep found nothing in a deliberately vulnerable app"
    for finding in result.findings:
        assert finding.severity in tuple(Severity)
        assert finding.rule_id and finding.file
    titles = " ".join(f.title.lower() for f in result.findings)
    assert any(word in titles for word in ("sql", "subprocess", "shell", "pickle", "debug"))


def test_trivy_finds_vulnerable_dependency(vulnapp, tmp_path):
    requires("trivy")
    result = TrivyRunner(_config(vulnapp, tmp_path)).run()
    assert result.status == "ok", result.message
    packages = {f.package for f in result.findings if f.package}
    assert packages & {"PyYAML", "Flask", "Jinja2", "requests"}, packages
    fixable = [f for f in result.findings if f.fixed_version]
    assert fixable and all("Upgrade" in f.remediation for f in fixable)


def test_gitleaks_finds_secret(vulnapp, tmp_path):
    requires("gitleaks")
    result = GitleaksRunner(_config(vulnapp, tmp_path)).run()
    assert result.status == "ok", result.message
    assert result.findings, "gitleaks found no secret in a file full of them"
    assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)
    assert all("CWE-798" in f.cwe for f in result.findings)
    assert all("rotate" in f.remediation.lower() for f in result.findings)


def test_diff_scoping_narrows_the_scan(vulnapp, tmp_path):
    requires("semgrep")
    whole = run_scan(
        ScanOptions(
            path=str(vulnapp), tools=["semgrep"], formats=["json"],
            out_dir=str(tmp_path / "whole"), semgrep_configs=["p/security-audit"],
        )
    )
    scoped = run_scan(
        ScanOptions(
            path=str(vulnapp), tools=["semgrep"], formats=["json"], diff="HEAD~1..HEAD",
            out_dir=str(tmp_path / "scoped"), semgrep_configs=["p/security-audit"],
        )
    )
    assert scoped.report.scope_paths == ["upload.py"]
    assert len(scoped.report.findings) < len(whole.report.findings)
    assert all(f.file == "upload.py" for f in scoped.report.findings if f.file)


def test_full_scan_writes_every_format(vulnapp, tmp_path):
    requires("gitleaks")
    outcome = run_scan(
        ScanOptions(
            path=str(vulnapp), tools=["gitleaks"], formats=["docx", "md", "json"],
            out_dir=str(tmp_path), fail_on="high",
        )
    )
    suffixes = sorted(p.suffix for p in outcome.written)
    assert suffixes == [".docx", ".json", ".md"]
    assert all(p.exists() and p.stat().st_size > 500 for p in outcome.written)
    assert outcome.exit_code == 2  # secrets are CRITICAL, so --fail-on high must trip
