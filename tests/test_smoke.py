"""Smoke tests: severity mapping, LLM-JSON repair, and report writing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from whatsrisky.models import Finding, ScanReport, Severity, ToolResult
from whatsrisky.report import write_docx, write_markdown
from whatsrisky.util import clean_text, extract_json, repair_json_text


def test_severity_parse_and_order():
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.parse("unknown") is Severity.INFO
    assert Severity.parse(None, Severity.MEDIUM) is Severity.MEDIUM
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank


def test_json_repair_handles_llm_slips():
    assert extract_json('{"line": 15-38, "a": 1}') == {"line": 15, "a": 1}
    assert extract_json('{"a": [1, 2,],}') == {"a": [1, 2]}
    assert extract_json('{"a": None}') == {"a": None}
    assert extract_json('noise before ```json\n{"a": 1}\n``` noise after') == {"a": 1}
    assert extract_json("not json at all") is None
    assert repair_json_text('{"line": 4–12}') == '{"line": 4}'


def test_clean_text_strips_control_and_ansi():
    assert clean_text("\x1b[32mINF\x1b[0m ok") == "INF ok"
    assert "\x00" not in clean_text("a\x00b")
    assert clean_text("a\r\nb") == "a\nb"


def test_finding_sanitizes_and_fingerprints():
    finding = Finding(
        tool="semgrep",
        severity=Severity.HIGH,
        title="tainted\x00sql",
        file="app.py",
        line=20,
    )
    assert "\x00" not in finding.title
    assert finding.location == "app.py:20"
    assert len(finding.fingerprint) == 12


def _report() -> ScanReport:
    findings = [
        Finding(
            tool="trivy",
            severity=Severity.CRITICAL,
            title="PyYAML arbitrary code execution",
            description="yaml.load() executes arbitrary code.",
            category="Dependency/pip",
            rule_id="CVE-2020-14343",
            file="requirements.txt",
            package="PyYAML",
            installed_version="3.13",
            fixed_version="5.4",
            cwe=["CWE-20"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
            remediation="Upgrade PyYAML to 5.4.",
        ),
        Finding(
            tool="semgrep",
            severity=Severity.MEDIUM,
            title="tainted sql string",
            description="User input reaches a raw SQL string.",
            file="app.py",
            line=20,
            snippet="> 20 | cur.execute(\"...%s\" % name)",
        ),
    ]
    report = ScanReport(
        project_path="/tmp/vulnapp",
        project_name="vulnapp",
        started_at="2026-01-01 00:00:00",
        finished_at="2026-01-01 00:00:10",
        duration_s=10.0,
        git_branch="main",
        git_commit="abc1234",
    )
    report.tools = [
        ToolResult(name="trivy", findings=[findings[0]], version="0.74.0", command="trivy fs ."),
        ToolResult(name="semgrep", findings=[findings[1]], version="1.174.0", command="semgrep scan ."),
        ToolResult(name="gitleaks", status="missing", message="not installed"),
    ]
    report.findings = findings
    return report


def test_counts_and_verdict():
    report = _report()
    counts = report.counts()
    assert counts[Severity.CRITICAL] == 1 and counts[Severity.MEDIUM] == 1
    assert report.verdict().startswith("CRITICAL")
    assert 0 < report.risk_score() <= 100
    assert report.sorted_findings()[0].severity is Severity.CRITICAL
    assert json.loads(json.dumps(report.to_dict()))["counts"]["CRITICAL"] == 1


def test_writers_produce_files(tmp_path: Path):
    report = _report()
    docx = write_docx(report, tmp_path / "r.docx")
    md = write_markdown(report, tmp_path / "r.md")
    assert docx.exists() and docx.stat().st_size > 5000
    text = md.read_text()
    assert "CRITICAL" in text and "PyYAML" in text and "vulnapp" in text

    from docx import Document

    body = "\n".join(p.text for p in Document(str(docx)).paragraphs)
    assert "Security Assessment Report" in body
    assert "CRIT-01" in body
    assert "gitleaks" in body  # coverage gap must be reported


# --- options, profiles, UI --------------------------------------------
def test_options_command_line_roundtrip():
    from whatsrisky.core import ScanOptions

    opts = ScanOptions(
        path="/tmp/p", tools=["semgrep", "trivy"], model="sonnet", claude_mode="review",
        min_severity="HIGH", fail_on="high", exclude=["node_modules"], jobs=2,
    )
    cmd = opts.command_line()
    for fragment in ("--tools semgrep,trivy", "--min-severity HIGH", "--fail-on high",
                     "--exclude node_modules", "--jobs 2"):
        assert fragment in cmd
    # claude flags are omitted when claude is not selected
    assert "--model" not in cmd and "--claude-mode" not in cmd
    assert ScanOptions.from_json(opts.to_json()) == opts


def test_offline_normalization_and_validation():
    from whatsrisky.core import ScanOptions, validate

    opts = ScanOptions(path="/definitely/not/here", offline=True).normalized()
    assert opts.semgrep_configs == ["p/security-audit"]  # `auto` needs the registry
    assert any("Not a directory" in p for p in validate(opts))
    assert validate(ScanOptions(path=".", tools=[]))
    assert validate(ScanOptions(path=".", formats=[]))
    assert not validate(ScanOptions(path="."))


def test_profiles_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    from whatsrisky import settings
    from whatsrisky.core import ScanOptions

    assert settings.profile_names() == []
    opts = ScanOptions(path="/tmp/p", model="sonnet", fail_on="high")
    settings.save_profile("ci", opts)
    settings.save_last(opts)
    assert settings.profile_names() == ["ci"]
    assert settings.load_profile("ci") == opts
    assert settings.load_last() == opts
    assert settings.delete_profile("ci") and not settings.delete_profile("ci")


def test_ui_collects_and_previews(tmp_path, monkeypatch):
    import asyncio

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    from textual.widgets import Checkbox, Select

    from whatsrisky.core import ScanOptions
    from whatsrisky.ui import WhatsriskyApp, SettingsScreen

    async def drive():
        app = WhatsriskyApp(ScanOptions(path=str(tmp_path)))
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SettingsScreen)
            screen.query_one("#tool-claude", Checkbox).value = False
            screen.query_one("#min-severity", Select).value = "HIGH"
            await pilot.pause()
            collected = screen.collect()
            assert "claude" not in collected.tools
            assert collected.min_severity == "HIGH"
            assert "--min-severity HIGH" in str(screen.query_one("#cmd-panel").content)
            screen.apply(ScanOptions(path=str(tmp_path), model="claude-opus-5", fail_on="high"))
            await pilot.pause()
            reloaded = screen.collect()
            assert reloaded.model == "claude-opus-5"  # custom model id survives the round trip
            assert reloaded.fail_on == "high"

    asyncio.run(drive())


# --- exclusions -------------------------------------------------------
def test_path_excluded_semantics():
    from whatsrisky.util import path_excluded, pattern_to_regex

    assert path_excluded("node_modules/pkg/a.js", ["node_modules"])
    assert path_excluded("src/node_modules/a.js", ["node_modules"])  # any depth
    assert not path_excluded("src/app.py", ["node_modules"])
    assert path_excluded("src/generated/api.py", ["src/generated"])  # subtree
    assert not path_excluded("src/generated_other/api.py", ["src/generated"])
    assert path_excluded("dist/app.min.js", ["*.min.js"])  # glob
    assert not path_excluded("src/app.js", ["*.min.js"])
    assert path_excluded("vendor/lib/x.go", ["vendor/"])  # trailing slash tolerated
    assert not path_excluded("", ["vendor"])
    # gitleaks needs Go-compatible regexes, not Python's fnmatch translation
    assert pattern_to_regex("node_modules") == "(^|/)node_modules(/|$)"
    assert "[^/]*" in pattern_to_regex("*.min.js")
    assert pattern_to_regex("") == ""


def test_effective_excludes_and_flag():
    from whatsrisky.core import DEFAULT_EXCLUDES, ScanOptions

    opts = ScanOptions(path=".", exclude=["mydir", "node_modules"])
    effective = opts.effective_excludes()
    assert "mydir" in effective
    assert effective.count("node_modules") == 1  # de-duplicated against the defaults
    assert len(effective) > len(DEFAULT_EXCLUDES) - 1

    bare = ScanOptions(path=".", exclude=["mydir"], use_default_excludes=False)
    assert bare.effective_excludes() == ["mydir"]
    assert "--no-default-excludes" in bare.command_line()
    assert "--exclude mydir" in bare.command_line()


def test_own_output_is_never_scanned(tmp_path):
    from whatsrisky.core import OUTPUT_MARKER, _self_output_excludes

    target = tmp_path / "project"
    (target / "src").mkdir(parents=True)
    old_reports = target / "old-reports"
    old_reports.mkdir()
    (old_reports / OUTPUT_MARKER).write_text("x", encoding="utf-8")
    out_dir = target / "reports"
    out_dir.mkdir()

    excludes = _self_output_excludes(target, out_dir, out_dir / ".work-x")
    assert "reports" in excludes           # this run's output
    assert "old-reports" in excludes       # a previous run's, found by its marker
    assert "src" not in excludes           # ordinary directories are untouched

    # Output written outside the target adds nothing, but marker-bearing directories
    # inside it are still skipped - that is what keeps old reports out of a rescan.
    outside = _self_output_excludes(target, tmp_path / "elsewhere")
    assert outside == ["old-reports"]


# --- progress ---------------------------------------------------------
def test_progress_model_tracks_tools():
    from whatsrisky.progress import ProgressModel

    model = ProgressModel()
    model.handle("info", {"message": "scanning /x", "tools": ["semgrep"]})
    model.handle("tool_start", {"tool": "semgrep"})
    assert model.running
    model.handle("tool_progress", {"tool": "semgrep", "message": "Scanning 412 files"})
    assert model.rows["semgrep"]["message"] == "Scanning 412 files"
    assert model.elapsed("semgrep") >= 0

    model.handle("tool_done", {"tool": "semgrep", "status": "ok", "findings": 7, "duration": 2.5})
    assert not model.running
    assert "7 findings" in model.line("semgrep")
    assert model.elapsed("semgrep") == 2.5
    # unknown tools must not raise: events can arrive for a runner that never started
    model.handle("tool_progress", {"tool": "ghost", "message": "hi"})
    assert "ghost" not in model.rows

    table = model.render_table()
    assert table.row_count == 1


def test_run_streaming_reports_lines(tmp_path):
    from whatsrisky.util import run_streaming

    lines: list[str] = []
    script = "import sys; print('to stdout'); print('step 1', file=sys.stderr); print('step 2', file=sys.stderr)"
    res = run_streaming(
        [sys.executable, "-c", script], timeout=30, on_stderr=lines.append
    )
    assert res.returncode == 0
    assert lines == ["step 1", "step 2"]      # streamed, in order
    assert "to stdout" in res.stdout

    out_file = tmp_path / "out.txt"
    res = run_streaming(
        [sys.executable, "-c", "print('captured')"], timeout=30, stdout_path=out_file
    )
    assert out_file.read_text().strip() == "captured"

    res = run_streaming([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert res.timed_out and res.returncode == 124

    assert run_streaming(["definitely-not-a-real-binary-xyz"]).returncode == 127
