"""Design-system guard for the HTML viewer.

The same rules whydiff enforces on its viewer, for the same reason: the two
windows sit side by side, so a colour literal or a 12px label here shows up as an
inconsistency there. Ported from whydiff's tests/design.mjs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATE = Path("whatsrisky/report/templates/viewer.html")
RESET = "* { box-sizing: border-box; }"
# Shadows are for things that float above the page. Named explicitly, so adding
# one has to be a decision.
OVERLAY_SELECTORS: tuple[str, ...] = ()


@pytest.fixture(scope="module")
def template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def css(template: str) -> str:
    style = template.index("<style>")
    end = template.index("</style>", style)
    return template[style:end]


def test_colour_literals_live_only_in_the_token_block(css: str):
    assert RESET in css, "no reset marker, so the token block cannot be delimited"
    body = css[css.index(RESET):]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    stray = sorted(set(re.findall(r"#[0-9a-fA-F]{3,8}\b", body)))
    assert not stray, f"colour literal outside the token block: {stray} - use a token"
    assert not re.search(r":\s*(rgb|hsl)a?\(", body), "colour function outside the token block"


def test_radii_stay_small(css: str):
    radii = [float(v) for v in re.findall(r"border-radius:\s*([0-9.]+)px", css)]
    assert all(r <= 5 for r in radii), f"border-radius above 5px: {sorted(set(radii))}"


def test_type_never_goes_below_thirteen_px(css: str):
    sizes = [float(v) for v in re.findall(r"font-size:\s*([0-9.]+)px", css)]
    assert sizes, "no font sizes found - the selector changed"
    assert min(sizes) >= 13, f"font-size below 13px: {sorted(set(sizes))}"


def test_no_all_caps_and_no_serif(css: str):
    assert "text-transform: uppercase" not in css, "ALL CAPS label"
    assert not re.search(r"font-family:[^;]*\bserif\b(?!-)", css), "a serif family is not permitted"


def test_shadows_only_on_overlays(css: str):
    for rule in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        selector, body = rule[0].strip(), rule[1]
        if not re.search(r"box-shadow:\s*(?!none)", body):
            continue
        assert any(o in selector for o in OVERLAY_SELECTORS), f"shadow on a non-overlay: {selector}"


def test_severity_labels_are_not_shouted(template: str):
    """The data is uppercase; the interface must not be."""
    assert 'SEV_LABEL = { CRITICAL: "Critical"' in template
    assert "lower(f.severity), lower(f.severity)" not in template


def test_the_page_fetches_nothing(template: str):
    """Self-contained means self-contained: a report must render offline."""
    assert not re.search(r"<link[\s>]", template), "a <link> would fetch a stylesheet"
    assert not re.search(r"<script[^>]+src=", template), "a script src would fetch code"
    assert "@import" not in template
    assert not re.search(r"url\(\s*['\"]?https?:", template)
    assert "fonts.googleapis" not in template


def test_hidden_cannot_be_overridden(css: str):
    """A display rule beats the hidden attribute; that bug shipped once."""
    assert "[hidden] { display: none !important; }" in css


# --- the viewer as an artifact ----------------------------------------
def test_report_round_trips_through_the_page(tmp_path):
    """The page is both the view and the data: extracting the JSON must be exact."""
    import json

    from whatsrisky.models import Finding, ScanReport, Severity, ToolResult
    from whatsrisky.report.html_writer import extract_json, write_html

    report = ScanReport(
        project_path="/p", project_name="p", scan_id="p-1", started_at="now", finished_at="later"
    )
    report.tools = [ToolResult(name="semgrep", status="ok", version="1", command="semgrep .")]
    report.findings = [
        Finding(
            tool="semgrep", severity=Severity.CRITICAL, title="tainted sql string",
            rule_id="python.django.security.injection.tainted-sql-string", file="app.py", line=20,
            cwe=["CWE-915"], snippet=">    20 | cur.execute('...' % name)",
            description="A </script> tag and a \"quote\" in the data must not break the page.",
            references=["https://example.invalid/a"],
        )
    ]
    path = write_html(report, tmp_path / "r.html")
    page = path.read_text(encoding="utf-8")

    assert extract_json(page) == json.loads(json.dumps(report.to_dict()))
    # a literal </script> in the data would close the tag that carries it
    assert "</script>" not in page.split('id="report-data"')[1].split("<\\/script")[0]
    assert page.count("<script") == 2
    assert path.stat().st_size > 5000


def test_a_running_report_is_never_painted_clean():
    """Absence of findings while scanning is not safety - the rule this project lives by."""
    from whatsrisky.models import ScanReport, ToolResult

    report = ScanReport(project_path="/p", project_name="p", started_at="now")
    report.status = "running"
    report.tools = [ToolResult(name="semgrep", status="pending"), ToolResult(name="trivy", status="ok")]
    verdict = report.verdict()
    assert "CLEAN" not in verdict
    assert "IN PROGRESS" in verdict and "1 of 2" in verdict

    report.status = "partial"
    assert "INCONCLUSIVE" in report.verdict()

    report.status = "complete"
    assert "CLEAN" in report.verdict()


def test_a_verdict_never_outruns_its_coverage():
    """A headline read alone must not hide that scanners were missing."""
    from whatsrisky.models import Finding, ScanReport, Severity, ToolResult

    report = ScanReport(project_path="/p", project_name="p", started_at="now")
    report.findings = [Finding(tool="semgrep", severity=Severity.MEDIUM, title="debug enabled")]
    report.tools = [ToolResult(name="semgrep", status="ok"), ToolResult(name="trivy", status="missing")]
    report.status = "partial"
    verdict = report.verdict()
    assert verdict.startswith("MODERATE")
    assert "partial coverage" in verdict and "trivy" in verdict

    report.tools = [ToolResult(name="semgrep", status="ok")]
    report.status = "complete"
    assert report.verdict() == "MODERATE - plan remediation"


# --- the workflow is code too -----------------------------------------
def test_ci_pins_actions_to_commits_and_tools_to_versions():
    """A mutable tag or a `latest` download is an unreviewed change in a security tool.

    Also guards the mistake that broke the first CI run: a uv-managed interpreter
    refuses `uv pip install --system`, so every command must go through a venv.
    """
    import re

    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert not re.search(r"uses:\s+[^@\s]+@v\d", workflow), "an action is pinned to a mutable tag"
    for _, sha in re.findall(r"uses:\s+([^@\s]+)@(\S+)", workflow):
        sha = sha.split()[0]
        assert re.fullmatch(r"[0-9a-f]{40}", sha), f"not a commit SHA: {sha}"

    # Comments mention the flag to explain its absence, so look at the commands.
    commands = "\n".join(
        line for line in workflow.splitlines() if not line.lstrip().startswith("#")
    )
    assert "--system" not in commands, "uv pip install --system fails on a uv-managed interpreter"
    assert workflow.count("uv venv") >= 3, "each job needs its own environment"

    # Downloads must name a version, never `latest`.
    for url in re.findall(r"https://github\.com/\S+/releases/\S+", workflow):
        assert "latest" not in url, f"a latest download is not reproducible: {url}"
    assert 'SEMGREP_VERSION: "' in workflow, "the self-scan gate needs a pinned scanner"
    assert 'SELF_SCAN_RULES: "p/' in workflow, "and a pinned ruleset, or `auto` breaks it overnight"
