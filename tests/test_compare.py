"""Rescan correlation: what a scan fixed, what is new, what merely moved.

The failure this suite exists to prevent: code moving and being reported as
`resolved` + `new`, which turns every refactor into fake progress and fake
regressions.
"""

from __future__ import annotations

import json

from whatsrisky.compare import correlate, find_baseline, load_report
from whatsrisky.models import Finding, ScanReport, Severity, Status

RULE = "python.lang.security.audit.subprocess-shell-true"
CODE = 'return subprocess.check_output("ping -c 1 " + host, shell=True)'


def finding(file="src/app.py", line=6, rule=RULE, code=CODE, context=True, **kwargs):
    """A finding whose evidence is rendered the way read_snippet renders it."""
    if context:
        snippet = (
            "      4 | def ping(host):\n"
            f">     {line} |     {code}\n"
            "      7 | \n"
        )
    else:
        snippet = code
    return Finding(
        tool="semgrep", severity=Severity.HIGH, title="subprocess shell true",
        rule_id=rule, file=file, line=line, snippet=snippet, **kwargs
    )


def report(*findings, scan_id="scan-2"):
    rep = ScanReport(project_path="/p", project_name="p", scan_id=scan_id, started_at="now")
    rep.findings = list(findings)
    return rep


def baseline(*findings, scan_id="scan-1"):
    rep = report(*findings, scan_id=scan_id)
    return json.loads(json.dumps(rep.to_dict()))


def statuses(rep):
    return {(f.file, f.line): f.status for f in rep.findings}


# --- the core cases ---------------------------------------------------
def test_unchanged_rescan_reports_everything_open():
    current = report(finding(), finding(file="src/net.py", line=12, code="eval(x)"))
    comparison = correlate(current, baseline(finding(), finding(file="src/net.py", line=12, code="eval(x)")))
    assert all(f.status == Status.OPEN for f in current.findings)
    assert comparison.counts["new"] == 0 and comparison.counts["resolved"] == 0
    assert comparison.moved == 0
    assert all(f.first_seen == "scan-1" and f.last_seen == "scan-2" for f in current.findings)


def test_a_fix_is_resolved_and_stays_in_the_report():
    current = report(finding())
    correlate(current, baseline(finding(), finding(file="src/old.py", line=3, code="pickle.loads(d)")))
    assert len(current.findings) == 2, "the resolved finding must be carried over, not dropped"
    resolved = [f for f in current.findings if f.status == Status.RESOLVED]
    assert len(resolved) == 1 and resolved[0].file == "src/old.py"
    assert resolved[0].last_seen == "scan-1"       # last seen in the baseline, not now
    assert [f.status for f in current.findings if f.file == "src/app.py"] == [Status.OPEN]


def test_code_moving_down_the_file_stays_open():
    current = report(finding(line=42))
    comparison = correlate(current, baseline(finding(line=6)))
    assert [f.status for f in current.findings] == [Status.OPEN]
    assert current.findings[0].moved_from == "src/app.py:6"
    assert comparison.moved == 1
    assert comparison.counts["new"] == 0 and comparison.counts["resolved"] == 0


def test_code_moving_to_another_file_stays_open():
    """The regression that motivated this suite."""
    current = report(finding(file="src/net.py", line=5))
    comparison = correlate(current, baseline(finding(file="src/app.py", line=6)))
    assert [f.status for f in current.findings] == [Status.OPEN], statuses(current)
    assert current.findings[0].moved_from == "src/app.py:6"
    assert comparison.counts["resolved"] == 0 and comparison.counts["new"] == 0


def test_context_lines_do_not_decide_identity():
    """Same offending line, different neighbours - still the same finding."""
    before = Finding(
        tool="semgrep", severity=Severity.HIGH, title="t", rule_id=RULE, file="a.py", line=6,
        snippet="      4 | import os\n      5 | def ping(host):\n>     6 |     " + CODE + "\n",
    )
    after = Finding(
        tool="semgrep", severity=Severity.HIGH, title="t", rule_id=RULE, file="b.py", line=90,
        snippet="     88 | # unrelated comment\n     89 | def ping(host):\n>    90 |     " + CODE + "\n",
    )
    assert before.content_key == after.content_key


def test_reintroducing_a_fixed_finding_is_flagged():
    was_resolved = finding()
    was_resolved.status = Status.RESOLVED
    current = report(finding())
    correlate(current, baseline(was_resolved))
    assert [f.status for f in current.findings] == [Status.REINTRODUCED]


def test_an_accepted_finding_stays_accepted():
    accepted = finding()
    accepted.status = Status.ACCEPTED
    current = report(finding())
    correlate(current, baseline(accepted))
    assert [f.status for f in current.findings] == [Status.ACCEPTED]


def test_a_genuinely_new_finding_is_new():
    current = report(finding(), finding(file="src/new.py", line=1, code="os.system(cmd)"))
    comparison = correlate(current, baseline(finding()))
    assert statuses(current)[("src/new.py", 1)] == Status.NEW
    assert comparison.counts["new"] == 1


def test_two_findings_of_one_rule_do_not_swap_histories():
    """Ambiguous match_key must not correlate arbitrarily."""
    current = report(
        finding(line=10, code="os.system(a)"),
        finding(line=20, code="os.system(b)"),
    )
    correlate(current, baseline(finding(line=11, code="os.system(a)"), finding(line=21, code="os.system(b)")))
    moved = {f.line: f.moved_from for f in current.findings}
    assert moved[10] == "src/app.py:11"   # matched by its own evidence
    assert moved[20] == "src/app.py:21"


def test_dependency_findings_correlate_on_the_package():
    """No evidence to hash, so identity is the package - which is what it is."""
    def cve(line=None, file="requirements.txt"):
        return Finding(
            tool="trivy", severity=Severity.CRITICAL, title="PyYAML rce", rule_id="CVE-2020-14343",
            file=file, line=line, package="PyYAML", installed_version="3.13", category="Dependency/pip",
        )

    current = report(cve())
    comparison = correlate(current, baseline(cve()))
    assert [f.status for f in current.findings] == [Status.OPEN]
    assert comparison.counts["resolved"] == 0


# --- baseline discovery ----------------------------------------------
def test_find_baseline_picks_the_latest_and_ignores_strangers(tmp_path):
    assert find_baseline(tmp_path) is None
    (tmp_path / "not-ours.json").write_text('{"hello": "world"}', encoding="utf-8")
    assert find_baseline(tmp_path) is None, "a foreign JSON must not be used as a baseline"

    older = tmp_path / "a.json"
    older.write_text(json.dumps(baseline(finding())), encoding="utf-8")
    import os, time

    newer = tmp_path / "b.json"
    newer.write_text(json.dumps(baseline(finding(), scan_id="scan-9")), encoding="utf-8")
    os.utime(older, (time.time() - 60, time.time() - 60))
    assert find_baseline(tmp_path) == newer
    assert find_baseline(tmp_path, exclude={str(newer)}) == older
    assert load_report(tmp_path / "not-ours.json") is None


# --- the contract -----------------------------------------------------
def test_report_validates_against_the_published_schema(tmp_path):
    """The schema is a contract with other tools, so it is tested like one."""
    import pytest

    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path

    from whatsrisky.models import SCHEMA_VERSION

    schema = json.loads(Path("schema/report.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION, (
        "SCHEMA_VERSION and the published schema disagree"
    )

    current = report(finding(), finding(file="requirements.txt", rule="CVE-2020-14343"))
    current.tools = [__import__("whatsrisky.models", fromlist=["ToolResult"]).ToolResult(
        name="semgrep", status="ok", version="1.0", command="semgrep .", duration_s=1.0
    )]
    correlate(current, baseline(finding(), finding(file="gone.py", line=1, code="eval(x)")))
    document = json.loads(json.dumps(current.to_dict()))

    jsonschema.validate(document, schema)
    # and the parts the schema cannot express
    assert document["active_findings"] + document["counts_by_status"].get("resolved", 0) == len(
        document["findings"]
    )
    assert document["comparison"]["counts"]["resolved"] == 1
