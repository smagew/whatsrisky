#!/usr/bin/env python3
"""Emit what the Python implementation computes, for the Go port to be tested against.

The rewrite (docs/go-rewrite.md) treats the Python code as the specification. These
files are the specification in machine-readable form: identity keys have to match
digit for digit, because a Go scan must be able to correlate against a baseline a
Python scan wrote.

Run through `make parity` and read the diff: any change here is a compatibility
break, whether or not it was intended.
"""

from __future__ import annotations

import json
from pathlib import Path

from whatsrisky import categories
from whatsrisky.compare import correlate
from whatsrisky.models import (
    SEVERITY_ORDER,
    Finding,
    ScanReport,
    Severity,
    Status,
    evidence_of,
    infer_source,
)

OUT = Path("testdata/parity")

FINDING_CASES = [
    dict(tool="semgrep", severity="HIGH", title="tainted sql string",
         rule_id="python.django.security.injection.tainted-sql-string", file="app.py", line=20,
         cwe=["CWE-915"], snippet="      4 | def get(n):\n>    20 |     cur.execute('...' % n)\n"),
    dict(tool="semgrep", severity="HIGH", title="tainted sql string",
         rule_id="python.django.security.injection.tainted-sql-string", file="handlers/app.py", line=88,
         cwe=["CWE-915"], snippet="     86 | # moved here\n>    88 |   cur.execute('...' % n)\n"),
    dict(tool="trivy", severity="CRITICAL", title="PyYAML: yaml.load() rce",
         rule_id="CVE-2020-14343", file="requirements.txt", package="PyYAML",
         installed_version="3.13", fixed_version="5.4", category="Dependency/pip", cwe=["CWE-20"]),
    dict(tool="gitleaks", severity="CRITICAL", title="Hardcoded secret: github-pat",
         rule_id="github-pat", file="Dockerfile", line=5, cwe=["CWE-798"],
         category="Secret/working-tree", pass_name="dir", snippet="REDACTED"),
    dict(tool="gitleaks", severity="HIGH", title="Hardcoded secret: generic-api-key",
         rule_id="generic-api-key", file="tests/fixtures/app.py", line=12,
         category="Secret/git-history", pass_name="git"),
    dict(tool="ai", severity="CRITICAL", title="OS command injection via shell=True",
         rule_id="ai:full", file="app.py", line=27, cwe=["CWE-78"], category="AI/Injection",
         provider="openai", model="gpt-5", pass_name="full"),
    dict(tool="semgrep", severity="MEDIUM", title="last user is root",
         rule_id="dockerfile.security.last-user-is-root.last-user-is-root", file="Dockerfile",
         line=2, cwe=["CWE-269"], category="SAST/security"),
    dict(tool="semgrep", severity="MEDIUM", title="github actions mutable action tag",
         rule_id="yaml.github-actions.security.mutable-action-tag", file=".github/workflows/ci.yml",
         line=18, category="SAST/security"),
    dict(tool="semgrep", severity="MEDIUM", title="dynamic urllib use detected",
         rule_id="python.lang.security.audit.dynamic-urllib-use-detected", file="ai/openai_api.py",
         line=99, category="SAST/security"),
    dict(tool="trivy", severity="MEDIUM", title="Secrets in build args",
         rule_id="AVD-DS-0031", file="Dockerfile", line=5, category="Misconfiguration/dockerfile",
         pass_name="misconfig"),
]

CLASSIFY_CASES = [
    (["CWE-89"], "SAST", "x", "y", "source-code"),
    (["CWE-915"], "SAST", "python.django.security.injection.tainted-sql-string", "t", "source-code"),
    ([], "Dependency/pip", "CVE-1", "PyYAML rce", "dependency-manifest"),
    ([], "SAST", "dockerfile.security.last-user-is-root", "last user is root", "container"),
    ([], "SAST", "detected-github-token", "detected github token", "container"),
    ([], "SAST", "yaml.github-actions.security.mutable-action-tag", "mutable tag", "ci-config"),
    ([], "SAST", "python.lang.security.audit.dynamic-urllib-use-detected", "dynamic urllib", "source-code"),
    (["CWE-327"], "SAST", "insecure-hash-algorithm-sha1", "sha1", "source-code"),
    ([], "SAST", "unknown-rule-xyz", "something odd", "source-code"),
    ([], "Secret/working-tree", "github-pat", "secret", "source-code"),
]

SOURCE_CASES = [
    ("gitleaks", "git", "a.py"), ("gitleaks", "dir", "a.py"),
    ("trivy", "vuln", "requirements.txt"), ("trivy", "misconfig", "Dockerfile"),
    ("trivy", "misconfig", "main.tf"), ("trivy", "misconfig", "k8s/deploy.yaml"),
    ("semgrep", "code", ".github/workflows/ci.yml"), ("semgrep", "code", "src/app.py"),
    ("ai", "full", "docker-compose.yml"),
]

RISK_CASES = [
    {}, {"INFO": 1}, {"LOW": 1}, {"MEDIUM": 1}, {"HIGH": 1}, {"CRITICAL": 1},
    {"CRITICAL": 4, "HIGH": 19, "MEDIUM": 16, "LOW": 2},
    {"LOW": 100}, {"MEDIUM": 40}, {"CRITICAL": 10}, {"HIGH": 12},
    {"INFO": 7, "LOW": 3}, {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
]

RULE = "python.lang.security.audit.subprocess-shell-true"
CODE = 'return subprocess.check_output("ping -c 1 " + host, shell=True)'


def write(name: str, payload) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"  {OUT / name}")


def findings() -> None:
    out = []
    for case in FINDING_CASES:
        kwargs = dict(case)
        kwargs["severity"] = Severity.parse(case["severity"])
        finding = Finding(**kwargs)
        out.append({
            "input": case,
            "expect": {
                "severity": finding.severity.value,
                "category": finding.norm_category,
                "category_label": finding.category_label,
                "source": finding.source,
                "fingerprint": finding.fingerprint,
                "content_key": finding.content_key,
                "match_key": finding.match_key,
                "location": finding.location,
            },
        })
    write("findings.json", out)


def taxonomy() -> None:
    write("categories.json", {
        "labels": {c: categories.label(c) for c in categories.VOCABULARY},
        "cwe": {str(k): v for k, v in sorted(categories.CWE_TO_CATEGORY.items())},
        "classify": [
            {"cwe": c, "native": n, "rule": r, "title": t, "source": s,
             "expect": categories.classify(cwe=c, native_category=n, rule_id=r, title=t, source=s)}
            for c, n, r, t, s in CLASSIFY_CASES
        ],
    })


def severity() -> None:
    write("severity.json", {
        "order": [s.value for s in SEVERITY_ORDER],
        "weights": {s.value: s.weight for s in Severity},
        "parse": {raw: Severity.parse(raw).value for raw in
                  ["CRITICAL", "critical", "ERROR", "error", "HIGH", "WARNING", "warn", "MEDIUM",
                   "moderate", "LOW", "minor", "note", "INFO", "unknown", "none", "", "nonsense"]},
        "evidence": {
            "marked": evidence_of("      4 | import os\n>     6 |   run(cmd, shell=True)\n"),
            "unmarked": evidence_of("def f():\n    return 1"),
            "empty": evidence_of(""),
        },
        "sources": {f"{t}|{p}|{f}": infer_source(t, p, f) for t, p, f in SOURCE_CASES},
    })


def risk() -> None:
    out = []
    for counts in RISK_CASES:
        report = ScanReport(project_path="/p", project_name="p", started_at="x")
        for sev, count in counts.items():
            for index in range(count):
                report.findings.append(
                    Finding(tool="t", severity=Severity.parse(sev), title=f"{sev}{index}")
                )
        out.append({"counts": counts, "score": report.risk_score(), "verdict": report.verdict()})
    write("risk.json", out)


def _finding(file="src/app.py", line=6, rule=RULE, code=CODE, status=Status.OPEN, context=True):
    snippet = f"      4 | def ping(host):\n>     {line} |     {code}\n" if context else code
    finding = Finding(tool="semgrep", severity=Severity.HIGH, title="subprocess shell true",
                      rule_id=rule, file=file, line=line, snippet=snippet)
    finding.status = status
    return finding


def _report(findings_, scan_id):
    report = ScanReport(project_path="/p", project_name="p", scan_id=scan_id, started_at="t")
    report.findings = list(findings_)
    return report


def comparison() -> None:
    scenarios = {
        "unchanged": ([_finding()], [_finding()]),
        "fixed": ([_finding(), _finding(file="src/old.py", line=3, code="pickle.loads(d)")], [_finding()]),
        "moved_line": ([_finding(line=6)], [_finding(line=42)]),
        "moved_file": ([_finding(file="src/app.py", line=6)], [_finding(file="src/net.py", line=5)]),
        "new": ([_finding()], [_finding(), _finding(file="src/new.py", line=1, code="os.system(cmd)")]),
        "reintroduced": ([_finding(status=Status.RESOLVED)], [_finding()]),
        "accepted_persists": ([_finding(status=Status.ACCEPTED)], [_finding()]),
        "two_of_one_rule": (
            [_finding(line=11, code="os.system(a)"), _finding(line=21, code="os.system(b)")],
            [_finding(line=10, code="os.system(a)"), _finding(line=20, code="os.system(b)")],
        ),
        "already_resolved_drops_off": (
            [_finding(status=Status.RESOLVED, file="src/gone.py", line=1, code="eval(x)"), _finding()],
            [_finding()],
        ),
    }
    out = {}
    for name, (before, after) in scenarios.items():
        baseline = json.loads(json.dumps(_report(before, "scan-1").to_dict()))
        current = _report(after, "scan-2")
        result = correlate(current, baseline, "b.json")
        out[name] = {
            "baseline": [f.to_dict() for f in _report(before, "scan-1").sorted_findings()],
            "current_input": [f.to_dict() for f in _report(after, "scan-2").sorted_findings()],
            "expect": {
                "counts": result.counts,
                "moved": result.moved,
                "findings": [
                    {"file": f.file, "line": f.line, "status": f.status, "moved_from": f.moved_from,
                     "first_seen": f.first_seen, "last_seen": f.last_seen}
                    for f in current.sorted_findings()
                ],
            },
        }
    write("compare.json", out)


if __name__ == "__main__":
    print("writing the parity specification:")
    findings()
    taxonomy()
    severity()
    risk()
    comparison()
