"""Markdown mirror of the DOCX report - handy for PRs, CI logs and diffing."""

from __future__ import annotations

from pathlib import Path

from ..models import SEVERITY_ORDER, ScanReport, Severity

EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def write_markdown(report: ScanReport, out_path: Path) -> Path:
    counts = report.counts()
    lines: list[str] = []
    add = lines.append

    add(f"# Security Assessment — {report.project_name}")
    add("")
    add(f"- **Verdict:** {report.verdict()}")
    add(f"- **Risk score:** {report.risk_score()}/100")
    add(f"- **Path:** `{report.project_path}`")
    if report.git_commit:
        add(f"- **Git:** {report.git_branch} @ {report.git_commit}")
    add(f"- **Scanned:** {report.started_at} → {report.finished_at} ({report.duration_s:.1f}s)")
    add("")
    add("## Findings by priority")
    add("")
    add("| Severity | Count |")
    add("| --- | --- |")
    for severity in SEVERITY_ORDER:
        add(f"| {EMOJI[severity]} {severity.value} | {counts[severity]} |")
    add("")

    add("## Scanners")
    add("")
    add("| Scanner | Status | Version | Time | Findings | Note |")
    add("| --- | --- | --- | --- | --- | --- |")
    for tool in report.tools:
        note = (tool.message or "").replace("\n", " ")[:160]
        add(
            f"| {tool.name} | {tool.status} | {tool.version or '-'} | "
            f"{tool.duration_s:.0f}s | {len(tool.findings)} | {note} |"
        )
    add("")

    add("## Findings")
    add("")
    if not report.findings:
        add("_No findings reported. Check the scanner table for coverage gaps._")
    current: Severity | None = None
    counters: dict[Severity, int] = {s: 0 for s in SEVERITY_ORDER}
    for finding in report.sorted_findings():
        if finding.severity is not current:
            current = finding.severity
            add(f"### {EMOJI[current]} {current.value} ({counts[current]})")
            add("")
        counters[finding.severity] += 1
        add(f"#### {finding.severity.value}-{counters[finding.severity]:02d} · {finding.title}")
        add("")
        add(f"- **Where:** `{finding.location}`")
        add(f"- **Tool / rule:** {finding.tool} · `{finding.rule_id or '-'}`")
        if finding.category:
            add(f"- **Category:** {finding.category}")
        if finding.package:
            fix = finding.fixed_version or "no fix available"
            add(f"- **Package:** `{finding.package} {finding.installed_version}` → {fix}")
        if finding.cwe or finding.owasp or finding.cvss:
            bits = []
            if finding.cwe:
                bits.append("CWE " + ", ".join(finding.cwe[:6]))
            if finding.owasp:
                bits.append("OWASP " + ", ".join(finding.owasp[:3]))
            if finding.cvss:
                bits.append(f"CVSS {finding.cvss}")
            add(f"- **Classification:** {' | '.join(bits)}")
        add("")
        if finding.description:
            add(finding.description.strip())
            add("")
        if finding.snippet:
            add("```")
            add(finding.snippet.strip()[:1200])
            add("```")
            add("")
        if finding.remediation:
            add(f"**Fix:** {finding.remediation.strip()}")
            add("")
        if finding.references:
            add("References: " + ", ".join(finding.references[:4]))
            add("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
