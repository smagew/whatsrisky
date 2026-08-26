package report

import (
	"fmt"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
)

// Markdown mirror of the report - handy for a pull request, a CI log, or a diff.

var severityMark = map[model.Severity]string{
	model.Critical: "🟥", model.High: "🟧", model.Medium: "🟨",
	model.Low: "🟦", model.Info: "⬜",
}

// RenderMarkdown writes the report as Markdown.
func RenderMarkdown(report model.Report) string {
	var out strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
		out.WriteString("\n")
	}
	counts := report.Counts()

	line("# Security Assessment — %s", report.ProjectName)
	line("")
	line("- **Verdict:** %s", report.Verdict())
	line("- **Risk score:** %d/100", report.RiskScore())
	line("- **Path:** `%s`", report.ProjectPath)
	if report.GitCommit != "" {
		line("- **Git:** %s @ %s", report.GitBranch, report.GitCommit)
	}
	if report.DiffRange != "" {
		line("- **Scope:** `%s` (%d changed file(s))", report.DiffRange, len(report.ScopePaths))
	}
	line("- **Scanned:** %s → %s (%.1fs)", report.StartedAt, report.FinishedAt, report.DurationS)
	line("")

	line("## Findings by priority")
	line("")
	line("| Severity | Count |")
	line("| --- | --- |")
	for _, severity := range model.Order {
		line("| %s %s | %d |", severityMark[severity], severity, counts[severity])
	}
	line("")

	line("## Scanners")
	line("")
	line("| Scanner | Status | Version | Time | Findings | Note |")
	line("| --- | --- | --- | --- | --- | --- |")
	for _, tool := range report.Tools {
		note := strings.ReplaceAll(tool.Message, "\n", " ")
		if len(note) > 160 {
			note = note[:160]
		}
		line("| %s | %s | %s | %.0fs | %d | %s |",
			tool.Name, tool.Status, orDash(tool.Version), tool.DurationS, len(tool.Findings), note)
	}
	line("")

	if len(report.Assets) > 0 {
		alive := 0
		for _, asset := range report.Assets {
			if asset.Alive {
				alive++
			}
		}
		line("## Estate — %d asset(s), %d alive", len(report.Assets), alive)
		line("")
		line("| Host | Alive | Status | URL | Stack |")
		line("| --- | --- | --- | --- | --- |")
		for _, asset := range report.Assets {
			mark, status, url := "no", "", ""
			if asset.Alive {
				mark = "yes"
				status = fmt.Sprintf("%d", asset.Status)
				url = asset.URL
			}
			line("| %s | %s | %s | %s | %s |",
				asset.Host, mark, status, url, strings.Join(asset.Tech, ", "))
		}
	}
	line("")

	if comparison := report.Comparison; comparison != nil {
		line("## Since %s", orDash(comparison.BaselineScanID))
		line("")
		for _, status := range model.AllStatuses {
			if count := comparison.Counts[status]; count > 0 {
				line("- **%s:** %d", status, count)
			}
		}
		if comparison.Moved > 0 {
			line("- **moved:** %d (tracked through code that changed place)", comparison.Moved)
		}
		line("")
	}

	line("## Findings")
	line("")
	if len(report.Findings) == 0 {
		line("_No findings reported. Check the scanner table for coverage gaps._")
		return out.String()
	}

	current := model.Severity("")
	counters := map[model.Severity]int{}
	for _, finding := range report.SortedFindings() {
		if finding.Severity != current {
			current = finding.Severity
			line("### %s %s (%d)", severityMark[current], current, counts[current])
			line("")
		}
		counters[finding.Severity]++
		line("#### %s-%02d · %s", finding.Severity, counters[finding.Severity], finding.Title)
		line("")
		line("- **Where:** `%s`", finding.Location())
		line("- **Tool / rule:** %s · `%s`", finding.Tool, orDash(finding.RuleID))
		line("- **Category:** %s", finding.CategoryLabel())
		if finding.Status != model.StatusOpen {
			line("- **Status:** %s%s", finding.Status, movedSuffix(finding))
		}
		if finding.Package != "" {
			fix := orText2(finding.FixedVersion, "no fix available")
			line("- **Package:** `%s %s` → %s", finding.Package, finding.InstalledVersion, fix)
		}
		if bits := classification(finding); bits != "" {
			line("- **Classification:** %s", bits)
		}
		line("")
		if finding.Description != "" {
			line("%s", strings.TrimSpace(finding.Description))
			line("")
		}
		if finding.Snippet != "" {
			line("```")
			line("%s", strings.TrimSpace(finding.Snippet))
			line("```")
			line("")
		}
		if finding.Remediation != "" {
			line("**Fix:** %s", strings.TrimSpace(finding.Remediation))
			line("")
		}
		if len(finding.References) > 0 {
			limit := finding.References
			if len(limit) > 4 {
				limit = limit[:4]
			}
			line("References: %s", strings.Join(limit, ", "))
			line("")
		}
	}
	return out.String()
}

func movedSuffix(finding model.Finding) string {
	if finding.MovedFrom == "" {
		return ""
	}
	return " (moved from " + finding.MovedFrom + ")"
}

func classification(finding model.Finding) string {
	var bits []string
	if len(finding.CWE) > 0 {
		bits = append(bits, "CWE "+strings.Join(trim(finding.CWE, 6), ", "))
	}
	if len(finding.OWASP) > 0 {
		bits = append(bits, "OWASP "+strings.Join(trim(finding.OWASP, 3), ", "))
	}
	if finding.CVSS != "" {
		bits = append(bits, "CVSS "+finding.CVSS)
	}
	return strings.Join(bits, " | ")
}

func trim(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}

func orDash(value string) string { return orText2(value, "-") }

func orText2(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// WriteMarkdown writes the Markdown mirror.
func WriteMarkdown(report model.Report, path string) error {
	return writeAtomic(path, []byte(RenderMarkdown(report)))
}
