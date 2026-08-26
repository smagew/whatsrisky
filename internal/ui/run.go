package ui

import (
	"fmt"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// runText is the progress screen. Its job is to never let absence read as safety:
// a scanner that did not run says why, and a verdict never outruns its coverage.
func (u *UI) runText(width int) string {
	var out strings.Builder

	title := passTag + "scanning " + resetTag + u.options.Path
	switch {
	case u.runErr != nil:
		title = flagTag + "scan failed" + resetTag
	case u.outcome != nil:
		title = passTag + "done " + resetTag + u.options.Path
	}
	out.WriteString(titleTag + title + resetTag + "\n")
	out.WriteString(dimTag + shorten(u.options.CommandLine(), maxInt(20, width-2)) + resetTag + "\n\n")

	for _, row := range u.progress.Rows() {
		mark, tag := "▪", passTag
		detail := fmt.Sprintf("%d findings · %s", row.Findings, row.Status)
		switch {
		case row.Running():
			mark, tag = u.progress.Spinner(), markTag
			detail = row.Message
		case row.Status != model.ToolOK:
			// "0 findings" says nothing about a scanner that never ran.
			tag = flagTag
			detail = row.Status
			if reason := u.toolReason(row.Tool); reason != "" {
				detail += " · " + reason
			}
		}
		out.WriteString(fmt.Sprintf("%s%s %-9s%s %5.0fs  %s%s%s\n",
			tag, mark, row.Tool, resetTag, row.Elapsed().Seconds(),
			dimTag, shorten(detail, maxInt(20, width-30)), resetTag))
	}

	out.WriteString("\n")
	for _, line := range u.log {
		out.WriteString(line + "\n")
	}

	if u.runErr != nil {
		out.WriteString("\n" + flagTag + "failed: " + u.runErr.Error() + resetTag + "\n")
	} else if u.outcome != nil {
		out.WriteString("\n" + u.summary())
	}
	return out.String()
}

// toolReason is why a scanner did not run, taken from the log line it wrote.
func (u *UI) toolReason(tool string) string {
	if u.outcome != nil {
		for _, result := range u.outcome.Report.Tools {
			if result.Name == tool && !result.OK() {
				return firstLine(result.Message)
			}
		}
	}
	return u.toolMessages[tool]
}

func (u *UI) summary() string {
	report := u.outcome.Report
	counts := report.Counts()
	var out strings.Builder

	worst := ""
	for _, severity := range model.Order {
		if counts[severity] > 0 {
			worst = string(severity)
			break
		}
	}
	verdict := passTag
	if worst != "" {
		verdict = severityTag(worst)
	}
	out.WriteString(titleTag + report.ProjectName + resetTag + "  " +
		verdict + report.Verdict() + resetTag + "\n")
	out.WriteString(fmt.Sprintf("%srisk score %d/100 · %d findings · %.0fs%s\n",
		dimTag, report.RiskScore(), len(report.ActiveFindings()), report.DurationS, resetTag))

	var cells []string
	for _, severity := range model.Order {
		cells = append(cells, fmt.Sprintf("%s%s %d%s",
			severityTag(string(severity)), severity, counts[severity], resetTag))
	}
	out.WriteString(strings.Join(cells, "   ") + "\n")

	// A coverage gap is as important as a finding: unscanned is not clean.
	var gaps []string
	for _, tool := range report.Tools {
		if !tool.OK() {
			gaps = append(gaps, fmt.Sprintf("%s (%s)", tool.Name, tool.Status))
		}
	}
	if len(gaps) > 0 {
		out.WriteString(flagTag + "coverage gaps: " + resetTag + strings.Join(gaps, ", ") + "\n")
	}
	if comparison := report.Comparison; comparison != nil {
		out.WriteString(fmt.Sprintf("%svs %s: %d new · %d open · %d resolved · %d moved%s\n",
			dimTag, comparison.BaselineScanID, comparison.Counts[model.StatusNew],
			comparison.Counts[model.StatusOpen], comparison.Counts[model.StatusResolved],
			comparison.Moved, resetTag))
	}
	if u.exit != 0 {
		out.WriteString(fmt.Sprintf("%sexit code %d (--fail-on %s)%s\n",
			flagTag, u.exit, u.options.FailOn, resetTag))
	}
	return out.String()
}

// handleEvent turns one scan event into what the screen shows.
func (u *UI) handleEvent(event scan.Event) {
	switch event.Kind {
	case "info":
		u.appendLog(dimTag + "▸ " + event.Message + resetTag)
	case "live":
		if len(event.Paths) > 0 {
			u.livePath = event.Paths[0]
			u.appendLog(dimTag + "live report ready — press v to open it any time" + resetTag)
		} else {
			u.appendLog(dimTag + "no html in this run — the report view is unavailable" + resetTag)
		}
	case "tool_start":
		u.progress.Start(event.Tool)
		u.appendLog(dimTag + "▸ " + event.Tool + " started" + resetTag)
	case "tool_progress":
		u.progress.Progress(event.Tool, event.Message)
	case "tool_done":
		u.progress.Done(event.Tool, event.Status, event.Findings, event.Duration)
		if event.Status == model.ToolOK {
			u.appendLog(fmt.Sprintf("%s▪ %s ok · %d findings · %.0fs%s",
				passTag, event.Tool, event.Findings, event.Duration.Seconds(), resetTag))
			return
		}
		// No finding count for a scanner that did not run: "0 findings" describes
		// a clean pass, and this was not one.
		u.toolMessages[event.Tool] = firstLine(event.Message)
		u.appendLog(fmt.Sprintf("%s▪ %s %s — nothing was checked%s",
			flagTag, event.Tool, event.Status, resetTag))
		if event.Message != "" {
			u.appendLog(dimTag + "  " + firstLine(event.Message) + resetTag)
		}
	case "report":
		for _, path := range event.Paths {
			u.appendLog(passTag + "report " + resetTag + path)
		}
	}
}

func (u *UI) appendLog(line string) {
	u.log = append(u.log, line)
	if len(u.log) > 200 {
		u.log = u.log[len(u.log)-200:]
	}
}

func (u *UI) finished() bool { return u.outcome != nil || u.runErr != nil }

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}
