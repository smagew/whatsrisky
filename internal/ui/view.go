package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// View renders whichever screen is current.
func (m *Model) View() string {
	if m.quit {
		return ""
	}
	if m.mode == modeRunning {
		return m.runView()
	}
	return m.settingsView()
}

func (m *Model) header() string {
	name := m.profile
	if name == "" {
		name = "no profile"
	}
	return titleStyle.Render("whatsrisky") + dimStyle.Render(
		fmt.Sprintf("  %s · %s · report schema %d", name, m.version, model.SchemaVersion))
}

// --- settings --------------------------------------------------------

func (m *Model) settingsView() string {
	options := m.collect().Normalized()
	formWidth := m.formWidth()

	var form strings.Builder
	form.WriteString(m.header() + "\n")
	section := ""
	for index, entry := range m.rows {
		if entry.section != section {
			section = entry.section
			form.WriteString("\n" + sectionStyle.Render(section) + "\n")
		}
		focused := index == m.cursor
		marker := "  "
		if focused {
			marker = focusStyle.Render("› ")
		}
		label := labelStyle.Render(fmt.Sprintf("%-26s", entry.field.label()))
		if focused {
			label = focusStyle.Render(fmt.Sprintf("%-26s", entry.field.label()))
		}
		value := entry.field.render(focused, formWidth)
		if !focused {
			// A long path used to wrap to column zero and break the column.
			value = shorten(value, maxInt(20, formWidth-30))
		}
		form.WriteString(marker + label + value + "\n")
		if focused && entry.field.hint() != "" {
			form.WriteString("    " + dimStyle.Render(entry.field.hint()) + "\n")
		}
	}
	form.WriteString(helpStyle.Render(
		"↑↓ move · ←→/space change · ctrl+r run · ctrl+s save profile · ctrl+q quit"))
	if m.notice != "" {
		form.WriteString("\n" + warnStyle.Render(m.notice))
	}

	side := m.sidePanel(options)
	if m.width < 100 {
		return form.String() + "\n\n" + side
	}
	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(formWidth+4).Render(form.String()),
		panelStyle.Width(m.width-formWidth-8).Render(side))
}

func (m *Model) formWidth() int {
	if m.width < 100 {
		return maxInt(40, m.width-4)
	}
	return (m.width * 6) / 10
}

func (m *Model) sidePanel(options scan.Options) string {
	var out strings.Builder

	out.WriteString(titleStyle.Render("Scanners on this machine") + "\n")
	switch {
	case m.probing:
		out.WriteString(dimStyle.Render("probing…") + "\n")
	default:
		for _, entry := range m.probes {
			mark, style := badStyle.Render("✗"), dimStyle
			if entry.found {
				mark, style = okStyle.Render("✓"), dimStyle
			}
			out.WriteString(fmt.Sprintf("%s %-9s %s\n", mark, entry.name, style.Render(shorten(entry.detail, 34))))
		}
	}

	out.WriteString("\n" + titleStyle.Render("Equivalent command") + "\n")
	out.WriteString(commandStyle.Render(options.CommandLine()) + "\n")

	out.WriteString("\n")
	for _, warning := range m.warnings(options) {
		out.WriteString(warning + "\n")
	}

	if names := profileNames(); len(names) > 0 {
		out.WriteString("\n" + titleStyle.Render("Saved profiles") + "\n")
		out.WriteString(dimStyle.Render(strings.Join(names, ", ")) + "\n")
		out.WriteString(dimStyle.Render("start from one with: whatsrisky ui --profile NAME") + "\n")
	}
	return out.String()
}

// --- run -------------------------------------------------------------

func (m *Model) runView() string {
	var out strings.Builder
	out.WriteString(m.header() + "\n")

	title := "scanning " + m.options.Path
	if m.runErr != nil {
		title = badStyle.Render("scan failed")
	} else if m.outcome != nil {
		title = okStyle.Render("done ") + m.options.Path
	}
	out.WriteString(titleStyle.Render(title) + "\n")
	out.WriteString(dimStyle.Render(m.options.CommandLine()) + "\n\n")

	for _, row := range m.progress.Rows() {
		mark, style := "▪", okStyle
		detail := fmt.Sprintf("%d findings · %s", row.Findings, row.Status)
		switch {
		case row.Running():
			mark, style = m.progress.Spinner(), warnStyle
			detail = row.Message
		case row.Status != model.ToolOK:
			// "0 findings" says nothing about a scanner that never ran.
			style = badStyle
			detail = row.Status
			if reason := m.toolReason(row.Tool); reason != "" {
				detail += " · " + reason
			}
		}
		out.WriteString(fmt.Sprintf("%s %-9s %5.0fs  %s\n",
			style.Render(mark), style.Render(row.Tool), row.Elapsed().Seconds(),
			dimStyle.Render(shorten(detail, maxInt(20, m.width-30)))))
	}

	out.WriteString("\n")
	for _, line := range m.tailLog() {
		out.WriteString(line + "\n")
	}

	if m.runErr != nil {
		out.WriteString("\n" + badStyle.Render("failed: "+m.runErr.Error()) + "\n")
	} else if m.outcome != nil {
		out.WriteString("\n" + m.summary() + "\n")
	}

	help := "v view report · esc back · q quit"
	if !m.finished() {
		help = "v view report (it is written already) · ctrl+c stop"
	}
	out.WriteString(helpStyle.Render(help))
	if m.notice != "" {
		out.WriteString("\n" + warnStyle.Render(m.notice))
	}
	return out.String()
}

// toolReason is why a scanner did not run, taken from the log line it wrote.
func (m *Model) toolReason(tool string) string {
	if m.outcome != nil {
		for _, result := range m.outcome.Report.Tools {
			if result.Name == tool && !result.OK() {
				return firstLine(result.Message)
			}
		}
	}
	return m.toolMessages[tool]
}

func (m *Model) tailLog() []string {
	limit := m.height - 18
	if limit < 4 {
		limit = 4
	}
	if len(m.log) <= limit {
		return m.log
	}
	return m.log[len(m.log)-limit:]
}

func (m *Model) summary() string {
	report := m.outcome.Report
	counts := report.Counts()
	var out strings.Builder

	worst := ""
	for _, severity := range model.Order {
		if counts[severity] > 0 {
			worst = string(severity)
			break
		}
	}
	verdictStyle := okStyle
	if worst != "" {
		verdictStyle = severityStyle(worst)
	}
	out.WriteString(titleStyle.Render(report.ProjectName) + "  " + verdictStyle.Render(report.Verdict()) + "\n")
	out.WriteString(dimStyle.Render(fmt.Sprintf("risk score %d/100 · %d findings · %.0fs",
		report.RiskScore(), len(report.ActiveFindings()), report.DurationS)) + "\n")

	var cells []string
	for _, severity := range model.Order {
		cells = append(cells, severityStyle(string(severity)).Render(
			fmt.Sprintf("%s %d", severity, counts[severity])))
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
		out.WriteString(badStyle.Render("coverage gaps: ") + strings.Join(gaps, ", ") + "\n")
	}
	if comparison := report.Comparison; comparison != nil {
		out.WriteString(dimStyle.Render(fmt.Sprintf("vs %s: %d new · %d open · %d resolved · %d moved",
			comparison.BaselineScanID, comparison.Counts[model.StatusNew],
			comparison.Counts[model.StatusOpen], comparison.Counts[model.StatusResolved],
			comparison.Moved)) + "\n")
	}
	if m.exit != 0 {
		out.WriteString(badStyle.Render(fmt.Sprintf("exit code %d (--fail-on %s)", m.exit, m.options.FailOn)) + "\n")
	}
	return out.String()
}

func shorten(text string, limit int) string {
	text = strings.ReplaceAll(text, "\n", " ")
	if len([]rune(text)) <= limit {
		return text
	}
	return string([]rune(text)[:maxInt(1, limit-1)]) + "…"
}
