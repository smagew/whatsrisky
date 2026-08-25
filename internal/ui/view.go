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
// --- settings --------------------------------------------------------

// settingsView is the form beside what the form implies: the equivalent command,
// the scanners actually installed, and anything worth warning about before a run.
func (m *Model) settingsView() string {
	options := m.collect()
	form := m.form.View()

	if m.width < 100 {
		// Narrow: no room for a column. Dropping the panel would take the
		// equivalent command with it - the thing that makes this UI worth using -
		// so keep that much, stacked.
		return m.header() + "\n" + form + "\n" + m.narrowPanel(options)
	}
	panelWidth := m.panelWidth()
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(m.formWidth()+2).Render(form),
		panelStyle.Width(panelWidth).
			Height(maxInt(8, m.bodyHeight())).Render(m.sidePanel(options, panelWidth)))
	return m.header() + "\n" + body + "\n" + m.footer()
}

func (m *Model) footer() string {
	var out strings.Builder
	out.WriteString(actionStyle.Render(" ▶ ctrl+r  run scan ") + "  " +
		dimStyle.Render("ctrl+s save profile · ctrl+q quit") + "\n")
	// No key list here on purpose: the form prints the keys that apply to the
	// field you are on, which beats a fixed line that has to be kept true. The
	// mouse hint used to live here and outlived the mouse.
	if m.notice != "" {
		out.WriteString("\n" + warnStyle.Render(shorten(m.notice, maxInt(30, m.formWidth()))))
	}
	return out.String()
}

// narrowPanel is what survives when there is no room for a column: the command,
// and the first thing worth warning about.
func (m *Model) narrowPanel(options scan.Options) string {
	lines := []string{commandStyle.Render(shorten(options.CommandLine(), maxInt(30, m.width-2)))}
	if warnings := m.warnings(options); len(warnings) > 0 {
		lines = append(lines, shorten(warnings[0], maxInt(30, m.width-2)))
	}
	return strings.Join(lines, "\n")
}

// bodyHeight is what is left for the form after the header and the pinned footer.
func (m *Model) bodyHeight() int {
	chrome := 4 // the header, the form's own help line, and the action line
	if m.width < 100 {
		chrome += 3 // the stacked command and warning
	}
	height := m.height
	if height <= 0 {
		height = 40
	}
	if m.notice != "" {
		chrome++
	}
	return maxInt(4, height-chrome)
}

// clampOffset scrolls just enough to keep the focused row and its hint in view.
func (m *Model) formWidth() int {
	if m.width < 100 {
		return maxInt(40, m.width-4)
	}
	return m.width - m.panelWidth() - 6
}

// panelWidth is decided before the form's, not after. The panel carries the
// equivalent command and the warnings, and starving it is what made both wrap
// mid-phrase - a command broken inside an argument, a warning cut in half. The
// form can absorb a narrower column; those two cannot.
func (m *Model) panelWidth() int {
	return minInt(48, maxInt(34, (m.width*35)/100))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// wrapArguments breaks a command line between arguments, never inside one. A
// token that cannot fit on its own is truncated with an ellipsis, because a
// silently split path looks like a command you could copy, and is not.
func wrapArguments(command string, width int) string {
	if width < 8 {
		width = 8
	}
	var lines []string
	current := ""
	for _, token := range strings.Fields(command) {
		switch {
		case current == "":
			current = token
		case len(current)+1+len(token) <= width:
			current += " " + token
		default:
			lines = append(lines, current)
			current = token
		}
		if len(current) > width {
			lines = append(lines, shorten(current, width))
			current = ""
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n")
}

func (m *Model) sidePanel(options scan.Options, width int) string {
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
			// Truncated against the panel's real width, or the line both wraps
			// and then gets an ellipsis - which reads as a rendering fault.
			out.WriteString(fmt.Sprintf("%s %-9s %s\n", mark, entry.name,
				style.Render(shorten(entry.detail, maxInt(12, width-12)))))
		}
	}

	out.WriteString("\n" + titleStyle.Render("Equivalent command") + "\n")
	out.WriteString(commandStyle.Render(wrapArguments(options.CommandLine(), width)) + "\n")

	out.WriteString("\n")
	for _, warning := range m.warnings(options) {
		out.WriteString(warning + "\n")
	}

	if names := profileNames(); len(names) > 0 {
		out.WriteString("\n" + titleStyle.Render("Saved profiles") + "\n")
		out.WriteString(dimStyle.Render(shorten(strings.Join(names, ", "), width)) + "\n")
		out.WriteString(dimStyle.Render(wrapArguments("start from one: whatsrisky ui --profile NAME", width)) + "\n")
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
