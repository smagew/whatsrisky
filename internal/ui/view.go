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

// bodyLine is one rendered line of the form, tagged with the field it belongs to
// so the viewport can keep the cursor visible and the mouse can hit it.
type bodyLine struct {
	text string
	row  int // -1 for a section heading or a hint
}

func (m *Model) settingsView() string {
	options := m.collect().Normalized()
	body := m.formLines(options)
	header := m.header()
	footer := m.footer()

	// The form is taller than most terminals, so it scrolls. Without this the
	// bottom sections and the key bindings were simply cut off - which is how a
	// form with no visible way to act reads as broken.
	visible := m.bodyHeight()
	m.clampOffset(body, visible)
	window, above, below := windowLines(body, m.offset, visible)

	var form strings.Builder
	form.WriteString(header + "\n")
	if above > 0 {
		form.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d more", above)) + "\n")
	} else {
		form.WriteString("\n")
	}
	for _, line := range window {
		form.WriteString(line.text + "\n")
	}
	if below > 0 {
		form.WriteString(dimStyle.Render(fmt.Sprintf("  ↓ %d more", below)) + "\n")
	}
	form.WriteString(footer)

	side := m.sidePanel(options)
	if m.width < 100 {
		// Narrow: the panel cannot sit beside the form, but dropping it takes the
		// equivalent command with it - which is the thing that makes this UI worth
		// using. Keep that much, stacked.
		return form.String() + "\n" + m.narrowPanel(options)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(m.formWidth()+4).Render(form.String()),
		panelStyle.Width(m.width-m.formWidth()-8).MaxHeight(maxInt(8, m.height-2)).Render(side))
}

// formLines renders every row, and records where the cursor's row sits.
func (m *Model) formLines(options scan.Options) []bodyLine {
	width := m.formWidth()
	var out []bodyLine
	section := ""
	for index, entry := range m.rows {
		if entry.section != section {
			section = entry.section
			out = append(out, bodyLine{text: sectionStyle.Render(section), row: -1})
		}
		focused := index == m.cursor
		marker := "  "
		label := labelStyle.Render(fmt.Sprintf("%-26s", entry.field.label()))
		if focused {
			marker = focusStyle.Render("› ")
			label = focusStyle.Render(fmt.Sprintf("%-26s", entry.field.label()))
		}
		value := entry.field.render(focused, width)
		if !focused {
			// A long path used to wrap to column zero and break the column.
			value = shorten(value, maxInt(20, width-30))
		}
		out = append(out, bodyLine{text: marker + label + value, row: index})
		if focused && entry.field.hint() != "" {
			out = append(out, bodyLine{text: "    " + dimStyle.Render(entry.field.hint()), row: -1})
		}
	}
	return out
}

// footer is pinned: the primary action and the keys must never scroll away.
func (m *Model) footer() string {
	var out strings.Builder
	out.WriteString(actionStyle.Render(" ▶ ctrl+r  run scan ") + "  " +
		dimStyle.Render("ctrl+s save profile · ctrl+q quit") + "\n")
	out.WriteString(helpStyle.Render("↑↓ move · ←→ or space change · click a row to jump to it"))
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
	chrome := 6 // header, the two scroll hints, and the two footer lines
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
func (m *Model) clampOffset(body []bodyLine, visible int) {
	if len(body) <= visible {
		m.offset = 0
		return
	}
	first, last := -1, -1
	for index, line := range body {
		if line.row == m.cursor {
			if first == -1 {
				first = index
			}
			last = index
		}
		if first != -1 && line.row == -1 && index == last+1 {
			last = index // the hint belongs to the focused row
		}
	}
	if first == -1 {
		return
	}
	if m.offset > first {
		m.offset = first
	}
	if last >= m.offset+visible {
		m.offset = last - visible + 1
	}
	if maximum := len(body) - visible; m.offset > maximum {
		m.offset = maximum
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func windowLines(body []bodyLine, offset, visible int) ([]bodyLine, int, int) {
	if offset < 0 {
		offset = 0
	}
	end := offset + visible
	if end > len(body) {
		end = len(body)
	}
	return body[offset:end], offset, len(body) - end
}

// rowAt maps a screen line to the field on it, for the mouse.
func (m *Model) rowAt(screenY int) int {
	body := m.formLines(m.collect())
	m.clampOffset(body, m.bodyHeight())
	index := m.offset + screenY - 2 // the header and the scroll hint line
	if index < 0 || index >= len(body) {
		return -1
	}
	return body[index].row
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
