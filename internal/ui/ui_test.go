package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// A Bubble Tea model is a function of messages, so these tests drive it directly:
// no terminal, no timing, and every assertion is about what the user would see.

func key(name string) tea.KeyMsg {
	switch name {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+r":
		return tea.KeyMsg{Type: tea.KeyCtrlR}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(name)}
}

func press(m *Model, names ...string) {
	for _, name := range names {
		m.Update(key(name))
	}
}

func newTestModel(t *testing.T, options scan.Options, profile string) *Model {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := New("0.3.0", options, profile)
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 44})
	return m
}

func TestTheFormRendersEverySettingAndItsCommand(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/some/project"
	m := newTestModel(t, options, "")

	view := m.View()
	for _, want := range []string{
		"whatsrisky", "no profile", "report schema 3",
		"Profile", "Project", "Scanners", "AI review", "Output", "Filtering", "Tuning",
		"Equivalent command", "whatsrisky /some/project",
		"ctrl+r run",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the form is missing %q", want)
		}
	}
}

func TestTheCommandFollowsTheForm(t *testing.T) {
	// The equivalent-command panel is what keeps the flags and the form from
	// drifting apart, so it has to track every change.
	options := scan.NewOptions()
	options.Path = "/p"
	m := newTestModel(t, options, "")

	// Move to the scanners field and turn the AI pass on.
	target := indexOfField(m, "scanners")
	m.cursor = target
	m.focusCurrent()
	multi := m.rows[target].field.(*multiField)
	multi.cursor = indexOfString(multi.values, "ai")
	press(m, "space")

	if got := m.collect().Normalized().CommandLine(); !strings.Contains(got, "--ai") {
		t.Errorf("turning on the ai pass did not reach the command: %s", got)
	}
	if !strings.Contains(m.View(), "spends tokens") {
		t.Error("the warning about tokens must appear as soon as the pass is on")
	}

	// And a severity floor. The list is in priority order - CRITICAL first - so
	// raising the floor from INFO means moving left through it.
	m.cursor = indexOfField(m, "minimum severity")
	m.focusCurrent()
	press(m, "left", "left", "left")
	if got := m.collect().Normalized().CommandLine(); !strings.Contains(got, "--min-severity HIGH") {
		t.Errorf("the severity floor did not reach the command: %s", got)
	}
	press(m, "right")
	if got := m.collect().Normalized().CommandLine(); !strings.Contains(got, "--min-severity MEDIUM") {
		t.Errorf("moving back did not reach the command: %s", got)
	}
}

func TestAnAPIBackendIsWarnedAboutBeforeTheScan(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	options.Tools = append(options.Tools, "ai")
	options.AIProvider = "openai"
	options.AIMode = "review"
	t.Setenv("OPENAI_API_KEY", "")
	m := newTestModel(t, options, "")

	view := m.View()
	// Everything that would surprise the user, said before the scan runs.
	for _, want := range []string{
		"OPENAI_API_KEY is not set",
		"cannot review a diff",
		"sees only the files we send it",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the form does not warn about %q", want)
		}
	}
}

func TestAProfileIsSavedAndNamedInTheHeader(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/p"
	options.MinSeverity = "HIGH"
	m := newTestModel(t, options, "")

	m.cursor = indexOfField(m, "save as")
	m.focusCurrent()
	press(m, "n", "i", "g", "h", "t", "l", "y")
	press(m, "ctrl+s")

	if !strings.Contains(m.notice, "saved 'nightly'") {
		t.Errorf("notice: %q", m.notice)
	}
	if m.profile != "nightly" {
		t.Errorf("active profile %q", m.profile)
	}
	if !strings.Contains(m.View(), "nightly") {
		t.Error("the header must name the profile in use")
	}
	// And it is what the next launch starts from.
	restored, active := config.StartupOptions()
	if active != "nightly" || restored.MinSeverity != "HIGH" {
		t.Errorf("startup options: %+v (active %q)", restored, active)
	}
}

func TestSavingWithoutANameSaysSo(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	press(m, "ctrl+s")
	if !strings.Contains(m.notice, "type a profile name") {
		t.Errorf("notice: %q", m.notice)
	}
}

func TestARunningScanShowsProgressAndOffersTheReport(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	m := newTestModel(t, options, "")
	m.mode = modeRunning
	m.options = options

	page := filepath.Join(t.TempDir(), "r.html")
	if err := os.WriteFile(page, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.handleEvent(scan.Event{Kind: "live", Paths: []string{page}})
	m.handleEvent(scan.Event{Kind: "tool_start", Tool: "semgrep"})
	m.handleEvent(scan.Event{Kind: "tool_progress", Tool: "semgrep", Message: "Scanning 412 files"})

	view := m.runView()
	if !strings.Contains(view, "semgrep") || !strings.Contains(view, "Scanning 412 files") {
		t.Errorf("the run screen hides what the scanner is doing:\n%s", view)
	}
	// The report is readable from the first second, and the help says so.
	if !strings.Contains(view, "v view report (it is written already)") {
		t.Errorf("the help does not offer the live report:\n%s", view)
	}
	if m.livePath != page {
		t.Errorf("live path %q", m.livePath)
	}
}

func TestViewReportOpensThePageOrSaysWhyNot(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	m.mode = modeRunning
	// No html in this run: the answer is a reason, not the JSON file.
	m.handleEvent(scan.Event{Kind: "live", Paths: nil})
	if notice := m.viewReport(); !strings.Contains(notice, "no html in this run") &&
		!strings.Contains(notice, "tick html in the formats") {
		t.Errorf("notice: %q", notice)
	}
	if !strings.Contains(strings.Join(m.log, "\n"), "no html in this run") {
		t.Error("the log must say the view is unavailable")
	}
}

func TestTheSummaryAdmitsCoverageGaps(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	m.mode = modeRunning

	finding := model.Finding{Tool: "semgrep", Severity: model.Medium, Title: "debug enabled"}
	finding.Normalize()
	report := model.Report{ProjectName: "p", Status: model.StatusPartial,
		Findings: []model.Finding{finding}, Tools: []model.ToolResult{
			{Name: "semgrep", Status: model.ToolOK},
			{Name: "trivy", Status: model.ToolMissing, Message: "not installed"},
		}}
	m.outcome = &scan.Outcome{Report: report}

	summary := m.summary()
	if !strings.Contains(summary, "coverage gaps") || !strings.Contains(summary, "trivy") {
		t.Errorf("a missing scanner must be visible in the summary:\n%s", summary)
	}
	if !strings.Contains(summary, "partial coverage") {
		t.Errorf("and in the verdict:\n%s", summary)
	}
}

func TestAnInvalidPathBlocksTheRun(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/definitely/not/here"
	m := newTestModel(t, options, "")

	if !strings.Contains(m.View(), "Not a directory") {
		t.Error("the form must say the path is wrong")
	}
	press(m, "ctrl+r")
	if m.mode == modeRunning {
		t.Error("a scan must not start with an invalid path")
	}
	if !strings.Contains(m.notice, "Not a directory") {
		t.Errorf("notice: %q", m.notice)
	}
}

func TestNavigationMovesAndWraps(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	if m.cursor != 0 {
		t.Fatalf("cursor starts at %d", m.cursor)
	}
	press(m, "up")
	if m.cursor != len(m.rows)-1 {
		t.Errorf("moving up from the first field should wrap, got %d", m.cursor)
	}
	press(m, "down")
	if m.cursor != 0 {
		t.Errorf("and back, got %d", m.cursor)
	}
}

func TestTypingGoesToTheFieldNotTheCommands(t *testing.T) {
	// The commands are chorded because a focused text field owns the letters.
	m := newTestModel(t, scan.NewOptions(), "")
	m.cursor = indexOfField(m, "path")
	m.focusCurrent()
	press(m, "/", "t", "m", "p")
	if got := m.collect().Path; got != "/tmp" {
		t.Errorf("the path field holds %q — letters were eaten by a command", got)
	}
	if m.mode == modeRunning {
		t.Error("typing must not start a scan")
	}
}

func TestTheProbeFillsTheScannerPanel(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	if !strings.Contains(m.View(), "probing…") {
		t.Error("the panel should say it is still probing")
	}
	m.Update(probeResult{rows: []probeRow{
		{name: "semgrep", found: true, detail: "semgrep 1.174.0"},
		{name: "trivy", found: false, detail: "`trivy` not found in PATH. Install: brew install trivy"},
	}})
	view := m.View()
	if !strings.Contains(view, "semgrep 1.174.0") {
		t.Error("a present scanner should show its version")
	}
	if !strings.Contains(view, "not found in PATH") {
		t.Error("a missing one should say how to get it")
	}
}

func indexOfField(m *Model, label string) int {
	for index, entry := range m.rows {
		if entry.field.label() == label {
			return index
		}
	}
	return 0
}

func indexOfString(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return 0
}

func TestAFailedScannerRowCarriesTheReasonNotAZero(t *testing.T) {
	// "0 findings" says nothing about a scanner that never ran.
	m := newTestModel(t, scan.NewOptions(), "")
	m.mode = modeRunning
	m.handleEvent(scan.Event{Kind: "tool_start", Tool: "trivy"})
	m.handleEvent(scan.Event{Kind: "tool_done", Tool: "trivy", Status: model.ToolMissing,
		Message: "`trivy` not found in PATH. Install: brew install trivy"})

	view := m.runView()
	if strings.Contains(view, "0 findings · missing") {
		t.Error("a missing scanner should not report a finding count")
	}
	if !strings.Contains(view, "not found in PATH") {
		t.Errorf("the row must carry the reason:\n%s", view)
	}
}

func TestTheFormHasNoBlankSectionGaps(t *testing.T) {
	// Two blank lines between sections is a styling bug, not a layout choice.
	m := newTestModel(t, scan.NewOptions(), "")
	if strings.Contains(m.settingsView(), "\n\n\n") {
		t.Error("the form has a double blank line")
	}
}

func TestAPlaceholderDoesNotReadLikeAValue(t *testing.T) {
	// A placeholder that looks like a real setting is a trap: "HEAD~1..HEAD" in the
	// git-range field read as if a range were already set.
	m := newTestModel(t, scan.NewOptions(), "")
	for _, entry := range m.rows {
		text, ok := entry.field.(*textField)
		if !ok {
			continue
		}
		placeholder := text.input.Placeholder
		switch entry.field.label() {
		case "git range", "model", "report directory", "skip these":
			if !strings.HasPrefix(placeholder, "blank =") {
				t.Errorf("%s: placeholder %q could be mistaken for a value",
					entry.field.label(), placeholder)
			}
		}
	}
}
