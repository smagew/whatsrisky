package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// A Bubble Tea model is a function of messages, so these tests drive it directly:
// no terminal, no timing, and every assertion is about what the user would see.
//
// The form itself is huh's, so these do not re-test widgets. What they test is
// what we got wrong by hand: that the form is not blank, that exactly one field
// looks focused, that every field can be reached, that a resize re-wraps, and
// that the panel never breaks a command it invites you to copy.

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
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
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

// press sends a key and then runs whatever the model asked for, because huh
// answers a keypress with a command and the focus only moves when the message it
// produces comes back in. A test that drops those commands reports a form that
// cannot be navigated, and misses one that genuinely cannot.
func press(m *Model, names ...string) {
	for _, name := range names {
		_, cmd := m.Update(key(name))
		settle(m, cmd)
	}
}

// settle runs the commands that answer immediately. A command that does not is a
// timer - a cursor blink, a progress tick - and waiting on those cost this suite
// twenty-six seconds per keystroke before this was bounded.
func settle(m *Model, cmd tea.Cmd) {
	queue := []tea.Cmd{cmd}
	for step := 0; len(queue) > 0 && step < 50; step++ {
		next := queue[0]
		queue = queue[1:]
		if next == nil {
			continue
		}
		msg, ok := immediate(next)
		if !ok || msg == nil {
			continue
		}
		if batch, isBatch := msg.(tea.BatchMsg); isBatch {
			queue = append(queue, batch...)
			continue
		}
		_, produced := m.Update(msg)
		queue = append(queue, produced)
	}
}

// immediate runs one command, giving up on anything that waits.
func immediate(cmd tea.Cmd) (tea.Msg, bool) {
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	select {
	case msg := <-done:
		return msg, true
	case <-time.After(50 * time.Millisecond):
		return nil, false
	}
}

func sized(t *testing.T, options scan.Options, profile string, width, height int) *Model {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := New("0.3.1", options, profile)
	// Init matters: without it huh has not focused a field and the form renders
	// empty - which is exactly how a blank form gets shipped.
	m.Init()
	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return m
}

func newTestModel(t *testing.T, options scan.Options, profile string) *Model {
	t.Helper()
	return sized(t, options, profile, 140, 44)
}

// lineWith returns the whole rendered line that first mentions text.
func lineWith(view, text string) string {
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, text) {
			return line
		}
	}
	return ""
}

func TestTheFormIsNotBlank(t *testing.T) {
	// The regression this exists for: a section heading as the first field makes
	// huh render the entire group as empty space. It shipped once looking like a
	// working UI with nothing in it.
	options := scan.NewOptions()
	options.Path = "/some/project"
	m := newTestModel(t, options, "")

	view := m.View()
	for _, want := range []string{
		"whatsrisky", "no profile", "report schema 3",
		"── Project", "path", "/some/project",
		"Equivalent command", "whatsrisky /some/project",
		"run scan", "ctrl+r",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the form is missing %q", want)
		}
	}
}

func TestExactlyOneFieldLooksFocused(t *testing.T) {
	// Copying the focused styles into the blurred ones put the focus bar on every
	// field at once, which is the same "where am I" defect the old hand-rolled
	// form had.
	m := newTestModel(t, scan.NewOptions(), "")
	view := m.View()

	if focused := lineWith(view, "path"); !strings.Contains(focused, "┃") {
		t.Errorf("the focused field carries no focus bar: %q", focused)
	}
	if blurred := lineWith(view, "git range"); strings.Contains(blurred, "┃") {
		t.Errorf("an unfocused field carries the focus bar: %q", blurred)
	}
}

func TestEveryFieldIsReachable(t *testing.T) {
	// Nothing may sit permanently below the fold. The old form drew past the
	// bottom of the terminal and the whole Tuning section was unreachable.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	m := sized(t, options, "", 100, 30)

	if strings.Contains(m.View(), "── Tuning") {
		t.Skip("the terminal is tall enough to show everything; nothing to reach")
	}
	for step := 0; step < 40; step++ {
		press(m, "tab")
		if strings.Contains(m.View(), "save as") {
			return
		}
		if m.mode == modeRunning {
			t.Fatalf("tabbing started a scan at step %d", step)
		}
	}
	t.Errorf("the last field never came into view:\n%s", m.View())
}

func TestTheActionNeverScrollsAway(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	m := sized(t, options, "", 100, 26)

	for step := 0; step < 30; step++ {
		if view := m.View(); !strings.Contains(view, "ctrl+r") {
			t.Fatalf("the run action disappeared at step %d:\n%s", step, view)
		}
		press(m, "tab")
	}
}

func TestADescriptionUsesTheWidthAfterAResize(t *testing.T) {
	// huh's WithWidth moves the frame but leaves every description wrapped for
	// the old width, so a widened terminal kept the narrow text. The fix is to
	// rebuild the form; this is what proves it still happens.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	m := sized(t, options, "", 80, 30)
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})

	const whole = "scope the scan to what a range changed; blank scans everything"
	if !strings.Contains(m.View(), whole) {
		t.Errorf("the description is still wrapped for the narrow terminal:\n%s",
			lineWith(m.View(), "scope the scan"))
	}
}

func TestAResizeKeepsWhatWasTyped(t *testing.T) {
	// Rebuilding the form on resize must not throw away the settings, which it
	// would if the fields were rebuilt from the stored options instead of the
	// live ones.
	m := sized(t, scan.NewOptions(), "", 100, 30)
	press(m, "/", "t", "m", "p")
	m.Update(tea.WindowSizeMsg{Width: 160, Height: 48})

	if got := m.collect().Path; got != "/tmp" {
		t.Errorf("the resize lost the path: %q", got)
	}
	if !strings.Contains(m.View(), "/tmp") {
		t.Error("and the rebuilt form does not show it")
	}
}

func TestTypingGoesToTheFieldNotTheCommands(t *testing.T) {
	// The commands are chorded because a focused text field owns the letters.
	m := newTestModel(t, scan.NewOptions(), "")
	press(m, "/", "t", "m", "p")
	if got := m.collect().Path; got != "/tmp" {
		t.Errorf("the path field holds %q — letters were eaten by a command", got)
	}
	if m.mode == modeRunning {
		t.Error("typing must not start a scan")
	}
}

func TestTheCommandFollowsTheForm(t *testing.T) {
	// The equivalent-command panel is what keeps the flags and the form from
	// drifting apart, so it has to track every change.
	options := scan.NewOptions()
	options.Path = "/p"
	m := newTestModel(t, options, "")

	m.values.tools = append(m.values.tools, "ai")
	if got := m.collect().Normalized().CommandLine(); !strings.Contains(got, "--ai") {
		t.Errorf("turning on the ai pass did not reach the command: %s", got)
	}
	if !strings.Contains(m.View(), "spends tokens") {
		t.Error("the warning about tokens must appear as soon as the pass is on")
	}

	m.values.minSeverity = "HIGH"
	if got := m.collect().Normalized().CommandLine(); !strings.Contains(got, "--min-severity HIGH") {
		t.Errorf("the severity floor did not reach the command: %s", got)
	}
}

func TestThePanelNeverBreaksACommandMidArgument(t *testing.T) {
	// A command broken across lines inside an argument reads like something you
	// could copy, and is not. Truncating is honest; splitting a path is not.
	options := scan.NewOptions()
	options.Path = "/Users/someone/work/a-project-with-a-long-name"
	m := sized(t, options, "", 100, 30)

	if !strings.Contains(m.View(), options.Path) {
		t.Errorf("the path was split across lines:\n%s", m.sidePanel(m.collect(), 34))
	}
}

func TestWrapArgumentsKeepsArgumentsWhole(t *testing.T) {
	got := wrapArguments("whatsrisky /a/path --tools semgrep,trivy --min-severity HIGH", 24)
	for _, line := range strings.Split(got, "\n") {
		if lipgloss.Width(line) > 24 {
			t.Errorf("line over the width: %q", line)
		}
	}
	for _, argument := range []string{"whatsrisky", "/a/path", "--tools", "semgrep,trivy", "HIGH"} {
		if !strings.Contains(got, argument) {
			t.Errorf("%q did not survive wrapping:\n%s", argument, got)
		}
	}
	// A token that cannot fit is truncated, not split into something that looks
	// like two arguments.
	long := wrapArguments("whatsrisky /a/very/long/path/that/cannot/fit/anywhere", 16)
	for _, line := range strings.Split(long, "\n") {
		if lipgloss.Width(line) > 16 {
			t.Errorf("an oversized token was not truncated: %q", line)
		}
	}
}

func TestTheFormFitsEveryReasonableTerminal(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	for _, size := range []struct{ width, height int }{
		{80, 24}, {100, 30}, {120, 40}, {160, 50}, {200, 60},
	} {
		m := sized(t, options, "", size.width, size.height)
		view := m.settingsView()
		if got := len(strings.Split(view, "\n")); got > size.height {
			t.Errorf("%dx%d: the form draws %d lines and does not fit",
				size.width, size.height, got)
		}
		for _, line := range strings.Split(view, "\n") {
			if got := lipgloss.Width(line); got > size.width {
				t.Errorf("%dx%d: a line is %d columns wide", size.width, size.height, got)
				break
			}
		}
	}
}

func TestTheEquivalentCommandSurvivesANarrowTerminal(t *testing.T) {
	// Dropping the side panel used to take the command with it, which is the thing
	// that makes this UI worth using.
	options := scan.NewOptions()
	options.Path = "/some/project"
	m := sized(t, options, "", 80, 24)
	if view := m.settingsView(); !strings.Contains(view, "whatsrisky /some/project") {
		t.Errorf("the equivalent command is gone at 80 columns:\n%s", view)
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

	m.values.profileName = "nightly"
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

func TestAProfileLaunchOffersItsOwnNameBack(t *testing.T) {
	// ctrl+s should update the profile you are looking at, not quietly ask for a
	// new name.
	m := newTestModel(t, scan.NewOptions(), "nightly")
	if m.values.profileName != "nightly" {
		t.Errorf("the save-as field holds %q", m.values.profileName)
	}
}

func TestSavingWithoutANameSaysSo(t *testing.T) {
	m := newTestModel(t, scan.NewOptions(), "")
	press(m, "ctrl+s")
	if !strings.Contains(m.notice, "type a profile name") {
		t.Errorf("notice: %q", m.notice)
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

func TestTheFormAppliesBackEverySetting(t *testing.T) {
	// One test that the whole binding is wired, so a field added to the form and
	// forgotten in apply cannot pass silently.
	base := scan.NewOptions()
	base.Path = "/before"
	m := newTestModel(t, base, "")

	v := m.values
	v.path = "/after"
	v.diff = "main..HEAD"
	v.tools = []string{"semgrep"}
	v.aiProvider = "openai"
	v.aiModel = "gpt-5"
	v.aiMode = "review"
	v.formats = []string{"json"}
	v.outDir = "/tmp/out"
	v.openReport = true
	v.minSeverity = "HIGH"
	v.failOn = "CRITICAL"
	v.exclude = "vendor, dist"
	v.skipNoise = false
	v.semgrep = "p/ci,p/golang"
	v.trivy = "vuln"
	v.gitleaks = "git"
	v.jobs = "4"
	v.offline = true
	v.compare = false

	got := m.collect()
	for _, check := range []struct {
		name string
		ok   bool
		got  any
	}{
		{"path", got.Path == "/after", got.Path},
		{"diff", got.Diff == "main..HEAD", got.Diff},
		{"tools", strings.Join(got.Tools, ",") == "semgrep", got.Tools},
		{"provider", got.AIProvider == "openai", got.AIProvider},
		{"model", got.Model == "gpt-5", got.Model},
		{"ai mode", got.AIMode == "review", got.AIMode},
		{"formats", strings.Join(got.Formats, ",") == "json", got.Formats},
		{"out dir", got.OutDir == "/tmp/out", got.OutDir},
		{"open report", got.OpenReport, got.OpenReport},
		{"min severity", got.MinSeverity == "HIGH", got.MinSeverity},
		{"fail-on", got.FailOn == "CRITICAL", got.FailOn},
		{"exclude", strings.Join(got.Exclude, ",") == "vendor,dist", got.Exclude},
		{"skip noise", !got.UseDefaultExcludes, got.UseDefaultExcludes},
		{"semgrep", strings.Join(got.SemgrepConfigs, ",") == "p/ci,p/golang", got.SemgrepConfigs},
		{"trivy", got.TrivyScanners == "vuln", got.TrivyScanners},
		{"gitleaks", got.GitleaksMode == "git", got.GitleaksMode},
		{"jobs", got.Jobs == 4, got.Jobs},
		{"offline", got.Offline, got.Offline},
		{"compare", !got.Compare, got.Compare},
	} {
		if !check.ok {
			t.Errorf("%s did not reach the options: %v", check.name, check.got)
		}
	}
}

func TestABlankTuningFieldKeepsTheDefault(t *testing.T) {
	// An empty --semgrep-config would scan with no rules at all and still look
	// like a scan.
	base := scan.NewOptions()
	m := newTestModel(t, base, "")
	m.values.semgrep = ""
	m.values.trivy = ""
	m.values.jobs = "0"

	got := m.collect()
	if len(got.SemgrepConfigs) == 0 {
		t.Error("a blank semgrep config must leave the default in place")
	}
	if got.TrivyScanners == "" {
		t.Error("a blank trivy scanner list must leave the default in place")
	}
	if got.Jobs < 1 {
		t.Errorf("jobs fell to %d", got.Jobs)
	}
}
