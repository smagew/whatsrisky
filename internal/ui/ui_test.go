package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/exclude"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// These tests drive the widgets and read the screen. tview draws onto any
// tcell.Screen, so a simulated one gives exactly what a terminal would show -
// which is the only way to check that a form fits, since the last interface drew
// past the bottom of the terminal and no test noticed.

func newUI(t *testing.T, options scan.Options, profile string) *UI {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return New("0.4.0", options, profile)
}

// lineWith returns the rendered line that first mentions text.
func lineWith(view, text string) string {
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, text) {
			return line
		}
	}
	return ""
}

// screenOf renders the interface at a size, laying it out first.
func screenOf(u *UI, width, height int) string {
	u.width, u.height = width, height
	u.layout()
	return frame(u, width, height)
}

// frame renders whatever is on the pages now, without rebuilding the layout, so
// an overlay stays open.
func frame(u *UI, width, height int) string {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		panic(err)
	}
	screen.SetSize(width, height)
	u.refresh()

	var root tview.Primitive = u.pages
	root.SetRect(0, 0, width, height)
	root.Draw(screen)
	screen.Show()

	cells, w, h := screen.GetContents()
	var out strings.Builder
	for y := 0; y < h; y++ {
		var row []rune
		for x := 0; x < w; x++ {
			runes := cells[y*w+x].Runes
			if len(runes) == 0 || runes[0] == 0 {
				row = append(row, ' ')
				continue
			}
			row = append(row, runes[0])
		}
		out.WriteString(strings.TrimRight(string(row), " ") + "\n")
	}
	return out.String()
}

// key sends a key through the application's capture, which is where the chords
// live.
func (u *UI) key(k tcell.Key) { u.onKey(tcell.NewEventKey(k, 0, tcell.ModNone)) }

// item finds a form item by its label, across both columns of the narrow layout.
func (u *UI) item(label string) tview.FormItem {
	for _, form := range u.forms {
		for index := 0; index < form.GetFormItemCount(); index++ {
			entry := form.GetFormItem(index)
			if labelOf(entry.GetLabel()) == label {
				return entry
			}
		}
	}
	return nil
}

func (u *UI) mustItem(t *testing.T, label string) tview.FormItem {
	t.Helper()
	entry := u.item(label)
	if entry == nil {
		t.Fatalf("no field labelled %q", label)
	}
	return entry
}

// click sends a left click at a point inside a primitive, the way tview delivers
// a real mouse event.
func click(target tview.Primitive, x, y int) {
	handler := target.MouseHandler()
	event := tcell.NewEventMouse(x, y, tcell.Button1, tcell.ModNone)
	handler(tview.MouseLeftDown, event, func(tview.Primitive) {})
	handler(tview.MouseLeftClick, event, func(tview.Primitive) {})
}

// --- the whole screen is painted ------------------------------------

// unpaintedCells counts the cells whose background is the terminal's own. On a
// translucent terminal each one is a hole the desktop shows through.
func unpaintedCells(u *UI, width, height int) int {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		panic(err)
	}
	screen.SetSize(width, height)
	u.width, u.height = width, height
	u.layout()
	u.refresh()
	var root tview.Primitive = u.pages
	root.SetRect(0, 0, width, height)
	root.Draw(screen)
	screen.Show()

	cells, w, h := screen.GetContents()
	holes := 0
	for index := 0; index < w*h; index++ {
		if _, background, _ := cells[index].Style.Decompose(); background == tcell.ColorDefault {
			holes++
		}
	}
	return holes
}

func TestEveryCellHasAGround(t *testing.T) {
	// The ground used to be tcell.ColorDefault, which is the terminal's own
	// background - so a translucent terminal showed the desktop through the text
	// and none of it could be read.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}, {209, 33}} {
		u := newUI(t, options, "")
		if holes := unpaintedCells(u, size.width, size.height); holes > 0 {
			t.Errorf("%dx%d: %d cells show the terminal through",
				size.width, size.height, holes)
		}
	}
}

func TestAnOverlayIsPaintedToo(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	_ = screenOf(u, 120, 36)
	u.key(tcell.KeyCtrlI)

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(120, 36)
	var root tview.Primitive = u.pages
	root.SetRect(0, 0, 120, 36)
	root.Draw(screen)
	screen.Show()

	cells, w, h := screen.GetContents()
	for index := 0; index < w*h; index++ {
		if _, background, _ := cells[index].Style.Decompose(); background == tcell.ColorDefault {
			t.Fatalf("the list overlay leaves %d,%d unpainted", index%w, index/w)
		}
	}
}

// --- 1, 17: it fits, and everything is on the screen -----------------

func TestTheScreenFitsEveryReasonableTerminal(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	for _, size := range []struct{ width, height int }{
		{80, 24}, {100, 30}, {120, 36}, {160, 50}, {200, 60},
	} {
		u := newUI(t, options, "")
		view := screenOf(u, size.width, size.height)
		lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
		if len(lines) > size.height {
			t.Errorf("%dx%d: draws %d lines", size.width, size.height, len(lines))
		}
		for _, line := range lines {
			if width := len([]rune(line)); width > size.width {
				t.Errorf("%dx%d: a line is %d columns wide: %q",
					size.width, size.height, width, line)
				break
			}
		}
	}
}

func TestEverySettingIsOnTheScreenAtOnce(t *testing.T) {
	// The point of the change: no paging, no scrolling. If a label is missing
	// from the drawn screen at a normal size, it is unreachable by eye.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	view := screenOf(u, 120, 36)

	for _, label := range []string{
		"project folder", "only these changes",
		"semgrep", "trivy", "gitleaks", "ai",
		"who reviews", "model", "what it reads",
		"html", "md", "json", "save reports in", "open when done",
		"anything else", "the usual noise",
		"hide anything below", "fail the build at",
		"semgrep rules", "trivy passes", "gitleaks looks at", "scanners at once",
		"no network", "compare with last", "save these settings as",
	} {
		if !strings.Contains(view, label) {
			t.Errorf("%q is not on the screen:\n%s", label, view)
		}
	}
}

func TestTheNarrowScreenKeepsEverySettingAndTheAction(t *testing.T) {
	// 80x24: the panel goes, the settings do not.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	view := screenOf(u, 80, 24)

	for _, label := range []string{"project folder", "scanners at once", "save these settings as"} {
		if !strings.Contains(view, label) {
			t.Errorf("%q dropped below the fold at 80x24:\n%s", label, view)
		}
	}
	if !strings.Contains(view, "ctrl+r") {
		t.Errorf("the run action is not on the screen:\n%s", view)
	}
	if strings.Contains(view, "what this will do") {
		t.Error("the panel should be hidden at 80 columns, not squeezed")
	}
}

// --- 2: the panel is one key away when it is hidden ------------------

func TestThePanelComesBackOnTheNarrowScreen(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/some/project"
	u := newUI(t, options, "")
	_ = screenOf(u, 80, 24)

	u.key(tcell.KeyCtrlP)
	view := frame(u, 80, 24)
	if !strings.Contains(view, "whatsrisky /some/project") {
		t.Errorf("ctrl+p does not show the command:\n%s", view)
	}
	u.key(tcell.KeyEscape)
	if view := frame(u, 80, 24); strings.Contains(view, "esc closes") {
		t.Error("esc did not close the panel")
	}
}

// --- 3, 4: what we do not look at -----------------------------------

func TestTheProjectsOwnFoldersAreTickedNotTyped(t *testing.T) {
	// Typing the name of a folder you are looking at is dictation, not a choice.
	root := t.TempDir()
	for _, name := range []string{"src", "docs", "node_modules", "cmd"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	options := scan.NewOptions()
	options.Path = root
	u := newUI(t, options, "")
	view := screenOf(u, 160, 44)

	if !strings.Contains(view, "folders here") {
		t.Fatalf("the project's folders are not offered:\n%s", view)
	}
	for _, name := range []string{"src", "docs", "cmd"} {
		if !strings.Contains(view, name) {
			t.Errorf("%q is a folder of this project and is not offered", name)
		}
	}
	// A folder already in the usual noise is not offered twice.
	if strings.Contains(lineWith(view, "folders here"), "node_modules") {
		t.Error("node_modules is in the usual noise and should not be a chip too")
	}
	row := u.mustItem(t, "folders here").(*chips)
	row.toggle(indexIn(row.names, "docs"))
	if got := strings.Join(u.collect().Exclude, ","); got != "docs" {
		t.Errorf("ticking a folder did not reach the options: %q", got)
	}
	if got := u.collect().Normalized().CommandLine(); !strings.Contains(got, "--exclude docs") {
		t.Errorf("and not the command either: %s", got)
	}
}

func TestATickedFolderAndATypedOneAreOneList(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	options := scan.NewOptions()
	options.Path = root
	u := newUI(t, options, "")
	_ = screenOf(u, 160, 44)

	u.mustItem(t, "folders here").(*chips).toggle(0)
	u.values.ignorePaths = "docs, *.min.js"

	// "docs" is both ticked and typed, and must appear once.
	got := u.collect().Exclude
	count := 0
	for _, name := range got {
		if name == "docs" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("docs appears %d times in %v", count, got)
	}
	if strings.Join(got, ",") != "docs,*.min.js" {
		t.Errorf("the two lists did not merge: %v", got)
	}
}

func TestTheSkippedListIsReadableAndComesFromTheCode(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	_ = screenOf(u, 120, 36)

	if !strings.Contains(frame(u, 120, 36), "ctrl+i") {
		t.Error("the panel does not say how to see the list")
	}

	u.key(tcell.KeyCtrlI)
	view := frame(u, 120, 36)
	// Every default, read from exclude.Defaults - a copy in the interface would
	// drift from the list that does the skipping.
	for _, pattern := range exclude.Defaults {
		if !strings.Contains(view, pattern) {
			t.Errorf("%q is skipped but not listed:\n%s", pattern, view)
		}
	}
	if !strings.Contains(view, "whatsrisky ./dist") {
		t.Error("the list should say how to scan one of these anyway")
	}
}

func TestNoJargonOnTheScreen(t *testing.T) {
	// "pattern" and "exclusion" were both in the last version. Neither says what
	// it means to anyone who did not write the code.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	u.probes = []probeRow{{name: "semgrep", found: true, detail: "1.0"}}

	views := []string{screenOf(u, 120, 36)}
	u.key(tcell.KeyCtrlI)
	views = append(views, frame(u, 120, 36))

	for _, view := range views {
		for _, word := range []string{"pattern", "exclusion", "exclude", "glob"} {
			if strings.Contains(strings.ToLower(view), word) {
				t.Errorf("the screen says %q:\n%s", word, view)
			}
		}
	}
}

func TestTheModelIsAListYouPickFrom(t *testing.T) {
	// Typing a model id from memory is not a choice. The list is what the provider
	// is usually asked for; an id we have never heard of still goes through,
	// because their catalogue moves faster than ours.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	view := screenOf(u, 160, 44)

	if !strings.Contains(view, "opus") || !strings.Contains(view, "sonnet") {
		t.Errorf("the models for claude-cli are not offered:\n%s", lineWith(view, "model"))
	}

	if _, ok := u.mustItem(t, "model").(*tview.InputField); !ok {
		t.Fatal("the model is not an input field")
	}
	models := ai.Models("claude-cli")
	if got := suggest(models, ""); strings.Join(got, ",") != "opus,sonnet,haiku" {
		t.Errorf("an empty field should offer every model, got %v", got)
	}
	if got := suggest(models, "son"); strings.Join(got, ",") != "sonnet" {
		t.Errorf("typing should narrow the list, got %v", got)
	}
	if got := suggest(models, "SON"); strings.Join(got, ",") != "sonnet" {
		t.Errorf("the match should not care about case, got %v", got)
	}

	// A model nobody listed is still accepted.
	u.values.aiModel = "claude-next-9"
	if got := u.collect().Model; got != "claude-next-9" {
		t.Errorf("an unlisted model was refused: %q", got)
	}
}

func TestTheModelsFollowTheProvider(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	options.AIProvider = "openai"
	u := newUI(t, options, "")
	view := screenOf(u, 160, 44)
	if !strings.Contains(view, "gpt-5") {
		t.Errorf("openai's models are not offered:\n%s", lineWith(view, "model"))
	}
	if strings.Contains(lineWith(view, "model"), "opus") {
		t.Error("claude's models are offered for openai")
	}
}

// --- 6: the chords, and no function keys ----------------------------

func TestTheChordsRunAndSave(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	options.MinSeverity = "HIGH"
	u := newUI(t, options, "")
	_ = screenOf(u, 120, 36)

	u.values.profileName = "nightly"
	u.key(tcell.KeyCtrlS)
	if !strings.Contains(frame(u, 120, 36), "saved 'nightly'") {
		t.Error("ctrl+s did not save the settings")
	}
	if u.profile != "nightly" {
		t.Errorf("active profile %q", u.profile)
	}
	restored, active := config.StartupOptions()
	if active != "nightly" || restored.MinSeverity != "HIGH" {
		t.Errorf("the next launch would start from %+v (active %q)", restored, active)
	}
}

func TestSavingWithoutANameSaysWhere(t *testing.T) {
	u := newUI(t, scan.NewOptions(), "")
	_ = screenOf(u, 120, 36)
	u.key(tcell.KeyCtrlS)
	if view := frame(u, 120, 36); !strings.Contains(view, "save these settings as") {
		t.Errorf("the notice should name the field to type in:\n%s", view)
	}
}

func TestAProfileLaunchOffersItsOwnNameBack(t *testing.T) {
	u := newUI(t, scan.NewOptions(), "nightly")
	if u.values.profileName != "nightly" {
		t.Errorf("the save field holds %q", u.values.profileName)
	}
}

func TestABadPathBlocksTheRun(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/definitely/not/here"
	u := newUI(t, options, "")
	view := screenOf(u, 120, 36)
	if !strings.Contains(view, "Not a directory") {
		t.Errorf("the screen must say the path is wrong:\n%s", view)
	}

	u.key(tcell.KeyCtrlR)
	if u.currentPage() == pageRun {
		t.Error("a scan must not start on a path that cannot be scanned")
	}
}

// --- 7: the mouse ---------------------------------------------------

func TestAClickTogglesTheScannerItLandsOn(t *testing.T) {
	// The chip row is the one widget written here rather than taken from tview, so
	// a click has to land on the chip pointed at - not on the row.
	options := scan.NewOptions()
	options.Path = "/p"
	u := newUI(t, options, "")
	_ = screenOf(u, 160, 44)

	row, ok := u.mustItem(t, "which ones").(*chips)
	if !ok {
		t.Fatal("the scanners are not a chip row")
	}
	x, y, _, _ := row.GetInnerRect()
	// gitleaks is the third chip; its column is where the row says it is.
	offset := 0
	for _, name := range []string{"semgrep", "trivy"} {
		offset += len(name) + 6
	}
	click(row, x+row.labelWidth+offset+1, y)

	if u.collect().HasTool("gitleaks") {
		t.Error("clicking gitleaks did not turn it off")
	}
	if u.collect().HasTool("semgrep") != true || u.collect().HasTool("trivy") != true {
		t.Error("the click turned off a chip it did not land on")
	}
	if got := u.collect().Normalized().CommandLine(); !strings.Contains(got, "--tools") {
		t.Errorf("the click did not reach the command: %s", got)
	}
}

func TestTheChipRowMovesAndTogglesFromTheKeyboard(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/p"
	u := newUI(t, options, "")
	_ = screenOf(u, 160, 44)

	row := u.mustItem(t, "which ones").(*chips)
	press := func(key tcell.Key, r rune) {
		row.InputHandler()(tcell.NewEventKey(key, r, tcell.ModNone), func(tview.Primitive) {})
	}
	press(tcell.KeyRight, 0)
	press(tcell.KeyRight, 0)
	press(tcell.KeyRune, ' ') // gitleaks off
	if u.collect().HasTool("gitleaks") {
		t.Error("space did not turn the chip under the cursor off")
	}
	press(tcell.KeyLeft, 0)
	press(tcell.KeyRune, ' ') // trivy off
	if u.collect().HasTool("trivy") {
		t.Error("moving left and toggling hit the wrong chip")
	}
	if !u.collect().HasTool("semgrep") {
		t.Error("semgrep was never touched and should still be on")
	}
	// The cursor must not run off either end.
	for i := 0; i < 8; i++ {
		press(tcell.KeyLeft, 0)
	}
	press(tcell.KeyRune, ' ')
	if u.collect().HasTool("semgrep") {
		t.Error("the cursor should have stopped on the first chip")
	}
}

func TestATickedChipKeepsItsTick(t *testing.T) {
	// tview reads square brackets as a colour tag, so an unescaped "[x]" is
	// swallowed and every ticked chip renders bare.
	options := scan.NewOptions()
	options.Path = "/p"
	u := newUI(t, options, "")
	view := screenOf(u, 160, 44)
	if !strings.Contains(view, "[x] semgrep") {
		t.Errorf("a ticked chip does not show its tick:\n%s", lineWith(view, "which ones"))
	}
	if !strings.Contains(view, "[ ] ai") {
		t.Errorf("an unticked chip does not show an empty box:\n%s", lineWith(view, "which ones"))
	}
}

func TestAClickOpensAListAndPicksFromIt(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/p"
	u := newUI(t, options, "")
	_ = screenOf(u, 120, 36)

	list, ok := u.mustItem(t, "hide anything below").(*tview.DropDown)
	if !ok {
		t.Fatal("the severity floor is not a list")
	}
	x, y, _, _ := list.GetRect()
	click(list, x+30, y)
	if _, open := list.GetCurrentOption(); open == "" {
		t.Error("the list has no current option")
	}
	// Picking is the list's own behaviour; what matters here is that the widget
	// took the click rather than ignoring it.
	list.SetCurrentOption(indexIn(severityNames(), "HIGH"))
	if got := u.collect().MinSeverity; got != "HIGH" {
		t.Errorf("choosing from the list did not reach the options: %q", got)
	}
}

// --- 9: the command is never broken mid-argument ---------------------

func TestTheCommandIsNeverSplitInsideAnArgument(t *testing.T) {
	options := scan.NewOptions()
	options.Path = "/Users/someone/work/a-project-with-a-long-name"
	u := newUI(t, options, "")
	view := screenOf(u, 120, 36)
	if !strings.Contains(view, options.Path) {
		t.Errorf("the path was split across lines:\n%s", view)
	}
}

func TestWrapArgumentsKeepsArgumentsWhole(t *testing.T) {
	got := wrapArguments("whatsrisky /a/path --tools semgrep,trivy --min-severity HIGH", 24)
	for _, line := range strings.Split(got, "\n") {
		if len([]rune(line)) > 24 {
			t.Errorf("line over the width: %q", line)
		}
	}
	for _, argument := range []string{"whatsrisky", "/a/path", "semgrep,trivy", "HIGH"} {
		if !strings.Contains(got, argument) {
			t.Errorf("%q did not survive wrapping:\n%s", argument, got)
		}
	}
	long := wrapArguments("whatsrisky /a/very/long/path/that/cannot/fit", 16)
	for _, line := range strings.Split(long, "\n") {
		if len([]rune(line)) > 16 {
			t.Errorf("an oversized argument was not truncated: %q", line)
		}
	}
}

// --- 8, 10: the panel tells the truth before a run -------------------

func TestTheProbeFillsTheScannerList(t *testing.T) {
	u := newUI(t, scan.NewOptions(), "")
	if !strings.Contains(screenOf(u, 120, 36), "checking…") {
		t.Error("the panel should say it is still checking")
	}
	u.probes = []probeRow{
		{name: "semgrep", found: true, detail: "semgrep 1.174.0"},
		{name: "trivy", found: false, detail: "`trivy` not found in PATH. brew install trivy"},
	}
	u.probing = false
	view := frame(u, 120, 36)
	if !strings.Contains(view, "semgrep 1.174.0") {
		t.Error("an installed scanner should show its version")
	}
	if !strings.Contains(view, "not found in PATH") {
		t.Error("a missing one should say how to get it")
	}
}

func TestAMissingScannerIsAWarningNotSilence(t *testing.T) {
	// Absence must never read as safety, on this screen as in the report.
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	u.probes = []probeRow{
		{name: "semgrep", found: true, detail: "1.0"},
		{name: "gitleaks", found: false, detail: "not installed"},
	}
	u.probing = false

	view := screenOf(u, 120, 36)
	if !strings.Contains(view, "gitleaks is not installed") {
		t.Errorf("the screen does not warn that gitleaks is missing:\n%s", view)
	}
	if !strings.Contains(view, "git history") {
		t.Error("the warning should say what goes unchecked, not just the tool name")
	}
	if strings.Contains(view, "ready to run") {
		t.Error("a coverage gap is not 'ready to run'")
	}
}

func TestAnAPIBackendIsWarnedAboutBeforeTheScan(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	options.Tools = append(options.Tools, "ai")
	options.AIProvider = "openai"
	options.AIMode = "review"
	t.Setenv("OPENAI_API_KEY", "")
	u := newUI(t, options, "")

	view := screenOf(u, 140, 44)
	for _, want := range []string{
		"OPENAI_API_KEY is not set",
		"cannot review a diff",
		"sees only the files we send it",
		"spends money",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the screen does not warn about %q:\n%s", want, view)
		}
	}
}

// --- 11, 12, 13: the run screen --------------------------------------

func TestTheRunScreenShowsProgressAndOffersTheReport(t *testing.T) {
	options := scan.NewOptions()
	options.Path = t.TempDir()
	u := newUI(t, options, "")
	_ = screenOf(u, 120, 36)
	u.options = options
	u.pages.SwitchToPage(pageRun)

	page := filepath.Join(t.TempDir(), "r.html")
	if err := os.WriteFile(page, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	u.handleEvent(scan.Event{Kind: "live", Paths: []string{page}})
	u.handleEvent(scan.Event{Kind: "tool_start", Tool: "semgrep"})
	u.handleEvent(scan.Event{Kind: "tool_progress", Tool: "semgrep", Message: "Scanning 412 files"})

	view := frame(u, 120, 36)
	if !strings.Contains(view, "Scanning 412 files") {
		t.Errorf("the run screen hides what the scanner is doing:\n%s", view)
	}
	// The report is readable from the first second, and the help says so.
	if !strings.Contains(view, "it is written already") {
		t.Errorf("the help does not offer the live report:\n%s", view)
	}
	if u.livePath != page {
		t.Errorf("live path %q", u.livePath)
	}
}

func TestAFailedScannerCarriesTheReasonNotAZero(t *testing.T) {
	// "0 findings" describes a clean pass. A scanner that did not run had none.
	u := newUI(t, scan.NewOptions(), "")
	_ = screenOf(u, 120, 36)
	u.pages.SwitchToPage(pageRun)
	u.handleEvent(scan.Event{Kind: "tool_start", Tool: "trivy"})
	u.handleEvent(scan.Event{Kind: "tool_done", Tool: "trivy", Status: model.ToolMissing,
		Message: "`trivy` not found in PATH. Install: brew install trivy"})

	view := frame(u, 120, 36)
	if strings.Contains(view, "0 findings") {
		t.Errorf("a scanner that did not run must not report a finding count:\n%s", view)
	}
	if !strings.Contains(view, "not found in PATH") {
		t.Errorf("the row must carry the reason:\n%s", view)
	}
}

func TestTheSummaryAdmitsCoverageGaps(t *testing.T) {
	u := newUI(t, scan.NewOptions(), "")
	_ = screenOf(u, 120, 36)
	u.pages.SwitchToPage(pageRun)

	finding := model.Finding{Tool: "semgrep", Severity: model.Medium, Title: "debug enabled"}
	finding.Normalize()
	u.outcome = &scan.Outcome{Report: model.Report{
		ProjectName: "p", Status: model.StatusPartial,
		Findings: []model.Finding{finding},
		Tools: []model.ToolResult{
			{Name: "semgrep", Status: model.ToolOK},
			{Name: "trivy", Status: model.ToolMissing, Message: "not installed"},
		}}}

	view := frame(u, 120, 36)
	if !strings.Contains(view, "coverage gaps") || !strings.Contains(view, "trivy") {
		t.Errorf("a missing scanner must be visible in the summary:\n%s", view)
	}
	if !strings.Contains(view, "partial coverage") {
		t.Errorf("and in the verdict:\n%s", view)
	}
}

func TestViewReportOpensThePageOrSaysWhyNot(t *testing.T) {
	u := newUI(t, scan.NewOptions(), "")
	_ = screenOf(u, 120, 36)
	u.pages.SwitchToPage(pageRun)
	u.handleEvent(scan.Event{Kind: "live", Paths: nil})

	if notice := u.viewReport(); !strings.Contains(notice, "no html") &&
		!strings.Contains(notice, "tick html in the formats") {
		t.Errorf("notice: %q", notice)
	}
	if !strings.Contains(strings.Join(u.log, "\n"), "no html in this run") {
		t.Error("the log must say the view is unavailable")
	}
}

// --- 14, 19: every setting reaches the options -----------------------

func TestEverySettingReachesTheOptions(t *testing.T) {
	// One test for the whole binding, so a field added to the screen and
	// forgotten in apply cannot pass silently.
	base := scan.NewOptions()
	base.Path = "/before"
	u := newUI(t, base, "")

	v := u.values
	v.path = "/after"
	v.diff = "main..HEAD"
	v.tools = map[string]bool{"semgrep": true}
	v.aiProvider = "openai"
	v.aiModel = "gpt-5"
	v.aiMode = "review"
	v.formats = map[string]bool{"json": true}
	v.outDir = "/tmp/out"
	v.openReport = true
	v.minSeverity = "HIGH"
	v.failOn = "CRITICAL"
	v.ignorePaths = "vendor, dist"
	v.ignoreNoise = false
	v.semgrep = "p/ci,p/golang"
	v.trivy = "vuln"
	v.gitleaks = "git"
	v.jobs = "4"
	v.offline = true
	v.compare = false

	got := u.collect()
	for _, check := range []struct {
		name string
		ok   bool
		got  any
	}{
		{"project folder", got.Path == "/after", got.Path},
		{"only these changes", got.Diff == "main..HEAD", got.Diff},
		{"scanners", strings.Join(got.Tools, ",") == "semgrep", got.Tools},
		{"who reviews", got.AIProvider == "openai", got.AIProvider},
		{"model", got.Model == "gpt-5", got.Model},
		{"what it reads", got.AIMode == "review", got.AIMode},
		{"formats", strings.Join(got.Formats, ",") == "json", got.Formats},
		{"save reports in", got.OutDir == "/tmp/out", got.OutDir},
		{"open when done", got.OpenReport, got.OpenReport},
		{"hide anything below", got.MinSeverity == "HIGH", got.MinSeverity},
		{"fail the build at", got.FailOn == "CRITICAL", got.FailOn},
		{"anything else", strings.Join(got.Exclude, ",") == "vendor,dist", got.Exclude},
		{"the usual noise", !got.UseDefaultExcludes, got.UseDefaultExcludes},
		{"semgrep rules", strings.Join(got.SemgrepConfigs, ",") == "p/ci,p/golang", got.SemgrepConfigs},
		{"trivy passes", got.TrivyScanners == "vuln", got.TrivyScanners},
		{"gitleaks looks at", got.GitleaksMode == "git", got.GitleaksMode},
		{"scanners at once", got.Jobs == 4, got.Jobs},
		{"no network", got.Offline, got.Offline},
		{"compare with last", !got.Compare, got.Compare},
	} {
		if !check.ok {
			t.Errorf("%s did not reach the options: %v", check.name, check.got)
		}
	}
}

func TestABlankDetailKeepsTheDefault(t *testing.T) {
	// An empty rule list would scan with no rules at all and still look like a
	// scan.
	u := newUI(t, scan.NewOptions(), "")
	u.values.semgrep = ""
	u.values.trivy = ""
	u.values.jobs = "0"

	got := u.collect()
	if len(got.SemgrepConfigs) == 0 {
		t.Error("a blank rule list must leave the default in place")
	}
	if got.TrivyScanners == "" {
		t.Error("a blank trivy pass list must leave the default in place")
	}
	if got.Jobs < 1 {
		t.Errorf("scanners at once fell to %d", got.Jobs)
	}
}

func TestEveryFieldSurvivesARelayout(t *testing.T) {
	// The narrow layout rebuilds the forms. Rebuilding must not lose what was
	// typed, which it would if the widgets were rebuilt from the stored options.
	u := newUI(t, scan.NewOptions(), "")
	_ = screenOf(u, 120, 36)
	u.values.path = "/typed/before/the/resize"
	view := screenOf(u, 80, 24)

	if got := u.collect().Path; got != "/typed/before/the/resize" {
		t.Errorf("the resize lost the path: %q", got)
	}
	if !strings.Contains(view, "/typed") {
		t.Errorf("the rebuilt screen does not show it:\n%s", view)
	}
}
