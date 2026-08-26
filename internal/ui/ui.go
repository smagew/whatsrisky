package ui

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/progress"
	"github.com/smagew/whatsrisky/internal/scan"
)

// Names of the pages. tview switches between them; there is no mode flag to keep
// in step with what is drawn.
const (
	pageSettings = "settings"
	pageRun      = "run"
	pageIgnore   = "ignore"
	pagePanel    = "panel"
)

// UI is the whole interface. tview is imperative: the widgets hold the state the
// user can see, and this holds the state they cannot.
type UI struct {
	version string
	options scan.Options // what a run will use, and what the form started from
	profile string
	values  *values

	app    *tview.Application
	pages  *tview.Pages
	header *tview.TextView
	panel  *tview.TextView
	notice *tview.TextView
	keys   *tview.TextView
	body   *tview.Flex
	run    *tview.TextView
	forms  []*tview.Form

	probes  []probeRow
	probing bool

	dirs    []string // the project's own folders, for the chips
	dirsFor string   // the path they were read from

	progress     *progress.Model
	toolMessages map[string]string
	log          []string
	livePath     string
	outcome      *scan.Outcome
	runErr       error

	width    int
	height   int
	held     string // the last notice, kept so a redraw does not wipe it
	forceOne bool   // tests only: measure the one-column arrangement
	exit     int
}

// New builds the interface from what a launch should start from.
// paintGround makes the ground apply to primitives this file never touches: the
// list a drop-down opens, the frame around a page. Without it those come up in the
// terminal's own colours and the screen looks half-painted.
func paintGround() {
	tview.Styles.PrimitiveBackgroundColor = groundColor
	tview.Styles.ContrastBackgroundColor = fieldColor
	tview.Styles.MoreContrastBackgroundColor = lineColor
	tview.Styles.PrimaryTextColor = inkColor
	tview.Styles.SecondaryTextColor = markColor
	tview.Styles.TertiaryTextColor = ink3Color
	tview.Styles.BorderColor = lineColor
	tview.Styles.TitleColor = markColor
	tview.Styles.InverseTextColor = groundColor
}

func New(version string, options scan.Options, profile string) *UI {
	paintGround()
	u := &UI{
		version:      version,
		options:      options,
		profile:      profile,
		values:       newValues(options),
		probing:      true,
		progress:     progress.New(),
		toolMessages: map[string]string{},
		width:        100,
		height:       30,
	}
	// Launched from a profile, offer that name back: ctrl+s should update the
	// settings you are looking at, not quietly ask for a new name.
	u.values.profileName = profile
	u.build()
	return u
}

// Run opens the interface and returns the process exit code.
func Run(version string, options scan.Options, profile string) (int, error) {
	u := New(version, options, profile)
	u.app = tview.NewApplication().
		SetRoot(u.pages, true).
		EnableMouse(true).
		SetInputCapture(u.onKey)
	go u.probe()
	if err := u.app.Run(); err != nil {
		return 1, err
	}
	return u.exit, nil
}

// build assembles the pages. Called again on a resize, because the narrow layout
// is a different arrangement rather than the same one squeezed.
func (u *UI) build() {
	u.header = textView()
	u.panel = textView()
	u.notice = textView()
	u.keys = textView()
	u.run = textView()
	u.run.SetScrollable(true)

	u.pages = tview.NewPages()
	u.pages.SetBackgroundColor(groundColor)
	u.layout()

	runPage := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.header, 1, 0, false).
		AddItem(u.run, 0, 1, true).
		AddItem(u.keys, 1, 0, false)
	runPage.SetBackgroundColor(groundColor)

	u.pages.AddPage(pageRun, runPage, true, false)
	u.pages.SwitchToPage(pageSettings)
	u.refresh()
}

// layout arranges the settings page for the current size. Wide: one column of
// settings beside the panel. Narrow: no panel, and the settings in two columns,
// so nothing sits below the fold.
func (u *UI) layout() {
	fields := u.fields()
	// The arrangement is chosen by whether the settings actually fit, and the
	// answer is measured rather than counted: a chip row is one field but may be
	// three lines, so counting fields would claim room that is not there.
	oneColumn := u.fitsOneColumn(fields)
	u.forms = nil

	var content tview.Primitive
	if !oneColumn {
		// Two columns because one is too tall - but the panel stays if there is
		// width for it. Losing the command and the warnings is a bigger loss than
		// a narrower field.
		half := (len(fields) + 1) / 2
		// Split on a section boundary, or a section's heading ends up in one
		// column and its settings in the other.
		for half < len(fields) && fields[half].section == fields[half-1].section {
			half++
		}
		room := u.width
		if u.hasPanel() {
			room -= u.panelWidth()
		}
		left := u.newForm(fields[:half], maxInt(8, room/2-22), false)
		right := u.newForm(fields[half:], maxInt(8, room/2-22), true)
		u.forms = []*tview.Form{left, right}
		content = tview.NewFlex().AddItem(left, 0, 1, true).AddItem(right, 0, 1, false)
		if u.hasPanel() {
			u.dressPanel()
			content = tview.NewFlex().
				AddItem(content, 0, 1, true).
				AddItem(u.panel, u.panelWidth(), 0, false)
		}
	} else {
		panelWidth := u.panelWidth()
		form := u.newForm(fields, maxInt(16, u.width-panelWidth-30), true)
		u.forms = []*tview.Form{form}

		u.dressPanel()
		content = tview.NewFlex().
			AddItem(form, 0, 1, true).
			AddItem(u.panel, panelWidth, 0, false)
	}

	page := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.header, 1, 0, false).
		AddItem(content, 0, 1, true).
		AddItem(u.notice, 1, 0, false).
		AddItem(u.keys, 1, 0, false)
	page.SetBackgroundColor(groundColor)

	u.pages.RemovePage(pageSettings)
	u.pages.AddPage(pageSettings, page, true, true)
}

// panelWidth is decided before the form's. The panel carries the command and the
// warnings, and starving it is what made both wrap mid-word. Beside two columns
// of settings it takes the minimum that still fits a path, because there the
// fields are the scarce thing.
//
// It cannot ask fitsOneColumn, which asks it back, so it goes on height alone -
// the wide panel is only ever wanted when there is room to spare.
func (u *UI) panelWidth() int {
	if u.width >= 100 && u.height >= 40 {
		return minInt(52, maxInt(34, u.width*38/100))
	}
	return 34
}

// fitsOneColumn asks the form itself how tall it would be. Five rows go to the
// header, the notice, the key line and the form's own padding at each end - a
// number measured once and then relied on.
func (u *UI) fitsOneColumn(fields []field) bool {
	if u.width < 100 {
		return false
	}
	return u.formRows(fields, u.width-u.panelWidth()-30)+5 <= u.height
}

// formRows builds the column and adds up what its items ask for. Throwaway work,
// once per resize, in exchange for not guessing.
func (u *UI) formRows(fields []field, width int) int {
	form := u.newForm(fields, width, false)
	rows := 0
	for index := 0; index < form.GetFormItemCount(); index++ {
		rows += form.GetFormItem(index).GetFieldHeight()
	}
	return rows
}

// hasPanel says whether the panel fits beside the form. Two columns of settings
// need about eighty columns, so the panel survives from about a hundred and
// twenty. Where it does not fit, ctrl+p brings it up: hidden is not gone.
func (u *UI) hasPanel() bool {
	if u.fitsOneColumn(u.fields()) {
		return true
	}
	return u.width >= 118
}

func (u *UI) dressPanel() {
	u.panel.SetBorder(true).SetBorderColor(lineColor).
		SetTitle(" what this will do ").SetTitleColor(markColor).
		SetTitleAlign(tview.AlignLeft)
}

// refresh redraws everything that is derived from the settings. Cheap enough to
// call on every keystroke, which is what keeps the panel honest.
func (u *UI) refresh() {
	options := u.collect()
	if problems := options.Validate(isDirectory); len(problems) > 0 {
		u.notice.SetText(flagTag + shorten(strings.Join(problems, "; "),
			maxInt(20, u.width-2)) + resetTag)
	} else if u.held == "" {
		u.notice.SetText("")
	}
	name := u.profile
	if name == "" {
		name = "unsaved"
	}
	u.header.SetText(titleTag + "whatsrisky" + resetTag + dimTag +
		"  " + name + " · " + u.version + " · report schema " +
		itoa(model.SchemaVersion) + resetTag)
	u.panel.SetText(u.panelText(options, u.panelWidth()-2))
	u.keys.SetText(u.keyLine())
	if u.pages != nil && u.currentPage() == pageRun {
		u.run.SetText(u.runText(u.width))
	}
}

func (u *UI) keyLine() string {
	if u.currentPage() == pageRun {
		if u.finished() {
			return markTag + " v " + resetTag + dimTag +
				" open the report · esc back to settings · ctrl+q quit" + resetTag
		}
		return markTag + " v " + resetTag + dimTag +
			" open the report (it is written already) · ctrl+q stop" + resetTag
	}
	run := "[#1c1c1c:#87af87:b] ▶ ctrl+r  run scan " + resetTag
	if u.width < 100 {
		// The action must never be the part that gets cut off.
		return run + dimTag + "  ctrl+p what this does · ctrl+s save · ctrl+q quit" + resetTag
	}
	return run + dimTag +
		"  ctrl+s save settings · ctrl+i what we skip · tab or click to move · ctrl+q quit" +
		resetTag
}

func (u *UI) currentPage() string {
	if u.pages == nil {
		return pageSettings
	}
	name, _ := u.pages.GetFrontPage()
	return name
}

// onKey is the application's capture, which tview runs before the focused widget.
// That is why the chords can be plain ctrl+r and ctrl+s: the fields never see
// them, and none of tview's fields bind either one.
func (u *UI) onKey(event *tcell.EventKey) *tcell.EventKey {
	switch event.Key() {
	case tcell.KeyCtrlQ:
		u.stop()
		return nil
	case tcell.KeyCtrlR:
		if u.currentPage() == pageSettings {
			u.start()
		}
		return nil
	case tcell.KeyCtrlS:
		if u.currentPage() == pageSettings {
			u.setNotice(u.saveProfile())
		}
		return nil
	case tcell.KeyCtrlI:
		u.toggleIgnore()
		return nil
	case tcell.KeyCtrlP:
		u.togglePanel()
		return nil
	case tcell.KeyEscape:
		switch u.currentPage() {
		case pageIgnore:
			u.pages.RemovePage(pageIgnore)
			return nil
		case pagePanel:
			u.pages.RemovePage(pagePanel)
			return nil
		case pagePicker:
			u.pages.RemovePage(pagePicker)
			u.refresh()
			return nil
		case pageRun:
			if u.finished() {
				u.pages.SwitchToPage(pageSettings)
				u.setNotice("")
				u.refresh()
			}
			return nil
		}
	case tcell.KeyRune:
		if event.Rune() == 'v' && u.currentPage() == pageRun {
			u.setNotice(u.viewReport())
			return nil
		}
	}
	return event
}

// toggleIgnore shows or hides the list of what is always skipped.
func (u *UI) toggleIgnore() {
	if u.currentPage() == pageIgnore {
		u.pages.RemovePage(pageIgnore)
		return
	}
	view := textView()
	view.SetScrollable(true)
	view.SetBorder(true).SetBorderColor(lineColor).
		SetTitle(" what we do not look at — esc closes ").SetTitleColor(markColor).
		SetTitleAlign(tview.AlignLeft)
	view.SetText(ignoreText(u.width - 8))
	u.pages.AddPage(pageIgnore, centred(view, u.width-8, minInt(u.height-2, 26)), true, true)
}

// togglePanel shows what the settings amount to when there is no room to keep it
// beside the form. Hidden is not gone: the command and the warnings are the
// reason this screen is worth using.
func (u *UI) togglePanel() {
	if u.currentPage() == pagePanel {
		u.pages.RemovePage(pagePanel)
		return
	}
	width := minInt(u.width-4, 60)
	view := textView()
	view.SetScrollable(true)
	view.SetBorder(true).SetBorderColor(lineColor).
		SetTitle(" what this will do — esc closes ").SetTitleColor(markColor).
		SetTitleAlign(tview.AlignLeft)
	view.SetText(u.panelText(u.collect(), width-2))
	u.pages.AddPage(pagePanel, centred(view, width, minInt(u.height-2, 22)), true, true)
}

// start validates and launches a scan. A bad path stops here: the run screen must
// never open on something that cannot be scanned.
func (u *UI) start() {
	options := u.collect().Normalized()
	if problems := options.Validate(isDirectory); len(problems) > 0 {
		u.setNotice(strings.Join(problems, "; "))
		return
	}
	_ = config.SaveLast(options)

	u.options = options
	u.progress = progress.New()
	u.toolMessages = map[string]string{}
	u.log = nil
	u.livePath = ""
	u.outcome = nil
	u.runErr = nil
	u.exit = 0

	u.pages.SwitchToPage(pageRun)
	u.setNotice("")
	u.refresh()

	go func() {
		outcome, err := scan.Run(options, func(event scan.Event) {
			u.update(func() { u.handleEvent(event) })
		})
		u.update(func() {
			if err != nil {
				u.runErr = err
			} else {
				u.outcome = &outcome
				u.exit = outcome.ExitCode
			}
		})
	}()
	u.tick()
}

// tick keeps the spinner turning while a scan runs, and stops as soon as it does.
// Redrawing is the whole job: progress.Spinner advances the frame itself.
func (u *UI) tick() {
	if u.app == nil {
		return
	}
	go func() {
		for !u.finished() {
			time.Sleep(120 * time.Millisecond)
			u.update(func() {})
		}
	}()
}

// update runs a change on the drawing goroutine. Every widget write from a scan
// goroutine goes through here; tview is not safe to touch from anywhere else.
func (u *UI) update(change func()) {
	if u.app == nil {
		change()
		u.refresh()
		return
	}
	u.app.QueueUpdateDraw(func() {
		change()
		u.refresh()
	})
}

func (u *UI) setNotice(text string) {
	u.held = text
	if text == "" {
		u.notice.SetText("")
		return
	}
	u.notice.SetText(markTag + shorten(text, maxInt(20, u.width-2)) + resetTag)
}

func (u *UI) stop() {
	if u.app != nil {
		u.app.Stop()
	}
}

// collect reads the widgets back into options.
func (u *UI) collect() scan.Options { return u.values.apply(u.options) }

func (u *UI) viewReport() string {
	target := u.livePath
	if target == "" && u.outcome != nil {
		for _, path := range u.outcome.Written {
			if filepath.Ext(path) == ".html" {
				target = path
				break
			}
		}
	}
	if target == "" {
		return "this run writes no html, so there is no page to view — tick html in the formats"
	}
	if !openFile(target) {
		return "could not open the file on this platform"
	}
	return "opened " + filepath.Base(target)
}

func openFile(path string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", path)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		command = exec.Command("xdg-open", path)
	}
	return command.Start() == nil
}

// --- small helpers ---------------------------------------------------

func textView() *tview.TextView {
	view := tview.NewTextView().SetDynamicColors(true)
	view.SetBackgroundColor(groundColor)
	view.SetTextColor(inkColor)
	return view
}

// centred puts a primitive in the middle of the screen without a modal's shadow.
func centred(inner tview.Primitive, width, height int) tview.Primitive {
	// Boxes rather than nil for the margins: a nil item paints nothing, so on a
	// translucent terminal the space around an overlay stays see-through.
	row := tview.NewFlex().
		AddItem(ground(), 0, 1, false).
		AddItem(inner, width, 0, true).
		AddItem(ground(), 0, 1, false)
	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ground(), 0, 1, false).
		AddItem(row, height, 0, true).
		AddItem(ground(), 0, 1, false)
	frame.SetBackgroundColor(groundColor)
	return frame
}

func ground() *tview.Box {
	box := tview.NewBox()
	box.SetBackgroundColor(groundColor)
	return box
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
