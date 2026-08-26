package ui

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/progress"
	"github.com/smagew/whatsrisky/internal/scan"
)

type mode int

const (
	modeSettings mode = iota
	modeRunning
)

// Model is the whole interface: a settings form and a live progress screen over
// the same scan.Options and scan.Run the CLI uses.
type Model struct {
	version string
	mode    mode
	options scan.Options
	profile string

	form   *huh.Form
	values *formValues

	probes  []probeRow
	probing bool
	notice  string

	progress     *progress.Model
	toolMessages map[string]string
	log          []string
	livePath     string
	outcome      *scan.Outcome
	runErr       error
	events       chan scan.Event
	done         chan runFinished

	width  int
	height int
	quit   bool
	exit   int
}

// New builds the interface from what a launch should start from.
func New(version string, options scan.Options, profile string) *Model {
	m := &Model{version: version, progress: progress.New(),
		toolMessages: map[string]string{}, options: options, profile: profile, probing: true}
	m.loadInto(options)
	// Launched from a profile, offer that name back: ctrl+s should update the
	// profile you are looking at, not silently ask for a new one.
	m.values.profileName = profile
	return m
}

// Run opens the interface and returns the process exit code.
func Run(version string, options scan.Options, profile string) (int, error) {
	m := New(version, options, profile)
	program := tea.NewProgram(m, tea.WithAltScreen())
	final, err := program.Run()
	if err != nil {
		return 1, err
	}
	if finished, ok := final.(*Model); ok {
		return finished.exit, nil
	}
	return 0, nil
}

func (m *Model) Init() tea.Cmd { return tea.Batch(probe, m.form.Init()) }

// --- messages --------------------------------------------------------

type runFinished struct {
	outcome scan.Outcome
	err     error
}

type scanEvent struct{ event scan.Event }

// start runs the scan in the background and forwards its events as messages.
func (m *Model) start() tea.Cmd {
	options := m.collect().Normalized()
	if problems := options.Validate(isDirectory); len(problems) > 0 {
		m.notice = strings.Join(problems, "; ")
		return nil
	}
	_ = config.SaveLast(options)

	m.mode = modeRunning
	m.options = options
	m.progress = progress.New()
	m.toolMessages = map[string]string{}
	m.log = nil
	m.livePath = ""
	m.outcome = nil
	m.runErr = nil
	m.events = make(chan scan.Event, 64)
	m.done = make(chan runFinished, 1)

	go func(options scan.Options, events chan scan.Event, done chan runFinished) {
		outcome, err := scan.Run(options, func(event scan.Event) { events <- event })
		close(events)
		done <- runFinished{outcome: outcome, err: err}
	}(options, m.events, m.done)

	return tea.Batch(waitForEvent(m.events, m.done), tick())
}

func waitForEvent(events chan scan.Event, done chan runFinished) tea.Cmd {
	return func() tea.Msg {
		if event, ok := <-events; ok {
			return scanEvent{event: event}
		}
		return <-done
	}
}

type tickMsg struct{}

// tick keeps the elapsed times moving while a scanner is silent.
func tick() tea.Cmd {
	return tea.Tick(300*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

// --- update ----------------------------------------------------------

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.WindowSizeMsg:
		if typed.Width == m.width && typed.Height == m.height {
			return m, nil
		}
		m.width, m.height = typed.Width, typed.Height
		// Rebuilt, not resized: WithWidth moves the frame but leaves every
		// description wrapped for the old width, so a widened terminal keeps the
		// narrow text. The fields bind to m.values, so nothing typed is lost.
		m.form = m.values.form(m.formWidth(), m.bodyHeight())
		return m, m.form.Init()

	case probeResult:
		m.probes = typed.rows
		m.probing = false
		return m, nil

	case scanEvent:
		m.handleEvent(typed.event)
		return m, waitForEvent(m.events, m.done)

	case runFinished:
		if typed.err != nil {
			m.runErr = typed.err
		} else {
			outcome := typed.outcome
			m.outcome = &outcome
			m.exit = outcome.ExitCode
		}
		return m, nil

	case tickMsg:
		if m.mode == modeRunning && m.outcome == nil && m.runErr == nil {
			return m, tick()
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(typed)
	}

	// Everything else goes to the form. huh answers a keypress with a command,
	// and the message that command produces is what actually moves the focus -
	// so a model that drops unknown messages has a form you cannot navigate.
	if m.mode == modeSettings {
		return m, m.updateForm(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		m.quit = true
		return m, tea.Quit
	}

	if m.mode == modeRunning {
		switch msg.String() {
		case "esc":
			if m.finished() {
				m.mode = modeSettings
				m.notice = ""
			}
			return m, nil
		case "v":
			m.notice = m.viewReport()
			return m, nil
		case "q":
			m.quit = true
			return m, tea.Quit
		}
		return m, nil
	}

	// A focused text field owns most keys, so the commands are chorded.
	switch msg.String() {
	case "ctrl+r":
		return m, m.start()
	case "ctrl+s":
		m.notice = m.saveProfile()
		return m, nil
	case "ctrl+q", "esc":
		m.quit = true
		return m, tea.Quit
	}

	m.notice = ""
	return m, m.updateForm(msg)
}

// updateForm hands a message to the form and keeps whatever it returns. A
// completed form is the other way to start the scan: filling the last field and
// confirming should run, not sit there.
func (m *Model) updateForm(msg tea.Msg) tea.Cmd {
	form, cmd := m.form.Update(msg)
	if updated, ok := form.(*huh.Form); ok {
		m.form = updated
	}
	if m.form.State == huh.StateCompleted {
		return m.start()
	}
	return cmd
}

func (m *Model) handleEvent(event scan.Event) {
	switch event.Kind {
	case "info":
		m.appendLog(dimStyle.Render("▸ " + event.Message))
	case "live":
		if len(event.Paths) > 0 {
			m.livePath = event.Paths[0]
			m.appendLog(dimStyle.Render("live report ready — press v to open it any time"))
		} else {
			m.appendLog(dimStyle.Render("no html in this run — the report view is unavailable"))
		}
	case "tool_start":
		m.progress.Start(event.Tool)
		m.appendLog(mutedStyle.Render("▸ " + event.Tool + " started"))
	case "tool_progress":
		m.progress.Progress(event.Tool, event.Message)
	case "tool_done":
		m.progress.Done(event.Tool, event.Status, event.Findings, event.Duration)
		if event.Status != model.ToolOK {
			m.toolMessages[event.Tool] = firstLine(event.Message)
		}
		style := okStyle
		if event.Status != model.ToolOK {
			style = badStyle
		}
		m.appendLog(style.Render(fmt.Sprintf("▪ %s %s · %d findings · %.0fs",
			event.Tool, event.Status, event.Findings, event.Duration.Seconds())))
		if event.Message != "" && event.Status != model.ToolOK {
			m.appendLog(dimStyle.Render("  " + firstLine(event.Message)))
		}
	case "report":
		for _, path := range event.Paths {
			m.appendLog(okStyle.Render("report ") + path)
		}
	}
}

func (m *Model) appendLog(line string) {
	m.log = append(m.log, line)
	if len(m.log) > 200 {
		m.log = m.log[len(m.log)-200:]
	}
}

func (m *Model) finished() bool { return m.outcome != nil || m.runErr != nil }

func (m *Model) viewReport() string {
	target := m.livePath
	if target == "" && m.outcome != nil {
		for _, path := range m.outcome.Written {
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

func firstLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			if len(trimmed) > 160 {
				return trimmed[:160]
			}
			return trimmed
		}
	}
	return ""
}
