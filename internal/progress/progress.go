// Package progress is the per-scanner status a front end shows: elapsed time and
// what each scanner is doing right now.
//
// One model, rendered twice - the CLI writes lines or a live table, the terminal
// UI draws it into a widget. Keeping the bookkeeping here is what stops the two
// from drifting apart.
package progress

import (
	"fmt"
	"sync"
	"time"
)

const spinnerFrames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

// Row is one scanner's state.
type Row struct {
	Tool     string
	Status   string
	Message  string
	Findings int
	Started  time.Time
	Duration time.Duration
}

// Elapsed is how long this scanner has been going, or how long it took.
func (r Row) Elapsed() time.Duration {
	if r.Duration > 0 {
		return r.Duration
	}
	return time.Since(r.Started)
}

// Running reports whether this scanner is still going.
func (r Row) Running() bool { return r.Status == "running" }

// Line is the one-line summary a finished scanner gets.
func (r Row) Line() string {
	return fmt.Sprintf("%s %s · %d findings · %.0fs", r.Tool, r.Status, r.Findings, r.Elapsed().Seconds())
}

// Model tracks every scanner. Safe for concurrent updates, because the scanners
// run in parallel.
type Model struct {
	guard sync.Mutex
	rows  map[string]*Row
	order []string
	frame int
}

// New builds an empty model.
func New() *Model { return &Model{rows: map[string]*Row{}} }

// Start records that a scanner began.
func (m *Model) Start(tool string) {
	m.guard.Lock()
	defer m.guard.Unlock()
	if _, ok := m.rows[tool]; !ok {
		m.order = append(m.order, tool)
	}
	m.rows[tool] = &Row{Tool: tool, Status: "running", Message: "starting", Started: time.Now()}
}

// Progress records what a scanner is doing now.
func (m *Model) Progress(tool, message string) {
	m.guard.Lock()
	defer m.guard.Unlock()
	if row, ok := m.rows[tool]; ok {
		row.Message = message
	}
}

// Done records the outcome.
func (m *Model) Done(tool, status string, findings int, duration time.Duration) {
	m.guard.Lock()
	defer m.guard.Unlock()
	if row, ok := m.rows[tool]; ok {
		row.Status = status
		row.Findings = findings
		row.Duration = duration
	}
}

// Rows is a snapshot, in the order the scanners started.
func (m *Model) Rows() []Row {
	m.guard.Lock()
	defer m.guard.Unlock()
	out := make([]Row, 0, len(m.order))
	for _, tool := range m.order {
		if row, ok := m.rows[tool]; ok {
			out = append(out, *row)
		}
	}
	return out
}

// Running reports whether any scanner is still going.
func (m *Model) Running() bool {
	for _, row := range m.Rows() {
		if row.Running() {
			return true
		}
	}
	return false
}

// Spinner advances and returns the frame for a running row.
func (m *Model) Spinner() string {
	m.guard.Lock()
	defer m.guard.Unlock()
	m.frame++
	runes := []rune(spinnerFrames)
	return string(runes[m.frame%len(runes)])
}
