package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/smagew/whatsrisky/internal/scan"
)

// These tests run the real Application against a simulated screen and inject real
// events. Everything else in this file's neighbour calls handlers directly, which
// is how three mouse bugs passed a green suite: the Application's own dispatch,
// its focus tracking and its redraw are exactly where they were failing.

type live struct {
	t      *testing.T
	ui     *UI
	screen tcell.SimulationScreen
	done   chan error
}

func start(t *testing.T, options scan.Options, width, height int) *live {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	screen.SetSize(width, height)

	u := New("0.4.0", options, "")
	u.probing = false
	u.width, u.height = width, height
	u.layout()

	u.app = u.newApp().SetScreen(screen)

	l := &live{t: t, ui: u, screen: screen, done: make(chan error, 1)}
	defer func() {
		// SetSize before Run does not reach the application, which then draws at
		// tcell's default 80x25 while the test measures a 120x40 screen. The resize
		// is delivered as an event, the way a terminal delivers one.
		screen.InjectMouse(0, 0, tcell.ButtonNone, tcell.ModNone)
	}()
	go func() {
		// A panic in the event loop is what a frozen terminal looks like from the
		// outside, so it is caught and reported rather than lost.
		defer func() {
			if r := recover(); r != nil {
				l.done <- errPanic{r}
			}
		}()
		l.done <- u.app.Run()
	}()
	l.settle()
	u.app.QueueUpdateDraw(func() {})
	screen.SetSize(width, height)
	u.app.QueueUpdateDraw(func() { u.width, u.height = width, height; u.layout() })
	l.settle()
	return l
}

type errPanic struct{ value any }

func (e errPanic) Error() string { return "panic in the event loop: " + toString(e.value) }

func toString(value any) string {
	if err, ok := value.(error); ok {
		return err.Error()
	}
	if text, ok := value.(string); ok {
		return text
	}
	return "unprintable"
}

// settle waits for the event loop to catch up, and fails if it has died.
func (l *live) settle() {
	l.t.Helper()
	for i := 0; i < 40; i++ {
		select {
		case err := <-l.done:
			l.t.Fatalf("the interface stopped: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (l *live) clickAt(x, y int) {
	l.t.Helper()
	l.screen.InjectMouse(x, y, tcell.Button1, tcell.ModNone)
	l.screen.InjectMouse(x, y, tcell.ButtonNone, tcell.ModNone)
	l.settle()
}

func (l *live) press(key tcell.Key, r rune) {
	l.t.Helper()
	l.screen.InjectKey(key, r, tcell.ModNone)
	l.settle()
}

// text is what is on the screen now.
func (l *live) text() string {
	l.t.Helper()
	var out strings.Builder
	l.ui.app.QueueUpdateDraw(func() {})
	time.Sleep(20 * time.Millisecond)
	cells, w, h := l.screen.GetContents()
	for y := 0; y < h; y++ {
		var row []rune
		for x := 0; x < w; x++ {
			r := ' '
			if rs := cells[y*w+x].Runes; len(rs) > 0 && rs[0] != 0 {
				r = rs[0]
			}
			row = append(row, r)
		}
		out.WriteString(strings.TrimRight(string(row), " ") + "\n")
	}
	return out.String()
}

func (l *live) stop() { l.ui.app.Stop() }

// lineOf finds the screen row that carries text, or -1.
func lineOf(view, text string) int {
	_, y := spotOf(view, text)
	return y
}

// spotOf is where text sits on the screen. Clicking a hardcoded column is how a
// test ends up clicking the panel and reporting the form as broken.
func spotOf(view, text string) (x, y int) {
	for index, line := range strings.Split(view, "\n") {
		if at := strings.Index(line, text); at >= 0 {
			return at, index
		}
	}
	return -1, -1
}

func TestAClickAnywhereKeepsTheInterfaceAlive(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	options := scan.NewOptions()
	options.Path = root

	l := start(t, options, 120, 40)
	defer l.stop()

	// Open the folder list by clicking its row.
	view := l.text()
	x, row := spotOf(view, "folders to skip")
	if row < 0 {
		t.Fatalf("no folder row on screen:\n%s", view)
	}
	l.clickAt(x+2, row)
	if view := l.text(); lineOf(view, "which folders to skip") < 0 {
		t.Fatalf("clicking the row did not open the list:\n%s", view)
	}

	// Tick two folders by clicking them, one after the other.
	view = l.text()
	firstX, first := spotOf(view, "alpha")
	secondX, second := spotOf(view, "bravo")
	if first < 0 || second < 0 {
		t.Fatalf("the folders are not in the list:\n%s", view)
	}
	l.clickAt(firstX, first)
	l.clickAt(secondX, second)
	if got := strings.Join(l.ui.collect().Exclude, ","); got != "alpha,bravo" {
		t.Errorf("after ticking two folders by click: %q", got)
	}

	// Click beside the list. It must close, and the interface must still answer.
	l.clickAt(2, 1)
	if view := l.text(); lineOf(view, "which folders to skip") >= 0 {
		t.Errorf("clicking beside the list did not close it:\n%s", view)
	}
	// Still alive: a key still reaches the interface.
	l.press(tcell.KeyCtrlI, 0)
	if view := l.text(); lineOf(view, "never looks at") < 0 {
		t.Errorf("the interface stopped answering the keyboard:\n%s", view)
	}
	l.press(tcell.KeyEscape, 0)
	// And a click on a setting still works afterwards.
	view = l.text()
	if sx, scanners := spotOf(view, "[x] semgrep"); scanners >= 0 {
		l.clickAt(sx+1, scanners)
		if l.ui.collect().HasTool("semgrep") {
			t.Error("clicking a scanner after all that did nothing")
		}
	}
	l.settle()
}
