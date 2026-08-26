package ui

import (
	"strings"

	"github.com/gdamore/tcell/v2"

	"github.com/rivo/tview"
)

// A picker is the full list, vertical and scrollable, over a set of names that can
// be ticked. It exists because a row of chips is the wrong shape for a list whose
// length you do not control: four scanners fit on a line, and a project's folders
// do not.
const pagePicker = "picker"

// openPicker shows every name, ticked or not, and closes on esc. Space or a click
// toggles the one under the cursor; the list scrolls, so there is no length at
// which it starts hiding things.
func (u *UI) openPicker(title, about string, names []string, on map[string]bool) {
	if len(names) == 0 {
		u.setNotice("there are no folders in " + orDot(u.values.path))
		return
	}

	list := tview.NewList().ShowSecondaryText(false)
	list.SetBackgroundColor(groundColor)
	list.SetMainTextColor(inkColor).
		SetSelectedTextColor(groundColor).
		SetSelectedBackgroundColor(markColor)
	list.SetBorder(true).SetBorderColor(lineColor).
		SetTitle(" " + title + " ").SetTitleColor(markColor).
		SetTitleAlign(tview.AlignLeft)

	// The list is rebuilt in place on every toggle: tview has no checkbox list, so
	// the tick is part of the line, and the line has to be rewritten to change.
	var fill func(keep int)
	fill = func(keep int) {
		list.Clear()
		for _, name := range names {
			box, tag := tview.Escape("[ ] "), dimTag
			if on[name] {
				box, tag = tview.Escape("[x] "), passTag
			}
			label := tag + box + resetTag + name
			list.AddItem(label, "", 0, func() {
				// Selecting is toggling, and the cursor stays where it was so a
				// run of folders can be ticked without hunting for the place.
				at := list.GetCurrentItem()
				on[names[at]] = !on[names[at]]
				u.refresh()
				fill(at)
			})
		}
		if keep >= 0 && keep < len(names) {
			list.SetCurrentItem(keep)
		}
	}
	fill(0)

	// tview's list selects on enter and binds nothing to space. The help line
	// promises space, so space has to work: it is the natural key for a tick.
	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune && event.Rune() == ' ' {
			return tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
		}
		return event
	})

	help := textView()
	help.SetText(dimTag + about + resetTag)

	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(list, 0, 1, true).
		AddItem(help, 1, 0, false)
	frame.SetBackgroundColor(groundColor)

	width := minInt(u.width-8, 52)
	height := minInt(u.height-4, len(names)+4)
	u.pages.AddPage(pagePicker, centred(frame, width, maxInt(6, height)), true, true)
}

// tickedOr says what a set amounts to in one line, for the row that opens the
// picker. A count alone would not say which, and the names alone would not say
// how many are missing.
func tickedOr(names []string, on map[string]bool, empty string, width int) string {
	var ticked []string
	for _, name := range names {
		if on[name] {
			ticked = append(ticked, name)
		}
	}
	if len(ticked) == 0 {
		return empty
	}
	joined := strings.Join(ticked, ", ")
	if len([]rune(joined)) <= width {
		return joined
	}
	return shorten(joined, maxInt(8, width-8)) + " (" + itoa(len(ticked)) + ")"
}
