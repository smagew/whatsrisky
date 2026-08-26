package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// chips is a row of things you tick: [x] semgrep  [x] trivy  [ ] ai.
//
// tview has no such item, and four checkboxes on four rows is what it offers
// instead. Three of those rows are roughly what decides whether a terminal gets
// one column of settings or two, so the row buys legibility twice: it is shorter,
// and it leaves the fields wider.
//
// This is the one widget written by hand here, and it is written because the gap
// is real - not to avoid learning the toolkit's own.
type chips struct {
	*tview.Box

	label  string
	names  []string
	on     map[string]bool
	cursor int

	labelWidth int
	labelColor tcell.Color
	textColor  tcell.Color
	fieldBg    tcell.Color
	disabled   bool

	changed  func(name string, on bool)
	finished func(key tcell.Key)
}

func newChips(label string, names []string, on map[string]bool,
	changed func(name string, on bool)) *chips {
	box := tview.NewBox()
	box.SetBackgroundColor(groundColor)
	return &chips{
		Box:        box,
		label:      label,
		names:      names,
		on:         on,
		labelColor: ink3Color,
		textColor:  inkColor,
		fieldBg:    fieldColor,
		changed:    changed,
	}
}

// --- the FormItem contract -------------------------------------------

func (c *chips) GetLabel() string { return c.label }

func (c *chips) SetFormAttributes(labelWidth int, labelColor, bgColor,
	fieldTextColor, fieldBgColor tcell.Color) tview.FormItem {
	c.labelWidth = labelWidth
	c.labelColor = labelColor
	c.textColor = fieldTextColor
	c.fieldBg = fieldBgColor
	c.SetBackgroundColor(bgColor)
	return c
}

// GetFieldWidth is the room the chips need: three cells for the box and a space
// after each name.
func (c *chips) GetFieldWidth() int {
	width := 0
	for _, name := range c.names {
		width += len(name) + 5
	}
	return width
}

func (c *chips) GetFieldHeight() int { return 1 }

func (c *chips) SetFinishedFunc(handler func(key tcell.Key)) tview.FormItem {
	c.finished = handler
	return c
}

func (c *chips) SetDisabled(disabled bool) tview.FormItem {
	c.disabled = disabled
	return c
}

func (c *chips) IsDisabled() bool { return c.disabled }

// --- drawing ---------------------------------------------------------

func (c *chips) Draw(screen tcell.Screen) {
	c.Box.DrawForSubclass(screen, c)
	x, y, width, height := c.GetInnerRect()
	if height < 1 {
		return
	}

	if c.label != "" {
		tview.Print(screen, c.label, x, y, c.labelWidth, tview.AlignLeft, c.labelColor)
	}
	at := x + c.labelWidth
	focused := c.HasFocus()

	for index, name := range c.names {
		// Escaped: tview reads square brackets as a colour tag, so a literal
		// "[x]" is swallowed and the ticked chips lose their tick.
		box, tag := tview.Escape("[ ] "), dimTag
		if c.on[name] {
			box, tag = tview.Escape("[x] "), passTag
		}
		text := tag + box + resetTag
		if focused && index == c.cursor {
			// The cursor has to be visible without colour alone: this row is one
			// field, and which chip a keypress lands on is the whole question.
			text += "[:" + colourTag(c.fieldBg) + "]" + name + resetTag
		} else {
			text += "[" + colourTag(c.textColor) + "]" + name + resetTag
		}
		_, printed := tview.Print(screen, text, at, y, maxInt(0, x+width-at),
			tview.AlignLeft, c.textColor)
		at += printed + 2
	}
}

// colourTag renders a colour as a tview markup tag.
func colourTag(colour tcell.Color) string {
	if colour == tcell.ColorDefault || !colour.Valid() {
		return "-"
	}
	return "#" + hexOf(colour)
}

func hexOf(colour tcell.Color) string {
	const digits = "0123456789abcdef"
	value := colour.Hex()
	out := make([]byte, 6)
	for index := 5; index >= 0; index-- {
		out[index] = digits[value&0xf]
		value >>= 4
	}
	return string(out)
}

// --- keys and mouse --------------------------------------------------

func (c *chips) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return c.WrapInputHandler(func(event *tcell.EventKey, _ func(tview.Primitive)) {
		if c.disabled {
			return
		}
		switch event.Key() {
		case tcell.KeyLeft:
			if c.cursor > 0 {
				c.cursor--
			}
		case tcell.KeyRight:
			if c.cursor < len(c.names)-1 {
				c.cursor++
			}
		case tcell.KeyRune:
			if event.Rune() != ' ' {
				return
			}
			c.toggle(c.cursor)
		case tcell.KeyEnter, tcell.KeyTab, tcell.KeyBacktab, tcell.KeyEscape:
			if c.finished != nil {
				c.finished(event.Key())
			}
		}
	})
}

func (c *chips) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse,
	setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return c.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse,
		setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		if c.disabled {
			return false, nil
		}
		mouseX, mouseY := event.Position()
		x, y, _, _ := c.GetInnerRect()
		if mouseY != y || !c.InRect(mouseX, mouseY) {
			return false, nil
		}
		switch action {
		case tview.MouseLeftDown:
			setFocus(c)
			return true, nil
		case tview.MouseLeftClick:
			if index := c.chipAt(mouseX - x - c.labelWidth); index >= 0 {
				c.cursor = index
				c.toggle(index)
			}
			setFocus(c)
			return true, nil
		}
		return false, nil
	})
}

// chipAt maps a column inside the field to the chip drawn there, so a click lands
// on what the user pointed at rather than on the row.
func (c *chips) chipAt(offset int) int {
	if offset < 0 {
		return -1
	}
	at := 0
	for index, name := range c.names {
		width := len(name) + 4
		if offset >= at && offset < at+width {
			return index
		}
		at += width + 2
	}
	return -1
}

func (c *chips) toggle(index int) {
	if index < 0 || index >= len(c.names) {
		return
	}
	name := c.names[index]
	c.on[name] = !c.on[name]
	if c.changed != nil {
		c.changed(name, c.on[name])
	}
}
