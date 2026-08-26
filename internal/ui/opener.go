package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// opener is a row that says what a setting amounts to and opens the full list
// when you press it. tview has no such item; a button belongs in a form's button
// row, and this belongs in the middle of the settings where the setting is.
type opener struct {
	*tview.Box

	label   string
	summary func(width int) string
	open    func()

	labelWidth int
	labelColor tcell.Color
	textColor  tcell.Color
	fieldBg    tcell.Color
	disabled   bool
	finished   func(key tcell.Key)
}

func newOpener(label string, summary func(width int) string, open func()) *opener {
	box := tview.NewBox()
	box.SetBackgroundColor(groundColor)
	return &opener{
		Box:        box,
		label:      label,
		summary:    summary,
		open:       open,
		labelColor: ink3Color,
		textColor:  inkColor,
		fieldBg:    fieldColor,
	}
}

func (o *opener) GetLabel() string { return o.label }

func (o *opener) SetFormAttributes(labelWidth int, labelColor, bgColor,
	fieldTextColor, fieldBgColor tcell.Color) tview.FormItem {
	o.labelWidth = labelWidth
	o.labelColor = labelColor
	o.textColor = fieldTextColor
	o.fieldBg = fieldBgColor
	o.SetBackgroundColor(bgColor)
	return o
}

func (o *opener) GetFieldWidth() int  { return 0 }
func (o *opener) GetFieldHeight() int { return 1 }

func (o *opener) SetFinishedFunc(handler func(key tcell.Key)) tview.FormItem {
	o.finished = handler
	return o
}

func (o *opener) SetDisabled(disabled bool) tview.FormItem {
	o.disabled = disabled
	return o
}

func (o *opener) IsDisabled() bool { return o.disabled }

func (o *opener) Draw(screen tcell.Screen) {
	o.Box.DrawForSubclass(screen, o)
	x, y, width, height := o.GetInnerRect()
	if height < 1 {
		return
	}
	if o.label != "" {
		tview.Print(screen, o.label, x, y, o.labelWidth, tview.AlignLeft, o.labelColor)
	}
	at := x + o.labelWidth
	room := maxInt(8, width-o.labelWidth)

	text := o.summary(maxInt(8, room-14))
	if o.HasFocus() {
		// Focused, it has to look pressable: the field colour behind it, and the
		// key that opens it said out loud.
		text = "[:" + colourTag(o.fieldBg) + "]" + text + resetTag
	}
	_, printed := tview.Print(screen, text, at, y, room, tview.AlignLeft, o.textColor)
	if hint := "  enter to choose"; printed+len(hint) <= room {
		tview.Print(screen, dimTag+hint+resetTag, at+printed, y,
			room-printed, tview.AlignLeft, ink3Color)
	}
}

func (o *opener) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return o.WrapInputHandler(func(event *tcell.EventKey, _ func(tview.Primitive)) {
		if o.disabled {
			return
		}
		switch event.Key() {
		case tcell.KeyEnter:
			o.open()
		case tcell.KeyRune:
			if event.Rune() == ' ' {
				o.open()
			}
		case tcell.KeyTab, tcell.KeyBacktab, tcell.KeyEscape:
			if o.finished != nil {
				o.finished(event.Key())
			}
		}
	})
}

func (o *opener) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse,
	setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return o.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse,
		setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		if o.disabled {
			return false, nil
		}
		mouseX, mouseY := event.Position()
		if !o.InRect(mouseX, mouseY) {
			return false, nil
		}
		switch action {
		case tview.MouseLeftDown:
			setFocus(o)
			return true, nil
		case tview.MouseLeftClick:
			setFocus(o)
			o.open()
			return true, nil
		}
		return false, nil
	})
}

// backdrop is the space around an overlay. It paints the ground, closes the
// overlay when clicked, and never takes the keyboard - a plain tview.Box would
// take focus on a click and then answer nothing, which is how one click beside a
// list left the whole interface unresponsive.
type backdropBox struct {
	*tview.Box
	dismiss func()
}

func backdrop(dismiss func()) *backdropBox {
	box := tview.NewBox()
	box.SetBackgroundColor(groundColor)
	return &backdropBox{Box: box, dismiss: dismiss}
}

func (b *backdropBox) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse,
	setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse,
		_ func(tview.Primitive)) (bool, tview.Primitive) {
		mouseX, mouseY := event.Position()
		if !b.InRect(mouseX, mouseY) {
			return false, nil
		}
		if action == tview.MouseLeftClick && b.dismiss != nil {
			b.dismiss()
		}
		// Consumed either way, and focus is never taken.
		return true, nil
	}
}

// InputHandler is nil: the backdrop is not a place the keyboard can end up.
func (b *backdropBox) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) { return nil }

// modalLayer is an overlay that nothing behind it can be clicked through.
//
// Without this the page underneath stayed live: a click the overlay did not want
// fell through to the settings form, and landing on a drop-down opened it behind
// the overlay - where it then captured every further mouse event. The interface was
// not frozen, it was answering a widget nobody could see.
type modalLayer struct {
	*tview.Flex
	dismiss func()
}

func modal(inner *tview.Flex, dismiss func()) *modalLayer {
	return &modalLayer{Flex: inner, dismiss: dismiss}
}

func (m *modalLayer) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse,
	setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse,
		setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		if consumed, capture := m.Flex.MouseHandler()(action, event, setFocus); consumed {
			return consumed, capture
		}
		if action == tview.MouseLeftClick || action == tview.MouseLeftDoubleClick {
			if m.dismiss != nil {
				m.dismiss()
			}
		}
		// Swallowed either way: an overlay that leaks clicks is worse than none.
		return true, nil
	}
}
