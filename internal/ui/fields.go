package ui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/smagew/whatsrisky/internal/scan"
)

// A field is one setting on screen. Every field reads from and writes to
// scan.Options, so the form cannot hold a setting the CLI does not have - which
// is what the equivalent-command panel then proves.
type field interface {
	label() string
	hint() string
	render(focused bool, width int) string
	// update handles a key press. Returns true when the key was consumed, so the
	// form knows not to treat it as navigation.
	update(msg tea.KeyMsg) bool
	load(options scan.Options)
	apply(options *scan.Options)
	focus()
	blur()
}

// --- text ------------------------------------------------------------

type textField struct {
	name        string
	description string
	input       textinput.Model
	get         func(scan.Options) string
	set         func(*scan.Options, string)
}

func newTextField(name, description, placeholder string,
	get func(scan.Options) string, set func(*scan.Options, string)) *textField {
	input := textinput.New()
	input.Placeholder = placeholder
	input.Prompt = ""
	input.CharLimit = 512
	return &textField{name: name, description: description, input: input, get: get, set: set}
}

func (f *textField) label() string { return f.name }
func (f *textField) hint() string  { return f.description }

func (f *textField) render(focused bool, width int) string {
	value := f.input.Value()
	if focused {
		f.input.Width = maxInt(20, width-4)
		return f.input.View()
	}
	if value == "" {
		return dimStyle.Render(orPlaceholder(f.input.Placeholder))
	}
	return valueStyle.Render(value)
}

func (f *textField) update(msg tea.KeyMsg) bool {
	switch msg.Type {
	case tea.KeyUp, tea.KeyDown, tea.KeyTab, tea.KeyShiftTab, tea.KeyEsc, tea.KeyEnter:
		return false // navigation belongs to the form
	}
	f.input, _ = f.input.Update(msg)
	return true
}

func (f *textField) load(options scan.Options)   { f.input.SetValue(f.get(options)) }
func (f *textField) apply(options *scan.Options) { f.set(options, strings.TrimSpace(f.input.Value())) }
func (f *textField) focus()                      { f.input.Focus() }
func (f *textField) blur()                       { f.input.Blur() }

// --- number ----------------------------------------------------------

type numberField struct {
	*textField
	getNumber func(scan.Options) int
	setNumber func(*scan.Options, int)
}

func newNumberField(name, description string,
	get func(scan.Options) int, set func(*scan.Options, int)) *numberField {
	base := newTextField(name, description, "", nil, nil)
	return &numberField{textField: base, getNumber: get, setNumber: set}
}

func (f *numberField) load(options scan.Options) {
	value := f.getNumber(options)
	if value == 0 {
		f.input.SetValue("")
		return
	}
	f.input.SetValue(strconv.Itoa(value))
}

func (f *numberField) apply(options *scan.Options) {
	text := strings.TrimSpace(f.input.Value())
	if text == "" {
		f.setNumber(options, 0)
		return
	}
	if value, err := strconv.Atoi(text); err == nil {
		f.setNumber(options, value)
	}
}

// --- choice ----------------------------------------------------------

// choiceField cycles a fixed set. The values carry their own explanation, because
// "review" needs one and "full" does not.
type choiceField struct {
	name        string
	description string
	values      []string
	labels      []string
	index       int
	get         func(scan.Options) string
	set         func(*scan.Options, string)
}

func newChoiceField(name, description string, values, labels []string,
	get func(scan.Options) string, set func(*scan.Options, string)) *choiceField {
	return &choiceField{name: name, description: description, values: values,
		labels: labels, get: get, set: set}
}

func (f *choiceField) label() string { return f.name }
func (f *choiceField) hint() string  { return f.description }

func (f *choiceField) render(focused bool, width int) string {
	text := f.labels[f.index]
	if focused {
		return focusStyle.Render("‹ " + text + " ›")
	}
	return valueStyle.Render(text)
}

func (f *choiceField) update(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "left", "h":
		f.index = (f.index - 1 + len(f.values)) % len(f.values)
		return true
	case "right", "l", " ":
		f.index = (f.index + 1) % len(f.values)
		return true
	}
	return false
}

func (f *choiceField) load(options scan.Options) {
	current := f.get(options)
	for index, value := range f.values {
		if value == current {
			f.index = index
			return
		}
	}
	f.index = 0
}

func (f *choiceField) apply(options *scan.Options) { f.set(options, f.values[f.index]) }
func (f *choiceField) focus()                      {}
func (f *choiceField) blur()                       {}

// --- toggle ----------------------------------------------------------

type toggleField struct {
	name        string
	description string
	value       bool
	get         func(scan.Options) bool
	set         func(*scan.Options, bool)
}

func newToggleField(name, description string,
	get func(scan.Options) bool, set func(*scan.Options, bool)) *toggleField {
	return &toggleField{name: name, description: description, get: get, set: set}
}

func (f *toggleField) label() string { return f.name }
func (f *toggleField) hint() string  { return f.description }

func (f *toggleField) render(focused bool, width int) string {
	mark := "no"
	style := dimStyle
	if f.value {
		mark, style = "yes", valueStyle
	}
	if focused {
		return focusStyle.Render("‹ " + mark + " ›")
	}
	return style.Render(mark)
}

func (f *toggleField) update(msg tea.KeyMsg) bool {
	switch msg.String() {
	case " ", "left", "right", "h", "l", "y", "n":
		f.value = !f.value
		return true
	}
	return false
}

func (f *toggleField) load(options scan.Options)   { f.value = f.get(options) }
func (f *toggleField) apply(options *scan.Options) { f.set(options, f.value) }
func (f *toggleField) focus()                      {}
func (f *toggleField) blur()                       {}

// --- multi -----------------------------------------------------------

// multiField is a set: the scanners, the output formats. The cursor moves inside
// it with left/right and space toggles the one under the cursor.
type multiField struct {
	name        string
	description string
	values      []string
	labels      []string
	chosen      map[string]bool
	cursor      int
	get         func(scan.Options) []string
	set         func(*scan.Options, []string)
}

func newMultiField(name, description string, values, labels []string,
	get func(scan.Options) []string, set func(*scan.Options, []string)) *multiField {
	return &multiField{name: name, description: description, values: values, labels: labels,
		chosen: map[string]bool{}, get: get, set: set}
}

func (f *multiField) label() string { return f.name }
func (f *multiField) hint() string  { return f.description }

func (f *multiField) render(focused bool, width int) string {
	var parts []string
	for index, value := range f.values {
		mark := "·"
		style := dimStyle
		if f.chosen[value] {
			mark, style = "×", valueStyle
		}
		text := mark + " " + f.labels[index]
		if focused && index == f.cursor {
			text = selectedStyle.Render(" " + text + " ")
		} else {
			text = style.Render(" " + text + " ")
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " ")
}

func (f *multiField) update(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "left", "h":
		f.cursor = (f.cursor - 1 + len(f.values)) % len(f.values)
		return true
	case "right", "l":
		f.cursor = (f.cursor + 1) % len(f.values)
		return true
	case " ":
		value := f.values[f.cursor]
		f.chosen[value] = !f.chosen[value]
		return true
	}
	return false
}

func (f *multiField) load(options scan.Options) {
	f.chosen = map[string]bool{}
	for _, value := range f.get(options) {
		f.chosen[value] = true
	}
}

func (f *multiField) apply(options *scan.Options) {
	var out []string
	for _, value := range f.values {
		if f.chosen[value] {
			out = append(out, value)
		}
	}
	f.set(options, out)
}

func (f *multiField) focus() {}
func (f *multiField) blur()  {}

// --- helpers ---------------------------------------------------------

// commaList and splitCommas keep the free-text list fields honest.
func commaList(values []string) string { return strings.Join(values, ",") }

func splitCommas(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func orPlaceholder(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
