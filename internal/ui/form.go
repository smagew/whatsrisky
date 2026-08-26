package ui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// A section is a heading inside the form. tview has no such item, so it is a
// label with no field - written once here rather than at every use.
// heading puts the section name in the label column and what it is for in the
// value column. Both in the label would make the heading the widest label in the
// form, and every value on the screen would line up after it.
func heading(form *tview.Form, title, about string) {
	form.AddTextView(markTag+"── "+title+resetTag, dimTag+about+resetTag, 0, 1, true, false)
}

// about is what each section is for, in one short phrase. On the heading line, so
// explaining a section costs no vertical room - and vertical room is what decides
// whether every setting fits on one screen.
var about = map[string]string{
	"Project":                "what to scan",
	"Scanners":               "each one off is a gap the report will admit to",
	"AI review":              "opt-in, and it spends your money",
	"Output":                 "html to read, json for other tools",
	"What we do not look at": "ctrl+i lists the 49 we always skip",
	"Filtering":              "what to hide, and what should fail a build",
	"Details":                "leave these alone unless you have a reason",
	"Profile":                "ctrl+s stores everything above under this name",
}

// field is one row of the form, described rather than built, so the same list can
// be laid out in one column or two without being written twice.
type field struct {
	section string
	build   func(form *tview.Form, width int)
}

// fieldWidth is how wide one field may be. tview paints the whole width, so a
// field sized to the terminal is a bar of background running off to the right -
// which reads as a redaction rather than as somewhere to type. The cap is per
// field: a path needs room, a model name does not.
func fieldWidth(room, want int) int { return minInt(want, maxInt(10, room)) }

// fields is every setting on the screen, in reading order: what to scan, then
// what runs, then what comes out, then what is left out, then the details.
//
// No word here is jargon. "pattern" and "exclusion" were both in the last
// version and neither said what it meant.
func (u *UI) fields() []field {
	v := u.values
	return []field{
		{"Project", func(f *tview.Form, w int) {
			input(f, 44, "project folder", v.path, "/path/to/the/project", w, func(text string) { v.path = text })
		}},
		{"Project", func(f *tview.Form, w int) {
			input(f, 20, "only these changes", v.diff, "main..HEAD", w, func(text string) { v.diff = text })
		}},

		{"Scanners", func(f *tview.Form, w int) {
			f.AddFormItem(newChips("which ones", scan.AllTools, u.values.tools,
				func(string, bool) { u.refresh() }))
		}},

		{"AI review", func(f *tview.Form, w int) {
			labels := []string{"claude-cli — reads the folder itself", "openai — sees only what we send"}
			f.AddDropDown("who reviews", labels, indexIn(ai.Providers, v.aiProvider),
				func(_ string, index int) { v.aiProvider = at(ai.Providers, index) })
		}},
		{"AI review", func(f *tview.Form, w int) {
			input(f, 22, "model", v.aiModel, "blank = the default", w, func(text string) { v.aiModel = text })
		}},
		{"AI review", func(f *tview.Form, w int) {
			modes := []string{"full", "review", "both"}
			labels := []string{"the whole folder", "only the changes", "both"}
			f.AddDropDown("what it reads", labels, indexIn(modes, v.aiMode),
				func(_ string, index int) { v.aiMode = at(modes, index) })
		}},

		{"Output", func(f *tview.Form, w int) {
			f.AddFormItem(newChips("formats", scan.FormatChoices, u.values.formats,
				func(string, bool) { u.refresh() }))
		}},
		{"Output", func(f *tview.Form, w int) {
			input(f, 34, "save reports in", v.outDir, "blank = ./whatsrisky-reports", w, func(text string) { v.outDir = text })
		}},
		{"Output", func(f *tview.Form, w int) {
			u.yesNo(f, "open when done", &v.openReport)
		}},

		{"What we do not look at", func(f *tview.Form, w int) {
			input(f, 34, "your folders and files", v.ignorePaths, "build, *.min.js", w, func(text string) { v.ignorePaths = text })
		}},
		{"What we do not look at", func(f *tview.Form, w int) {
			u.yesNo(f, "the usual noise", &v.ignoreNoise)
		}},

		{"Filtering", func(f *tview.Form, w int) {
			f.AddDropDown("hide anything below", severityNames(), indexIn(severityNames(), v.minSeverity),
				func(text string, _ int) { v.minSeverity = text })
		}},
		{"Filtering", func(f *tview.Form, w int) {
			f.AddDropDown("fail the build at", scan.FailOnChoices, indexIn(scan.FailOnChoices, v.failOn),
				func(text string, _ int) { v.failOn = text })
		}},

		{"Details", func(f *tview.Form, w int) {
			input(f, 26, "semgrep rules", v.semgrep, "auto", w, func(text string) { v.semgrep = text })
		}},
		{"Details", func(f *tview.Form, w int) {
			input(f, 22, "trivy passes", v.trivy, "vuln,misconfig", w, func(text string) { v.trivy = text })
		}},
		{"Details", func(f *tview.Form, w int) {
			modes := []string{"auto", "dir", "git"}
			labels := []string{"files, plus history if this is a repo", "files only", "history only"}
			f.AddDropDown("gitleaks looks at", labels, indexIn(modes, v.gitleaks),
				func(_ string, index int) { v.gitleaks = at(modes, index) })
		}},
		{"Details", func(f *tview.Form, w int) {
			f.AddInputField("scanners at once", v.jobs, 6, tview.InputFieldInteger,
				func(text string) { v.jobs = text })
		}},
		{"Details", func(f *tview.Form, w int) { u.yesNo(f, "no network", &v.offline) }},
		{"Details", func(f *tview.Form, w int) {
			u.yesNo(f, "compare with last", &v.compare)
		}},

		{"Profile", func(f *tview.Form, w int) {
			input(f, 20, "save these settings as", v.profileName, "a name", w, func(text string) { v.profileName = text })
		}},
	}
}

// yesNo is a named value rather than a checkbox: tview draws an unchecked box as
// an empty cell, which reads as "no widget here" instead of "no". The panel is
// refreshed on every change so the equivalent command never lags the screen.
func (u *UI) yesNo(form *tview.Form, label string, target *bool) {
	selected := 1
	if *target {
		selected = 0
	}
	form.AddDropDown(label, []string{"yes", "no"}, selected, func(text string, _ int) {
		*target = text == "yes"
		u.refresh()
	})
}

// newForm lays the fields out. Sections are headings in a single column, not
// pages: you came to change one setting, not to walk through all of them.
// input is a text field with an example in it while it is empty.
func input(form *tview.Form, want int, label, value, example string, room int, set func(string)) {
	form.AddInputField(label, value, fieldWidth(room, want), nil, set)
	item := form.GetFormItem(form.GetFormItemCount() - 1)
	if field, ok := item.(*tview.InputField); ok {
		field.SetPlaceholder(example).
			SetPlaceholderTextColor(lineColor)
	}
}

// newForm lays out one column. withAction puts the run button at the end of it -
// a key hint is not a button, and the old interface had one you could click.
func (u *UI) newForm(fields []field, width int, withAction bool) *tview.Form {
	form := tview.NewForm().SetItemPadding(0)
	form.SetBackgroundColor(groundColor)
	form.SetLabelColor(ink3Color).
		SetFieldBackgroundColor(fieldColor).
		SetFieldTextColor(inkColor).
		SetButtonBackgroundColor(fieldColor).
		SetButtonTextColor(inkColor)

	section := ""
	for _, entry := range fields {
		if entry.section != section {
			section = entry.section
			heading(form, section, about[section])
		}
		entry.build(form, width)
	}
	if withAction {
		form.AddButton("▶ run scan", func() { u.start() })
		form.SetButtonBackgroundColor(passColor).
			SetButtonTextColor(tcell.ColorBlack).
			SetButtonsAlign(tview.AlignLeft)
	}
	return form
}

func severityNames() []string {
	out := make([]string, 0, len(model.Order))
	for _, severity := range model.Order {
		out = append(out, string(severity))
	}
	return out
}

func indexIn(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return 0
}

func at(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

// labelOf strips the colour tags a checkbox label carries, for tests and for the
// narrow layout's measurements.
func labelOf(label string) string {
	for _, tag := range []string{dimTag, resetTag, markTag, passTag, flagTag, inkTag} {
		label = strings.ReplaceAll(label, tag, "")
	}
	return strings.TrimSpace(label)
}
