package ui

import (
	"strings"

	"github.com/rivo/tview"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// A section is a heading inside the form. tview has no such item, so it is a
// label with no field - written once here rather than at every use.
func heading(form *tview.Form, title string) {
	form.AddTextView(markTag+"── "+title+resetTag, "", 0, 1, true, false)
}

// field is one row of the form, described rather than built, so the same list can
// be laid out in one column or two without being written twice.
type field struct {
	section string
	build   func(form *tview.Form, width int)
}

// fields is every setting on the screen, in reading order: what to scan, then
// what runs, then what comes out, then what is left out, then the details.
//
// No word here is jargon. "pattern" and "exclusion" were both in the last
// version and neither said what it meant.
func (u *UI) fields() []field {
	v := u.values
	return []field{
		{"Project", func(f *tview.Form, w int) {
			f.AddInputField("project folder", v.path, w, nil, func(text string) { v.path = text })
		}},
		{"Project", func(f *tview.Form, w int) {
			f.AddInputField("only these changes", v.diff, w, nil, func(text string) { v.diff = text })
		}},

		{"Scanners", func(f *tview.Form, w int) { u.toolBox(f, "semgrep") }},
		{"Scanners", func(f *tview.Form, w int) { u.toolBox(f, "trivy") }},
		{"Scanners", func(f *tview.Form, w int) { u.toolBox(f, "gitleaks") }},
		{"Scanners", func(f *tview.Form, w int) { u.toolBox(f, "ai") }},

		{"AI review", func(f *tview.Form, w int) {
			labels := []string{"claude-cli — reads the folder itself", "openai — sees only what we send"}
			f.AddDropDown("who reviews", labels, indexIn(ai.Providers, v.aiProvider),
				func(_ string, index int) { v.aiProvider = at(ai.Providers, index) })
		}},
		{"AI review", func(f *tview.Form, w int) {
			f.AddInputField("model", v.aiModel, w, nil, func(text string) { v.aiModel = text })
		}},
		{"AI review", func(f *tview.Form, w int) {
			modes := []string{"full", "review", "both"}
			labels := []string{"the whole folder", "only the changes", "both"}
			f.AddDropDown("what it reads", labels, indexIn(modes, v.aiMode),
				func(_ string, index int) { v.aiMode = at(modes, index) })
		}},

		{"Output", func(f *tview.Form, w int) { u.formatBox(f, "html") }},
		{"Output", func(f *tview.Form, w int) { u.formatBox(f, "md") }},
		{"Output", func(f *tview.Form, w int) { u.formatBox(f, "json") }},
		{"Output", func(f *tview.Form, w int) {
			f.AddInputField("save reports in", v.outDir, w, nil, func(text string) { v.outDir = text })
		}},
		{"Output", func(f *tview.Form, w int) {
			u.yesNo(f, "open when done", &v.openReport)
		}},

		{"What we do not look at", func(f *tview.Form, w int) {
			f.AddInputField("your folders and files", v.ignorePaths, w, nil,
				func(text string) { v.ignorePaths = text })
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
			f.AddInputField("semgrep rules", v.semgrep, w, nil, func(text string) { v.semgrep = text })
		}},
		{"Details", func(f *tview.Form, w int) {
			f.AddInputField("trivy passes", v.trivy, w, nil, func(text string) { v.trivy = text })
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
			f.AddInputField("save these settings as", v.profileName, w, nil,
				func(text string) { v.profileName = text })
		}},
	}
}

// toolBox is one scanner. Turning one off is a gap the report will admit to, so
// the label says what the scanner is for rather than only its name.
func (u *UI) toolBox(form *tview.Form, tool string) {
	form.AddCheckbox(tool, u.values.tools[tool],
		func(on bool) { u.values.tools[tool] = on; u.refresh() })
}

func (u *UI) formatBox(form *tview.Form, format string) {
	form.AddCheckbox(format, u.values.formats[format],
		func(on bool) { u.values.formats[format] = on; u.refresh() })
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
func (u *UI) newForm(fields []field, fieldWidth int) *tview.Form {
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
			heading(form, section)
		}
		entry.build(form, fieldWidth)
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
