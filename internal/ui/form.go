package ui

import (
	"errors"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// formValues is what the form edits. Every field binds to one of these, so the
// side panel can read the settings while they are still being typed - the
// equivalent command has to stay live, not wait for a finished form.
//
// Numbers live here as strings because that is what an input holds; apply is the
// one place that converts, and a value it cannot parse leaves the option alone.
type formValues struct {
	path        string
	diff        string
	tools       []string
	aiProvider  string
	aiModel     string
	aiMode      string
	formats     []string
	outDir      string
	openReport  bool
	minSeverity string
	failOn      string
	exclude     string
	skipNoise   bool
	semgrep     string
	trivy       string
	gitleaks    string
	jobs        string
	offline     bool
	compare     bool
	profileName string
}

func newFormValues(options scan.Options) *formValues {
	return &formValues{
		path:        options.Path,
		diff:        options.Diff,
		tools:       append([]string(nil), options.Tools...),
		aiProvider:  options.AIProvider,
		aiModel:     options.Model,
		aiMode:      options.AIMode,
		formats:     append([]string(nil), options.Formats...),
		outDir:      options.OutDir,
		openReport:  options.OpenReport,
		minSeverity: options.MinSeverity,
		failOn:      options.FailOn,
		exclude:     commaList(options.Exclude),
		skipNoise:   options.UseDefaultExcludes,
		semgrep:     commaList(options.SemgrepConfigs),
		trivy:       options.TrivyScanners,
		gitleaks:    options.GitleaksMode,
		jobs:        strconv.Itoa(options.Jobs),
		offline:     options.Offline,
		compare:     options.Compare,
	}
}

// apply reads the form back over the options it started from. A blank tuning
// field means "leave the default alone", not "set it to empty" - an empty
// --semgrep-config would scan with no rules at all and still look like a scan.
func (v *formValues) apply(base scan.Options) scan.Options {
	options := base
	options.Path = strings.TrimSpace(v.path)
	options.Diff = strings.TrimSpace(v.diff)
	options.Tools = append([]string(nil), v.tools...)
	options.AIProvider = v.aiProvider
	options.Model = strings.TrimSpace(v.aiModel)
	options.AIMode = v.aiMode
	options.Formats = append([]string(nil), v.formats...)
	options.OutDir = strings.TrimSpace(v.outDir)
	options.OpenReport = v.openReport
	options.MinSeverity = v.minSeverity
	options.FailOn = v.failOn
	options.Exclude = splitCommas(v.exclude)
	options.UseDefaultExcludes = v.skipNoise
	options.GitleaksMode = v.gitleaks
	options.Offline = v.offline
	options.Compare = v.compare
	if list := splitCommas(v.semgrep); len(list) > 0 {
		options.SemgrepConfigs = list
	}
	if trivy := strings.TrimSpace(v.trivy); trivy != "" {
		options.TrivyScanners = trivy
	}
	if jobs, err := strconv.Atoi(strings.TrimSpace(v.jobs)); err == nil && jobs > 0 {
		options.Jobs = jobs
	}
	return options
}

// form builds the whole settings form. Sections are huh groups, which means they
// are pages: a section is either fully on screen or it is the next page. Nothing
// is ever half-drawn, and no field can hide below a fold.
func (v *formValues) form(width, height int) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("path").Description("the project to scan").
				Placeholder("/path/to/project").Value(&v.path).
				Validate(func(value string) error {
					if strings.TrimSpace(value) == "" {
						return errors.New("a path is required")
					}
					return nil
				}),
			huh.NewInput().Title("git range").
				Description("scope the scan to what a range changed; blank scans everything").
				Placeholder("main..HEAD").Value(&v.diff),
			section("Scanners"),
			huh.NewMultiSelect[string]().Title("scanners").
				Description("each one that is off is a gap the report will admit to").
				Options(options(scan.AllTools, scan.AllTools)...).Value(&v.tools),
			section("AI review"),
			huh.NewSelect[string]().Title("provider").
				Description("claude-cli reads the repository itself; openai sees only what we send it").
				Options(options(ai.Providers, []string{
					"claude-cli — reads the repo itself",
					"openai — api, sees what we send",
				})...).Value(&v.aiProvider),
			huh.NewInput().Title("model").
				Description("opus, gpt-5, or a full model id; blank takes the backend's default").
				Placeholder("blank = default").Value(&v.aiModel),
			huh.NewSelect[string]().Title("mode").
				Description("review needs a backend with git access").
				Options(options(
					[]string{"full", "review", "both"},
					[]string{
						"full — audit the whole project",
						"review — the branch diff",
						"both — the project and the diff",
					})...).Value(&v.aiMode),
			section("Output"),
			huh.NewMultiSelect[string]().Title("formats").
				Description("html is the view, json is the contract another tool reads").
				Options(options(scan.FormatChoices, scan.FormatChoices)...).Value(&v.formats),
			huh.NewInput().Title("report directory").
				Description("where the reports go; blank means ./whatsrisky-reports").
				Placeholder("blank = ./whatsrisky-reports").Value(&v.outDir),
			huh.NewConfirm().Title("open when done").
				Description("open the report as soon as the scan finishes").
				Affirmative("yes").Negative("no").Value(&v.openReport),
			section("Filtering"),
			huh.NewSelect[string]().Title("minimum severity").
				Description("findings below this are dropped from the report").
				Options(options(severityNames(), severityNames())...).Value(&v.minSeverity),
			huh.NewSelect[string]().Title("fail-on").
				Description("exit 2 at or above this, so CI can gate on it").
				Options(options(scan.FailOnChoices, scan.FailOnChoices)...).Value(&v.failOn),
			huh.NewInput().Title("skip these").
				Description("directories, paths or globs, comma separated").
				Placeholder("blank = nothing extra").Value(&v.exclude),
			huh.NewConfirm().Title("skip the usual noise").
				Description("node_modules, vendor, dist and the rest").
				Affirmative("yes").Negative("no").Value(&v.skipNoise),
			section("Tuning"),
			huh.NewInput().Title("semgrep --config").
				Description("comma separated rule packs").
				Placeholder("auto").Value(&v.semgrep),
			huh.NewInput().Title("trivy --scanners").
				Description("which trivy passes to run").
				Placeholder("vuln,misconfig").Value(&v.trivy),
			huh.NewSelect[string]().Title("gitleaks").
				Description("the working tree, the history, or both").
				Options(options(
					[]string{"auto", "dir", "git"},
					[]string{
						"auto — tree, plus history if this is a repo",
						"dir — working tree only",
						"git — history only",
					})...).Value(&v.gitleaks),
			huh.NewInput().Title("parallel jobs").
				Description("1 runs the scanners one after another").
				Placeholder("1").Value(&v.jobs).
				Validate(func(value string) error {
					value = strings.TrimSpace(value)
					if value == "" {
						return nil
					}
					jobs, err := strconv.Atoi(value)
					if err != nil || jobs < 1 {
						return errors.New("a whole number of jobs, 1 or more")
					}
					return nil
				}),
			huh.NewConfirm().Title("offline").
				Description("no network; trivy skips its database update").
				Affirmative("yes").Negative("no").Value(&v.offline),
			huh.NewConfirm().Title("compare with last").
				Description("off means no new, resolved or reintroduced statuses").
				Affirmative("yes").Negative("no").Value(&v.compare),
			section("Profile"),
			huh.NewInput().Title("save as").
				Description("ctrl+s stores everything above under this name").
				Placeholder("a name").Value(&v.profileName),
		).Title("── Project"),
	).WithWidth(width).WithHeight(height).WithShowHelp(true).WithShowErrors(true).
		WithTheme(formTheme())
}

// section is a heading, not a field: NewNote skips itself when the cursor moves
// past, so the form reads as seven named parts without seven pages.
func section(title string) *huh.Note {
	// No Description here: huh leaks a reset sequence into a note's description,
	// and a heading does not need one.
	return huh.NewNote().Title("── " + title)
}

// options pairs values with the labels a human reads. The two lists are written
// side by side at the call site, so a mismatch is a programming error, not input.
func options(values, labels []string) []huh.Option[string] {
	out := make([]huh.Option[string], 0, len(values))
	for index, value := range values {
		label := value
		if index < len(labels) {
			label = labels[index]
		}
		out = append(out, huh.NewOption(label, value))
	}
	return out
}

func severityNames() []string {
	out := make([]string, 0, len(model.Order))
	for _, severity := range model.Order {
		out = append(out, string(severity))
	}
	return out
}

// formTheme is the base theme wearing our palette, so the form and the HTML
// viewer are recognisably the same tool.
func formTheme() *huh.Theme {
	theme := huh.ThemeBase()

	theme.Focused.Base = theme.Focused.Base.BorderForeground(markColor)
	theme.Focused.Title = theme.Focused.Title.Foreground(markColor).Bold(true)
	theme.Focused.Description = theme.Focused.Description.Foreground(ink3Color)
	theme.Focused.SelectSelector = theme.Focused.SelectSelector.Foreground(markColor)
	theme.Focused.MultiSelectSelector = theme.Focused.MultiSelectSelector.Foreground(markColor)
	theme.Focused.SelectedOption = theme.Focused.SelectedOption.Foreground(passColor)
	theme.Focused.SelectedPrefix = lipgloss.NewStyle().SetString("[x] ").Foreground(passColor)
	theme.Focused.UnselectedPrefix = lipgloss.NewStyle().SetString("[ ] ").Foreground(lineColor)
	theme.Focused.UnselectedOption = theme.Focused.UnselectedOption.Foreground(ink2Color)
	theme.Focused.Option = theme.Focused.Option.Foreground(inkColor)
	theme.Focused.ErrorIndicator = theme.Focused.ErrorIndicator.Foreground(flagColor)
	theme.Focused.ErrorMessage = theme.Focused.ErrorMessage.Foreground(flagColor)
	theme.Focused.FocusedButton = theme.Focused.FocusedButton.
		Background(passColor).Foreground(lipgloss.Color("235")).Bold(true)
	theme.Focused.BlurredButton = theme.Focused.BlurredButton.Foreground(ink3Color)
	theme.Focused.TextInput.Cursor = theme.Focused.TextInput.Cursor.Foreground(markColor)
	theme.Focused.TextInput.Placeholder = theme.Focused.TextInput.Placeholder.Foreground(lineColor)
	theme.Focused.TextInput.Prompt = theme.Focused.TextInput.Prompt.Foreground(markColor)
	theme.Focused.TextInput.Text = theme.Focused.TextInput.Text.Foreground(inkColor)

	// Blurred must NOT be a copy of Focused: the focus bar is how you know where
	// you are, and copying put it on all twenty fields at once.
	theme.Blurred.Title = theme.Blurred.Title.Foreground(ink3Color)
	theme.Blurred.Description = theme.Blurred.Description.Foreground(lineColor)
	theme.Blurred.SelectedOption = theme.Blurred.SelectedOption.Foreground(passColor)
	theme.Blurred.SelectedPrefix = lipgloss.NewStyle().SetString("[x] ").Foreground(passColor)
	theme.Blurred.UnselectedPrefix = lipgloss.NewStyle().SetString("[ ] ").Foreground(lineColor)
	theme.Blurred.UnselectedOption = theme.Blurred.UnselectedOption.Foreground(ink3Color)
	theme.Blurred.TextInput.Text = theme.Blurred.TextInput.Text.Foreground(ink2Color)
	theme.Blurred.TextInput.Placeholder = theme.Blurred.TextInput.Placeholder.Foreground(lineColor)
	theme.Focused.NoteTitle = theme.Focused.NoteTitle.Foreground(markColor).Bold(true).MarginTop(1)
	theme.Blurred.NoteTitle = theme.Focused.NoteTitle

	theme.Group.Title = theme.Group.Title.Foreground(markColor).Bold(true)
	theme.Group.Description = theme.Group.Description.Foreground(ink3Color)
	theme.Help.ShortKey = theme.Help.ShortKey.Foreground(ink3Color)
	theme.Help.ShortDesc = theme.Help.ShortDesc.Foreground(lineColor)
	theme.Help.ShortSeparator = theme.Help.ShortSeparator.Foreground(lineColor)
	return theme
}
