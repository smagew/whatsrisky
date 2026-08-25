package ui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/runner"
	"github.com/smagew/whatsrisky/internal/scan"
)

// row is a field with the section it belongs to. The sections are the reading
// order: the profile you start from, then what to scan, then how.
type row struct {
	section string
	field   field
}

type probeRow struct {
	name   string
	found  bool
	detail string
}

type probeResult struct{ rows []probeRow }

// buildRows is the form. Every entry maps onto a scan.Options field, so a setting
// that exists here must exist in the CLI too.
func buildRows() []row {
	severities := make([]string, 0, len(model.Order))
	for _, severity := range model.Order {
		severities = append(severities, string(severity))
	}
	return []row{
		{"Profile", newTextField("save as", "ctrl+s stores the current settings under this name", "a name",
			func(scan.Options) string { return "" }, func(*scan.Options, string) {})},

		{"Project", newTextField("path", "the project to scan", "/path/to/project",
			func(o scan.Options) string { return o.Path },
			func(o *scan.Options, v string) { o.Path = v })},
		{"Project", newTextField("git range", "scope the scan to what a range changed", "blank = the whole project",
			func(o scan.Options) string { return o.Diff },
			func(o *scan.Options, v string) { o.Diff = v })},

		{"Scanners", newMultiField("scanners", "space toggles the one under the cursor",
			scan.AllTools, scan.AllTools,
			func(o scan.Options) []string { return o.Tools },
			func(o *scan.Options, v []string) { o.Tools = v })},

		{"AI review", newChoiceField("provider", "claude-cli reads the repository; openai sees only what we send",
			ai.Providers, []string{"claude-cli — reads the repo itself", "openai — api, sees what we send"},
			func(o scan.Options) string { return o.AIProvider },
			func(o *scan.Options, v string) { o.AIProvider = v })},
		{"AI review", newTextField("model", "opus, gpt-5, or a full model id", "blank = the backend's default",
			func(o scan.Options) string { return o.Model },
			func(o *scan.Options, v string) { o.Model = v })},
		{"AI review", newChoiceField("mode", "review needs a backend with git access",
			[]string{"full", "review", "both"},
			[]string{"full — audit the whole project", "review — the branch diff", "both"},
			func(o scan.Options) string { return o.AIMode },
			func(o *scan.Options, v string) { o.AIMode = v })},

		{"Output", newMultiField("formats", "html is the view, json is the contract",
			scan.FormatChoices, scan.FormatChoices,
			func(o scan.Options) []string { return o.Formats },
			func(o *scan.Options, v []string) { o.Formats = v })},
		{"Output", newTextField("report directory", "where the reports go", "blank = ./whatsrisky-reports",
			func(o scan.Options) string { return o.OutDir },
			func(o *scan.Options, v string) { o.OutDir = v })},
		{"Output", newToggleField("open when done", "open the report when the scan finishes",
			func(o scan.Options) bool { return o.OpenReport },
			func(o *scan.Options, v bool) { o.OpenReport = v })},

		{"Filtering", newChoiceField("minimum severity", "drop findings below this", severities, severities,
			func(o scan.Options) string { return o.MinSeverity },
			func(o *scan.Options, v string) { o.MinSeverity = v })},
		{"Filtering", newChoiceField("fail-on", "exit 2 at or above this, for CI",
			scan.FailOnChoices, scan.FailOnChoices,
			func(o scan.Options) string { return o.FailOn },
			func(o *scan.Options, v string) { o.FailOn = v })},
		{"Filtering", newTextField("skip these", "directories, paths or globs, comma separated", "blank = nothing extra",
			func(o scan.Options) string { return commaList(o.Exclude) },
			func(o *scan.Options, v string) { o.Exclude = splitCommas(v) })},
		{"Filtering", newToggleField("skip the usual noise", "node_modules, vendor, dist and the rest",
			func(o scan.Options) bool { return o.UseDefaultExcludes },
			func(o *scan.Options, v bool) { o.UseDefaultExcludes = v })},

		{"Tuning", newTextField("semgrep --config", "comma separated rule packs", "auto",
			func(o scan.Options) string { return commaList(o.SemgrepConfigs) },
			func(o *scan.Options, v string) {
				if list := splitCommas(v); len(list) > 0 {
					o.SemgrepConfigs = list
				}
			})},
		{"Tuning", newTextField("trivy --scanners", "which trivy passes to run", "vuln,misconfig",
			func(o scan.Options) string { return o.TrivyScanners },
			func(o *scan.Options, v string) {
				if v != "" {
					o.TrivyScanners = v
				}
			})},
		{"Tuning", newChoiceField("gitleaks", "which passes to run",
			[]string{"auto", "dir", "git"},
			[]string{"auto — tree + history if git", "dir — working tree only", "git — history only"},
			func(o scan.Options) string { return o.GitleaksMode },
			func(o *scan.Options, v string) { o.GitleaksMode = v })},
		{"Tuning", newNumberField("parallel jobs", "1 = sequential",
			func(o scan.Options) int { return o.Jobs },
			func(o *scan.Options, v int) {
				if v > 0 {
					o.Jobs = v
				}
			})},
		{"Tuning", newToggleField("offline", "no network; trivy skips its DB update",
			func(o scan.Options) bool { return o.Offline },
			func(o *scan.Options, v bool) { o.Offline = v })},
		{"Tuning", newToggleField("compare with last", "off = no new/resolved statuses",
			func(o scan.Options) bool { return o.Compare },
			func(o *scan.Options, v bool) { o.Compare = v })},
	}
}

// collect reads the form back into options.
func (m *Model) collect() scan.Options {
	options := m.options
	for _, entry := range m.rows {
		entry.field.apply(&options)
	}
	return options
}

// loadInto pushes options into the form.
func (m *Model) loadInto(options scan.Options) {
	m.options = options
	for _, entry := range m.rows {
		entry.field.load(options)
	}
}

// probe asks each scanner whether it is there. In a goroutine, because a version
// check spawns processes.
func probe() tea.Msg {
	config := runner.Config{Target: ".", WorkDir: os.TempDir(), AIProvider: "claude-cli"}
	rows := make([]probeRow, 0, len(scan.AllTools))
	for _, name := range scan.AllTools {
		entry := probeRow{name: name}
		built, err := runner.New(name, config)
		switch {
		case err != nil:
			entry.detail = err.Error()
		case built.Available():
			entry.found = true
			entry.detail = built.Version()
		default:
			entry.detail = built.UnavailableReason()
		}
		rows = append(rows, entry)
	}
	return probeResult{rows: rows}
}

// warnings are what to say before the scan runs, not after. Anything that would
// surprise the user belongs here.
func (m *Model) warnings(options scan.Options) []string {
	var out []string
	for _, problem := range options.Validate(isDirectory) {
		out = append(out, badStyle.Render("• ")+problem)
	}
	if options.HasTool("ai") {
		out = append(out, warnStyle.Render("• ")+"the ai pass spends tokens on your account")
		backend, err := ai.New(options.AIProvider, orDot(options.Path), os.TempDir())
		switch {
		case err != nil:
			out = append(out, badStyle.Render("• ")+err.Error())
		default:
			if ready, reason := backend.Available(); !ready {
				out = append(out, badStyle.Render("• ")+reason)
			}
			if !backend.Agentic() {
				if options.AIMode == "review" || options.AIMode == "both" {
					out = append(out, badStyle.Render("• ")+options.AIProvider+
						" cannot review a diff — use full")
				}
				out = append(out, dimStyle.Render("• this backend sees only the files we send it"))
			} else if firstNonEmptyString(options.Model, backend.DefaultModel()) == "opus" {
				out = append(out, dimStyle.Render("• opus is the priciest pass; sonnet is ~5x cheaper"))
			}
		}
	}
	if options.Diff != "" && options.HasTool("trivy") {
		out = append(out, dimStyle.Render("• trivy ignores --diff (CVEs are manifest-wide)"))
	}
	if count := len(options.EffectiveExcludes()); count > 0 {
		out = append(out, dimStyle.Render(fmt.Sprintf("• skipping %d pattern(s)", count)))
	}
	if len(out) == 0 {
		out = append(out, okStyle.Render("ready to run"))
	}
	return out
}

// saveProfile stores the form under the name in the profile field.
func (m *Model) saveProfile() string {
	name := strings.TrimSpace(m.profileNameField().input.Value())
	if name == "" {
		return "type a profile name first"
	}
	if err := config.SaveProfile(name, m.collect()); err != nil {
		return "saving the profile: " + err.Error()
	}
	m.profile = name
	return "saved '" + name + "' — the next launch starts from it"
}

func (m *Model) profileNameField() *textField {
	if len(m.rows) > 0 {
		if field, ok := m.rows[0].field.(*textField); ok {
			return field
		}
	}
	return newTextField("", "", "", nil, nil)
}

// profileNames is the saved list, for the side panel.
func profileNames() []string { return config.ProfileNames() }

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func orDot(value string) string {
	if value == "" {
		return "."
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
