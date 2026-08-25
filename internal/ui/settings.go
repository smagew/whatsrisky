package ui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/runner"
	"github.com/smagew/whatsrisky/internal/scan"
)

type probeRow struct {
	name   string
	found  bool
	detail string
}

type probeResult struct{ rows []probeRow }

// buildRows is the form. Every entry maps onto a scan.Options field, so a setting
// that exists here must exist in the CLI too.
// collect reads the form back into options. The form's variables are live, so
// this is cheap and safe to call on every frame - the side panel depends on it.
func (m *Model) collect() scan.Options { return m.values.apply(m.options) }

// loadInto rebuilds the form around a different set of options - loading a
// profile, for instance. Rebuilt rather than refilled, because a huh field binds
// to its variable when it is constructed.
func (m *Model) loadInto(options scan.Options) {
	name := ""
	if m.values != nil {
		name = m.values.profileName
	}
	m.options = options
	m.values = newFormValues(options)
	m.values.profileName = name
	m.form = m.values.form(m.formWidth(), m.bodyHeight())
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
	name := strings.TrimSpace(m.values.profileName)
	if name == "" {
		return "type a profile name first"
	}
	if err := config.SaveProfile(name, m.collect()); err != nil {
		return "saving the profile: " + err.Error()
	}
	m.profile = name
	return "saved '" + name + "' — the next launch starts from it"
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
