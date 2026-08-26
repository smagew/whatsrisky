package ui

import (
	"os"
	"sort"
	"strings"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/exclude"
	"github.com/smagew/whatsrisky/internal/runner"
	"github.com/smagew/whatsrisky/internal/scan"
)

type probeRow struct {
	name   string
	found  bool
	detail string
}

// probe asks each scanner whether it is there. Off the drawing goroutine, because
// a version check spawns processes.
func (u *UI) probe() {
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
	u.update(func() {
		u.probes = rows
		u.probing = false
	})
}

// warnings is everything worth saying before a scan rather than after it. Plain
// sentences: the panel adds the bullets, and nothing here uses a word the user
// would have to look up.
func (u *UI) warnings(options scan.Options) []string {
	var out []string
	out = append(out, options.Validate(isDirectory)...)

	if options.HasTool("ai") {
		out = append(out, "the ai pass spends money on your account")
		backend, err := ai.New(options.AIProvider, orDot(options.Path), os.TempDir())
		switch {
		case err != nil:
			out = append(out, err.Error())
		default:
			if ready, reason := backend.Available(); !ready {
				out = append(out, reason)
			}
			if !backend.Agentic() {
				if options.AIMode == "review" || options.AIMode == "both" {
					out = append(out, options.AIProvider+
						" cannot review a diff — choose the whole folder")
				}
				out = append(out, "this backend sees only the files we send it")
			} else if firstNonEmptyString(options.Model, backend.DefaultModel()) == "opus" {
				out = append(out, "opus is the priciest pass; sonnet is ~5x cheaper")
			}
		}
	}
	for _, entry := range u.probes {
		if entry.found || !options.HasTool(entry.name) {
			continue
		}
		out = append(out, entry.name+" is not installed, so "+whatItCovers(entry.name)+
			" will not be checked — the report will say so")
	}
	if options.Diff != "" && options.HasTool("trivy") {
		out = append(out, "trivy ignores --diff: it checks dependency versions, which are not per-change")
	}
	if len(out) == 0 {
		out = append(out, "ready to run")
	}
	return out
}

// whatItCovers says what is lost when a scanner is missing, in the terms of the
// thing that goes unchecked rather than the name of the tool.
func whatItCovers(tool string) string {
	switch tool {
	case "semgrep":
		return "the code itself"
	case "trivy":
		return "dependency versions and container images"
	case "gitleaks":
		return "secrets, including the ones in git history"
	case "ai":
		return "the review pass"
	}
	return tool
}

// saveProfile writes the settings where the next launch will look for them: in
// the project itself. A name, if one was typed, also stores them under that name
// for --profile, which is asked for explicitly and is not per-project.
func (u *UI) saveProfile() string {
	options := u.collect()
	target := strings.TrimSpace(options.Path)
	if target == "" {
		return "there is no project folder to save into"
	}
	if err := config.SaveProject(target, options); err != nil {
		return "saving " + config.ProjectFile + ": " + err.Error()
	}
	saved := "saved to " + config.ProjectFile + " — this folder starts from it"

	name := strings.TrimSpace(u.values.profileName)
	if name == "" {
		return saved
	}
	if err := config.SaveProfile(name, options); err != nil {
		return saved + ", but the named copy failed: " + err.Error()
	}
	u.profile = name
	return saved + ", and as '" + name + "' for --profile"
}

// profileNames is the saved list, for the panel.
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

// projectDirs is the folders of the project as it stands, so they can be ticked
// instead of typed. Read at layout time: one directory listing, and it is the
// folder the user is looking at.
//
// Hidden folders are included - .github and .claude are exactly the kind of thing
// someone wants out of a scan - but the ones we always skip are not, because they
// are already covered by the switch beside this. Every folder is returned: the row
// wraps, and whatever still does not fit is counted on screen rather than dropped.
func (u *UI) projectDirs() []string {
	path := strings.TrimSpace(u.values.path)
	if path == "" {
		return nil
	}
	if path == u.dirsFor {
		return u.dirs
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		u.dirsFor, u.dirs = path, nil
		return nil
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() || exclude.Path(entry.Name(), exclude.Defaults) {
			continue
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	u.dirsFor, u.dirs = path, out
	return out
}
