package ui

import (
	"strconv"
	"strings"

	"github.com/smagew/whatsrisky/internal/scan"
)

// values is what the screen edits. Every widget writes into one of these on
// change, so the panel can read the settings while they are being typed - the
// equivalent command has to stay live.
//
// Numbers live here as strings because that is what a field holds; apply is the
// one place that converts, and a value it cannot parse leaves the option alone.
type values struct {
	path        string
	diff        string
	tools       map[string]bool
	aiProvider  string
	aiModel     string
	aiMode      string
	formats     map[string]bool
	outDir      string
	openReport  bool
	minSeverity string
	failOn      string
	ignorePaths string
	ignoreNoise bool
	semgrep     string
	trivy       string
	gitleaks    string
	jobs        string
	offline     bool
	compare     bool
	profileName string
}

func newValues(options scan.Options) *values {
	return &values{
		path:        options.Path,
		diff:        options.Diff,
		tools:       setOf(scan.AllTools, options.Tools),
		aiProvider:  options.AIProvider,
		aiModel:     options.Model,
		aiMode:      options.AIMode,
		formats:     setOf(scan.FormatChoices, options.Formats),
		outDir:      options.OutDir,
		openReport:  options.OpenReport,
		minSeverity: options.MinSeverity,
		failOn:      options.FailOn,
		ignorePaths: commaList(options.Exclude),
		ignoreNoise: options.UseDefaultExcludes,
		semgrep:     commaList(options.SemgrepConfigs),
		trivy:       options.TrivyScanners,
		gitleaks:    options.GitleaksMode,
		jobs:        strconv.Itoa(options.Jobs),
		offline:     options.Offline,
		compare:     options.Compare,
	}
}

// apply reads the screen back over the options it started from. A blank tuning
// field means "leave the default alone", not "set it to empty" - an empty
// --semgrep-config would scan with no rules at all and still look like a scan.
func (v *values) apply(base scan.Options) scan.Options {
	options := base
	options.Path = strings.TrimSpace(v.path)
	options.Diff = strings.TrimSpace(v.diff)
	options.Tools = chosen(scan.AllTools, v.tools)
	options.AIProvider = v.aiProvider
	options.Model = strings.TrimSpace(v.aiModel)
	options.AIMode = v.aiMode
	options.Formats = chosen(scan.FormatChoices, v.formats)
	options.OutDir = strings.TrimSpace(v.outDir)
	options.OpenReport = v.openReport
	options.MinSeverity = v.minSeverity
	options.FailOn = v.failOn
	options.Exclude = splitCommas(v.ignorePaths)
	options.UseDefaultExcludes = v.ignoreNoise
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

// setOf turns a chosen list into a lookup over every possible value, so a widget
// can ask "is this one on" without scanning a slice.
func setOf(all, on []string) map[string]bool {
	out := make(map[string]bool, len(all))
	for _, name := range all {
		out[name] = false
	}
	for _, name := range on {
		out[name] = true
	}
	return out
}

// chosen puts the selection back in the canonical order, not the order the user
// happened to tick things in.
func chosen(all []string, on map[string]bool) []string {
	var out []string
	for _, name := range all {
		if on[name] {
			out = append(out, name)
		}
	}
	return out
}
