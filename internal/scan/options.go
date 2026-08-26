// Package scan owns what a scan is: every setting, the exclusions, and the run
// itself. It has no terminal and no UI, so the CLI, the terminal UI and a library
// caller all share one source of truth for the defaults.
package scan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/smagew/whatsrisky/internal/exclude"
)

// AllTools is every scanner that exists; DefaultTools is what runs unless asked
// otherwise. The AI pass is not a default: it spends the caller's money and sends
// code to a third party.
var (
	AllTools     = []string{"semgrep", "trivy", "gitleaks", "ai"}
	DefaultTools = []string{"semgrep", "trivy", "gitleaks", "ai"}

	// ToolsWithoutAI is the default set with the review pass taken out. It exists
	// so turning the pass off is one flag rather than a list of the other three.
	ToolsWithoutAI = []string{"semgrep", "trivy", "gitleaks"}

	// ToolAliases keeps configs written before the pass became provider-neutral.
	ToolAliases = map[string]string{"claude": "ai"}

	// FormatChoices is ordered: html is the view, json is the contract.
	FormatChoices = []string{"html", "md", "json"}

	FailOnChoices = []string{"none", "critical", "high", "medium", "low", "info"}

	ToolCoverage = map[string]string{
		"semgrep":  "First-party source code (SAST)",
		"trivy":    "Dependency CVEs, IaC misconfig",
		"gitleaks": "Secrets in tree and git history",
		"ai":       "LLM review of logic and authz",
	}
)

// Options is every knob, serializable, and the keys match the Python
// implementation's so an existing ~/.config/whatsrisky/config.json keeps working.
type Options struct {
	Path               string   `json:"path"`
	Diff               string   `json:"diff"`
	Tools              []string `json:"tools"`
	Formats            []string `json:"formats"`
	OutDir             string   `json:"out_dir"`
	Out                string   `json:"out"`
	AIProvider         string   `json:"ai_provider"`
	Model              string   `json:"model"`
	AIMode             string   `json:"ai_mode"`
	AITimeout          int      `json:"ai_timeout"`
	AIMaxFindings      int      `json:"ai_max_findings"`
	AIContextBytes     int      `json:"ai_context_bytes"`
	SemgrepConfigs     []string `json:"semgrep_configs"`
	TrivyScanners      string   `json:"trivy_scanners"`
	GitleaksMode       string   `json:"gitleaks_mode"`
	Exclude            []string `json:"exclude"`
	UseDefaultExcludes bool     `json:"use_default_excludes"`
	Offline            bool     `json:"offline"`
	Timeout            int      `json:"timeout"`
	Jobs               int      `json:"jobs"`
	MinSeverity        string   `json:"min_severity"`
	MaxPerSeverity     *int     `json:"max_per_severity"`
	FailOn             string   `json:"fail_on"`
	WorkDir            string   `json:"work_dir"`
	KeepWork           bool     `json:"keep_work"`
	OpenReport         bool     `json:"open_report"`
	Baseline           string   `json:"baseline"`
	Compare            bool     `json:"compare"`
}

// NewOptions is the defaults. Anything that reads a stored config must start here
// so a missing key means "the default", not the zero value.
func NewOptions() Options {
	return Options{
		Tools:              append([]string(nil), DefaultTools...),
		Formats:            append([]string(nil), FormatChoices...),
		AIProvider:         "claude-cli",
		AIMode:             "full",
		AITimeout:          3600,
		AIMaxFindings:      40,
		AIContextBytes:     240000,
		SemgrepConfigs:     []string{"auto"},
		TrivyScanners:      "vuln,misconfig",
		GitleaksMode:       "auto",
		UseDefaultExcludes: true,
		Timeout:            1800,
		Jobs:               4,
		MinSeverity:        "INFO",
		FailOn:             "none",
		Compare:            true,
	}
}

// Normalized resolves the combinations that cannot work as configured.
func (o Options) Normalized() Options {
	out := o
	out.Tools = canonicalTools(o.Tools)
	out.Formats = keepOrder(FormatChoices, o.Formats)
	if out.Offline && len(out.SemgrepConfigs) == 1 && out.SemgrepConfigs[0] == "auto" {
		// `--config auto` fetches rules from the registry; offline needs a pack.
		out.SemgrepConfigs = []string{"p/security-audit"}
	}
	if out.Jobs < 1 {
		out.Jobs = 1
	} else if out.Jobs > 8 {
		out.Jobs = 8
	}
	return out
}

func canonicalTools(tools []string) []string {
	seen := map[string]bool{}
	for _, tool := range tools {
		if mapped, ok := ToolAliases[tool]; ok {
			tool = mapped
		}
		seen[tool] = true
	}
	return keepOrderSet(AllTools, seen)
}

func keepOrder(order, chosen []string) []string {
	seen := map[string]bool{}
	for _, item := range chosen {
		seen[item] = true
	}
	return keepOrderSet(order, seen)
}

func keepOrderSet(order []string, seen map[string]bool) []string {
	out := make([]string, 0, len(order))
	for _, item := range order {
		if seen[item] {
			out = append(out, item)
		}
	}
	return out
}

// EffectiveExcludes is the user's exclusions plus the default set, de-duplicated
// and in a stable order.
func (o Options) EffectiveExcludes() []string {
	var candidates []string
	if o.UseDefaultExcludes {
		candidates = append(candidates, exclude.Defaults...)
	}
	candidates = append(candidates, o.Exclude...)

	seen := map[string]bool{}
	out := make([]string, 0, len(candidates))
	for _, pattern := range candidates {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || seen[pattern] {
			continue
		}
		seen[pattern] = true
		out = append(out, pattern)
	}
	return out
}

// HasTool reports whether a scanner is selected.
func (o Options) HasTool(name string) bool {
	for _, tool := range o.Tools {
		if tool == name {
			return true
		}
	}
	return false
}

// CommandLine is the equivalent invocation. The terminal UI shows it, which is
// what keeps the flags and the form from drifting apart.
func (o Options) CommandLine() string {
	parts := []string{"whatsrisky", or(o.Path, ".")}
	add := func(values ...string) { parts = append(parts, values...) }

	if o.Diff != "" {
		add("--diff", o.Diff)
	}
	// The review pass is in the default set, so the flag worth printing is the one
	// that drops it. "--ai" would be noise, and a list of the other three would
	// leave the reader to work out what changed.
	switch {
	case sameSet(o.Tools, DefaultTools):
	case sameSet(o.Tools, ToolsWithoutAI):
		add("--no-ai")
	case len(o.Tools) > 0:
		add("--tools", strings.Join(o.Tools, ","))
	default:
		add("--tools", "none")
	}
	if !sameSet(o.Formats, FormatChoices) {
		add("--format", strings.Join(o.Formats, ","))
	}
	if o.OutDir != "" {
		add("--out-dir", o.OutDir)
	}
	if o.Out != "" {
		add("--out", o.Out)
	}
	if o.HasTool("ai") {
		if o.AIProvider != "claude-cli" {
			add("--ai-provider", o.AIProvider)
		}
		if o.Model != "" {
			add("--model", o.Model)
		}
		if o.AIMode != "full" {
			add("--ai-mode", o.AIMode)
		}
		if o.AITimeout != 3600 {
			add("--ai-timeout", strconv.Itoa(o.AITimeout))
		}
		if o.AIMaxFindings != 40 {
			add("--ai-max-findings", strconv.Itoa(o.AIMaxFindings))
		}
		if o.AIContextBytes != 240000 {
			add("--ai-context-bytes", strconv.Itoa(o.AIContextBytes))
		}
	}
	if !(len(o.SemgrepConfigs) == 1 && o.SemgrepConfigs[0] == "auto") {
		for _, config := range o.SemgrepConfigs {
			add("--semgrep-config", config)
		}
	}
	if o.TrivyScanners != "vuln,misconfig" {
		add("--trivy-scanners", o.TrivyScanners)
	}
	if o.GitleaksMode != "auto" {
		add("--gitleaks-mode", o.GitleaksMode)
	}
	for _, pattern := range o.Exclude {
		add("--exclude", pattern)
	}
	if !o.UseDefaultExcludes {
		add("--no-default-excludes")
	}
	if o.Offline {
		add("--offline")
	}
	if o.Timeout != 1800 {
		add("--timeout", strconv.Itoa(o.Timeout))
	}
	if o.Jobs != 4 {
		add("--jobs", strconv.Itoa(o.Jobs))
	}
	if o.MinSeverity != "INFO" {
		add("--min-severity", o.MinSeverity)
	}
	if o.MaxPerSeverity != nil && *o.MaxPerSeverity > 0 {
		add("--max-per-severity", strconv.Itoa(*o.MaxPerSeverity))
	}
	if o.FailOn != "none" {
		add("--fail-on", o.FailOn)
	}
	if o.Baseline != "" {
		add("--baseline", o.Baseline)
	}
	if !o.Compare {
		add("--no-compare")
	}
	if o.KeepWork {
		add("--keep-work")
	}
	if o.OpenReport {
		add("--open")
	}
	return strings.Join(parts, " ")
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, item := range a {
		seen[item] = true
	}
	for _, item := range b {
		if !seen[item] {
			return false
		}
	}
	return true
}

// Validate lists the reasons a scan cannot start. Empty means good to go.
func (o Options) Validate(isDir func(string) bool) []string {
	var problems []string
	switch {
	case strings.TrimSpace(o.Path) == "":
		problems = append(problems, "Project path is empty.")
	case isDir != nil && !isDir(o.Path):
		problems = append(problems, fmt.Sprintf("Not a directory: %s", o.Path))
	}
	if len(o.Tools) == 0 {
		problems = append(problems, "No scanners selected.")
	}
	for _, tool := range o.Tools {
		if _, ok := ToolCoverage[tool]; !ok {
			problems = append(problems, fmt.Sprintf("Unknown scanner: %s", tool))
		}
	}
	if len(o.Formats) == 0 {
		problems = append(problems, "No output format selected.")
	}
	return problems
}
