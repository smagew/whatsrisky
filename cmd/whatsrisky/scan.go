package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/progress"
	"github.com/smagew/whatsrisky/internal/report"
	"github.com/smagew/whatsrisky/internal/scan"
)

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func cmdScan(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		out          = flags.String("out", "", "explicit output path for the primary report")
		outDir       = flags.String("out-dir", "", "directory for reports (default ./whatsrisky-reports)")
		format       = flags.String("format", "", "comma list: html,md,json (default all)")
		tools        = flags.String("tools", "", "comma list of scanners (default semgrep,trivy,gitleaks)")
		skip         = flags.String("skip", "", "comma list of scanners to skip")
		useAI        = flags.Bool("ai", false, "keep the AI review pass (on by default)")
		noAI         = flags.Bool("no-ai", false, "drop the AI review pass: it spends money and sends code to a third party")
		aiProvider   = flags.String("ai-provider", "", "who runs the model: claude-cli|openai (implies --ai)")
		modelName    = flags.String("model", "", "model for the AI review (implies --ai; default: the backend's own)")
		aiMode       = flags.String("ai-mode", "", "full|review|both (implies --ai)")
		aiTimeout    = flags.Int("ai-timeout", 0, "seconds for each AI pass")
		aiMax        = flags.Int("ai-max-findings", 0, "cap on AI findings")
		aiContext    = flags.Int("ai-context-bytes", 0, "source shown to a non-agentic backend")
		diff         = flags.String("diff", "", "scope the scan to a git range, e.g. HEAD~1..HEAD")
		trivyScan    = flags.String("trivy-scanners", "", "trivy --scanners value")
		gitleaksMode = flags.String("gitleaks-mode", "", "auto|dir|git")
		offline      = flags.Bool("offline", false, "no network: skip the trivy DB update")
		timeout      = flags.Int("timeout", 0, "per-scanner timeout in seconds")
		jobs         = flags.Int("jobs", 0, "scanners to run in parallel (1 = sequential)")
		minSeverity  = flags.String("min-severity", "", "drop findings below this severity")
		maxPer       = flags.Int("max-per-severity", 0, "cap findings per severity in the rendered report")
		failOn       = flags.String("fail-on", "", "exit 2 at or above this severity (for CI)")
		baseline     = flags.String("baseline", "", "report to compare against (default: the latest in the output directory)")
		noCompare    = flags.Bool("no-compare", false, "do not compare against a previous report")
		profileName  = flags.String("profile", "", "start from a saved profile")
		saveProfile  = flags.String("save-profile", "", "store these settings under this name")
		workDir      = flags.String("work-dir", "", "where to keep raw scanner output")
		keepWork     = flags.Bool("keep-work", false, "do not delete raw scanner output")
		openReport   = flags.Bool("open", false, "open the report when done")
		quiet        = flags.Bool("quiet", false, "print only the written report paths")
		jsonStdout   = flags.Bool("json-stdout", false, "write the JSON report to stdout and nothing else")
		showExcl     = flags.Bool("show-excludes", false, "print the effective skip list and exit")
		noDefaults   = flags.Bool("no-default-excludes", false, "also scan node_modules, vendor, dist and the rest")
	)
	var excludes, semgrepConfigs stringList
	flags.Var(&excludes, "exclude", "directory, path or glob to skip (repeatable)")
	flags.Var(&semgrepConfigs, "semgrep-config", "semgrep --config value (repeatable)")

	positional, err := parseInterleaved(flags, args)
	if err != nil {
		return 1
	}

	options := scan.NewOptions()
	if *profileName != "" {
		loaded, ok := config.LoadProfile(*profileName)
		if !ok {
			fmt.Fprintf(stderr, "no such profile: %s (have: %s)\n",
				*profileName, orNone(strings.Join(config.ProfileNames(), ", ")))
			return 1
		}
		options = loaded
	}

	if len(positional) > 0 {
		options.Path = positional[0]
	}
	if options.Path == "" {
		fmt.Fprintln(stderr, "which project? give a path, or run `whatsrisky ui`")
		return 1
	}

	// The folder's own settings, unless a profile was named - a name is asked for
	// explicitly and wins. Flags are applied after either, so a flag on the line
	// always has the last word.
	//
	// Said out loud: settings coming from a file the caller did not mention on the
	// line is exactly the kind of thing that has to be visible.
	if *profileName == "" {
		if stored, ok := config.LoadProject(options.Path); ok {
			target := options.Path
			options = stored
			options.Path = target
			fmt.Fprintf(stderr, "using %s from %s\n", config.ProjectFile, options.Path)
		}
	}

	// Naming a Claude setting is an unambiguous request for the AI pass.
	wantsAI := *useAI || *aiProvider != "" || *modelName != "" || *aiMode != ""
	options.Tools = chooseTools(options.Tools, *tools, wantsAI, *noAI)
	if *skip != "" {
		skipped := map[string]bool{}
		for _, name := range splitList(*skip) {
			skipped[name] = true
		}
		var kept []string
		for _, name := range options.Tools {
			if !skipped[name] {
				kept = append(kept, name)
			}
		}
		options.Tools = kept
	}

	if *format != "" {
		requested := splitList(*format)
		// A dropped feature that fails quietly is worse than one that fails loudly.
		for _, name := range requested {
			if name == "docx" {
				fmt.Fprintln(stderr, "DOCX was removed in 0.3.0. Print the HTML report from a "+
					"browser, or use the tagged v0.2.0 release for a Word file.")
				return 1
			}
		}
		options.Formats = requested
	}

	setString(&options.Out, *out)
	setString(&options.OutDir, *outDir)
	setString(&options.AIProvider, *aiProvider)
	setString(&options.Model, *modelName)
	setString(&options.AIMode, *aiMode)
	setString(&options.Diff, *diff)
	setString(&options.TrivyScanners, *trivyScan)
	setString(&options.GitleaksMode, *gitleaksMode)
	setString(&options.MinSeverity, *minSeverity)
	setString(&options.FailOn, *failOn)
	setString(&options.Baseline, *baseline)
	setString(&options.WorkDir, *workDir)
	setInt(&options.AITimeout, *aiTimeout)
	setInt(&options.AIMaxFindings, *aiMax)
	setInt(&options.AIContextBytes, *aiContext)
	setInt(&options.Timeout, *timeout)
	setInt(&options.Jobs, *jobs)
	if *maxPer > 0 {
		value := *maxPer
		options.MaxPerSeverity = &value
	}
	if len(excludes) > 0 {
		options.Exclude = excludes
	}
	if len(semgrepConfigs) > 0 {
		options.SemgrepConfigs = semgrepConfigs
	}
	if *offline {
		options.Offline = true
	}
	if *noDefaults {
		options.UseDefaultExcludes = false
	}
	if *noCompare {
		options.Compare = false
	}
	if *keepWork {
		options.KeepWork = true
	}
	if *openReport {
		options.OpenReport = true
	}
	if *aiProvider != "" {
		if _, err := ai.New(*aiProvider, ".", os.TempDir()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	if *showExcl {
		patterns := options.EffectiveExcludes()
		user := map[string]bool{}
		for _, pattern := range options.Exclude {
			user[pattern] = true
		}
		fmt.Fprintf(stdout, "%d exclusion pattern(s) in effect:\n", len(patterns))
		for _, pattern := range patterns {
			origin := "default"
			if user[pattern] {
				origin = "user"
			}
			fmt.Fprintf(stdout, "  %s  (%s)\n", pattern, origin)
		}
		return 0
	}

	if *saveProfile != "" {
		if err := config.SaveProfile(*saveProfile, options); err != nil {
			fmt.Fprintf(stderr, "saving the profile: %v\n", err)
		} else if !*quiet && !*jsonStdout {
			fmt.Fprintf(stdout, "saved profile %s\n", *saveProfile)
		}
	}

	report.Version = Version
	view := newConsole(stdout, stderr, *quiet || *jsonStdout)
	outcome, err := scan.Run(options, view.handle)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	view.finish(outcome, options, *jsonStdout, *quiet)
	return outcome.ExitCode
}

// console renders a scan for a terminal. Quiet mode prints nothing but the paths,
// because stdout may belong to a JSON payload.
type console struct {
	stdout, stderr *os.File
	quiet          bool
	model          *progress.Model
}

func newConsole(stdout, stderr *os.File, quiet bool) *console {
	return &console{stdout: stdout, stderr: stderr, quiet: quiet, model: progress.New()}
}

func (c *console) handle(event scan.Event) {
	if c.quiet {
		return
	}
	switch event.Kind {
	case "info":
		fmt.Fprintf(c.stdout, "whatsrisky %s %s\n", Version, event.Message)
		if len(event.Tools) > 0 {
			line := "scanners: " + strings.Join(event.Tools, ", ")
			if contains(event.Tools, "ai") {
				line += fmt.Sprintf("  ·  ai: %s (%s)", orDefault(event.Model), event.AIMode)
			}
			fmt.Fprintln(c.stdout, line)
		}
	case "live":
		if len(event.Paths) > 0 {
			fmt.Fprintf(c.stdout, "live report %s\n", event.Paths[0])
		}
	case "tool_start":
		c.model.Start(event.Tool)
		fmt.Fprintf(c.stdout, "▸ %s started\n", event.Tool)
	case "tool_progress":
		c.model.Progress(event.Tool, event.Message)
		fmt.Fprintf(c.stdout, "  %s: %s\n", event.Tool, event.Message)
	case "tool_done":
		c.model.Done(event.Tool, event.Status, event.Findings, event.Duration)
		fmt.Fprintf(c.stdout, "▪ %s %s · %d findings · %.0fs\n",
			event.Tool, event.Status, event.Findings, event.Duration.Seconds())
	}
}

func (c *console) finish(outcome scan.Outcome, options scan.Options, jsonStdout, quiet bool) {
	current := outcome.Report
	if jsonStdout {
		body, err := report.Marshal(current)
		if err == nil {
			c.stdout.Write(body)
		}
	} else if quiet {
		for _, path := range outcome.Written {
			fmt.Fprintln(c.stdout, path)
		}
	} else {
		fmt.Fprintln(c.stdout)
		counts := current.Counts()
		fmt.Fprintf(c.stdout, "%s — %s\n", current.ProjectName, current.Verdict())
		for _, severity := range model.Order {
			fmt.Fprintf(c.stdout, "  %-8s %d\n", severity, counts[severity])
		}
		fmt.Fprintf(c.stdout, "  %-8s %d\n", "TOTAL", len(current.ActiveFindings()))
		if comparison := current.Comparison; comparison != nil {
			fmt.Fprintf(c.stdout, "vs %s: %d new · %d open · %d resolved",
				orNone(comparison.BaselineScanID), comparison.Counts[model.StatusNew],
				comparison.Counts[model.StatusOpen], comparison.Counts[model.StatusResolved])
			if count := comparison.Counts[model.StatusReintroduced]; count > 0 {
				fmt.Fprintf(c.stdout, " · %d reintroduced", count)
			}
			if comparison.Moved > 0 {
				fmt.Fprintf(c.stdout, " · %d moved", comparison.Moved)
			}
			fmt.Fprintln(c.stdout)
		}
		for _, tool := range current.Tools {
			if !tool.OK() {
				fmt.Fprintf(c.stdout, "! %s %s: %s\n", tool.Name, tool.Status, firstLineOf(tool.Message))
			}
		}
		if current.ExcludedCount > 0 {
			fmt.Fprintf(c.stdout, "%d finding(s) dropped by exclusions (%d patterns; --show-excludes to list)\n",
				current.ExcludedCount, len(current.Excludes))
		}
		for _, path := range outcome.Written {
			fmt.Fprintf(c.stdout, "report %s\n", path)
		}
		if options.KeepWork {
			fmt.Fprintf(c.stdout, "raw scanner output kept in %s\n", outcome.WorkDir)
		}
	}

	if options.OpenReport {
		// The HTML is the view; the rest are deliverables. Open the view.
		for _, suffix := range []string{".html", ".md", ".json"} {
			for _, path := range outcome.Written {
				if filepath.Ext(path) == suffix {
					if !openFile(path) {
						fmt.Fprintln(c.stderr, "could not open the report on this platform")
					}
					return
				}
			}
		}
	}
}

// parseInterleaved lets flags follow the path, which is the documented form:
// `whatsrisky <path> --ai`. The standard flag package stops at the first
// non-flag argument, so a flag written after the path was silently ignored -
// including --out-dir and --no-compare, which is how this was found.
// chooseTools settles which scanners run. Separate from the command so it can be
// tested: the AI pass costs money, so which flag wins is not a detail.
//
// --no-ai has the last word, deliberately, and beats every way of asking for the
// pass including naming a model. Someone who spelled out "do not spend my money"
// must not be overruled by a flag they left on the line.
func chooseTools(current []string, named string, wantsAI, noAI bool) []string {
	tools := current
	if named != "" {
		tools = splitList(named)
	}
	if wantsAI && !contains(tools, "ai") {
		tools = append(tools, "ai")
	}
	if noAI {
		tools = withoutTool(tools, "ai")
	}
	return tools
}

func withoutTool(tools []string, drop string) []string {
	out := make([]string, 0, len(tools))
	for _, name := range tools {
		if name != drop {
			out = append(out, name)
		}
	}
	return out
}

func parseInterleaved(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := flags.Parse(rest); err != nil {
			return nil, err
		}
		remaining := flags.Args()
		if len(remaining) == 0 {
			return positional, nil
		}
		positional = append(positional, remaining[0])
		rest = remaining[1:]
	}
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func setString(target *string, value string) {
	if value != "" {
		*target = value
	}
}

func setInt(target *int, value int) {
	if value != 0 {
		*target = value
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func orDefault(value string) string {
	if value == "" {
		return "backend default"
	}
	return value
}

func firstLineOf(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			if len(trimmed) > 200 {
				return trimmed[:200]
			}
			return trimmed
		}
	}
	return ""
}
