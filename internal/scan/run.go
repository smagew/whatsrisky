package scan

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/smagew/whatsrisky/internal/compare"
	"github.com/smagew/whatsrisky/internal/exclude"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
	"github.com/smagew/whatsrisky/internal/report"
	"github.com/smagew/whatsrisky/internal/runner"
)

// OutputMarker names a directory as ours. Without it a second scan finds the first
// scan's report: our own JSON quotes the secrets it found, so a secret scanner
// flags it. The tool must never scan its own output.
const OutputMarker = ".whatsrisky-output"

const markerBody = "Written by whatsrisky. This directory holds generated reports, which quote source\n" +
	"code and redacted secrets. It is skipped by later scans and should not be committed.\n"

// Event is what a front end is told while a scan runs.
type Event struct {
	Kind     string // info | live | tool_start | tool_progress | tool_done | report
	Tool     string
	Message  string
	Status   string
	Findings int
	Duration time.Duration
	Paths    []string
	Tools    []string
	Model    string
	AIMode   string
}

// Handler receives events. Nil is fine.
type Handler func(Event)

func (h Handler) emit(event Event) {
	if h != nil {
		h(event)
	}
}

// Outcome is a finished scan.
type Outcome struct {
	Report   model.Report
	Written  []string
	ExitCode int
	WorkDir  string
}

// Run performs a scan. It writes the machine-readable artifacts from the first
// second, so a viewer can be opened while it is still going.
func Run(options Options, handler Handler) (Outcome, error) {
	options = options.Normalized()
	if problems := options.Validate(isDir); len(problems) > 0 {
		return Outcome{}, errors.New(strings.Join(problems, "; "))
	}

	var err error
	network := options.IsNetwork()
	target := options.Path
	label := filepath.Base(target)
	if network {
		target = options.Target
		label = targetSlug(target)
	} else {
		abs, absErr := filepath.Abs(options.Path)
		if absErr != nil {
			return Outcome{}, absErr
		}
		target = abs
		label = filepath.Base(target)
	}
	stamp := time.Now()
	base := fmt.Sprintf("%s-%s", slugify(label), stamp.Format("20060102-150405"))

	outDir := options.OutDir
	if outDir == "" {
		cwd, _ := os.Getwd()
		outDir = filepath.Join(cwd, "whatsrisky-reports")
	}
	if outDir, err = filepath.Abs(outDir); err != nil {
		return Outcome{}, err
	}
	workDir := options.WorkDir
	if workDir == "" {
		workDir = filepath.Join(outDir, ".work-"+base)
	}
	for _, dir := range []string{outDir, workDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Outcome{}, err
		}
	}
	marker := filepath.Join(outDir, OutputMarker)
	if _, err := os.Stat(marker); err != nil {
		_ = os.WriteFile(marker, []byte(markerBody), 0o600)
	}

	// The baseline is chosen before anything is written, so this run's own report
	// can never become its own baseline.
	var baselineFindings []model.Finding
	var baselineScanID, baselineAt, baselinePath string
	if options.Compare {
		path := options.Baseline
		if path == "" {
			path = compare.FindBaseline(outDir, nil)
		} else if _, err := os.Stat(path); err != nil {
			return Outcome{}, fmt.Errorf("baseline %s: %w", path, err)
		}
		if path != "" {
			loaded, scanID, at, err := compare.LoadReport(path)
			if err != nil {
				if options.Baseline != "" {
					return Outcome{}, fmt.Errorf("not a whatsrisky report: %s", path)
				}
			} else {
				baselineFindings, baselineScanID, baselineAt, baselinePath = loaded, scanID, at, path
			}
		}
	}

	var scopePaths []string
	if options.Diff != "" && !network {
		if scopePaths, err = ChangedFiles(target, options.Diff); err != nil {
			return Outcome{}, err
		}
		handler.emit(Event{Kind: "info",
			Message: fmt.Sprintf("diff %s: %d changed file(s)", options.Diff, len(scopePaths)),
			Tools:   options.Tools, Model: options.Model, AIMode: options.AIMode})
		if len(scopePaths) == 0 {
			return Outcome{}, fmt.Errorf("git range %q touches no existing files", options.Diff)
		}
	}

	var excludes []string
	var commit, branch string
	if !network {
		excludes = append(options.EffectiveExcludes(), selfOutputExcludes(target, outDir, workDir)...)
		commit, branch = gitInfo(target)
	}

	current := model.Report{
		ProjectPath: target, ProjectName: label, ScanID: base,
		StartedAt: stamp.Format("2006-01-02 15:04:05"),
		GitCommit: commit, GitBranch: branch,
		DiffRange: options.Diff, ScopePaths: scopePaths,
		Excludes: excludes, Status: model.StatusRunning,
	}
	for _, name := range options.Tools {
		current.Tools = append(current.Tools, model.ToolResult{Name: name, Status: model.ToolPending})
	}

	live := newLiveWriter(outDir, base, options.Formats)
	live.write(current)
	handler.emit(Event{Kind: "live", Paths: live.paths()})
	handler.emit(Event{Kind: "info", Message: "scanning " + target,
		Tools: options.Tools, Model: options.Model, AIMode: options.AIMode})

	config := runner.Config{
		Target: target, WorkDir: workDir, ScopePaths: scopePaths, DiffRange: options.Diff,
		Exclude:         excludes,
		SemgrepConfigs:  options.SemgrepConfigs,
		SemgrepTimeout:  seconds(options.Timeout),
		TrivyScanners:   options.TrivyScanners,
		TrivyTimeout:    seconds(options.Timeout),
		TrivyOffline:    options.Offline,
		GitleaksMode:    options.GitleaksMode,
		GitleaksTimeout: seconds(minInt(options.Timeout, 900)),
		AIProvider:      options.AIProvider,
		AIModel:         options.Model,
		AIMode:          options.AIMode,
		AITimeout:       seconds(options.AITimeout),
		AIMaxFindings:   options.AIMaxFindings,
		AIContextBytes:  options.AIContextBytes,
		SurfaceTimeout:  seconds(minInt(options.Timeout, 60)),
		NucleiTimeout:   seconds(options.Timeout),
		NetActive:       options.NetActive,
	}

	started := time.Now()
	current.Tools = runTools(options, config, handler, func(updated []model.ToolResult) {
		snapshot := current
		snapshot.Tools = updated
		live.write(snapshot)
	})
	current.DurationS = time.Since(started).Seconds()
	current.FinishedAt = time.Now().Format("2006-01-02 15:04:05")
	current.Status = model.StatusComplete
	for _, tool := range current.Tools {
		if !tool.OK() {
			current.Status = model.StatusPartial
		}
	}

	floor := model.ParseSeverity(options.MinSeverity, model.Info)
	seen := map[string]bool{}
	for _, tool := range current.Tools {
		for _, finding := range tool.Findings {
			// Backstop: some scanners cannot be told to skip a path, so filter here
			// too. Counted, not hidden - the report says how many were dropped.
			if finding.File != "" && exclude.Path(finding.File, excludes) {
				current.ExcludedCount++
				continue
			}
			if finding.Severity.Rank() > floor.Rank() || seen[finding.Fingerprint()] {
				continue
			}
			seen[finding.Fingerprint()] = true
			current.Findings = append(current.Findings, finding)
		}
	}

	if baselineFindings != nil {
		compare.Correlate(&current, baselineFindings, baselineScanID, baselineAt, baselinePath)
	}

	written := live.writeFinal(current)
	handler.emit(Event{Kind: "report", Paths: written})

	if !options.KeepWork && strings.HasPrefix(filepath.Base(workDir), ".work-") {
		_ = os.RemoveAll(workDir)
	}
	return Outcome{Report: current, Written: written, ExitCode: ExitCode(current, options.FailOn), WorkDir: workDir}, nil
}

// runTools runs the scanners, in parallel unless asked otherwise, reporting each
// transition so a front end can show progress and the live report can be refreshed.
func runTools(options Options, config runner.Config, handler Handler, onChange func([]model.ToolResult)) []model.ToolResult {
	results := make([]model.ToolResult, len(options.Tools))
	var guard sync.Mutex

	execute := func(index int, name string) {
		handler.emit(Event{Kind: "tool_start", Tool: name})
		guard.Lock()
		results[index] = model.ToolResult{Name: name, Status: model.ToolRunning}
		snapshot := append([]model.ToolResult(nil), results...)
		guard.Unlock()
		onChange(snapshot)

		started := time.Now()
		var result model.ToolResult
		built, err := runner.New(name, config)
		if err != nil {
			result = model.ToolResult{Name: name, Status: model.ToolError, Message: err.Error()}
		} else {
			result = runner.Run(built, func(message string) {
				handler.emit(Event{Kind: "tool_progress", Tool: name, Message: message})
			})
		}

		guard.Lock()
		results[index] = result
		snapshot = append([]model.ToolResult(nil), results...)
		guard.Unlock()
		onChange(snapshot)
		handler.emit(Event{Kind: "tool_done", Tool: name, Status: result.Status,
			Findings: len(result.Findings), Duration: time.Since(started), Message: result.Message})
	}

	if options.Jobs <= 1 || len(options.Tools) == 1 {
		for index, name := range options.Tools {
			execute(index, name)
		}
		return results
	}

	slots := make(chan struct{}, options.Jobs)
	var wait sync.WaitGroup
	for index, name := range options.Tools {
		wait.Add(1)
		go func(index int, name string) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			execute(index, name)
		}(index, name)
	}
	wait.Wait()
	return results
}

// ExitCode is 2 when a finding at or above the threshold exists, for CI.
func ExitCode(report model.Report, failOn string) int {
	if failOn == "" || failOn == "none" {
		return 0
	}
	threshold := model.ParseSeverity(failOn, model.High)
	counts := report.Counts()
	for _, severity := range model.Order {
		if severity.Rank() <= threshold.Rank() && counts[severity] > 0 {
			return 2
		}
	}
	return 0
}

type liveWriter struct {
	jsonPath string
	htmlPath string
	mdPath   string
}

func newLiveWriter(outDir, base string, formats []string) *liveWriter {
	writer := &liveWriter{}
	for _, format := range formats {
		switch format {
		case "json":
			writer.jsonPath = filepath.Join(outDir, base+".json")
		case "html":
			writer.htmlPath = filepath.Join(outDir, base+".html")
		case "md":
			writer.mdPath = filepath.Join(outDir, base+".md")
		}
	}
	return writer
}

func (w *liveWriter) paths() []string {
	// The page first: it is the view, and it is what "View report" opens.
	var out []string
	for _, path := range []string{w.htmlPath, w.jsonPath} {
		if path != "" {
			out = append(out, path)
		}
	}
	return out
}

// write refreshes the machine-readable artifacts. Markdown is not refreshed: it is
// a deliverable, not a working view.
func (w *liveWriter) write(current model.Report) {
	if w.jsonPath != "" {
		_ = report.WriteJSON(current, w.jsonPath)
	}
	if w.htmlPath != "" {
		_ = report.WriteHTML(current, w.htmlPath)
	}
}

func (w *liveWriter) writeFinal(current model.Report) []string {
	w.write(current)
	var written []string
	for _, path := range []string{w.htmlPath, w.mdPath, w.jsonPath} {
		if path == "" {
			continue
		}
		if path == w.mdPath {
			if err := report.WriteMarkdown(current, path); err != nil {
				continue
			}
		}
		written = append(written, path)
	}
	return written
}

// --- helpers ---------------------------------------------------------

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func seconds(value int) time.Duration { return time.Duration(value) * time.Second }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var slugPattern = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// targetSlug turns a URL into the host, so a report file is named for the site
// rather than for "https:".
func targetSlug(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

func slugify(value string) string {
	out := strings.Trim(slugPattern.ReplaceAllString(value, "-"), "-")
	if out == "" {
		return "project"
	}
	return out
}

// gitInfo returns (commit, branch), or empty strings when this is not a repo.
func gitInfo(dir string) (string, string) {
	commit := gitOutput(dir, "rev-parse", "--short", "HEAD")
	branch := gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	return commit, branch
}

func gitOutput(dir string, args ...string) string {
	result, err := proc.Run(append([]string{"git"}, args...), proc.Options{Dir: dir, Timeout: 15 * time.Second})
	if err != nil || result.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(result.Stdout)
}

// ChangedFiles lists the files a git range touched, relative to root. Deleted
// files are dropped: there is nothing left in them to scan.
func ChangedFiles(root, diffRange string) ([]string, error) {
	result, err := proc.Run(
		[]string{"git", "diff", "--name-only", "--diff-filter=d", diffRange},
		proc.Options{Dir: root, Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		detail := proc.Tail(result.Stderr, 3)
		if detail == "" {
			detail = "git failed"
		}
		return nil, fmt.Errorf("cannot resolve git range %q in %s: %s", diffRange, root, detail)
	}
	var out []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		rel := strings.TrimSpace(line)
		if rel == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(root, rel)); err == nil && !info.IsDir() {
			out = append(out, rel)
		}
	}
	return out, nil
}

// selfOutputExcludes lists report directories inside the scanned tree: this run's,
// and any earlier run's, found by the marker we write ourselves.
func selfOutputExcludes(target string, directories ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, directory := range directories {
		if rel := relativeInside(target, directory); rel != "" && !seen[rel] {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	for _, rel := range findOutputDirs(target, 4) {
		if !seen[rel] {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	return out
}

func relativeInside(root, directory string) string {
	absoluteRoot, err1 := filepath.Abs(root)
	absoluteDir, err2 := filepath.Abs(directory)
	if err1 != nil || err2 != nil {
		return ""
	}
	rel, err := filepath.Rel(absoluteRoot, absoluteDir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

// findOutputDirs walks shallowly for our own marker, so it only ever skips our own
// output - never a directory that merely looks like it.
func findOutputDirs(root string, maxDepth int) []string {
	var found []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.Name() == OutputMarker {
				if rel := relativeInside(root, dir); rel != "" {
					found = append(found, rel)
				}
				return // no need to descend into our own output
			}
		}
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != ".git" && entry.Name() != "node_modules" {
				walk(filepath.Join(dir, entry.Name()), depth+1)
			}
		}
	}
	walk(root, 0)
	return found
}
