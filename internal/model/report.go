package model

import (
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion versions the JSON report - the contract other tools read. It
// moves on its own schedule, independently of the package version.
const SchemaVersion = 4

// Report-level status. A scan is written from its first second, so a reader has
// to be able to tell an unfinished report from a finished one.
const (
	StatusRunning  = "running"
	StatusComplete = "complete"
	StatusPartial  = "partial" // finished, but a scanner failed
)

// Tool status. Pending and running exist because the report is live.
const (
	ToolPending = "pending"
	ToolRunning = "running"
	ToolOK      = "ok"
	ToolSkipped = "skipped"
	ToolError   = "error"
	ToolMissing = "missing"
)

// ToolResult is the outcome of one scanner run.
type ToolResult struct {
	Name       string
	Status     string
	Findings   []Finding
	Version    string
	Command    string
	DurationS  float64
	Message    string
	StderrTail string
}

// OK reports whether this scanner contributed findings.
func (t ToolResult) OK() bool { return t.Status == ToolOK }

// Comparison is the result of correlating against a baseline report.
type Comparison struct {
	BaselinePath   string         `json:"baseline_path"`
	BaselineScanID string         `json:"baseline_scan_id"`
	BaselineAt     string         `json:"baseline_at"`
	Counts         map[string]int `json:"counts"`
	Moved          int            `json:"moved"`
}

// Report is one scan.
type Report struct {
	ProjectPath   string
	ProjectName   string
	ScanID        string
	StartedAt     string
	FinishedAt    string
	DurationS     float64
	GitCommit     string
	GitBranch     string
	DiffRange     string
	ScopePaths    []string
	Excludes      []string
	ExcludedCount int
	Status        string
	Comparison    *Comparison
	Tools         []ToolResult
	Findings      []Finding

	// Assets is the estate a perimeter scan mapped: the live and dead hosts under a
	// domain. Empty for a single-target or filesystem scan. Added in schema 4.
	Assets []Asset
}

// Asset is one host a perimeter scan discovered: whether it resolved, whether it
// answered HTTP, and — when it did — the URL that was scanned and the stack it
// advertised. It is part of the JSON contract, so it lives here rather than in the
// perimeter package.
type Asset struct {
	Host       string   `json:"host"`
	IPs        []string `json:"ips,omitempty"`
	URL        string   `json:"url,omitempty"`
	Status     int      `json:"status,omitempty"`
	Title      string   `json:"title,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	Alive      bool     `json:"alive"`
	Screenshot string   `json:"screenshot,omitempty"` // set by a later gowitness pass
}

// ActiveFindings are the ones that still count.
func (r Report) ActiveFindings() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.IsActive() {
			out = append(out, finding)
		}
	}
	return out
}

// Counts is the per-severity tally over the active findings only.
func (r Report) Counts() map[Severity]int {
	out := make(map[Severity]int, len(Order))
	for _, severity := range Order {
		out[severity] = 0
	}
	for _, finding := range r.ActiveFindings() {
		out[finding.Severity]++
	}
	return out
}

// CountsBy tallies the active findings by an arbitrary key.
func (r Report) CountsBy(key func(Finding) string) map[string]int {
	out := map[string]int{}
	for _, finding := range r.ActiveFindings() {
		out[key(finding)]++
	}
	return out
}

// CountsByStatus tallies every finding, including the ones that no longer count.
func (r Report) CountsByStatus() map[string]int {
	out := map[string]int{}
	for _, finding := range r.Findings {
		out[finding.Status]++
	}
	return out
}

// RiskScore is the saturating aggregate over the active findings.
func (r Report) RiskScore() int { return RiskScore(r.Findings) }

// Verdict is the headline. Three rules it must obey, all of them the same rule:
// absence of findings is not safety.
func (r Report) Verdict() string {
	// A scan still running has no verdict.
	if r.Status == StatusRunning {
		done := 0
		for _, tool := range r.Tools {
			if tool.Status != ToolPending && tool.Status != ToolRunning {
				done++
			}
		}
		return fmt.Sprintf("SCAN IN PROGRESS - %d of %d scanners done, no verdict yet", done, len(r.Tools))
	}

	counts := r.Counts()
	var headline string
	switch {
	case counts[Critical] > 0:
		headline = "CRITICAL - immediate remediation required"
	case counts[High] > 0:
		headline = "HIGH RISK - fix before release"
	case counts[Medium] > 0:
		headline = "MODERATE - plan remediation"
	case counts[Low] > 0 || counts[Info] > 0:
		headline = "LOW - hygiene issues only"
	case r.Status == StatusPartial:
		return "INCONCLUSIVE - a scanner failed, so parts were not scanned"
	default:
		return "CLEAN - no findings from the configured scanners"
	}

	// The headline must not sound more confident than the coverage allows: a
	// reader who reads nothing else has to see that scanners were missing.
	var gaps []string
	for _, tool := range r.Tools {
		switch tool.Status {
		case ToolMissing, ToolError, ToolSkipped:
			gaps = append(gaps, tool.Name)
		}
	}
	if len(gaps) > 0 {
		return fmt.Sprintf("%s · partial coverage (%s did not run)", headline, strings.Join(gaps, ", "))
	}
	return headline
}

// SortedFindings is priority order, with what no longer counts pushed to the end.
func (r Report) SortedFindings() []Finding {
	out := make([]Finding, len(r.Findings))
	copy(out, r.Findings)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.IsActive() != b.IsActive() {
			return a.IsActive()
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Title < b.Title
	})
	return out
}
