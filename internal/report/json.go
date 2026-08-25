// Package report writes what a scan found: JSON for machines, a self-contained
// HTML page for people, Markdown for a pull request.
//
// The JSON shape is the contract other tools read, so it is spelled out field by
// field here rather than reflected out of the model - a rename in the model must
// not silently rename a key in the contract.
package report

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"

	"github.com/smagew/whatsrisky/internal/model"
)

// Version is the package version, and the one stamped into every report. Set from
// main so this package does not import it back.
var Version = "dev"

type generatorJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolJSON struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Version   string  `json:"version"`
	Command   string  `json:"command"`
	DurationS float64 `json:"duration_s"`
	Findings  int     `json:"findings"`
	Message   string  `json:"message"`
}

type findingJSON struct {
	Tool             string       `json:"tool"`
	Detector         detectorJSON `json:"detector"`
	Severity         string       `json:"severity"`
	Status           string       `json:"status"`
	Title            string       `json:"title"`
	Description      string       `json:"description"`
	Category         string       `json:"category"`
	CategoryLabel    string       `json:"category_label"`
	Source           string       `json:"source"`
	ScannerCategory  string       `json:"scanner_category"`
	RuleID           string       `json:"rule_id"`
	File             string       `json:"file"`
	Line             *int         `json:"line"`
	EndLine          *int         `json:"end_line"`
	CWE              []string     `json:"cwe"`
	OWASP            []string     `json:"owasp"`
	References       []string     `json:"references"`
	Remediation      string       `json:"remediation"`
	Package          string       `json:"package"`
	InstalledVersion string       `json:"installed_version"`
	FixedVersion     string       `json:"fixed_version"`
	Confidence       string       `json:"confidence"`
	Snippet          string       `json:"snippet"`
	CVSS             string       `json:"cvss"`
	Fingerprint      string       `json:"fingerprint"`
	ContentKey       string       `json:"content_key"`
	MatchKey         string       `json:"match_key"`
	FirstSeen        string       `json:"first_seen"`
	LastSeen         string       `json:"last_seen"`
	MovedFrom        string       `json:"moved_from"`
}

// detectorJSON keeps provider and model nullable: they are absent for a local
// scanner, and null says that more clearly than an empty string.
type detectorJSON struct {
	Tool     string  `json:"tool"`
	Provider *string `json:"provider"`
	Model    *string `json:"model"`
	Pass     *string `json:"pass"`
}

type reportJSON struct {
	SchemaVersion    int               `json:"schema_version"`
	Generator        generatorJSON     `json:"generator"`
	ScanID           string            `json:"scan_id"`
	Status           string            `json:"status"`
	ProjectPath      string            `json:"project_path"`
	ProjectName      string            `json:"project_name"`
	StartedAt        string            `json:"started_at"`
	FinishedAt       string            `json:"finished_at"`
	DurationS        float64           `json:"duration_s"`
	GitCommit        string            `json:"git_commit"`
	GitBranch        string            `json:"git_branch"`
	DiffRange        string            `json:"diff_range"`
	ScopePaths       []string          `json:"scope_paths"`
	Excludes         []string          `json:"excludes"`
	ExcludedFindings int               `json:"excluded_findings"`
	Comparison       *model.Comparison `json:"comparison"`
	CountsByCategory map[string]int    `json:"counts_by_category"`
	CountsBySource   map[string]int    `json:"counts_by_source"`
	CountsByStatus   map[string]int    `json:"counts_by_status"`
	RiskScore        int               `json:"risk_score"`
	Verdict          string            `json:"verdict"`
	Counts           map[string]int    `json:"counts"`
	TotalFindings    int               `json:"total_findings"`
	ActiveFindings   int               `json:"active_findings"`
	Tools            []toolJSON        `json:"tools"`
	Findings         []findingJSON     `json:"findings"`
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func optionalInt(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

func emptyIfNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// round2 matches the reference implementation's rounding of durations.
func round2(value float64) float64 { return math.Round(value*100) / 100 }

// Document builds the JSON contract for a report.
func Document(report model.Report) any {
	counts := map[string]int{}
	for severity, count := range report.Counts() {
		counts[string(severity)] = count
	}

	tools := make([]toolJSON, 0, len(report.Tools))
	for _, tool := range report.Tools {
		tools = append(tools, toolJSON{
			Name: tool.Name, Status: tool.Status, Version: tool.Version,
			Command: tool.Command, DurationS: round2(tool.DurationS),
			Findings: len(tool.Findings), Message: tool.Message,
		})
	}

	sorted := report.SortedFindings()
	findings := make([]findingJSON, 0, len(sorted))
	for _, finding := range sorted {
		detector := finding.Detector()
		findings = append(findings, findingJSON{
			Tool: finding.Tool,
			Detector: detectorJSON{
				Tool: detector.Tool, Provider: optional(detector.Provider),
				Model: optional(detector.Model), Pass: optional(detector.Pass),
			},
			Severity: string(finding.Severity), Status: finding.Status,
			Title: finding.Title, Description: finding.Description,
			Category: finding.Category, CategoryLabel: finding.CategoryLabel(),
			Source: finding.Source, ScannerCategory: finding.ScannerCategory,
			RuleID: finding.RuleID, File: finding.File,
			Line: optionalInt(finding.Line), EndLine: optionalInt(finding.EndLine),
			CWE: emptyIfNil(finding.CWE), OWASP: emptyIfNil(finding.OWASP),
			References: emptyIfNil(finding.References), Remediation: finding.Remediation,
			Package: finding.Package, InstalledVersion: finding.InstalledVersion,
			FixedVersion: finding.FixedVersion, Confidence: finding.Confidence,
			Snippet: finding.Snippet, CVSS: finding.CVSS,
			Fingerprint: finding.Fingerprint(), ContentKey: finding.ContentKey(),
			MatchKey: finding.MatchKey(), FirstSeen: finding.FirstSeen,
			LastSeen: finding.LastSeen, MovedFrom: finding.MovedFrom,
		})
	}

	return reportJSON{
		SchemaVersion: model.SchemaVersion,
		Generator:     generatorJSON{Name: "whatsrisky", Version: Version},
		ScanID:        report.ScanID, Status: report.Status,
		ProjectPath: report.ProjectPath, ProjectName: report.ProjectName,
		StartedAt: report.StartedAt, FinishedAt: report.FinishedAt,
		DurationS: round2(report.DurationS),
		GitCommit: report.GitCommit, GitBranch: report.GitBranch,
		DiffRange: report.DiffRange, ScopePaths: emptyIfNil(report.ScopePaths),
		Excludes: emptyIfNil(report.Excludes), ExcludedFindings: report.ExcludedCount,
		Comparison:       report.Comparison,
		CountsByCategory: report.CountsBy(func(f model.Finding) string { return f.Category }),
		CountsBySource:   report.CountsBy(func(f model.Finding) string { return f.Source }),
		CountsByStatus:   report.CountsByStatus(),
		RiskScore:        report.RiskScore(), Verdict: report.Verdict(),
		Counts: counts, TotalFindings: len(report.Findings),
		ActiveFindings: len(report.ActiveFindings()),
		Tools:          tools, Findings: findings,
	}
}

// Marshal renders the contract, indented as the reference does.
func Marshal(report model.Report) ([]byte, error) {
	body, err := json.MarshalIndent(Document(report), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// WriteJSON writes the report atomically: a reader polling a live scan must never
// see half a document.
func WriteJSON(report model.Report, path string) error {
	body, err := Marshal(report)
	if err != nil {
		return err
	}
	return writeAtomic(path, body)
}

func writeAtomic(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".part"
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
