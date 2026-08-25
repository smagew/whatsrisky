// Package compare answers what a rescan actually fixed.
//
// The only hard part is telling a fixed finding from one whose code moved. Three
// identity keys make that decidable: the exact location, then the evidence
// itself, then the location without the line. Anything still unmatched is
// genuinely new or genuinely gone.
//
// Resolved findings are carried into the new report - showing them is the whole
// point - for one generation. A finding already resolved in the baseline and
// still absent drops off, so reports do not accumulate history forever.
package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
)

// Baseline is a previous report, consumable: a match claims its entry so two
// current findings can never both correlate to the same one.
type Baseline struct {
	entries       []model.Finding
	taken         map[int]bool
	byFingerprint map[string][]int
	byContent     map[string][]int
	byMatch       map[string][]int
	scanID        string
}

// NewBaseline indexes a baseline report's findings.
func NewBaseline(findings []model.Finding, scanID string) *Baseline {
	baseline := &Baseline{
		entries:       findings,
		taken:         map[int]bool{},
		byFingerprint: map[string][]int{},
		byContent:     map[string][]int{},
		byMatch:       map[string][]int{},
		scanID:        scanID,
	}
	for position, finding := range findings {
		baseline.byFingerprint[finding.Fingerprint()] = append(baseline.byFingerprint[finding.Fingerprint()], position)
		baseline.byContent[finding.ContentKey()] = append(baseline.byContent[finding.ContentKey()], position)
		baseline.byMatch[finding.MatchKey()] = append(baseline.byMatch[finding.MatchKey()], position)
	}
	return baseline
}

func (b *Baseline) free(index map[string][]int, key string) []int {
	var out []int
	for _, position := range index[key] {
		if !b.taken[position] {
			out = append(out, position)
		}
	}
	return out
}

func (b *Baseline) claim(position int) model.Finding {
	b.taken[position] = true
	return b.entries[position]
}

// Match correlates one current finding, in order of decreasing certainty.
// The bool reports whether the code moved.
func (b *Baseline) Match(finding model.Finding) (*model.Finding, bool) {
	if exact := b.free(b.byFingerprint, finding.Fingerprint()); len(exact) > 0 {
		entry := b.claim(exact[0])
		return &entry, false
	}

	// The evidence is the same, so this is the same finding in a new place. Prefer
	// a candidate in the same file: a copy-paste elsewhere should not capture the
	// original's history.
	if content := b.free(b.byContent, finding.ContentKey()); len(content) > 0 {
		position := content[0]
		for _, candidate := range content {
			if b.entries[candidate].File == finding.File {
				position = candidate
				break
			}
		}
		entry := b.claim(position)
		moved := entry.File != finding.File || entry.Line != finding.Line
		return &entry, moved
	}

	// Same rule, same file, line drifted - only trustworthy when unambiguous.
	if byMatch := b.free(b.byMatch, finding.MatchKey()); len(byMatch) == 1 {
		entry := b.claim(byMatch[0])
		return &entry, entry.Line != finding.Line
	}
	return nil, false
}

// Unclaimed is what the baseline had and this scan did not.
func (b *Baseline) Unclaimed() []model.Finding {
	var out []model.Finding
	for position, entry := range b.entries {
		if !b.taken[position] {
			out = append(out, entry)
		}
	}
	return out
}

// Correlate assigns a status to every finding in the report, relative to the
// baseline. It mutates the report: statuses and seen-timestamps are filled in,
// and findings the baseline had but this scan does not are appended as resolved.
func Correlate(report *model.Report, baselineFindings []model.Finding, baselineScanID, baselineAt, baselinePath string) *model.Comparison {
	index := NewBaseline(baselineFindings, baselineScanID)
	scanID := report.ScanID
	if scanID == "" {
		scanID = report.StartedAt
	}
	moved := 0

	for i := range report.Findings {
		finding := &report.Findings[i]
		entry, wasMoved := index.Match(*finding)
		finding.LastSeen = scanID
		if entry == nil {
			finding.Status = model.StatusNew
			finding.FirstSeen = scanID
			continue
		}
		switch entry.Status {
		case model.StatusResolved:
			finding.Status = model.StatusReintroduced
		case model.StatusAccepted:
			finding.Status = model.StatusAccepted // a human decision outlives a rescan
		default:
			finding.Status = model.StatusOpen
		}
		finding.FirstSeen = firstNonEmpty(entry.FirstSeen, baselineScanID, scanID)
		if wasMoved {
			moved++
			finding.MovedFrom = entry.Location()
		}
	}

	// Already-resolved entries drop off instead of trailing through every report.
	for _, entry := range index.Unclaimed() {
		if entry.Status == model.StatusResolved {
			continue
		}
		resolved := entry
		resolved.Status = model.StatusResolved
		resolved.FirstSeen = firstNonEmpty(entry.FirstSeen, baselineScanID)
		resolved.LastSeen = firstNonEmpty(entry.LastSeen, baselineScanID)
		report.Findings = append(report.Findings, resolved)
	}

	counts := map[string]int{}
	for _, status := range model.AllStatuses {
		counts[status] = 0
	}
	for _, finding := range report.Findings {
		counts[finding.Status]++
	}

	comparison := &model.Comparison{
		BaselinePath:   baselinePath,
		BaselineScanID: baselineScanID,
		BaselineAt:     baselineAt,
		Counts:         counts,
		Moved:          moved,
	}
	report.Comparison = comparison
	return comparison
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// --- reading a baseline off disk -------------------------------------

// LoadReport reads a report JSON and returns its findings, scan id and finish
// time. It refuses anything that is not one of ours: a foreign JSON in the output
// directory must not be treated as a baseline.
func LoadReport(path string) ([]model.Finding, string, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", err
	}
	var document struct {
		Generator struct {
			Name string `json:"name"`
		} `json:"generator"`
		ScanID     string `json:"scan_id"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
		Findings   []struct {
			Tool     string `json:"tool"`
			Detector struct {
				Tool     string  `json:"tool"`
				Provider *string `json:"provider"`
				Model    *string `json:"model"`
				Pass     *string `json:"pass"`
			} `json:"detector"`
			Severity         string   `json:"severity"`
			Status           string   `json:"status"`
			Title            string   `json:"title"`
			Description      string   `json:"description"`
			Category         string   `json:"category"`
			Source           string   `json:"source"`
			ScannerCategory  string   `json:"scanner_category"`
			RuleID           string   `json:"rule_id"`
			File             string   `json:"file"`
			Line             *int     `json:"line"`
			EndLine          *int     `json:"end_line"`
			CWE              []string `json:"cwe"`
			OWASP            []string `json:"owasp"`
			References       []string `json:"references"`
			Remediation      string   `json:"remediation"`
			Package          string   `json:"package"`
			InstalledVersion string   `json:"installed_version"`
			FixedVersion     string   `json:"fixed_version"`
			Confidence       string   `json:"confidence"`
			Snippet          string   `json:"snippet"`
			CVSS             string   `json:"cvss"`
			FirstSeen        string   `json:"first_seen"`
			LastSeen         string   `json:"last_seen"`
			MovedFrom        string   `json:"moved_from"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, "", "", err
	}
	if document.Generator.Name != "" && document.Generator.Name != "whatsrisky" {
		return nil, "", "", errNotOurs
	}
	if document.Findings == nil {
		return nil, "", "", errNotOurs
	}

	findings := make([]model.Finding, 0, len(document.Findings))
	for _, stored := range document.Findings {
		finding := model.Finding{
			Tool:     firstNonEmpty(stored.Tool, stored.Detector.Tool),
			Severity: model.ParseSeverity(stored.Severity, model.Info),
			Title:    stored.Title, Description: stored.Description,
			Category: stored.Category, Source: stored.Source,
			ScannerCategory: stored.ScannerCategory, RuleID: stored.RuleID,
			File: stored.File, Line: deref(stored.Line), EndLine: deref(stored.EndLine),
			CWE: stored.CWE, OWASP: stored.OWASP, References: stored.References,
			Remediation: stored.Remediation, Package: stored.Package,
			InstalledVersion: stored.InstalledVersion, FixedVersion: stored.FixedVersion,
			Confidence: stored.Confidence, Snippet: stored.Snippet, CVSS: stored.CVSS,
			Provider: derefString(stored.Detector.Provider),
			Model:    derefString(stored.Detector.Model),
			Pass:     derefString(stored.Detector.Pass),
			Status:   stored.Status, FirstSeen: stored.FirstSeen,
			LastSeen: stored.LastSeen, MovedFrom: stored.MovedFrom,
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	finishedAt := firstNonEmpty(document.FinishedAt, document.StartedAt)
	return findings, firstNonEmpty(document.ScanID, document.StartedAt), finishedAt, nil
}

// FindBaseline is the most recent report in a directory, or "".
func FindBaseline(dir string, exclude map[string]bool) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	newest, newestTime := "", time.Time{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if exclude[path] {
			continue
		}
		if _, _, _, err := LoadReport(path); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newestTime) {
			newest, newestTime = path, info.ModTime()
		}
	}
	return newest
}

func deref(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type compareError string

func (e compareError) Error() string { return string(e) }

const errNotOurs compareError = "not a whatsrisky report"
