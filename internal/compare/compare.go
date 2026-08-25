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
