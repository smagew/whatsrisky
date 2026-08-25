package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

// The scenarios and their outcomes come from the Python implementation, which is
// the specification for this rewrite. The failure they exist to prevent: code
// moving and being reported as resolved plus new, which turns every refactor into
// fake progress and fake regressions.

type storedFinding struct {
	Tool     string `json:"tool"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
	Status   string `json:"status"`
	Package  string `json:"package"`
}

func (s storedFinding) toModel() model.Finding {
	finding := model.Finding{
		Tool: s.Tool, Severity: model.ParseSeverity(s.Severity, model.Info), Title: s.Title,
		RuleID: s.RuleID, File: s.File, Line: s.Line, Snippet: s.Snippet,
		Status: s.Status, Package: s.Package,
	}
	finding.Normalize()
	return finding
}

type outcome struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Status    string `json:"status"`
	MovedFrom string `json:"moved_from"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

func TestCorrelationMatchesTheReferenceImplementation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "parity", "compare.json"))
	if err != nil {
		t.Fatalf("reading the golden scenarios: %v", err)
	}
	var scenarios map[string]struct {
		Baseline     []storedFinding `json:"baseline"`
		CurrentInput []storedFinding `json:"current_input"`
		Expect       struct {
			Counts   map[string]int `json:"counts"`
			Moved    int            `json:"moved"`
			Findings []outcome      `json:"findings"`
		} `json:"expect"`
	}
	if err := json.Unmarshal(raw, &scenarios); err != nil {
		t.Fatalf("parsing the golden scenarios: %v", err)
	}
	if len(scenarios) == 0 {
		t.Fatal("no scenarios; the parity data is missing")
	}

	for name, scenario := range scenarios {
		t.Run(name, func(t *testing.T) {
			baseline := make([]model.Finding, 0, len(scenario.Baseline))
			for _, stored := range scenario.Baseline {
				baseline = append(baseline, stored.toModel())
			}
			report := &model.Report{ProjectName: "p", ScanID: "scan-2", Status: model.StatusComplete}
			for _, stored := range scenario.CurrentInput {
				report.Findings = append(report.Findings, stored.toModel())
			}

			comparison := Correlate(report, baseline, "scan-1", "then", "b.json")

			for status, want := range scenario.Expect.Counts {
				if got := comparison.Counts[status]; got != want {
					t.Errorf("%s count: got %d, reference says %d", status, got, want)
				}
			}
			if comparison.Moved != scenario.Expect.Moved {
				t.Errorf("moved: got %d, reference says %d", comparison.Moved, scenario.Expect.Moved)
			}

			got := report.SortedFindings()
			if len(got) != len(scenario.Expect.Findings) {
				t.Fatalf("finding count: got %d, reference says %d", len(got), len(scenario.Expect.Findings))
			}
			for i, want := range scenario.Expect.Findings {
				have := got[i]
				if have.File != want.File || have.Line != want.Line {
					t.Errorf("finding %d location: got %s:%d, want %s:%d", i, have.File, have.Line, want.File, want.Line)
				}
				if have.Status != want.Status {
					t.Errorf("finding %d (%s) status: got %s, reference says %s", i, have.Location(), have.Status, want.Status)
				}
				if have.MovedFrom != want.MovedFrom {
					t.Errorf("finding %d moved_from: got %q, want %q", i, have.MovedFrom, want.MovedFrom)
				}
				if have.FirstSeen != want.FirstSeen || have.LastSeen != want.LastSeen {
					t.Errorf("finding %d seen: got %s/%s, want %s/%s",
						i, have.FirstSeen, have.LastSeen, want.FirstSeen, want.LastSeen)
				}
			}
		})
	}
}

func TestTwoFindingsOfOneRuleDoNotSwapHistories(t *testing.T) {
	// An ambiguous match key must not correlate arbitrarily; the evidence decides.
	mk := func(line int, code string) model.Finding {
		finding := model.Finding{Tool: "semgrep", Severity: model.High, Title: "t", RuleID: "r",
			File: "a.py", Line: line, Snippet: ">   " + code}
		finding.Normalize()
		return finding
	}
	baseline := []model.Finding{mk(11, "os.system(a)"), mk(21, "os.system(b)")}
	report := &model.Report{ScanID: "s2", Findings: []model.Finding{mk(10, "os.system(a)"), mk(20, "os.system(b)")}}

	Correlate(report, baseline, "s1", "then", "")
	for _, finding := range report.Findings {
		want := map[int]string{10: "a.py:11", 20: "a.py:21"}[finding.Line]
		if finding.MovedFrom != want {
			t.Errorf("line %d correlated to %q, want %q", finding.Line, finding.MovedFrom, want)
		}
	}
}
