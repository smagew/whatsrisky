package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Python implementation is the specification for this rewrite. These tests
// read what it computed (testdata/parity, generated from it) and require the same
// answers - identity keys digit for digit, so a Go scan can correlate against a
// baseline a Python scan wrote.

func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "parity", name)
}

func readGolden(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(goldenPath(t, name))
	if err != nil {
		t.Fatalf("reading the golden file: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
}

type findingCase struct {
	Input struct {
		Tool             string   `json:"tool"`
		Severity         string   `json:"severity"`
		Title            string   `json:"title"`
		RuleID           string   `json:"rule_id"`
		File             string   `json:"file"`
		Line             int      `json:"line"`
		CWE              []string `json:"cwe"`
		Category         string   `json:"category"`
		Snippet          string   `json:"snippet"`
		Package          string   `json:"package"`
		InstalledVersion string   `json:"installed_version"`
		FixedVersion     string   `json:"fixed_version"`
		Provider         string   `json:"provider"`
		Model            string   `json:"model"`
		PassName         string   `json:"pass_name"`
	} `json:"input"`
	Expect struct {
		Severity      string `json:"severity"`
		Category      string `json:"category"`
		CategoryLabel string `json:"category_label"`
		Source        string `json:"source"`
		Fingerprint   string `json:"fingerprint"`
		ContentKey    string `json:"content_key"`
		MatchKey      string `json:"match_key"`
		Location      string `json:"location"`
	} `json:"expect"`
}

func TestFindingsMatchTheReferenceImplementation(t *testing.T) {
	var cases []findingCase
	readGolden(t, "findings.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no golden findings; the parity data is missing")
	}

	for _, testCase := range cases {
		in := testCase.Input
		t.Run(in.RuleID+"@"+in.File, func(t *testing.T) {
			finding := Finding{
				Tool: in.Tool, Severity: ParseSeverity(in.Severity, Info), Title: in.Title,
				RuleID: in.RuleID, File: in.File, Line: in.Line, CWE: in.CWE,
				ScannerCategory: in.Category, Snippet: in.Snippet, Package: in.Package,
				InstalledVersion: in.InstalledVersion, FixedVersion: in.FixedVersion,
				Provider: in.Provider, Model: in.Model, Pass: in.PassName,
			}
			finding.Normalize()

			for _, check := range []struct{ name, got, want string }{
				{"severity", string(finding.Severity), testCase.Expect.Severity},
				{"category", finding.Category, testCase.Expect.Category},
				{"category label", finding.CategoryLabel(), testCase.Expect.CategoryLabel},
				{"source", finding.Source, testCase.Expect.Source},
				{"fingerprint", finding.Fingerprint(), testCase.Expect.Fingerprint},
				{"content key", finding.ContentKey(), testCase.Expect.ContentKey},
				{"match key", finding.MatchKey(), testCase.Expect.MatchKey},
				{"location", finding.Location(), testCase.Expect.Location},
			} {
				if check.got != check.want {
					t.Errorf("%s: got %q, reference says %q", check.name, check.got, check.want)
				}
			}
		})
	}
}

func TestMovedCodeKeepsItsContentKey(t *testing.T) {
	// The regression the identity keys exist for: the same offending line in a
	// different file, with different neighbours, is the same finding.
	before := Finding{Tool: "semgrep", RuleID: "r", File: "a.py", Line: 6,
		Snippet: "      4 | import os\n      5 | def ping(host):\n>     6 |     run(host, shell=True)\n"}
	after := Finding{Tool: "semgrep", RuleID: "r", File: "b.py", Line: 90,
		Snippet: "     88 | # unrelated\n     89 | def ping(host):\n>    90 |     run(host, shell=True)\n"}
	if before.ContentKey() != after.ContentKey() {
		t.Errorf("content key changed when the code moved: %s vs %s", before.ContentKey(), after.ContentKey())
	}
	if before.Fingerprint() == after.Fingerprint() {
		t.Error("fingerprint must be exact, so it has to differ here")
	}
}

func TestSeverityAndSourcesMatchTheReferenceImplementation(t *testing.T) {
	var golden struct {
		Order    []string           `json:"order"`
		Weights  map[string]float64 `json:"weights"`
		Parse    map[string]string  `json:"parse"`
		Evidence map[string]string  `json:"evidence"`
		Sources  map[string]string  `json:"sources"`
	}
	readGolden(t, "severity.json", &golden)

	if len(golden.Order) != len(Order) {
		t.Fatalf("severity order length: got %d, reference says %d", len(Order), len(golden.Order))
	}
	for i, want := range golden.Order {
		if string(Order[i]) != want {
			t.Errorf("severity order at %d: got %s, want %s", i, Order[i], want)
		}
	}
	for name, want := range golden.Weights {
		if got := Severity(name).Weight(); got != want {
			t.Errorf("weight of %s: got %v, want %v", name, got, want)
		}
	}
	for raw, want := range golden.Parse {
		if got := string(ParseSeverity(raw, Info)); got != want {
			t.Errorf("ParseSeverity(%q): got %s, want %s", raw, got, want)
		}
	}

	evidence := map[string]string{
		"marked":   EvidenceOf("      4 | import os\n>     6 |   run(cmd, shell=True)\n"),
		"unmarked": EvidenceOf("def f():\n    return 1"),
		"empty":    EvidenceOf(""),
	}
	for name, want := range golden.Evidence {
		if evidence[name] != want {
			t.Errorf("EvidenceOf %s: got %q, want %q", name, evidence[name], want)
		}
	}

	for key, want := range golden.Sources {
		var tool, pass, file string
		parts := splitThree(key)
		tool, pass, file = parts[0], parts[1], parts[2]
		if got := InferSource(tool, pass, file); got != want {
			t.Errorf("InferSource(%s, %s, %s): got %s, want %s", tool, pass, file, got, want)
		}
	}
}

func splitThree(key string) [3]string {
	var out [3]string
	index := 0
	start := 0
	for i := 0; i < len(key) && index < 2; i++ {
		if key[i] == '|' {
			out[index] = key[start:i]
			index++
			start = i + 1
		}
	}
	out[index] = key[start:]
	return out
}

func TestCategoriesMatchTheReferenceImplementation(t *testing.T) {
	var golden struct {
		Labels   map[string]string `json:"labels"`
		CWE      map[string]string `json:"cwe"`
		Classify []struct {
			CWE    []string `json:"cwe"`
			Native string   `json:"native"`
			Rule   string   `json:"rule"`
			Title  string   `json:"title"`
			Source string   `json:"source"`
			Expect string   `json:"expect"`
		} `json:"classify"`
	}
	readGolden(t, "categories.json", &golden)

	if len(golden.Labels) != len(CategoryLabels) {
		t.Errorf("vocabulary size: got %d, reference says %d", len(CategoryLabels), len(golden.Labels))
	}
	for category, want := range golden.Labels {
		if got := CategoryLabel(category); got != want {
			t.Errorf("label of %s: got %q, want %q", category, got, want)
		}
	}
	if len(golden.CWE) != len(CWEToCategory) {
		t.Errorf("cwe table size: got %d, reference says %d", len(CWEToCategory), len(golden.CWE))
	}
	for raw, want := range golden.CWE {
		numbers := ParseCWE([]string{raw})
		if len(numbers) != 1 {
			t.Fatalf("cannot parse CWE key %q", raw)
		}
		if got := CWEToCategory[numbers[0]]; got != want {
			t.Errorf("CWE-%s: got %s, want %s", raw, got, want)
		}
	}
	for _, item := range golden.Classify {
		got := Classify(item.CWE, item.Native, item.Rule, item.Title, item.Source)
		if got != item.Expect {
			t.Errorf("Classify(%v, %q, %q, %q, %q): got %s, want %s",
				item.CWE, item.Native, item.Rule, item.Title, item.Source, got, item.Expect)
		}
	}
}

func TestRiskScoresAndVerdictsMatchTheReferenceImplementation(t *testing.T) {
	var golden []struct {
		Counts  map[string]int `json:"counts"`
		Score   int            `json:"score"`
		Verdict string         `json:"verdict"`
	}
	readGolden(t, "risk.json", &golden)

	for _, item := range golden {
		report := Report{ProjectName: "p", Status: StatusComplete}
		report.Tools = []ToolResult{{Name: "t", Status: ToolOK}}
		for severity, count := range item.Counts {
			for i := 0; i < count; i++ {
				finding := Finding{Tool: "t", Severity: Severity(severity), Title: severity}
				finding.Normalize()
				report.Findings = append(report.Findings, finding)
			}
		}
		if got := report.RiskScore(); got != item.Score {
			t.Errorf("risk score for %v: got %d, reference says %d", item.Counts, got, item.Score)
		}
		if got := report.Verdict(); got != item.Verdict {
			t.Errorf("verdict for %v: got %q, reference says %q", item.Counts, got, item.Verdict)
		}
	}
}

func TestARunningScanIsNeverPaintedClean(t *testing.T) {
	report := Report{Status: StatusRunning, Tools: []ToolResult{
		{Name: "semgrep", Status: ToolPending}, {Name: "trivy", Status: ToolOK},
	}}
	verdict := report.Verdict()
	if want := "SCAN IN PROGRESS - 1 of 2 scanners done, no verdict yet"; verdict != want {
		t.Errorf("got %q, want %q", verdict, want)
	}

	report.Status = StatusPartial
	if got := report.Verdict(); got != "INCONCLUSIVE - a scanner failed, so parts were not scanned" {
		t.Errorf("a partial scan with no findings: got %q", got)
	}
}

func TestAVerdictNeverOutrunsItsCoverage(t *testing.T) {
	finding := Finding{Tool: "semgrep", Severity: Medium, Title: "debug enabled"}
	finding.Normalize()
	report := Report{Status: StatusPartial, Findings: []Finding{finding}, Tools: []ToolResult{
		{Name: "semgrep", Status: ToolOK}, {Name: "trivy", Status: ToolMissing},
	}}
	verdict := report.Verdict()
	if !strings.HasPrefix(verdict, "MODERATE") || !strings.Contains(verdict, "trivy did not run") {
		t.Errorf("the headline hides the coverage gap: %q", verdict)
	}
}

func TestResolvedFindingsDoNotInflateTheCounts(t *testing.T) {
	open := Finding{Tool: "t", Severity: High, Title: "open", Status: StatusOpen}
	resolved := Finding{Tool: "t", Severity: Critical, Title: "resolved", Status: StatusResolved}
	accepted := Finding{Tool: "t", Severity: Critical, Title: "accepted", Status: StatusAccepted}
	for _, f := range []*Finding{&open, &resolved, &accepted} {
		f.Normalize()
	}
	report := Report{Status: StatusComplete, Findings: []Finding{resolved, open, accepted},
		Tools: []ToolResult{{Name: "t", Status: ToolOK}}}

	counts := report.Counts()
	if counts[Critical] != 0 || counts[High] != 1 {
		t.Errorf("history and decisions must not count: %v", counts)
	}
	if got := report.Verdict(); !strings.HasPrefix(got, "HIGH RISK") {
		t.Errorf("verdict follows the active findings: %q", got)
	}
	if sorted := report.SortedFindings(); sorted[0].Title != "open" {
		t.Errorf("active findings come first, got %q", sorted[0].Title)
	}
	if len(report.Findings) != 3 {
		t.Error("and nothing is dropped from the report")
	}
}
