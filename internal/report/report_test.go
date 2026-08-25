package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

func sampleReport() model.Report {
	finding := model.Finding{
		Tool: "semgrep", Severity: model.Critical, Title: "tainted sql string",
		RuleID: "python.django.security.injection.tainted-sql-string",
		File:   "app.py", Line: 20, CWE: []string{"CWE-915"},
		Snippet: ">    20 | cur.execute('...' % name)", Pass: "code",
		Description: `A </script> tag and a "quote" in the data must not break the page.`,
		References:  []string{"https://example.invalid/a"},
	}
	finding.Normalize()
	dependency := model.Finding{
		Tool: "trivy", Severity: model.High, Title: "PyYAML rce", RuleID: "CVE-2020-14343",
		File: "requirements.txt", Package: "PyYAML", InstalledVersion: "3.13",
		FixedVersion: "5.4", ScannerCategory: "Dependency/pip", Pass: "vuln",
	}
	dependency.Normalize()
	report := model.Report{
		ProjectPath: "/p", ProjectName: "p", ScanID: "p-1",
		StartedAt: "2026-08-25 12:00:00", FinishedAt: "2026-08-25 12:00:09",
		DurationS: 9.123, Status: model.StatusComplete,
		Findings: []model.Finding{finding, dependency},
	}
	report.Tools = []model.ToolResult{
		{Name: "semgrep", Status: model.ToolOK, Version: "semgrep 1", Command: "semgrep .",
			DurationS: 6.006, Findings: []model.Finding{finding}},
		{Name: "trivy", Status: model.ToolMissing, Message: "`trivy` not found in PATH."},
	}
	return report
}

func TestTheJSONContractHasTheExpectedShape(t *testing.T) {
	body, err := Marshal(sampleReport())
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("parsing our own output: %v", err)
	}

	for _, key := range []string{
		"schema_version", "generator", "scan_id", "status", "project_path", "project_name",
		"started_at", "finished_at", "duration_s", "git_commit", "git_branch", "diff_range",
		"scope_paths", "excludes", "excluded_findings", "comparison", "counts_by_category",
		"counts_by_source", "counts_by_status", "risk_score", "verdict", "counts",
		"total_findings", "active_findings", "tools", "findings",
	} {
		if _, ok := document[key]; !ok {
			t.Errorf("the contract is missing %q", key)
		}
	}
	if document["schema_version"].(float64) != float64(model.SchemaVersion) {
		t.Errorf("schema version %v", document["schema_version"])
	}
	// Durations are rounded the way the reference rounds them.
	if document["duration_s"].(float64) != 9.12 {
		t.Errorf("duration_s %v, want 9.12", document["duration_s"])
	}

	findings := document["findings"].([]any)
	first := findings[0].(map[string]any)
	detector := first["detector"].(map[string]any)
	// provider and model are null for a local scanner: that says it better than "".
	if detector["provider"] != nil || detector["model"] != nil {
		t.Errorf("a local scanner has no provider or model: %v", detector)
	}
	if detector["pass"] != "code" {
		t.Errorf("pass %v", detector["pass"])
	}
	if first["category"] != model.CatInjectionSQL {
		t.Errorf("category %v", first["category"])
	}
	for _, key := range []string{"fingerprint", "content_key", "match_key"} {
		if value, _ := first[key].(string); len(value) != 12 {
			t.Errorf("%s is %q, want 12 hex characters", key, value)
		}
	}
	// A dependency finding has no line, and null is the honest answer.
	second := findings[1].(map[string]any)
	if second["line"] != nil {
		t.Errorf("line %v, want null", second["line"])
	}

	// A missing scanner must be visible to a machine, not only to a reader.
	tools := document["tools"].([]any)
	if tools[1].(map[string]any)["status"] != model.ToolMissing {
		t.Errorf("tool status %v", tools[1])
	}
	if !strings.Contains(document["verdict"].(string), "partial coverage") {
		t.Errorf("verdict %q must admit the gap", document["verdict"])
	}
}

func TestThePageIsTheViewAndTheData(t *testing.T) {
	report := sampleReport()
	page, err := RenderHTML(report)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}

	recovered, err := ExtractJSON(page)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	var written map[string]any
	body, _ := Marshal(report)
	_ = json.Unmarshal(body, &written)
	got, _ := json.Marshal(recovered)
	want, _ := json.Marshal(written)
	if string(got) != string(want) {
		t.Error("the JSON in the page is not the JSON we would have written")
	}

	// A finding's own text can contain </script>, which would close the tag that
	// carries it. Go's JSON encoder escapes < as \u003c, so it never appears
	// literally - and the round trip above proves it survived either way.
	descriptions := recovered["findings"].([]any)[0].(map[string]any)
	if !strings.Contains(descriptions["description"].(string), "</script>") {
		t.Error("the dangerous text did not survive the round trip")
	}
	dataBlock := page[strings.Index(page, `type="application/json"`):]
	dataBlock = dataBlock[:strings.Index(dataBlock, "</script>")]
	if strings.Contains(dataBlock, "</script>") {
		t.Error("an unescaped </script> reached the data block")
	}
	if strings.Count(page, "<script") != 2 {
		t.Errorf("%d script tags; the page should have exactly two", strings.Count(page, "<script"))
	}
}

func TestThePageFetchesNothing(t *testing.T) {
	// Self-contained means self-contained: a report must render offline.
	viewer, err := Viewer()
	if err != nil {
		t.Fatalf("reading the viewer: %v", err)
	}
	for pattern, why := range map[string]string{
		`<link[\s>]`:           "a <link> would fetch a stylesheet",
		`<script[^>]+src=`:     "a script src would fetch code",
		`@import`:              "an @import would fetch a stylesheet",
		`url\(\s*['"]?https?:`: "a url() would fetch an asset",
	} {
		if regexp.MustCompile(pattern).MatchString(viewer) {
			t.Error(why)
		}
	}
}

func TestTheEmbeddedViewerIsTheFileInTheRepository(t *testing.T) {
	embedded, err := Viewer()
	if err != nil {
		t.Fatalf("reading the embedded viewer: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join("templates", "viewer.html"))
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	if embedded != string(onDisk) {
		t.Error("the embedded viewer and the file have drifted apart")
	}
}

func TestWritesAreAtomic(t *testing.T) {
	// A reader polling a live scan must never see half a document.
	dir := t.TempDir()
	report := sampleReport()
	for name, write := range map[string]func(model.Report, string) error{
		"r.json": WriteJSON, "r.html": WriteHTML, "r.md": WriteMarkdown,
	} {
		path := filepath.Join(dir, name)
		if err := write(report, path); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		if _, err := os.Stat(path + ".part"); err == nil {
			t.Errorf("%s.part was left behind", name)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Errorf("%s is missing or empty", name)
		}
	}
}

func TestMarkdownStatesWhatChangedAndWhatWasMissed(t *testing.T) {
	report := sampleReport()
	report.Comparison = &model.Comparison{
		BaselineScanID: "p-0",
		Counts:         map[string]int{model.StatusNew: 1, model.StatusResolved: 2},
		Moved:          1,
	}
	body := RenderMarkdown(report)
	for _, want := range []string{
		"# Security Assessment — p",
		"| trivy | missing |", // a coverage gap is in the table
		"## Since p-0",
		"**resolved:** 2",
		"**moved:** 1",
		"SQL injection", // the normalized category, not the scanner's words
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the Markdown is missing %q", want)
		}
	}
}
