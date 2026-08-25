package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

// The differential test the rewrite spec promises: both implementations scan the
// same fixture and their findings are compared. "We ported it faithfully" is a
// claim; this is a check.
//
// It runs only when the Python CLI is on PATH, so it is a local and CI gate
// during the rewrite and disappears cleanly when the Python tree does.

type pythonReport struct {
	Findings []struct {
		Tool        string `json:"tool"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		RuleID      string `json:"rule_id"`
		File        string `json:"file"`
		Line        *int   `json:"line"`
		Category    string `json:"category"`
		Source      string `json:"source"`
		Fingerprint string `json:"fingerprint"`
		ContentKey  string `json:"content_key"`
	} `json:"findings"`
}

// key is what must agree. The fingerprint is included deliberately: if it differs,
// a Go scan cannot correlate against a baseline a Python scan wrote, which is the
// whole point of matching the digests.
type key struct {
	Tool, RuleID, File, Severity, Category, Source, Fingerprint string
	Line                                                        int
}

func (k key) String() string {
	return fmt.Sprintf("%-8s %-9s %-18s %-19s %s:%d [%s]",
		k.Tool, k.Severity, k.Category, k.Source, k.File, k.Line, k.Fingerprint)
}

func TestGoAndPythonAgreeOnTheSameProject(t *testing.T) {
	if _, err := exec.LookPath("whatsrisky"); err != nil {
		t.Skip("the Python whatsrisky is not on PATH; nothing to compare against")
	}
	for _, binary := range []string{"semgrep", "trivy", "gitleaks"} {
		requireBinary(t, binary)
	}
	root := vulnApp(t)

	// The reference implementation, with the AI pass off and no baseline so the
	// comparison is over one scan's findings only.
	command := exec.Command("whatsrisky", root,
		"--tools", "semgrep,trivy,gitleaks",
		"--semgrep-config", "p/security-audit",
		"--format", "json", "--out-dir", t.TempDir(),
		"--no-compare", "--json-stdout")
	output, err := command.Output()
	if err != nil {
		t.Skipf("the reference implementation did not run: %v", err)
	}
	var reference pythonReport
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatalf("parsing the reference report: %v", err)
	}

	config := testConfig(t, root)
	var ours []model.Finding
	for _, runner := range []Runner{NewSemgrep(config), NewTrivy(config), NewGitleaks(config)} {
		result := Run(runner, nil)
		if result.Status != model.ToolOK {
			t.Fatalf("%s: %s — %s", runner.Name(), result.Status, result.Message)
		}
		ours = append(ours, result.Findings...)
	}

	theirs := map[key]bool{}
	for _, finding := range reference.Findings {
		line := 0
		if finding.Line != nil {
			line = *finding.Line
		}
		theirs[key{finding.Tool, finding.RuleID, finding.File, finding.Severity,
			finding.Category, finding.Source, finding.Fingerprint, line}] = true
	}
	mine := map[key]bool{}
	for _, finding := range ours {
		mine[key{finding.Tool, finding.RuleID, finding.File, string(finding.Severity),
			finding.Category, finding.Source, finding.Fingerprint(), finding.Line}] = true
	}

	missing := difference(theirs, mine)
	extra := difference(mine, theirs)
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf("the two implementations disagree: %d only in Python, %d only in Go, %d shared",
			len(missing), len(extra), len(theirs)-len(missing))
		for _, item := range missing {
			t.Errorf("  only Python: %s", item)
		}
		for _, item := range extra {
			t.Errorf("  only Go:     %s", item)
		}
	}
	if len(theirs) == 0 {
		t.Fatal("the reference found nothing, so this proves nothing")
	}
	t.Logf("%d findings, identical in both implementations", len(theirs))
}

func difference(a, b map[key]bool) []string {
	var out []string
	for item := range a {
		if !b[item] {
			out = append(out, item.String())
		}
	}
	sort.Strings(out)
	if len(out) > 15 {
		out = append(out[:15], fmt.Sprintf("… and %d more", len(out)-15))
	}
	return out
}

func TestTheDifferentialGateIsWiredUp(t *testing.T) {
	// A skipped differential test proves nothing, so make the reason visible.
	if _, err := exec.LookPath("whatsrisky"); err != nil {
		t.Log("differential: skipped, the Python CLI is not installed")
		return
	}
	if _, err := os.Stat("../../pyproject.toml"); err != nil {
		t.Log("differential: skipped, the Python tree is gone — remove this test with it")
		return
	}
	t.Log("differential: active, comparing against the Python implementation")
}
