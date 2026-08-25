package runner

import (
	"strings"
	"testing"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
)

// These are the tests that catch a scanner changing its JSON shape. They skip
// when the binary is absent, so the rest of the suite runs anywhere.

const timeout = 5 * time.Minute

func TestSemgrepFindsInjection(t *testing.T) {
	requireBinary(t, "semgrep")
	root := vulnApp(t)
	result := Run(NewSemgrep(testConfig(t, root)), nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if len(result.Findings) == 0 {
		t.Fatal("semgrep found nothing in a deliberately vulnerable app")
	}
	titles := strings.ToLower(joinTitles(result.Findings))
	if !containsAny(titles, "sql", "subprocess", "shell", "pickle", "debug") {
		t.Errorf("none of the planted flaws were named: %s", titles)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "" || finding.File == "" {
			t.Errorf("a finding without a rule or a file: %+v", finding.Title)
		}
		if finding.Category == "" || finding.Source == "" {
			t.Errorf("%s was not normalized", finding.Title)
		}
	}
}

func TestTrivyFindsVulnerableDependencies(t *testing.T) {
	requireBinary(t, "trivy")
	root := vulnApp(t)
	result := Run(NewTrivy(testConfig(t, root)), nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	packages := map[string]bool{}
	fixable := 0
	for _, finding := range result.Findings {
		if finding.Package != "" {
			packages[finding.Package] = true
		}
		if finding.FixedVersion != "" {
			fixable++
			if !strings.Contains(finding.Remediation, "Upgrade") {
				t.Errorf("a fixable CVE must say what to upgrade to: %q", finding.Remediation)
			}
		}
	}
	if !packages["PyYAML"] && !packages["Flask"] && !packages["Jinja2"] && !packages["requests"] {
		t.Errorf("none of the pinned vulnerable packages were found: %v", packages)
	}
	if fixable == 0 {
		t.Error("expected at least one CVE with a fixed version")
	}
}

func TestTrivySaysItCannotHonourADiff(t *testing.T) {
	requireBinary(t, "trivy")
	root := vulnApp(t)
	config := testConfig(t, root)
	config.DiffRange = "HEAD~1..HEAD"
	result := Run(NewTrivy(config), nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	// Fake precision is worse than a stated limitation.
	if !strings.Contains(result.Message, "ignored --diff") {
		t.Errorf("the report must say the diff was ignored, got %q", result.Message)
	}
}

func TestGitleaksFindsSecretsAndRespectsExclusions(t *testing.T) {
	requireBinary(t, "gitleaks")
	root := vulnApp(t)

	result := Run(NewGitleaks(testConfig(t, root)), nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if len(result.Findings) == 0 {
		t.Fatal("gitleaks found no secret in a file full of them")
	}
	for _, finding := range result.Findings {
		if finding.Severity != model.Critical && finding.Severity != model.High {
			t.Errorf("a leaked credential is not %s", finding.Severity)
		}
		if finding.Category != model.CatSecret {
			t.Errorf("category %q, want %q", finding.Category, model.CatSecret)
		}
		if !strings.Contains(strings.ToLower(finding.Remediation), "rotate") {
			t.Error("the remediation must say to rotate the credential")
		}
	}

	// gitleaks has no --exclude flag, so this exercises the generated allowlist.
	excluded := testConfig(t, root)
	excluded.Exclude = []string{"Dockerfile"}
	result = Run(NewGitleaks(excluded), nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	for _, finding := range result.Findings {
		if strings.Contains(finding.File, "Dockerfile") {
			t.Errorf("an excluded path was still reported: %s", finding.File)
		}
	}
}

func TestDiffScopingNarrowsTheScan(t *testing.T) {
	requireBinary(t, "semgrep")
	root := vulnApp(t)

	whole := Run(NewSemgrep(testConfig(t, root)), nil)
	scoped := testConfig(t, root)
	scoped.DiffRange = "HEAD~1..HEAD"
	scoped.ScopePaths = []string{"upload.py"}
	narrowed := Run(NewSemgrep(scoped), nil)

	if narrowed.Status != model.ToolOK {
		t.Fatalf("status %s: %s", narrowed.Status, narrowed.Message)
	}
	if len(narrowed.Findings) >= len(whole.Findings) {
		t.Errorf("scoping to one file did not narrow anything: %d vs %d",
			len(narrowed.Findings), len(whole.Findings))
	}
	for _, finding := range narrowed.Findings {
		if finding.File != "" && finding.File != "upload.py" {
			t.Errorf("a file outside the scope was scanned: %s", finding.File)
		}
	}
}

func TestAMissingScannerIsReportedNotFatal(t *testing.T) {
	runner := NewSemgrep(Config{Target: t.TempDir(), WorkDir: t.TempDir()})
	runner.binary = "definitely-not-installed-xyz"
	result := Run(runner, nil)
	if result.Status != model.ToolMissing {
		t.Errorf("status %s, want %s", result.Status, model.ToolMissing)
	}
	if !strings.Contains(result.Message, "not found in PATH") || !strings.Contains(result.Message, "Install:") {
		t.Errorf("the message must say what is missing and how to get it: %q", result.Message)
	}
}

func TestProgressIsReportedWhileScanning(t *testing.T) {
	requireBinary(t, "semgrep")
	root := vulnApp(t)
	var messages []string
	Run(NewSemgrep(testConfig(t, root)), func(message string) {
		messages = append(messages, message)
	})
	if len(messages) == 0 {
		t.Fatal("a long scan must not be silent")
	}
	if !containsAny(strings.ToLower(strings.Join(messages, " ")), "scanning", "rules", "findings") {
		t.Errorf("the progress said nothing useful: %v", messages)
	}
}

func joinTitles(findings []model.Finding) string {
	var titles []string
	for _, finding := range findings {
		titles = append(titles, finding.Title)
	}
	return strings.Join(titles, " ")
}

func containsAny(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}
