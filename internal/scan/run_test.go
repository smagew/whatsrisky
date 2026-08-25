package scan

import (
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smagew/whatsrisky/internal/fixture"
	"github.com/smagew/whatsrisky/internal/model"
)

// vulnApp is the rich fixture: a planted flaw for every scanner.
func vulnApp(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := t.TempDir()
	if err := fixture.Write(root); err != nil {
		t.Fatalf("building the fixture: %v", err)
	}
	return root
}

func projectWithASecret(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Derived from a fixed seed, not written down: a literal token in a test file
	// trips every secret scanner pointed at this repository, and a repeating
	// pattern has too little entropy for gitleaks to accept as a real one.
	token := "ghp_" + randomBody(36)
	body := "TOKEN = \"" + token + "\"\n"
	if err := os.WriteFile(filepath.Join(root, "src", "app.py"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q", "."}, {"add", "-A"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	return root
}

// randomBody is deterministic: the same fixture every run, no literal anywhere.
func randomBody(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	source := rand.New(rand.NewSource(20260825))
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[source.Intn(len(alphabet))]
	}
	return string(out)
}

func gitleaksOptions(t *testing.T, root, outDir string) Options {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks is not installed")
	}
	options := NewOptions()
	options.Path = root
	options.Tools = []string{"gitleaks"}
	options.Formats = []string{"html", "json"}
	options.OutDir = outDir
	options.Compare = false
	options.Timeout = 120
	return options
}

func TestAScanWritesTheReportBeforeTheFirstScanner(t *testing.T) {
	root := projectWithASecret(t)
	outDir := filepath.Join(t.TempDir(), "reports")
	var livePaths []string
	var order []string

	outcome, err := Run(gitleaksOptions(t, root, outDir), func(event Event) {
		order = append(order, event.Kind)
		if event.Kind == "live" {
			livePaths = event.Paths
			// The artifact must exist by the time it is announced, and say it is running.
			for _, path := range event.Paths {
				if _, statErr := os.Stat(path); statErr != nil {
					t.Errorf("%s was announced but does not exist", path)
				}
			}
			body, readErr := os.ReadFile(strings.TrimSuffix(livePaths[0], ".html") + ".json")
			if readErr == nil {
				var document map[string]any
				if json.Unmarshal(body, &document) == nil {
					if document["status"] != model.StatusRunning {
						t.Errorf("a live report says status %v", document["status"])
					}
					if verdict, _ := document["verdict"].(string); strings.Contains(verdict, "CLEAN") {
						t.Errorf("a running scan must not read as clean: %q", verdict)
					}
				}
			}
		}
	})
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if len(livePaths) == 0 {
		t.Fatal("no live artifacts were announced")
	}
	// The page comes first: it is the view, and it is what "View report" opens.
	if filepath.Ext(livePaths[0]) != ".html" {
		t.Errorf("the first live path is %s, want the page", livePaths[0])
	}
	if indexOfString(order, "live") > indexOfString(order, "tool_start") {
		t.Error("the report must exist before the first scanner starts")
	}
	if outcome.Report.Status != model.StatusComplete {
		t.Errorf("final status %s", outcome.Report.Status)
	}
	if len(outcome.Report.Findings) == 0 {
		t.Error("the planted secret was not found")
	}
}

func TestAScanNeverFindsItsOwnReports(t *testing.T) {
	// Our JSON quotes the secrets it found, so a second run used to re-report them
	// from the first run's file.
	root := projectWithASecret(t)
	inside := filepath.Join(root, "reports")

	first, err := Run(gitleaksOptions(t, root, inside), nil)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if len(first.Report.Findings) == 0 {
		t.Fatal("the first scan found nothing, so this proves nothing")
	}

	second, err := Run(gitleaksOptions(t, root, filepath.Join(root, "reports2")), nil)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	for _, finding := range second.Report.Findings {
		if strings.HasPrefix(finding.File, "reports") {
			t.Errorf("the second scan reported our own output: %s", finding.File)
		}
	}
	if !containsPrefix(second.Report.Excludes, "reports") {
		t.Errorf("the earlier report directory was not excluded: %v", second.Report.Excludes)
	}
}

func TestExitCodeFollowsFailOn(t *testing.T) {
	finding := model.Finding{Tool: "t", Severity: model.High, Title: "x"}
	finding.Normalize()
	report := model.Report{Findings: []model.Finding{finding}, Status: model.StatusComplete}

	for failOn, want := range map[string]int{
		"none": 0, "": 0, "critical": 0, "high": 2, "medium": 2, "low": 2, "info": 2,
	} {
		if got := ExitCode(report, failOn); got != want {
			t.Errorf("--fail-on %q: exit %d, want %d", failOn, got, want)
		}
	}

	// A resolved finding is history: it must not fail a build.
	resolved := model.Finding{Tool: "t", Severity: model.Critical, Title: "y", Status: model.StatusResolved}
	resolved.Normalize()
	report.Findings = append(report.Findings, resolved)
	if got := ExitCode(report, "critical"); got != 0 {
		t.Errorf("a resolved critical must not fail the build, exit %d", got)
	}
}

func TestAnEmptyDiffRangeIsRefused(t *testing.T) {
	root := projectWithASecret(t)
	options := gitleaksOptions(t, root, t.TempDir())
	options.Diff = "HEAD..HEAD" // touches nothing
	if _, err := Run(options, nil); err == nil {
		t.Error("scoping to an empty range must fail rather than report a clean project")
	} else if !strings.Contains(err.Error(), "touches no existing files") {
		t.Errorf("the reason must be clear: %v", err)
	}
}

func TestChangedFilesDropsDeletions(t *testing.T) {
	root := projectWithASecret(t)
	if err := os.Remove(filepath.Join(root, "src", "app.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-A"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "swap"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}

	files, err := ChangedFiles(root, "HEAD~1..HEAD")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	// There is nothing left in a deleted file to scan.
	for _, file := range files {
		if file == "src/app.py" {
			t.Error("a deleted file must not be scanned")
		}
	}
	if len(files) != 1 || files[0] != "new.py" {
		t.Errorf("changed files: %v", files)
	}

	if _, err := ChangedFiles(root, "not-a-ref..HEAD"); err == nil {
		t.Error("an unresolvable range must be an error")
	}
}

func TestSlugifyKeepsFilenamesSane(t *testing.T) {
	for input, want := range map[string]string{
		"my project":  "my-project",
		"weird/name":  "weird-name",
		"ok_name-1.2": "ok_name-1.2",
		"":            "project",
		"///":         "project",
	} {
		if got := slugify(input); got != want {
			t.Errorf("slugify(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestATimeoutIsHonouredPerScanner(t *testing.T) {
	root := projectWithASecret(t)
	options := gitleaksOptions(t, root, t.TempDir())
	options.Timeout = 1 // gitleaks gets one second
	started := time.Now()
	outcome, err := Run(options, nil)
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 60*time.Second {
		t.Errorf("the timeout was ignored: took %s", elapsed)
	}
	// Whether it finished in time or not, the scan itself must not fall over.
	if outcome.Report.Status == "" {
		t.Error("the report has no status")
	}
}

func indexOfString(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return len(values)
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
