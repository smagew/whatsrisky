package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The differential gate the rewrite spec promises, at report level: both
// implementations scan the same project and every field of the JSON contract must
// agree, except the ones that cannot (timestamps, durations, scan ids, the exact
// command lines, and the absolute path).
//
// It runs only when both binaries are available, so it is a local and CI gate
// during the rewrite and disappears cleanly when the Python tree does.

// volatile fields differ by construction and are excluded deliberately, one by
// one - not by a wildcard, so a new field is compared until someone decides
// otherwise.
var volatile = map[string]bool{
	"scan_id": true, "started_at": true, "finished_at": true, "duration_s": true,
	"project_path": true, "generator": true, "tools": true, "comparison": true,
	"excludes": true,
}

func TestBothImplementationsProduceTheSameReport(t *testing.T) {
	goBinary := buildGoBinary(t)
	python, err := exec.LookPath("whatsrisky")
	if err != nil {
		t.Skip("the Python whatsrisky is not on PATH; nothing to compare against")
	}
	for _, binary := range []string{"semgrep", "trivy", "gitleaks", "git"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s is not installed", binary)
		}
	}
	project := vulnApp(t)

	shared := []string{
		"--tools", "semgrep,trivy,gitleaks",
		"--semgrep-config", "p/security-audit",
		"--no-compare", "--json-stdout",
	}
	ours := runReport(t, goBinary, append([]string{project, "--out-dir", t.TempDir()}, shared...))
	theirs := runReport(t, python, append([]string{project, "--out-dir", t.TempDir(), "--format", "json"}, shared...))

	// 1. the same keys
	if missing, extra := keyDifference(theirs, ours); len(missing) > 0 || len(extra) > 0 {
		t.Errorf("contract keys differ: only Python %v, only Go %v", missing, extra)
	}

	// 2. the same values, field by field
	for key := range theirs {
		if volatile[key] || key == "findings" {
			continue
		}
		if !sameJSON(ours[key], theirs[key]) {
			t.Errorf("%s differs:\n  go     %s\n  python %s", key, render(ours[key]), render(theirs[key]))
		}
	}

	// 3. the same findings, every field of every one
	ourFindings := byFingerprint(t, ours)
	theirFindings := byFingerprint(t, theirs)
	if len(theirFindings) == 0 {
		t.Fatal("the reference found nothing, so this proves nothing")
	}
	for fingerprint, reference := range theirFindings {
		mine, ok := ourFindings[fingerprint]
		if !ok {
			t.Errorf("only Python reports %s at %v", reference["title"], reference["file"])
			continue
		}
		for field, want := range reference {
			if !sameJSON(mine[field], want) {
				t.Errorf("%s · %s: %s is %s in Go and %s in Python",
					reference["title"], field, field, render(mine[field]), render(want))
			}
		}
	}
	for fingerprint, mine := range ourFindings {
		if _, ok := theirFindings[fingerprint]; !ok {
			t.Errorf("only Go reports %s at %v", mine["title"], mine["file"])
		}
	}
	t.Logf("%d findings and %d contract fields identical in both implementations",
		len(theirFindings), len(theirs)-len(volatile))
}

func buildGoBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "whatsrisky-go")
	build := exec.Command("go", "build", "-o", path, "github.com/smagew/whatsrisky/cmd/whatsrisky")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the Go binary: %v\n%s", err, output)
	}
	return path
}

func runReport(t *testing.T, binary string, args []string) map[string]any {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s %v: %v", filepath.Base(binary), args, err)
	}
	var document map[string]any
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("parsing %s output: %v", filepath.Base(binary), err)
	}
	return document
}

func byFingerprint(t *testing.T, document map[string]any) map[string]map[string]any {
	t.Helper()
	raw, _ := document["findings"].([]any)
	out := make(map[string]map[string]any, len(raw))
	for _, entry := range raw {
		finding, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		fingerprint, _ := finding["fingerprint"].(string)
		if fingerprint == "" {
			t.Fatal("a finding without a fingerprint cannot be correlated")
		}
		out[fingerprint] = finding
	}
	return out
}

func keyDifference(reference, mine map[string]any) (missing, extra []string) {
	for key := range reference {
		if _, ok := mine[key]; !ok {
			missing = append(missing, key)
		}
	}
	for key := range mine {
		if _, ok := reference[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func sameJSON(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}

func render(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	text := string(body)
	if len(text) > 200 {
		text = text[:200] + "…"
	}
	return strings.ReplaceAll(text, "\n", " ")
}
