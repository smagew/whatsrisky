package exclude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readGolden(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "parity", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
}

func TestExclusionsMatchTheReferenceImplementation(t *testing.T) {
	var golden struct {
		Defaults []string `json:"defaults"`
		Match    []struct {
			Path     string   `json:"path"`
			Patterns []string `json:"patterns"`
			Expect   bool     `json:"expect"`
		} `json:"match"`
		Regex map[string]string `json:"regex"`
	}
	readGolden(t, "excludes.json", &golden)

	if len(golden.Defaults) != len(Defaults) {
		t.Errorf("default list size: got %d, reference says %d", len(Defaults), len(golden.Defaults))
	}
	for i, want := range golden.Defaults {
		if i < len(Defaults) && Defaults[i] != want {
			t.Errorf("default %d: got %q, want %q", i, Defaults[i], want)
		}
	}

	for _, item := range golden.Match {
		if got := Path(item.Path, item.Patterns); got != item.Expect {
			t.Errorf("Path(%q, %v): got %v, reference says %v",
				item.Path, item.Patterns, got, item.Expect)
		}
	}

	// gitleaks has no exclude flag, so these regexes are the mechanism.
	for pattern, want := range golden.Regex {
		if got := PatternToRegex(pattern); got != want {
			t.Errorf("PatternToRegex(%q): got %q, want %q", pattern, got, want)
		}
	}

}
