package scan

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
		Regex     map[string]string `json:"regex"`
		Effective []struct {
			User     []string `json:"user"`
			Defaults bool     `json:"defaults"`
			Expect   []string `json:"expect"`
		} `json:"effective"`
	}
	readGolden(t, "excludes.json", &golden)

	if len(golden.Defaults) != len(DefaultExcludes) {
		t.Errorf("default list size: got %d, reference says %d", len(DefaultExcludes), len(golden.Defaults))
	}
	for i, want := range golden.Defaults {
		if i < len(DefaultExcludes) && DefaultExcludes[i] != want {
			t.Errorf("default %d: got %q, want %q", i, DefaultExcludes[i], want)
		}
	}

	for _, item := range golden.Match {
		if got := PathExcluded(item.Path, item.Patterns); got != item.Expect {
			t.Errorf("PathExcluded(%q, %v): got %v, reference says %v",
				item.Path, item.Patterns, got, item.Expect)
		}
	}

	// gitleaks has no exclude flag, so these regexes are the mechanism.
	for pattern, want := range golden.Regex {
		if got := PatternToRegex(pattern); got != want {
			t.Errorf("PatternToRegex(%q): got %q, want %q", pattern, got, want)
		}
	}

	for _, item := range golden.Effective {
		options := NewOptions()
		options.Exclude = item.User
		options.UseDefaultExcludes = item.Defaults
		got := options.EffectiveExcludes()
		if len(got) != len(item.Expect) {
			t.Fatalf("effective excludes: got %d patterns, reference says %d", len(got), len(item.Expect))
		}
		for i := range got {
			if got[i] != item.Expect[i] {
				t.Errorf("effective exclude %d: got %q, want %q", i, got[i], item.Expect[i])
			}
		}
	}
}

func TestCommandLinesMatchTheReferenceImplementation(t *testing.T) {
	// The equivalent-command panel is what keeps the flags and the form honest, so
	// it has to render exactly as the reference does.
	var golden []struct {
		Options json.RawMessage `json:"options"`
		Expect  string          `json:"expect"`
	}
	readGolden(t, "commands.json", &golden)
	if len(golden) == 0 {
		t.Fatal("no command cases; the parity data is missing")
	}

	for _, item := range golden {
		options := NewOptions()
		if err := json.Unmarshal(item.Options, &options); err != nil {
			t.Fatalf("applying the stored options: %v", err)
		}
		if got := options.Normalized().CommandLine(); got != item.Expect {
			t.Errorf("command line:\n  got  %s\n  want %s", got, item.Expect)
		}
	}
}

func TestOfflineCannotUseTheRegistry(t *testing.T) {
	options := NewOptions()
	options.Offline = true
	if got := options.Normalized().SemgrepConfigs[0]; got != "p/security-audit" {
		t.Errorf("offline semgrep config: got %q", got)
	}

	options.SemgrepConfigs = []string{"p/owasp-top-ten"}
	if got := options.Normalized().SemgrepConfigs[0]; got != "p/owasp-top-ten" {
		t.Errorf("an explicit config must be left alone, got %q", got)
	}
}

func TestClaudeIsStillAcceptedAsAToolName(t *testing.T) {
	options := NewOptions()
	options.Tools = []string{"semgrep", "claude"}
	if got := options.Normalized().Tools; len(got) != 2 || got[1] != "ai" {
		t.Errorf("an old config's tool list must keep working, got %v", got)
	}
}

func TestValidationNamesEveryProblem(t *testing.T) {
	options := NewOptions()
	options.Path = ""
	options.Tools = nil
	options.Formats = nil
	problems := options.Validate(nil)
	if len(problems) != 3 {
		t.Errorf("expected three problems, got %v", problems)
	}

	options = NewOptions()
	options.Path = "/nope"
	if problems := options.Validate(func(string) bool { return false }); len(problems) != 1 {
		t.Errorf("a missing directory is one problem, got %v", problems)
	}
	if problems := options.Validate(func(string) bool { return true }); len(problems) != 0 {
		t.Errorf("a valid setup has none, got %v", problems)
	}
}
