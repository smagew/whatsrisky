package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/smagew/whatsrisky/internal/scan"
)

func configHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	return home
}

func writeConfig(t *testing.T, home string, document any) {
	t.Helper()
	dir := filepath.Join(home, "whatsrisky")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestASavedProfileIsWhatTheNextLaunchStartsFrom(t *testing.T) {
	configHome(t)
	options := scan.NewOptions()
	options.Path = "/some/project"
	options.MinSeverity = "HIGH"
	options.Tools = []string{"semgrep"}
	if err := SaveProfile("nightly", options); err != nil {
		t.Fatalf("saving: %v", err)
	}

	restored, active := StartupOptions()
	if active != "nightly" {
		t.Errorf("active profile %q", active)
	}
	if restored.MinSeverity != "HIGH" || len(restored.Tools) != 1 {
		t.Errorf("the profile was not restored: %+v", restored)
	}
	// The target stays where you were pointing, taken from the last run.
	if restored.Path != "/some/project" {
		t.Errorf("path %q", restored.Path)
	}
}

func TestAProfileDoesNotCarryTheTargetOrTheDiff(t *testing.T) {
	// A profile says HOW to scan; what to scan is per-invocation. Reusing one on
	// another project used to drag the old path, range and output file along.
	configHome(t)
	options := scan.NewOptions()
	options.Path = "/old/project"
	options.Out = "/old/report.html"
	options.Diff = "HEAD~1..HEAD"
	options.Baseline = "/old/b.json"
	options.OutDir = "/reports"
	options.MinSeverity = "HIGH"
	if err := SaveProfile("ci", options); err != nil {
		t.Fatalf("saving: %v", err)
	}

	stored, ok := LoadProfile("ci")
	if !ok {
		t.Fatal("the profile is missing")
	}
	for name, value := range map[string]string{
		"path": stored.Path, "out": stored.Out, "diff": stored.Diff, "baseline": stored.Baseline,
	} {
		if value != "" {
			t.Errorf("%s should not be stored, got %q", name, value)
		}
	}
	if stored.OutDir != "/reports" {
		t.Errorf("where reports go is a setting: %q", stored.OutDir)
	}
	if stored.MinSeverity != "HIGH" {
		t.Errorf("min severity %q", stored.MinSeverity)
	}
}

func TestAPythonWrittenConfigKeepsWorking(t *testing.T) {
	// The file on disk is the compatibility surface: nobody re-creates their
	// profiles because the tool changed language.
	home := configHome(t)
	writeConfig(t, home, map[string]any{
		"version":        3,
		"active_profile": "os",
		"last":           map[string]any{"path": "/p", "formats": []string{"html", "json"}},
		"profiles": map[string]any{
			"os": map[string]any{
				"tools": []string{"semgrep", "trivy", "gitleaks"},
				// The Python default set; docx is gone and must not resurface.
				"formats":      []string{"html", "md", "json"},
				"fail_on":      "high",
				"min_severity": "HIGH",
				"exclude":      []string{"legacy"},
				// A key this version does not know must not break the read.
				"some_future_setting": true,
			},
		},
	})

	if names := ProfileNames(); len(names) != 1 || names[0] != "os" {
		t.Fatalf("profiles: %v", names)
	}
	options, ok := LoadProfile("os")
	if !ok {
		t.Fatal("the profile did not load")
	}
	if options.FailOn != "high" || options.MinSeverity != "HIGH" {
		t.Errorf("settings lost: %+v", options)
	}
	if len(options.Exclude) != 1 || options.Exclude[0] != "legacy" {
		t.Errorf("exclusions lost: %v", options.Exclude)
	}
	// A key the file did not carry must come from the defaults, not the zero value.
	if options.Timeout != scan.NewOptions().Timeout || options.Jobs != scan.NewOptions().Jobs {
		t.Errorf("defaults were not applied: timeout=%d jobs=%d", options.Timeout, options.Jobs)
	}
	if _, active := StartupOptions(); active != "os" {
		t.Errorf("active profile %q", active)
	}
}

func TestAnOldConfigIsMigratedInSteps(t *testing.T) {
	home := configHome(t)
	writeConfig(t, home, map[string]any{
		// No version at all: the very first shape.
		"last": map[string]any{"path": "/p", "formats": []string{"docx", "md", "json"}},
		"profiles": map[string]any{
			"os": map[string]any{
				"formats": []string{"json"}, // no html: the View button had nothing to open
				"path":    "/old/project",   // and the path followed the profile around
				"diff":    "HEAD~1..HEAD",
				"out_dir": "/reports",
			},
		},
	})

	profile, ok := LoadProfile("os")
	if !ok {
		t.Fatal("the profile did not survive the migration")
	}
	if !containsString(profile.Formats, "html") {
		t.Errorf("html was not added back: %v", profile.Formats)
	}
	if containsString(profile.Formats, "docx") {
		t.Error("docx must not survive; it no longer exists")
	}
	if profile.Path != "" || profile.Diff != "" {
		t.Errorf("per-run fields were not stripped: path=%q diff=%q", profile.Path, profile.Diff)
	}
	if profile.OutDir != "/reports" {
		t.Errorf("a real setting was lost: %q", profile.OutDir)
	}

	// The migration is recorded, so it happens once.
	raw, err := os.ReadFile(filepath.Join(home, "whatsrisky", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct{ Version int }
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Version != Version {
		t.Errorf("version on disk %d, want %d", stored.Version, Version)
	}
}

func TestTheLastRunIsUsedWhenNoProfileIsActive(t *testing.T) {
	configHome(t)
	options := scan.NewOptions()
	options.Jobs = 2
	options.Path = "/p"
	if err := SaveLast(options); err != nil {
		t.Fatalf("saving: %v", err)
	}
	restored, active := StartupOptions()
	if active != "" {
		t.Errorf("no profile should be active, got %q", active)
	}
	if restored.Jobs != 2 {
		t.Errorf("jobs %d", restored.Jobs)
	}
}

func TestDeletingAProfileClearsItAsActive(t *testing.T) {
	configHome(t)
	if err := SaveProfile("gone", scan.NewOptions()); err != nil {
		t.Fatal(err)
	}
	if ActiveProfile() != "gone" {
		t.Fatalf("active %q", ActiveProfile())
	}
	if !DeleteProfile("gone") {
		t.Error("deleting should report success")
	}
	if ActiveProfile() != "" {
		t.Errorf("still active: %q", ActiveProfile())
	}
	if DeleteProfile("gone") {
		t.Error("deleting twice should report failure")
	}
}

func TestACorruptConfigFallsBackToTheDefaults(t *testing.T) {
	home := configHome(t)
	dir := filepath.Join(home, "whatsrisky")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if names := ProfileNames(); len(names) != 0 {
		t.Errorf("profiles from a corrupt file: %v", names)
	}
	options, active := StartupOptions()
	if active != "" || options.Timeout != scan.NewOptions().Timeout {
		t.Errorf("a corrupt file must not break a launch: %+v", options)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
