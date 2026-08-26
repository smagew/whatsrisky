package config

import (
	"bytes"
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

func TestAFolderWithNoSettingsOfItsOwnStartsFromTheDefaults(t *testing.T) {
	// The defect: settings lived in one shared file, so running whatsrisky in a
	// second project came up showing the first project's folder and profile.
	configHome(t)
	first := t.TempDir()
	settings := scan.NewOptions()
	settings.MinSeverity = "HIGH"
	settings.Tools = []string{"semgrep"}
	if err := SaveProject(first, settings); err != nil {
		t.Fatalf("saving the first project: %v", err)
	}
	if err := SaveProfile("nightly", settings); err != nil {
		t.Fatalf("saving a named profile: %v", err)
	}
	if err := SetActiveProfile("nightly"); err != nil {
		t.Fatalf("marking it active: %v", err)
	}

	second := t.TempDir()
	restored, active := StartupOptions(second)
	if active != "" {
		t.Errorf("a folder with no settings reports %q", active)
	}
	if restored.Path != second {
		t.Errorf("path %q, want the folder we are in", restored.Path)
	}
	if restored.MinSeverity != scan.NewOptions().MinSeverity {
		t.Errorf("the other project's severity floor came along: %q", restored.MinSeverity)
	}
	if len(restored.Tools) != len(scan.NewOptions().Tools) {
		t.Errorf("the other project's scanners came along: %v", restored.Tools)
	}
}

func TestAFolderWithItsOwnSettingsUsesThem(t *testing.T) {
	configHome(t)
	project := t.TempDir()
	settings := scan.NewOptions()
	settings.MinSeverity = "HIGH"
	settings.Tools = []string{"semgrep"}
	settings.Offline = true
	if err := SaveProject(project, settings); err != nil {
		t.Fatalf("saving: %v", err)
	}

	restored, active := StartupOptions(project)
	if active != ProjectFile {
		t.Errorf("the launch reports %q, want %q", active, ProjectFile)
	}
	if restored.MinSeverity != "HIGH" || len(restored.Tools) != 1 || !restored.Offline {
		t.Errorf("the folder's own settings were not used: %+v", restored)
	}
	if restored.Path != project {
		t.Errorf("path %q, want %q", restored.Path, project)
	}
}

func TestAProjectFileNeverCarriesAPathOrARange(t *testing.T) {
	// A file that stored a path would hand the next reader someone else's folder,
	// which is the whole defect in miniature. The settings are for the folder they
	// were found in.
	configHome(t)
	project := t.TempDir()
	settings := scan.NewOptions()
	settings.Path = "/somewhere/else"
	settings.Diff = "main..HEAD"
	settings.Baseline = "/old/report.json"
	settings.Out = "/tmp/out.json"
	settings.FailOn = "high"
	if err := SaveProject(project, settings); err != nil {
		t.Fatalf("saving: %v", err)
	}

	raw, err := os.ReadFile(ProjectPath(project))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range perRunFields {
		if bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Errorf("the file stores %q, which belongs to one run", field)
		}
	}
	restored, _ := StartupOptions(project)
	if restored.Path != project {
		t.Errorf("path %q, want the folder the file was found in", restored.Path)
	}
	if restored.Diff != "" || restored.Baseline != "" || restored.Out != "" {
		t.Errorf("a per-run field survived: %+v", restored)
	}
	if restored.FailOn != "high" {
		t.Errorf("a real setting was lost: %q", restored.FailOn)
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
	// The migration still marks it active for `profiles` to report; a launch no
	// longer starts from it, which is what the per-project file is for.
	if active := ActiveProfile(); active != "os" {
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

func TestTheLastRunIsNotCarriedIntoAnotherFolder(t *testing.T) {
	// Deliberately the opposite of what this used to assert. A remembered run is
	// how one project's folder and settings turned up in another, so a launch now
	// reads the folder it is in and nothing else.
	configHome(t)
	options := scan.NewOptions()
	options.Jobs = 2
	options.Path = "/p"
	if err := SaveLast(options); err != nil {
		t.Fatalf("saving: %v", err)
	}
	elsewhere := t.TempDir()
	restored, active := StartupOptions(elsewhere)
	if active != "" {
		t.Errorf("no settings should be reported, got %q", active)
	}
	if restored.Jobs != scan.NewOptions().Jobs {
		t.Errorf("the last run's jobs came along: %d", restored.Jobs)
	}
	if restored.Path != elsewhere {
		t.Errorf("path %q, want the folder we are in", restored.Path)
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
	options, active := StartupOptions(t.TempDir())
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
