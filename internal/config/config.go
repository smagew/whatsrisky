// Package config is the persisted settings: the last run, named profiles, and
// which one is active.
//
// A profile answers "how do I scan", not "what do I scan". The target path, the
// git range, the baseline and an explicit output file are per-invocation and are
// deliberately not stored: reusing a profile on another project used to drag the
// old project's path along with it.
//
// The file format is the Python implementation's, version and all, so nobody
// re-creates their profiles because the tool changed language.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/smagew/whatsrisky/internal/scan"
)

// Version of the config file on disk. The migrations below run in steps.
const Version = 3

// perRunFields belong to one invocation rather than to a way of scanning.
var perRunFields = []string{"path", "out", "diff", "baseline"}

type file struct {
	Version       int                                   `json:"version"`
	ActiveProfile string                                `json:"active_profile,omitempty"`
	Last          map[string]json.RawMessage            `json:"last,omitempty"`
	Profiles      map[string]map[string]json.RawMessage `json:"profiles,omitempty"`
}

// ProjectFile is what a project's own settings are called. It sits in the folder
// being scanned, so the settings belong to the project rather than to whoever ran
// the tool last - and it can be committed, which is how a team shares one way of
// scanning.
const ProjectFile = ".whatsrisky.json"

// ProjectPath is where a given project keeps its settings.
func ProjectPath(dir string) string { return filepath.Join(dir, ProjectFile) }

// LoadProject reads a project's own settings. The stored path is ignored: the
// settings are for the folder they were found in, and honouring a path written
// somewhere else is exactly how one project came up showing another's.
func LoadProject(dir string) (scan.Options, bool) {
	raw, err := os.ReadFile(ProjectPath(dir))
	if err != nil {
		return scan.NewOptions(), false
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stored); err != nil {
		return scan.NewOptions(), false
	}
	for _, field := range perRunFields {
		delete(stored, field)
	}
	options, ok := decode(stored)
	if !ok {
		return scan.NewOptions(), false
	}
	options.Path = dir
	return options, true
}

// SaveProject writes a project's own settings beside the project. Per-run fields
// are left out: a path, a diff range and a baseline belong to one invocation, and
// a file that carried them would hand the next reader someone else's run.
func SaveProject(dir string, options scan.Options) error {
	stored := encode(options)
	for _, field := range perRunFields {
		delete(stored, field)
	}
	stored["version"] = json.RawMessage(strconv.Itoa(Version))
	raw, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ProjectPath(dir), append(raw, '\n'), 0o600)
}

// Path is where the shared settings live: the named profiles, which are asked for
// by name and are deliberately not per-project.
func Path() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".config", "whatsrisky", "config.json")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "whatsrisky", "config.json")
}

func load() file {
	raw, err := os.ReadFile(Path())
	if err != nil {
		return file{Version: Version}
	}
	var stored file
	if json.Unmarshal(raw, &stored) != nil {
		return file{Version: Version}
	}
	if migrate(&stored) {
		_ = save(stored) // migrate once, not on every read
	}
	return stored
}

// migrate brings an older file forward, one step at a time.
func migrate(stored *file) bool {
	if stored.Version >= Version {
		return false
	}
	if stored.Version < 2 {
		// The HTML view did not exist in v1, so stored formats have none - which
		// leaves the "View report" button with nothing to open.
		addHTML(stored.Last)
		for _, profile := range stored.Profiles {
			addHTML(profile)
		}
	}
	if stored.Version < 3 {
		// v1 and v2 profiles stored the project path and the git range, which then
		// followed the profile onto every other project.
		for _, profile := range stored.Profiles {
			for _, field := range perRunFields {
				delete(profile, field)
			}
		}
	}
	stored.Version = Version
	return true
}

func addHTML(options map[string]json.RawMessage) {
	if options == nil {
		return
	}
	raw, ok := options["formats"]
	if !ok {
		return
	}
	var formats []string
	if json.Unmarshal(raw, &formats) != nil {
		return
	}
	for _, format := range formats {
		if format == "html" {
			return
		}
	}
	present := map[string]bool{"html": true}
	for _, format := range formats {
		present[format] = true
	}
	var updated []string
	for _, format := range scan.FormatChoices {
		if present[format] {
			updated = append(updated, format)
		}
	}
	if encoded, err := json.Marshal(updated); err == nil {
		options["formats"] = encoded
	}
}

func save(stored file) error {
	stored.Version = Version
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func decode(stored map[string]json.RawMessage) (scan.Options, bool) {
	if stored == nil {
		return scan.Options{}, false
	}
	body, err := json.Marshal(stored)
	if err != nil {
		return scan.Options{}, false
	}
	// Start from the defaults so a missing key means "the default", not the zero value.
	options := scan.NewOptions()
	if json.Unmarshal(body, &options) != nil {
		return scan.Options{}, false
	}
	return options, true
}

func encode(options scan.Options) map[string]json.RawMessage {
	body, err := json.Marshal(options)
	if err != nil {
		return nil
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return out
}

// LoadLast is what the interactive form remembered.
func LoadLast() (scan.Options, bool) { return decode(load().Last) }

// SaveLast records the form. Only the UI calls this: a scripted CLI run must not
// decide what the interactive defaults are.
func SaveLast(options scan.Options) error {
	stored := load()
	stored.Last = encode(options)
	return save(stored)
}

// ProfileNames lists the saved profiles.
func ProfileNames() []string {
	stored := load()
	names := make([]string, 0, len(stored.Profiles))
	for name := range stored.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LoadProfile reads one profile.
func LoadProfile(name string) (scan.Options, bool) {
	stored := load()
	if stored.Profiles == nil {
		return scan.Options{}, false
	}
	return decode(stored.Profiles[name])
}

// SaveProfile stores the way of scanning, and makes it the one the next launch
// starts from.
func SaveProfile(name string, options scan.Options) error {
	encoded := encode(options)
	for _, field := range perRunFields {
		delete(encoded, field)
	}
	stored := load()
	if stored.Profiles == nil {
		stored.Profiles = map[string]map[string]json.RawMessage{}
	}
	stored.Profiles[name] = encoded
	stored.ActiveProfile = name
	stored.Last = encode(options)
	return save(stored)
}

// DeleteProfile removes one, and clears it as active.
func DeleteProfile(name string) bool {
	stored := load()
	if stored.Profiles == nil {
		return false
	}
	if _, ok := stored.Profiles[name]; !ok {
		return false
	}
	delete(stored.Profiles, name)
	if stored.ActiveProfile == name {
		stored.ActiveProfile = ""
	}
	return save(stored) == nil
}

// ActiveProfile is the profile a launch starts from, if it still exists.
func ActiveProfile() string {
	stored := load()
	if stored.ActiveProfile == "" || stored.Profiles == nil {
		return ""
	}
	if _, ok := stored.Profiles[stored.ActiveProfile]; !ok {
		return ""
	}
	return stored.ActiveProfile
}

// SetActiveProfile records which profile is in use.
func SetActiveProfile(name string) error {
	stored := load()
	stored.ActiveProfile = name
	return save(stored)
}

// StartupOptions is what a fresh launch starts from.
//
// The project's own file wins, and nothing else is consulted: launched in a folder
// with no settings of its own, the answer is the defaults. Carrying the last run
// forward is what made whatsrisky come up in one project showing another project's
// folder and another project's profile.
func StartupOptions(dir string) (scan.Options, string) {
	if options, ok := LoadProject(dir); ok {
		return options, ProjectFile
	}
	options := scan.NewOptions()
	options.Path = dir
	return options, ""
}
