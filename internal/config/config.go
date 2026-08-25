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

// Path is where the settings live.
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
// The active profile wins: a profile you saved is what you meant to come back to.
// Without one, the last run. Without that, the defaults. The target stays where
// you were pointing either way.
func StartupOptions() (scan.Options, string) {
	name := ActiveProfile()
	if name != "" {
		if profile, ok := LoadProfile(name); ok {
			if last, hadLast := LoadLast(); hadLast {
				profile.Path = last.Path
				profile.Out = last.Out
				profile.Diff = last.Diff
				profile.Baseline = last.Baseline
			}
			return profile, name
		}
	}
	if last, ok := LoadLast(); ok {
		return last, ""
	}
	return scan.NewOptions(), ""
}
