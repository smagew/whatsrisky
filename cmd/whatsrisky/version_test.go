package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The version is a release contract: it is stamped into every report, so a stale
// one makes a report claim it came from software that never wrote it. The release
// workflow refuses to publish when the tag and this disagree.

var semver = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
		`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

func TestTheVersionIsSemver(t *testing.T) {
	if !semver.MatchString(Version) {
		t.Errorf("%q is not a semantic version", Version)
	}
}

func TestTheChangelogDocumentsThisVersion(t *testing.T) {
	body, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatalf("reading the changelog: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "## ["+Version+"]") {
		t.Errorf("CHANGELOG.md has no section for %s", Version)
	}
	if !strings.Contains(text, "## [Unreleased]") {
		t.Error("keep an Unreleased section open for the next change")
	}
}

func TestTheMakefileReadsTheVersionFromTheSource(t *testing.T) {
	// The release workflow compares the tag against `make print-version`, so that
	// extraction has to keep working.
	body, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("reading the makefile: %v", err)
	}
	if !strings.Contains(string(body), "cmd/whatsrisky/main.go") {
		t.Error("the Makefile no longer reads the version from the source")
	}
	if !strings.Contains(string(body), "print-version") {
		t.Error("the release workflow needs a print-version target")
	}
}

func TestTheVersionReachesTheReport(t *testing.T) {
	// The report writer is told the version by main; if that wiring breaks, every
	// report claims to come from "dev".
	body, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatalf("reading scan.go: %v", err)
	}
	if !strings.Contains(string(body), "report.Version = Version") {
		t.Error("the report writer is never told which build produced it")
	}
}
