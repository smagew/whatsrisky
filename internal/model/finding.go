package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Status is where a finding stands relative to the previous scan.
const (
	StatusNew          = "new"          // absent from the baseline
	StatusOpen         = "open"         // present in both
	StatusResolved     = "resolved"     // was present, is gone; carried over so it can be shown
	StatusReintroduced = "reintroduced" // was resolved in the baseline, back again
	StatusAccepted     = "accepted"     // a human decided to live with it
)

// AllStatuses is every status; ActiveStatuses is what still counts against the
// project. A resolved finding is history and an accepted one is a decision
// already taken: both stay visible, neither inflates the counts, the verdict or
// the exit code.
var (
	AllStatuses    = []string{StatusNew, StatusOpen, StatusResolved, StatusReintroduced, StatusAccepted}
	ActiveStatuses = []string{StatusNew, StatusOpen, StatusReintroduced}
)

// Source is the kind of artifact a finding lives in - the axis that makes
// "only the dependency problems" one filter instead of a mental exercise.
const (
	SourceCode       = "source-code"
	SourceDependency = "dependency-manifest"
	SourceGitHistory = "git-history"
	SourceIaC        = "iac"
	SourceContainer  = "container"
	SourceCI         = "ci-config"
	// SourceNetwork is a live address a network or perimeter scan looked at, as
	// opposed to a file on disk. surface, testssl, nuclei, zap, ffuf and llm-recon
	// all report against it.
	SourceNetwork = "live-target"
)

// networkTools produce findings about a live address, not a file. Listed here in
// the base package because the source of a finding is a model concern; kept in step
// with scan.NetTools by hand (a small, rarely-changing set).
var networkTools = map[string]bool{
	"surface": true, "testssl": true, "nuclei": true,
	"zap": true, "ffuf": true, "llm-recon": true,
}

var (
	containerFile = regexp.MustCompile(`(?i)(^|/)(dockerfile|containerfile)|docker-compose|compose\.ya?ml`)
	iacFile       = regexp.MustCompile(`(?i)\.(tf|tfvars|hcl)$|(^|/)(k8s|kubernetes|helm|charts|manifests)/`)
	ciFile        = regexp.MustCompile(`(?i)(^|/)\.(github|gitlab|circleci)/|(^|/)(jenkinsfile|\.travis\.yml|azure-pipelines\.ya?ml)`)
)

// InferSource decides which artifact class a finding belongs to.
func InferSource(tool, pass, file string) string {
	if networkTools[tool] {
		return SourceNetwork
	}
	if tool == "gitleaks" {
		if pass == "git" {
			return SourceGitHistory
		}
		return SourceCode
	}
	if tool == "trivy" && pass == "vuln" {
		return SourceDependency
	}
	switch {
	case ciFile.MatchString(file):
		return SourceCI
	case containerFile.MatchString(file):
		return SourceContainer
	case iacFile.MatchString(file):
		return SourceIaC
	case tool == "trivy" && pass == "misconfig":
		return SourceIaC
	}
	return SourceCode
}

// Detector records who found a finding. Provider and Model are empty for local
// scanners and carry the AI backend's vendor and model otherwise, which is what
// makes "group by who found it" a real axis.
type Detector struct {
	Tool     string `json:"tool"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Pass     string `json:"pass"`
}

// Finding is one normalized security finding, whatever tool produced it.
type Finding struct {
	Tool             string
	Severity         Severity
	Title            string
	Description      string
	ScannerCategory  string // the scanner's own words, kept for traceability
	Category         string // the normalized vocabulary entry
	Source           string
	RuleID           string
	File             string
	Line             int
	EndLine          int
	CWE              []string
	OWASP            []string
	References       []string
	Remediation      string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Confidence       string
	Snippet          string
	CVSS             string
	Provider         string
	Model            string
	Pass             string
	Status           string
	FirstSeen        string
	LastSeen         string
	MovedFrom        string
	Raw              map[string]string
}

// Normalize sanitizes the text fields and fills in what is derived. Every runner
// calls it before handing a finding on, so the derivation happens in one place.
func (f *Finding) Normalize() {
	f.Tool = CleanText(f.Tool)
	f.Title = CleanText(f.Title)
	f.Description = CleanText(f.Description)
	f.ScannerCategory = CleanText(f.ScannerCategory)
	f.RuleID = CleanText(f.RuleID)
	f.File = CleanText(f.File)
	f.Remediation = CleanText(f.Remediation)
	f.Package = CleanText(f.Package)
	f.InstalledVersion = CleanText(f.InstalledVersion)
	f.FixedVersion = CleanText(f.FixedVersion)
	f.Confidence = CleanText(f.Confidence)
	f.Snippet = CleanText(f.Snippet)
	f.CVSS = CleanText(f.CVSS)
	for i, value := range f.CWE {
		f.CWE[i] = CleanText(value)
	}
	for i, value := range f.OWASP {
		f.OWASP[i] = CleanText(value)
	}
	for i, value := range f.References {
		f.References[i] = CleanText(value)
	}
	if f.Status == "" {
		f.Status = StatusOpen
	}
	// Source before Category: the artifact is one of the category's inputs.
	if f.Source == "" {
		f.Source = InferSource(f.Tool, f.Pass, f.File)
	}
	if f.Category == "" {
		f.Category = Classify(f.CWE, f.ScannerCategory, f.RuleID, f.Title, f.Source)
	}
}

// IsActive reports whether this finding still counts against the project.
func (f Finding) IsActive() bool {
	for _, status := range ActiveStatuses {
		if f.Status == status {
			return true
		}
	}
	return false
}

// Location is the human-readable "where".
func (f Finding) Location() string {
	switch {
	case f.File != "" && f.Line > 0:
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	case f.File != "":
		return f.File
	case f.Package != "":
		return f.Package
	}
	return "-"
}

// Directory is the grouping key for "by directory".
func (f Finding) Directory() string {
	if f.File == "" {
		if f.Package != "" {
			return "(dependencies)"
		}
		return "(no file)"
	}
	if !strings.Contains(f.File, "/") {
		return "(root)"
	}
	return path.Dir(f.File)
}

// CategoryLabel is the display name of the normalized category.
func (f Finding) CategoryLabel() string { return CategoryLabel(f.Category) }

// Detector is who found it.
func (f Finding) Detector() Detector {
	return Detector{Tool: f.Tool, Provider: f.Provider, Model: f.Model, Pass: f.Pass}
}

func digest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

func (f Finding) ruleOrTitle() string {
	if f.RuleID != "" {
		return f.RuleID
	}
	return f.Title
}

func (f Finding) lineText() string {
	if f.Line > 0 {
		return strconv.Itoa(f.Line)
	}
	return ""
}

// Fingerprint is exact identity: it changes when anything about the location does.
func (f Finding) Fingerprint() string {
	return digest(f.Tool, f.ruleOrTitle(), f.File, f.lineText(), f.Package, f.InstalledVersion)
}

// ContentKey survives the code moving, within a file or between files, because it
// is keyed on the evidence rather than the location. Dependency findings have no
// evidence to hash, so they fall back to the package identity - which is what
// actually identifies them.
func (f Finding) ContentKey() string {
	evidence := EvidenceOf(f.Snippet)
	if evidence == "" {
		parts := make([]string, 0, 2)
		for _, value := range []string{f.Package, f.InstalledVersion} {
			if value != "" {
				parts = append(parts, value)
			}
		}
		evidence = strings.Join(parts, " ")
		if evidence == "" {
			evidence = f.Title
		}
	}
	return digest(f.Tool, f.ruleOrTitle(), evidence)
}

// MatchKey survives a line drifting inside the same file.
func (f Finding) MatchKey() string {
	return digest(f.Tool, f.ruleOrTitle(), f.File, f.Package)
}
