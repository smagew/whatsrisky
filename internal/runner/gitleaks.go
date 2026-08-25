package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/smagew/whatsrisky/internal/exclude"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Gitleaks - hardcoded secrets in the working tree and in git history.
type Gitleaks struct{ binaryRunner }

// NewGitleaks builds the runner.
func NewGitleaks(config Config) *Gitleaks {
	return &Gitleaks{binaryRunner{
		binary: "gitleaks",
		hints: installHints{
			"darwin":  "brew install gitleaks",
			"linux":   "download a release from https://github.com/gitleaks/gitleaks/releases",
			"windows": "scoop install gitleaks",
			"default": "https://github.com/gitleaks/gitleaks/releases",
		},
		config: config,
	}}
}

func (g *Gitleaks) Name() string { return "gitleaks" }

func (g *Gitleaks) Version() string {
	if version := proc.Version(g.binary, "version"); version != "" {
		return "gitleaks " + version
	}
	return ""
}

var (
	versionNumbers = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	// gitleaks logs as "11:07PM INF message"; only the message is worth showing.
	logPrefix = regexp.MustCompile(`(?i)^\d{1,2}:\d{2}(AM|PM)?\s+(INF|WRN|ERR|DBG|TRC)\s+`)

	// Rules that match on shape or entropy alone produce more false positives than
	// provider-specific ones, so they land one notch lower.
	genericRules = map[string]bool{
		"generic-api-key": true, "generic-api-token": true,
		"high-entropy-string": true, "jwt": true, "private-key": true,
	}
	nonProdPath = regexp.MustCompile(
		`(?i)(^|/)(tests?|spec|specs|fixtures?|examples?|samples?|mocks?|__tests__|testdata)(/|$)` +
			`|\.(example|sample|template|dist|md|mdx|rst|txt)$`)
)

func (g *Gitleaks) versionAtLeast(major, minor, patch int) bool {
	match := versionNumbers.FindStringSubmatch(g.Version())
	if len(match) != 4 {
		return false
	}
	have := [3]int{atoi(match[1]), atoi(match[2]), atoi(match[3])}
	want := [3]int{major, minor, patch}
	for i := range have {
		if have[i] != want[i] {
			return have[i] > want[i]
		}
	}
	return true
}

func atoi(text string) int {
	value := 0
	for _, char := range text {
		if char < '0' || char > '9' {
			return value
		}
		value = value*10 + int(char-'0')
	}
	return value
}

// modes decides which passes to run: the working tree, git history, or both.
func (g *Gitleaks) modes() []string {
	if g.config.DiffRange != "" {
		return []string{"git"} // only the commits in the range matter
	}
	switch g.config.GitleaksMode {
	case "dir":
		return []string{"dir"}
	case "git":
		return []string{"git"}
	}
	if isGitRepo(g.config.Target) {
		return []string{"dir", "git"}
	}
	return []string{"dir"}
}

func isGitRepo(dir string) bool {
	result, err := proc.Run([]string{"git", "rev-parse", "--is-inside-work-tree"},
		proc.Options{Dir: dir, Timeout: gitProbeTimeout})
	return err == nil && result.ExitCode == 0 && strings.TrimSpace(result.Stdout) == "true"
}

// excludeConfig writes the allowlist gitleaks needs: it has no --exclude flag, so
// paths are excluded through a config.
func (g *Gitleaks) excludeConfig() (string, error) {
	var patterns []string
	for _, pattern := range g.config.Exclude {
		if regex := exclude.PatternToRegex(pattern); regex != "" {
			patterns = append(patterns, regex)
		}
	}
	if len(patterns) == 0 {
		return "", nil
	}
	const triple = "'''"
	lines := []string{
		"[extend]", "useDefault = true", "",
		"[[allowlists]]", `description = "whatsrisky excludes"`, "paths = [",
	}
	for _, pattern := range patterns {
		lines = append(lines, "  "+triple+pattern+triple+",")
	}
	lines = append(lines, "]")

	path := filepath.Join(g.config.WorkDir, "gitleaks-excludes.toml")
	return path, WriteFile(path, strings.Join(lines, "\n")+"\n")
}

func (g *Gitleaks) argv(mode, report, configPath string) []string {
	common := []string{
		"--report-format", "json", "--report-path", report,
		"--exit-code", "0", "--no-banner", "--redact",
	}
	var scoped []string
	if mode == "git" && g.config.DiffRange != "" {
		scoped = append(scoped, "--log-opts", g.config.DiffRange)
	}
	if configPath != "" {
		scoped = append(scoped, "--config", configPath)
	}
	if g.versionAtLeast(8, 19, 0) {
		return append(append([]string{g.binary, mode, "."}, common...), scoped...)
	}
	argv := append(append([]string{g.binary, "detect", "--source", "."}, common...), scoped...)
	if mode == "dir" {
		argv = append(argv, "--no-git")
	}
	return argv
}

type gitleaksFinding struct {
	Description string  `json:"Description"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	Match       string  `json:"Match"`
	File        string  `json:"File"`
	Commit      string  `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
	Author      string  `json:"Author"`
	Email       string  `json:"Email"`
	Date        string  `json:"Date"`
	RuleID      string  `json:"RuleID"`
	Fingerprint string  `json:"Fingerprint"`
}

func (g *Gitleaks) Scan(progress func(string)) (Outcome, error) {
	config := g.config
	configPath, err := g.excludeConfig()
	if err != nil {
		return Outcome{}, fmt.Errorf("writing the gitleaks allowlist: %w", err)
	}

	var findings []model.Finding
	var commands, stderrs []string
	seen := map[string]bool{}

	for _, mode := range g.modes() {
		report := filepath.Join(config.WorkDir, "gitleaks-"+mode+".json")
		_ = os.Remove(report)
		where := "working tree"
		if mode == "git" {
			where = "git history"
		}
		progress("scanning " + where)

		result, err := proc.Run(g.argv(mode, report, configPath), proc.Options{
			Dir:     config.Target,
			Timeout: config.GitleaksTimeout,
			OnStderr: func(line string) {
				progress(logPrefix.ReplaceAllString(strings.TrimSpace(line), ""))
			},
		})
		if err != nil {
			return Outcome{}, err
		}
		commands = append(commands, result.Command())
		stderrs = append(stderrs, result.Stderr)

		raw, readErr := os.ReadFile(report)
		if readErr != nil {
			if result.ExitCode != 0 && result.ExitCode != 1 {
				stderrs = append(stderrs, fmt.Sprintf("[whatsrisky] gitleaks %s exit %d", mode, result.ExitCode))
			}
			continue
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}
		var entries []gitleaksFinding
		if err := json.Unmarshal(raw, &entries); err != nil {
			stderrs = append(stderrs, fmt.Sprintf("[whatsrisky] unparsable gitleaks %s report: %v", mode, err))
			continue
		}
		for _, entry := range entries {
			finding := g.toFinding(entry, mode)
			if seen[finding.Fingerprint()] {
				continue
			}
			seen[finding.Fingerprint()] = true
			findings = append(findings, finding)
		}
	}
	if len(commands) == 0 {
		return Outcome{}, fmt.Errorf("gitleaks did not run")
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(commands, " && "),
		Stderr:   strings.Join(stderrs, "\n"),
	}, nil
}

// toFinding maps a gitleaks hit onto the shared scale. gitleaks has no severity of
// its own, so this is where one is assigned - and where the reasoning lives.
func (g *Gitleaks) toFinding(entry gitleaksFinding, mode string) model.Finding {
	rel := Relative(g.config.Target, entry.File)
	severity := model.Critical
	if genericRules[entry.RuleID] {
		severity = model.High
	}
	if rel != "" && nonProdPath.MatchString(rel) {
		if severity == model.Critical {
			severity = model.High
		} else {
			severity = model.Medium
		}
	}

	where := "working tree"
	category := "Secret/working-tree"
	if entry.Commit != "" {
		where = "git history"
		category = "Secret/git-history"
	}
	detail := []string{
		fmt.Sprintf("gitleaks rule `%s` matched a likely credential in the %s.", entry.RuleID, where),
		"Description: " + entry.Description,
	}
	if entry.Commit != "" {
		commit := entry.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		detail = append(detail, fmt.Sprintf("Commit %s by %s <%s> on %s",
			commit, orText(entry.Author, "?"), orText(entry.Email, "?"), orText(entry.Date, "?")))
	}
	if entry.Entropy != 0 {
		detail = append(detail, fmt.Sprintf("Entropy: %g", entry.Entropy))
	}

	finding := model.Finding{
		Tool:            "gitleaks",
		Severity:        severity,
		Title:           model.Truncate("Hardcoded secret: "+orText(entry.RuleID, "unknown rule"), 140),
		Description:     strings.Join(detail, "\n"),
		ScannerCategory: category,
		RuleID:          entry.RuleID,
		File:            rel,
		Line:            entry.StartLine,
		EndLine:         entry.EndLine,
		CWE:             []string{"CWE-798"},
		Remediation: "1) Treat the credential as compromised and rotate it at the provider. " +
			"2) Remove it from the source and load it from a secret manager/env var. " +
			"3) If it is in git history, purge it (git filter-repo / BFG) and force-push. " +
			"4) Add a pre-commit gitleaks hook to prevent recurrence.",
		Snippet: model.Truncate(entry.Match, 240),
		Pass:    mode,
		Raw:     map[string]string{"mode": mode, "commit": entry.Commit, "fingerprint": entry.Fingerprint},
	}
	finding.Normalize()
	return finding
}
