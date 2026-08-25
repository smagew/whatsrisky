package runner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Semgrep - static analysis of first-party source code.
type Semgrep struct{ binaryRunner }

// NewSemgrep builds the runner.
func NewSemgrep(config Config) *Semgrep {
	return &Semgrep{binaryRunner{
		binary: "semgrep",
		hints: installHints{
			"darwin":  "brew install semgrep",
			"linux":   "pipx install semgrep  (or: pip install semgrep)",
			"windows": "pipx install semgrep  (WSL recommended)",
			"default": "pipx install semgrep",
		},
		config: config,
	}}
}

func (s *Semgrep) Name() string { return "semgrep" }

func (s *Semgrep) Version() string { return "semgrep " + proc.Version(s.binary) }

// semgrepSeverity: semgrep speaks ERROR/WARNING/INFO, and CRITICAL/HIGH in newer
// versions.
var semgrepSeverity = map[string]model.Severity{
	"CRITICAL": model.Critical,
	"ERROR":    model.High,
	"HIGH":     model.High,
	"WARNING":  model.Medium,
	"MEDIUM":   model.Medium,
	"INFO":     model.Low,
	"LOW":      model.Low,
}

type semgrepOutput struct {
	Results []struct {
		CheckID string             `json:"check_id"`
		Path    string             `json:"path"`
		Start   struct{ Line int } `json:"start"`
		End     struct{ Line int } `json:"end"`
		Extra   struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Fix      string `json:"fix"`
			Metadata struct {
				CWE        json.RawMessage `json:"cwe"`
				OWASP      json.RawMessage `json:"owasp"`
				References json.RawMessage `json:"references"`
				Technology json.RawMessage `json:"technology"`
				Category   string          `json:"category"`
				Confidence string          `json:"confidence"`
				Impact     string          `json:"impact"`
				Shortlink  string          `json:"shortlink"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func (s *Semgrep) argv() []string {
	config := s.config
	// No --quiet: its stderr is where the scan plan and progress live.
	argv := []string{s.binary, "scan", "--json", "--timeout", "60", "--max-target-bytes", "2000000"}
	usesAuto := false
	for _, entry := range config.SemgrepConfigs {
		if entry == "auto" {
			usesAuto = true
		}
	}
	// `--config auto` needs metrics enabled; everything else runs fully offline.
	if usesAuto {
		argv = append(argv, "--metrics", "auto")
	} else {
		argv = append(argv, "--metrics", "off")
	}
	for _, entry := range config.SemgrepConfigs {
		argv = append(argv, "--config", entry)
	}
	for _, pattern := range config.Exclude {
		argv = append(argv, "--exclude", pattern)
	}
	// A diff-scoped run passes the changed files explicitly instead of the tree.
	if len(config.ScopePaths) > 0 {
		argv = append(argv, config.ScopePaths...)
	} else {
		argv = append(argv, ".")
	}
	return argv
}

// noise: semgrep frames its status in box-drawing characters; only the prose is useful.
const noise = "┌┐└┘─│├┤┬┴┼ "

func (s *Semgrep) reportLine(progress func(string)) func(string) {
	return func(line string) {
		text := strings.TrimSpace(line)
		if text == "" || strings.Trim(text, noise) == "" {
			return
		}
		lowered := strings.ToLower(text)
		if strings.HasPrefix(lowered, "language") || strings.Contains(lowered, "--verbose flag") {
			return // column headers and hints, not progress
		}
		for _, key := range []string{"scanning", "rules run", "findings", "ran ", "error", "skipped"} {
			if strings.Contains(lowered, key) {
				progress(text)
				return
			}
		}
	}
}

func (s *Semgrep) Scan(progress func(string)) (Outcome, error) {
	argv := s.argv()
	result, err := proc.Run(argv, proc.Options{
		Dir:      s.config.Target,
		Timeout:  s.config.SemgrepTimeout,
		OnStderr: s.reportLine(progress),
	})
	if err != nil {
		return Outcome{}, err
	}

	var parsed semgrepOutput
	if strings.TrimSpace(result.Stdout) == "" || json.Unmarshal([]byte(result.Stdout), &parsed) != nil {
		detail := result.Stderr
		if detail == "" {
			detail = result.Stdout
		}
		return Outcome{}, fmt.Errorf("semgrep produced no parsable JSON (exit %d): %s",
			result.ExitCode, model.Truncate(detail, 400))
	}

	findings := make([]model.Finding, 0, len(parsed.Results))
	for _, item := range parsed.Results {
		extra := item.Extra
		severity := model.ParseSeverityStrict(extra.Severity, semgrepSeverity, model.Medium)
		// A high-impact, high-confidence ERROR rule is a genuine critical.
		if severity == model.High && strings.EqualFold(extra.Metadata.Impact, "HIGH") {
			confidence := strings.ToUpper(extra.Metadata.Confidence)
			if confidence == "HIGH" || confidence == "" {
				severity = model.Critical
			}
		}

		snippet := extra.Lines
		if strings.TrimSpace(snippet) == "" || strings.TrimSpace(snippet) == "requires login" {
			snippet = ReadSnippet(s.config.Target, item.Path, item.Start.Line, 2)
		}
		remediation := ""
		if extra.Fix != "" {
			remediation = "Suggested fix:\n" + extra.Fix
		}
		if extra.Metadata.Shortlink != "" {
			remediation = strings.TrimSpace(remediation + "\nRule docs: " + extra.Metadata.Shortlink)
		}

		finding := model.Finding{
			Tool:            "semgrep",
			Severity:        severity,
			Title:           semgrepTitle(item.CheckID, extra.Message),
			Description:     model.Truncate(extra.Message, 4000),
			ScannerCategory: semgrepCategory(extra.Metadata.Category),
			RuleID:          item.CheckID,
			File:            Relative(s.config.Target, item.Path),
			Line:            item.Start.Line,
			EndLine:         item.End.Line,
			CWE:             asStrings(extra.Metadata.CWE),
			OWASP:           asStrings(extra.Metadata.OWASP),
			References:      limit(asStrings(extra.Metadata.References), 5),
			Remediation:     remediation,
			Confidence:      extra.Metadata.Confidence,
			Snippet:         model.Truncate(snippet, 1500),
			Pass:            "code",
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	return Outcome{Findings: findings, Command: result.Command(), Stderr: result.Stderr}, nil
}

func semgrepTitle(ruleID, message string) string {
	parts := strings.Split(ruleID, ".")
	short := parts[len(parts)-1]
	short = strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ").Replace(short))
	if short != "" {
		return model.Truncate(short, 120)
	}
	return model.Truncate(message, 120)
}

func semgrepCategory(category string) string {
	if strings.TrimSpace(category) == "" {
		return "SAST"
	}
	return "SAST/" + category
}
