package runner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Nuclei runs ProjectDiscovery's template scanner against a live address: known
// CVEs, misconfigurations and exposures, each matched by a community template.
//
// By default it excludes the templates that send attack-shaped traffic - fuzzing
// and injection - so a run only checks for things that can be told apart by a
// normal request. NetActive lifts that exclusion, and the report says which it
// was.
type Nuclei struct {
	binaryRunner
}

// NewNuclei builds the runner.
func NewNuclei(config Config) *Nuclei {
	return &Nuclei{binaryRunner: binaryRunner{
		binary: "nuclei",
		hints: installHints{
			"darwin":  "brew install nuclei",
			"linux":   "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest, or see https://github.com/projectdiscovery/nuclei",
			"windows": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			"default": "https://github.com/projectdiscovery/nuclei#install-nuclei",
		},
		config: config,
	}}
}

func (n *Nuclei) Name() string { return "nuclei" }

func (n *Nuclei) Version() string { return proc.Version(n.binary, "-version") }

// argv is the command line. Kept apart from Scan so a test can assert that the
// observational run really does exclude the attacking templates.
func (n *Nuclei) argv() []string {
	return n.argvWith("")
}

// argvWith builds the command line. When listPath is set, nuclei reads its targets
// from that file (the seed plus a katana crawl); otherwise it scans the one target.
func (n *Nuclei) argvWith(listPath string) []string {
	args := []string{n.binary, "-jsonl", "-silent", "-no-color", "-disable-update-check"}
	if listPath != "" {
		args = append(args, "-list", listPath)
	} else {
		args = append(args, "-target", n.config.Target)
	}
	if !n.config.NetActive {
		// Observational: leave out the template classes that send payloads. This is
		// the whole difference between looking and probing.
		args = append(args, "-exclude-tags", "fuzz,fuzzing,dast,intrusive,injection,sqli,xss,rce,lfi,ssrf")
	}
	return args
}

// nucleiEvent is one line of nuclei's JSONL output, the fields we use.
type nucleiEvent struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Remediation    string   `json:"remediation"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
}

func (n *Nuclei) Scan(progress func(string)) (Outcome, error) {
	mode := "observational"
	if n.config.NetActive {
		mode = "active"
	}
	progress("running nuclei templates (" + mode + ") against " + n.config.Target)

	timeout := n.config.NucleiTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	argv := n.argv()
	if len(n.config.ExtraTargets) > 0 {
		listPath := filepath.Join(n.config.WorkDir, "nuclei-targets.txt")
		if err := WriteFile(listPath, strings.Join(n.allTargets(), "\n")); err == nil {
			argv = n.argvWith(listPath)
		}
	}
	result, err := proc.Run(argv, proc.Options{Timeout: timeout, OnStderr: nucleiProgress(progress)})
	// nuclei exits non-zero on some template errors while still producing valid
	// findings, so the output is parsed regardless and the error is only reported
	// if nothing came back at all.
	findings := n.parse(result.Stdout, progress)
	if err != nil && len(findings) == 0 && strings.TrimSpace(result.Stdout) == "" {
		return Outcome{Stderr: result.Stderr}, fmt.Errorf("nuclei: %w", err)
	}

	note := "nuclei ran observational templates only; templates that send payloads (fuzzing, injection) were excluded — pass --net-active to include them"
	if n.config.NetActive {
		note = "nuclei ran with --net-active: templates that send attack-shaped traffic were included"
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(argv, " "),
		Stderr:   result.Stderr,
		Note:     note,
	}, nil
}

func (n *Nuclei) parse(output string, progress func(string)) []model.Finding {
	var findings []model.Finding
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event nucleiEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		location := event.MatchedAt
		if location == "" {
			location = event.Host
		}
		title := event.Info.Name
		if title == "" {
			title = event.TemplateID
		}
		references := event.Info.Reference
		for _, cve := range event.Info.Classification.CVEID {
			title = strings.TrimSpace(title)
			if cve != "" && !strings.Contains(title, cve) {
				title = title + " (" + cve + ")"
			}
		}
		finding := model.Finding{
			Tool:            "nuclei",
			Severity:        nucleiSeverity(event.Info.Severity),
			Title:           model.Truncate(title, 140),
			Description:     model.Truncate(event.Info.Description, 4000),
			ScannerCategory: strings.Join(event.Info.Tags, ","),
			RuleID:          "nuclei:" + event.TemplateID,
			File:            location,
			CWE:             event.Info.Classification.CWEID,
			References:      references,
			Remediation:     model.Truncate(event.Info.Remediation, 2000),
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	if progress != nil {
		progress(fmt.Sprintf("nuclei: %d finding(s)", len(findings)))
	}
	return findings
}

// allTargets is the seed plus any crawled endpoints, de-duplicated.
func (n *Nuclei) allTargets() []string {
	seen := map[string]bool{}
	var out []string
	for _, url := range append([]string{n.config.Target}, n.config.ExtraTargets...) {
		if url != "" && !seen[url] {
			seen[url] = true
			out = append(out, url)
		}
	}
	return out
}

// nucleiProgress forwards the lines nuclei writes to stderr as it works.
func nucleiProgress(progress func(string)) func(string) {
	return func(line string) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[INF]") || strings.Contains(line, "Templates loaded") {
			progress(strings.TrimPrefix(line, "[INF] "))
		}
	}
}

// nucleiSeverity maps nuclei's own levels onto the shared scale. "unknown" is
// treated as info rather than dropped: a match we cannot rank is still a match.
func nucleiSeverity(level string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	case "low":
		return model.Low
	default:
		return model.Info
	}
}
