package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Ffuf discovers paths a site does not link to by trying a wordlist against it —
// the way forgotten admin panels and left-over endpoints turn up. That is
// brute-force traffic by nature, so it runs only with --net-active, and it needs a
// wordlist. When either is missing it reports itself as a gap with the reason,
// rather than quietly doing nothing.
type Ffuf struct {
	binaryRunner
}

// NewFfuf builds the runner.
func NewFfuf(config Config) *Ffuf {
	return &Ffuf{binaryRunner: binaryRunner{
		binary: "ffuf",
		hints: installHints{
			"darwin":  "brew install ffuf",
			"linux":   "apt install ffuf, or go install github.com/ffuf/ffuf/v2@latest",
			"windows": "go install github.com/ffuf/ffuf/v2@latest",
			"default": "https://github.com/ffuf/ffuf",
		},
		config: config,
	}}
}

func (f *Ffuf) Name() string { return "ffuf" }

func (f *Ffuf) Version() string { return proc.Version(f.binary, "-V") }

// Available folds the gating into the honest "can this run" answer: the binary,
// the authorization to send attack traffic, and a wordlist. A no with a reason is
// how the report shows a pass that did not run and why.
func (f *Ffuf) Available() bool {
	return f.Installed() && f.config.NetActive && f.wordlist() != ""
}

// Installed reports only whether the binary is present, which is what doctor asks:
// whether ffuf can run at all is a scan-time gate (--net-active, a wordlist), not an
// install question. Folding the gate into Available made an installed ffuf read as
// missing.
func (f *Ffuf) Installed() bool { return proc.Which(f.binary) != "" }

func (f *Ffuf) UnavailableReason() string {
	if proc.Which(f.binary) == "" {
		return f.binaryRunner.UnavailableReason()
	}
	if !f.config.NetActive {
		return "ffuf brute-forces paths, which is attack-shaped traffic; pass --net-active to run it"
	}
	if f.wordlist() == "" {
		return "ffuf needs a wordlist; pass --wordlist PATH (e.g. a SecLists file)"
	}
	return ""
}

// wordlist is the configured list, or a common one if it happens to be present.
func (f *Ffuf) wordlist() string {
	if f.config.Wordlist != "" {
		return f.config.Wordlist
	}
	for _, candidate := range commonWordlists {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

var commonWordlists = []string{
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/usr/share/wordlists/dirb/common.txt",
	"/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
}

func (f *Ffuf) argv(jsonPath string) []string {
	target := strings.TrimRight(f.config.Target, "/") + "/FUZZ"
	return []string{f.binary, "-u", target, "-w", f.wordlist(),
		"-mc", "200,204,301,302,307,401,403,405", "-of", "json", "-o", jsonPath, "-s"}
}

type ffufReport struct {
	Results []struct {
		Input  map[string]string `json:"input"`
		URL    string            `json:"url"`
		Status int               `json:"status"`
		Length int               `json:"length"`
	} `json:"results"`
}

func (f *Ffuf) Scan(progress func(string)) (Outcome, error) {
	jsonPath := filepath.Join(f.config.WorkDir, "ffuf.json")
	timeout := f.config.NucleiTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	progress("ffuf: discovering paths on " + f.config.Target + " with " + filepath.Base(f.wordlist()))

	result, err := proc.Run(f.argv(jsonPath), proc.Options{Timeout: timeout, OnStderr: Progress(progress)})
	raw, readErr := os.ReadFile(jsonPath)
	if readErr != nil {
		if err != nil {
			return Outcome{Stderr: result.Stderr}, fmt.Errorf("ffuf: %w", err)
		}
		return Outcome{Stderr: result.Stderr}, fmt.Errorf("ffuf wrote no results to %s", jsonPath)
	}

	findings, parseErr := f.parse(raw)
	if parseErr != nil {
		return Outcome{Stderr: result.Stderr}, parseErr
	}
	if progress != nil {
		progress(fmt.Sprintf("ffuf: %d path(s)", len(findings)))
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(f.argv(jsonPath), " "),
		Stderr:   result.Stderr,
		Note:     "ffuf brute-forced paths from a wordlist (--net-active); each finding is a path that answered, to look at by hand",
	}, nil
}

func (f *Ffuf) parse(raw []byte) ([]model.Finding, error) {
	var report ffufReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("ffuf JSON: %w", err)
	}
	var findings []model.Finding
	for _, result := range report.Results {
		// A discovered path is a lead, not a hole: info by default, low when the
		// status suggests something guarded is there (401/403).
		severity := model.Info
		if result.Status == 401 || result.Status == 403 {
			severity = model.Low
		}
		finding := model.Finding{
			Tool:            "ffuf",
			Severity:        severity,
			Title:           fmt.Sprintf("Path answers %d: %s", result.Status, pathOf(result.URL)),
			Description:     fmt.Sprintf("%s returned HTTP %d (%d bytes). It is not linked from the site but is reachable; check whether it should be.", result.URL, result.Status, result.Length),
			ScannerCategory: "content-discovery",
			RuleID:          "ffuf:" + pathOf(result.URL),
			File:            result.URL,
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	return findings, nil
}

func pathOf(rawURL string) string {
	if index := strings.Index(rawURL, "://"); index >= 0 {
		if slash := strings.IndexByte(rawURL[index+3:], '/'); slash >= 0 {
			return rawURL[index+3+slash:]
		}
	}
	return rawURL
}
