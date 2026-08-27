package runner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// TestSSL runs testssl.sh, the deep TLS check: cipher suites, protocol versions,
// certificate chain, and the named transport vulnerabilities (Heartbleed, ROBOT,
// downgrade). It is observational — it only speaks TLS handshakes — so it needs no
// --net-active. surface keeps a shallow TLS check as a baseline; this is the real
// analysis when the binary is installed.
type TestSSL struct {
	binaryRunner
}

// NewTestSSL builds the runner.
func NewTestSSL(config Config) *TestSSL {
	return &TestSSL{binaryRunner: binaryRunner{
		binary: "testssl.sh",
		hints: installHints{
			"darwin":  "brew install testssl",
			"linux":   "apt install testssl.sh, or git clone https://github.com/testssl/testssl.sh",
			"windows": "run testssl.sh under WSL or Docker (drwetter/testssl.sh)",
			"default": "https://github.com/testssl/testssl.sh",
		},
		config: config,
	}}
}

func (t *TestSSL) Name() string { return "testssl" }

func (t *TestSSL) Version() string { return proc.Version(t.binary, "--version") }

// hostPort is what testssl scans: the host and port of the target, defaulting to
// 443 so an https URL without a port still lands on the TLS service.
func (t *TestSSL) hostPort() string {
	u, err := url.Parse(t.config.Target)
	if err != nil || u.Host == "" {
		return t.config.Target
	}
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "http" {
		return u.Hostname() + ":80"
	}
	return u.Hostname() + ":443"
}

func (t *TestSSL) argv(jsonPath string) []string {
	// --fast trims the slowest part (probing every cipher one by one) while still
	// checking protocols, the certificate and the named vulnerabilities. A full
	// per-cipher sweep can take many minutes against a live host.
	return []string{t.binary, "--quiet", "--color", "0", "--fast", "--jsonfile", jsonPath,
		"--severity", "LOW", t.hostPort()}
}

// testsslEntry is one line of testssl's JSON output, the fields we use.
type testsslEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve"`
	CWE      string `json:"cwe"`
}

func (t *TestSSL) Scan(progress func(string)) (Outcome, error) {
	jsonPath := filepath.Join(t.config.WorkDir, "testssl.json")
	timeout := t.config.NucleiTimeout
	if timeout <= 0 {
		timeout = 8 * time.Minute
	}
	progress("testssl: analysing TLS on " + t.hostPort())

	// testssl exits non-zero when it finds problems, which is the normal case, so
	// the JSON is read regardless and the error is only reported if none was written.
	result, err := proc.Run(t.argv(jsonPath), proc.Options{Timeout: timeout, OnStderr: Progress(progress)})
	raw, readErr := os.ReadFile(jsonPath)
	if readErr != nil {
		if err != nil {
			return Outcome{Stderr: result.Stderr}, fmt.Errorf("testssl: %w", err)
		}
		return Outcome{Stderr: result.Stderr}, fmt.Errorf("testssl wrote no JSON to %s", jsonPath)
	}

	findings, parseErr := t.parse(raw)
	if parseErr != nil {
		return Outcome{Stderr: result.Stderr}, parseErr
	}
	if progress != nil {
		progress(fmt.Sprintf("testssl: %d finding(s)", len(findings)))
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(t.argv(jsonPath), " "),
		Stderr:   result.Stderr,
		Note:     "testssl is observational: it only completes TLS handshakes, it sends no attack traffic",
	}, nil
}

func (t *TestSSL) parse(raw []byte) ([]model.Finding, error) {
	entries, err := decodeTestSSL(raw)
	if err != nil {
		return nil, err
	}
	var findings []model.Finding
	for _, entry := range entries {
		severity, keep := testsslSeverity(entry.Severity)
		if !keep {
			// OK / INFO / DEBUG entries are the passing checks; a report of what is
			// fine is noise, so only the negative results become findings.
			continue
		}
		var cwe []string
		if entry.CWE != "" {
			cwe = strings.Fields(entry.CWE)
		}
		var refs []string
		if entry.CVE != "" {
			refs = strings.Fields(entry.CVE)
		}
		finding := model.Finding{
			Tool:            "testssl",
			Severity:        severity,
			Title:           model.Truncate(testsslTitle(entry), 140),
			Description:     model.Truncate(entry.Finding, 2000),
			ScannerCategory: "tls",
			RuleID:          "testssl:" + entry.ID,
			File:            t.config.Target,
			CWE:             cwe,
			References:      refs,
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	return findings, nil
}

// decodeTestSSL copes with both shapes testssl writes: a flat array of entries
// (--jsonfile) and an object wrapping "scanResult" (--jsonfile-pretty), so a
// version difference does not silently yield nothing.
func decodeTestSSL(raw []byte) ([]testsslEntry, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var flat []testsslEntry
		if err := json.Unmarshal(raw, &flat); err != nil {
			return nil, fmt.Errorf("testssl JSON: %w", err)
		}
		return flat, nil
	}
	var wrapped struct {
		ScanResult []struct {
			// Each scanResult groups entries under named sections; collect them all.
			Protocols       []testsslEntry `json:"protocols"`
			Ciphers         []testsslEntry `json:"ciphers"`
			Vulnerabilities []testsslEntry `json:"vulnerabilities"`
			ServerDefaults  []testsslEntry `json:"serverDefaults"`
		} `json:"scanResult"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("testssl JSON: %w", err)
	}
	var out []testsslEntry
	for _, section := range wrapped.ScanResult {
		out = append(out, section.Protocols...)
		out = append(out, section.Ciphers...)
		out = append(out, section.Vulnerabilities...)
		out = append(out, section.ServerDefaults...)
	}
	return out, nil
}

func testsslTitle(entry testsslEntry) string {
	name := strings.ReplaceAll(entry.ID, "_", " ")
	if entry.CVE != "" {
		name += " (" + strings.Fields(entry.CVE)[0] + ")"
	}
	return name
}

// testsslSeverity maps testssl's levels onto the shared scale and says whether the
// entry is worth keeping at all. OK/INFO/DEBUG are passing checks, not findings.
func testsslSeverity(level string) (model.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "CRITICAL", "FATAL":
		return model.Critical, true
	case "HIGH":
		return model.High, true
	case "MEDIUM":
		return model.Medium, true
	case "LOW", "WARN":
		return model.Low, true
	default:
		return model.Info, false
	}
}
