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

// ZAP is OWASP ZAP driven through its packaged scan scripts. The baseline scan
// spiders the site and reports what its passive rules see — it crawls, following
// links, but sends no attacks — so it is the default. --net-active switches to the
// full scan, which adds active injection; the report says which ran.
//
// ZAP is a heavyweight (Java), so it is not in the default network set: you ask
// for it with --passes.
type ZAP struct {
	binaryRunner
}

// NewZAP builds the runner. The binary is the baseline script; the full script is
// its sibling and is resolved from the same directory when --net-active is set.
func NewZAP(config Config) *ZAP {
	return &ZAP{binaryRunner: binaryRunner{
		binary: "zap-baseline.py",
		hints: installHints{
			// The packaged scan scripts are not on PATH from the desktop app or the
			// Homebrew cask; the Docker image ships them ready to run.
			"default": "run the ghcr.io/zaproxy/zaproxy Docker image, which ships zap-baseline.py — see https://www.zaproxy.org/docs/docker/",
		},
		config: config,
	}}
}

func (z *ZAP) Name() string { return "zap" }

const zapImage = "ghcr.io/zaproxy/zaproxy"

// hasScript is true when the ZAP scan scripts are on PATH (a local ZAP install).
func (z *ZAP) hasScript() bool { return proc.Which("zap-baseline.py") != "" }

// hasDocker is true when Docker is available to run the ZAP image, which ships the
// scripts. This is the usual way to run them, since the Homebrew cask and the
// desktop app do not put them on PATH.
func (z *ZAP) hasDocker() bool { return proc.Which("docker") != "" }

// Available and Installed both mean "can ZAP run": with the scripts on PATH, or via
// the Docker image. doctor asks Installed; the scan asks Available.
func (z *ZAP) Available() bool { return z.hasScript() || z.hasDocker() }
func (z *ZAP) Installed() bool { return z.Available() }

func (z *ZAP) UnavailableReason() string {
	return "install Docker (Desktop) to run " + zapImage + ", or put zap-baseline.py on PATH"
}

func (z *ZAP) Version() string {
	if z.hasScript() {
		return proc.Version("zap-baseline.py", "-h")
	}
	return "via Docker: " + zapImage
}

// script is the baseline scan by default, the full scan when active traffic is
// allowed.
func (z *ZAP) script() string {
	if z.config.NetActive {
		return "zap-full-scan.py"
	}
	return "zap-baseline.py"
}

// argv runs the script directly when it is on PATH, otherwise through the Docker
// image. Under Docker the working directory is mounted at /zap/wrk, where the
// script writes its report, so both paths leave zap.json in WorkDir.
func (z *ZAP) argv() []string {
	if z.hasScript() {
		return []string{z.script(), "-t", z.config.Target, "-J", "zap.json", "-I"}
	}
	return []string{
		"docker", "run", "--rm", "-v", z.config.WorkDir + ":/zap/wrk:rw",
		zapImage, z.script(), "-t", z.config.Target, "-J", "zap.json", "-I",
	}
}

// zapReport is the standard ZAP JSON report, the fields used.
type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			Alert     string `json:"alert"`
			RiskCode  string `json:"riskcode"`
			Desc      string `json:"desc"`
			Solution  string `json:"solution"`
			CWEID     string `json:"cweid"`
			Reference string `json:"reference"`
			Instances []struct {
				URI string `json:"uri"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

func (z *ZAP) Scan(progress func(string)) (Outcome, error) {
	mode := "baseline (passive)"
	if z.config.NetActive {
		mode = "full (active)"
	}
	progress("ZAP " + mode + " scan of " + z.config.Target)

	jsonPath := filepath.Join(z.config.WorkDir, "zap.json")
	timeout := z.config.NucleiTimeout
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	argv := z.argv()
	// Both the local script and the Docker run leave zap.json in WorkDir: the script
	// writes relative to Dir, and the container writes to the mounted /zap/wrk.
	result, err := proc.Run(argv, proc.Options{Timeout: timeout, Dir: z.config.WorkDir, OnStderr: Progress(progress)})
	raw, readErr := os.ReadFile(jsonPath)
	if readErr != nil {
		if err != nil {
			return Outcome{Stderr: result.Stderr}, fmt.Errorf("zap: %w", err)
		}
		return Outcome{Stderr: result.Stderr}, fmt.Errorf("zap wrote no report to %s", jsonPath)
	}

	findings, parseErr := z.parse(raw)
	if parseErr != nil {
		return Outcome{Stderr: result.Stderr}, parseErr
	}
	note := "ZAP baseline: it spidered the site and reported passive findings; it sent no attacks. Pass --net-active for the full active scan."
	if z.config.NetActive {
		note = "ZAP full scan: it ran active attack rules against the site (--net-active)."
	}
	if progress != nil {
		progress(fmt.Sprintf("zap: %d finding(s)", len(findings)))
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(argv, " "),
		Stderr:   result.Stderr,
		Note:     note,
	}, nil
}

func (z *ZAP) parse(raw []byte) ([]model.Finding, error) {
	var report zapReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("zap JSON: %w", err)
	}
	var findings []model.Finding
	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			location := site.Name
			if len(alert.Instances) > 0 && alert.Instances[0].URI != "" {
				location = alert.Instances[0].URI
			}
			var cwe []string
			if alert.CWEID != "" && alert.CWEID != "-1" {
				cwe = []string{"CWE-" + alert.CWEID}
			}
			var refs []string
			if alert.Reference != "" {
				refs = strings.Fields(alert.Reference)
			}
			finding := model.Finding{
				Tool:            "zap",
				Severity:        zapSeverity(alert.RiskCode),
				Title:           model.Truncate(alert.Alert, 140),
				Description:     model.Truncate(stripHTML(alert.Desc), 4000),
				ScannerCategory: "dast",
				RuleID:          "zap:" + strings.ToLower(strings.ReplaceAll(alert.Alert, " ", "-")),
				File:            location,
				CWE:             cwe,
				References:      refs,
				Remediation:     model.Truncate(stripHTML(alert.Solution), 2000),
			}
			finding.Normalize()
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// zapSeverity maps ZAP's riskcode (0 info … 3 high) onto the shared scale.
func zapSeverity(code string) model.Severity {
	switch strings.TrimSpace(code) {
	case "3":
		return model.High
	case "2":
		return model.Medium
	case "1":
		return model.Low
	default:
		return model.Info
	}
}

// stripHTML removes the tags ZAP wraps its descriptions in, so the report reads as
// text rather than as markup.
func stripHTML(text string) string {
	var b strings.Builder
	depth := 0
	for _, r := range text {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return strings.TrimSpace(b.String())
}
