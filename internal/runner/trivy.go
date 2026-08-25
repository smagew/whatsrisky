package runner

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Trivy - dependency CVEs, IaC misconfiguration and, optionally, secrets.
type Trivy struct {
	binaryRunner
	scopeNote string
}

// NewTrivy builds the runner.
func NewTrivy(config Config) *Trivy {
	return &Trivy{binaryRunner: binaryRunner{
		binary: "trivy",
		hints: installHints{
			"darwin":  "brew install trivy",
			"linux":   "see https://trivy.dev/latest/getting-started/installation/",
			"windows": "scoop install trivy  (or winget install AquaSecurity.Trivy)",
			"default": "https://trivy.dev/latest/getting-started/installation/",
		},
		config: config,
	}}
}

func (t *Trivy) Name() string { return "trivy" }

func (t *Trivy) Version() string { return proc.Version(t.binary, "--version") }

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			PkgPath          string   `json:"PkgPath"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Severity         string   `json:"Severity"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			References       []string `json:"References"`
			CweIDs           []string `json:"CweIDs"`
			PrimaryURL       string   `json:"PrimaryURL"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			Type          string   `json:"Type"`
			ID            string   `json:"ID"`
			AVDID         string   `json:"AVDID"`
			Title         string   `json:"Title"`
			Description   string   `json:"Description"`
			Message       string   `json:"Message"`
			Resolution    string   `json:"Resolution"`
			Severity      string   `json:"Severity"`
			References    []string `json:"References"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Match     string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func (t *Trivy) Scan(progress func(string)) (Outcome, error) {
	config := t.config
	outFile := filepath.Join(config.WorkDir, "trivy.json")
	argv := []string{
		t.binary, "fs",
		"--scanners", config.TrivyScanners,
		"--format", "json",
		"--output", outFile,
		"--exit-code", "0",
	}
	if config.TrivyOffline {
		argv = append(argv, "--offline-scan", "--skip-db-update", "--skip-java-db-update")
	}
	for _, pattern := range config.Exclude {
		argv = append(argv, "--skip-dirs", strings.TrimSuffix(pattern, "/"))
	}
	argv = append(argv, ".")

	result, err := proc.Run(argv, proc.Options{
		Dir:      config.Target,
		Timeout:  config.TrivyTimeout,
		OnStderr: trivyProgress(progress),
	})
	if err != nil {
		return Outcome{}, err
	}

	note := ""
	if config.DiffRange != "" {
		// A dependency CVE is a property of the manifest, not of the diff: a
		// lockfile untouched by this range can still be vulnerable. Scanning the
		// whole tree is the honest choice, and the report says so.
		note = fmt.Sprintf("trivy ignored --diff %s: dependency and IaC findings are "+
			"properties of the whole manifest, not of the changed lines.", config.DiffRange)
	}

	var report trivyReport
	if err := ReadJSONFile(outFile, &report); err != nil {
		detail := result.Stderr
		if detail == "" {
			detail = result.Stdout
		}
		return Outcome{}, fmt.Errorf("trivy wrote no usable report (exit %d): %s",
			result.ExitCode, model.Truncate(detail, 400))
	}

	var findings []model.Finding
	for _, section := range report.Results {
		target := Relative(config.Target, section.Target)

		for _, item := range section.Vulnerabilities {
			remediation := fmt.Sprintf("No fixed version published yet for %s %s. Evaluate "+
				"mitigations, pin an alternative, or accept the risk explicitly.",
				item.PkgName, item.InstalledVersion)
			if item.FixedVersion != "" {
				remediation = fmt.Sprintf("Upgrade %s from %s to %s or later.",
					item.PkgName, item.InstalledVersion, item.FixedVersion)
			}
			category := "Dependency"
			if section.Type != "" {
				category = "Dependency/" + section.Type
			}
			file := item.PkgPath
			if file == "" {
				file = target
			}
			finding := model.Finding{
				Tool:             "trivy",
				Severity:         model.ParseSeverity(item.Severity, model.Medium),
				Title:            model.Truncate(orText(item.Title, item.VulnerabilityID+" in "+item.PkgName), 140),
				Description:      model.Truncate(item.Description, 3000),
				ScannerCategory:  category,
				RuleID:           item.VulnerabilityID,
				File:             Relative(config.Target, file),
				CWE:              item.CweIDs,
				References:       limit(item.References, 5),
				Remediation:      remediation,
				Package:          item.PkgName,
				InstalledVersion: item.InstalledVersion,
				FixedVersion:     item.FixedVersion,
				CVSS:             trivyCVSS(item.CVSS),
				Pass:             "vuln",
				Raw:              map[string]string{"primary_url": item.PrimaryURL},
			}
			finding.Normalize()
			findings = append(findings, finding)
		}

		for _, item := range section.Misconfigurations {
			category := "Misconfiguration"
			if item.Type != "" {
				category += "/" + item.Type
			}
			finding := model.Finding{
				Tool:            "trivy",
				Severity:        model.ParseSeverity(item.Severity, model.Medium),
				Title:           model.Truncate(orText(item.Title, item.ID), 140),
				Description:     model.Truncate(item.Description+"\n\n"+item.Message, 3000),
				ScannerCategory: category,
				RuleID:          orText(item.AVDID, item.ID),
				File:            target,
				Line:            item.CauseMetadata.StartLine,
				EndLine:         item.CauseMetadata.EndLine,
				References:      limit(item.References, 5),
				Remediation:     model.Truncate(item.Resolution, 1200),
				Snippet:         ReadSnippet(config.Target, target, item.CauseMetadata.StartLine, 2),
				Pass:            "misconfig",
			}
			finding.Normalize()
			findings = append(findings, finding)
		}

		for _, item := range section.Secrets {
			finding := model.Finding{
				Tool:            "trivy",
				Severity:        model.ParseSeverity(item.Severity, model.Critical),
				Title:           model.Truncate("Secret: "+orText(item.Title, item.RuleID), 140),
				Description:     fmt.Sprintf("Trivy secret rule `%s` (%s) matched in %s.", item.RuleID, item.Category, target),
				ScannerCategory: "Secret",
				RuleID:          item.RuleID,
				File:            target,
				Line:            item.StartLine,
				EndLine:         item.EndLine,
				Remediation: "Revoke and rotate the credential at the provider, purge it from the " +
					"file and from git history, then load it from a secret manager or environment.",
				Snippet: model.Truncate(item.Match, 300),
				Pass:    "secret",
			}
			finding.Normalize()
			findings = append(findings, finding)
		}
	}
	return Outcome{Findings: findings, Command: result.Command(), Stderr: result.Stderr, Note: note}, nil
}

func trivyProgress(progress func(string)) func(string) {
	return func(line string) {
		for _, level := range []string{"\tINFO\t", "\tWARN\t", "\tERROR\t"} {
			if strings.Contains(line, level) {
				progress(trivyMessage(line))
				return
			}
		}
	}
}

// trivyMessage strips the timestamp and level, keeping the rest.
func trivyMessage(line string) string {
	parts := strings.Split(line, "\t")
	if len(parts) < 3 {
		return strings.TrimSpace(line)
	}
	var kept []string
	for _, part := range parts[2:] {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, " ")
}

func trivyCVSS(scores map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) string {
	for _, source := range []string{"nvd", "redhat", "ghsa"} {
		if entry, ok := scores[source]; ok {
			if entry.V3Score > 0 {
				return fmt.Sprintf("%g (%s)", entry.V3Score, strings.ToUpper(source))
			}
			if entry.V2Score > 0 {
				return fmt.Sprintf("%g (%s)", entry.V2Score, strings.ToUpper(source))
			}
		}
	}
	return ""
}

func orText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
