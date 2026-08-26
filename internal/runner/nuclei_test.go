package runner

import (
	"strings"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

func TestNucleiParsesRealJSONL(t *testing.T) {
	// A line of nuclei's actual JSONL output, trimmed to the fields used.
	line := `{"template-id":"CVE-2021-44228","type":"http","host":"https://x","matched-at":"https://x/api",` +
		`"info":{"name":"Apache Log4j RCE","severity":"critical","description":"log4shell",` +
		`"tags":["cve","rce"],"classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]}}}`
	n := NewNuclei(Config{Target: "https://x"})
	findings := n.parse(line+"\ngarbage not json\n", func(string) {})
	if len(findings) != 1 {
		t.Fatalf("parsed %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != model.Critical {
		t.Errorf("severity %s", f.Severity)
	}
	if !strings.Contains(f.Title, "CVE-2021-44228") {
		t.Errorf("the CVE is not in the title: %q", f.Title)
	}
	if f.RuleID != "nuclei:CVE-2021-44228" || f.File != "https://x/api" {
		t.Errorf("rule/location: %q %q", f.RuleID, f.File)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-502" {
		t.Errorf("cwe %v", f.CWE)
	}
}

func TestObservationalNucleiExcludesTheAttackingTemplates(t *testing.T) {
	// The whole difference between looking and probing: the observational run must
	// not pull in the templates that send payloads.
	observational := NewNuclei(Config{Target: "https://x", NetActive: false}).argv()
	joined := strings.Join(observational, " ")
	if !strings.Contains(joined, "-exclude-tags") {
		t.Errorf("observational run does not exclude the attacking templates: %s", joined)
	}
	for _, tag := range []string{"fuzz", "injection", "sqli", "xss"} {
		if !strings.Contains(joined, tag) {
			t.Errorf("observational run does not exclude %q: %s", tag, joined)
		}
	}
	active := NewNuclei(Config{Target: "https://x", NetActive: true}).argv()
	if strings.Contains(strings.Join(active, " "), "-exclude-tags") {
		t.Errorf("active run should not exclude the attacking templates: %v", active)
	}
}
