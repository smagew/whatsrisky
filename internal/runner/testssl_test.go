package runner

import (
	"strings"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

func TestTestSSLParsesTheFlatArray(t *testing.T) {
	// testssl's --jsonfile shape: a flat array, one entry per check. The passing
	// ones (OK/INFO) must be dropped; only the negative results are findings.
	raw := []byte(`[
	  {"id":"SSLv3","severity":"HIGH","finding":"offered (NOT ok)","cve":"","cwe":"CWE-310"},
	  {"id":"heartbleed","severity":"CRITICAL","finding":"vulnerable","cve":"CVE-2014-0160","cwe":"CWE-119"},
	  {"id":"TLS1_2","severity":"OK","finding":"offered","cve":"","cwe":""},
	  {"id":"cert_expiration","severity":"INFO","finding":"89 days","cve":"","cwe":""},
	  {"id":"cipher_order","severity":"LOW","finding":"not set","cve":"","cwe":""}
	]`)
	ts := NewTestSSL(Config{Target: "https://x"})
	findings, err := ts.parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("kept %d findings, want 3 (OK and INFO dropped); got %v", len(findings), titlesOf(findings))
	}
	bySeverity := map[model.Severity]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
	}
	if bySeverity[model.Critical] != 1 || bySeverity[model.High] != 1 || bySeverity[model.Low] != 1 {
		t.Errorf("severities: %v", bySeverity)
	}
	// The CVE reaches the title and the references.
	var heartbleed *model.Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "heartbleed") {
			heartbleed = &findings[i]
		}
	}
	if heartbleed == nil {
		t.Fatalf("heartbleed missing from %v", titlesOf(findings))
	}
	if !strings.Contains(heartbleed.Title, "CVE-2014-0160") {
		t.Errorf("CVE not in title: %q", heartbleed.Title)
	}
}

func TestTestSSLDefaultsToPort443ForHTTPS(t *testing.T) {
	for target, want := range map[string]string{
		"https://example.com":      "example.com:443",
		"https://example.com:8443": "example.com:8443",
		"http://example.com":       "example.com:80",
	} {
		ts := NewTestSSL(Config{Target: target})
		if got := ts.hostPort(); got != want {
			t.Errorf("%s → %q, want %q", target, got, want)
		}
	}
}

func titlesOf(findings []model.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Title)
	}
	return out
}
