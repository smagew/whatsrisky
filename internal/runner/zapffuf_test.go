package runner

import (
	"strings"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

func TestZAPParsesTheReport(t *testing.T) {
	raw := []byte(`{"site":[{"@name":"https://x","alerts":[
	  {"alert":"SQL Injection","riskcode":"3","desc":"<p>bad</p>","solution":"<p>parameterise</p>",
	   "cweid":"89","reference":"https://owasp.org/x","instances":[{"uri":"https://x/login"}]},
	  {"alert":"Cookie without SameSite","riskcode":"1","desc":"minor","solution":"set it","cweid":"-1","instances":[]}
	]}]}`)
	z := NewZAP(Config{Target: "https://x"})
	findings, err := z.parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("parsed %d, want 2", len(findings))
	}
	sqli := findings[0]
	if sqli.Severity != model.High {
		t.Errorf("severity %s", sqli.Severity)
	}
	if sqli.File != "https://x/login" {
		t.Errorf("location %q", sqli.File)
	}
	if len(sqli.CWE) != 1 || sqli.CWE[0] != "CWE-89" {
		t.Errorf("cwe %v", sqli.CWE)
	}
	// HTML is stripped from the description and solution.
	if strings.Contains(sqli.Description, "<p>") || strings.Contains(sqli.Remediation, "<p>") {
		t.Errorf("HTML survived: %q / %q", sqli.Description, sqli.Remediation)
	}
	// A -1 CWE is not turned into "CWE--1".
	if len(findings[1].CWE) != 0 {
		t.Errorf("a missing CWE became %v", findings[1].CWE)
	}
}

func TestZAPBaselineIsPassiveUnlessActive(t *testing.T) {
	if got := NewZAP(Config{NetActive: false}).script(); got != "zap-baseline.py" {
		t.Errorf("default script %q, want the baseline", got)
	}
	if got := NewZAP(Config{NetActive: true}).script(); got != "zap-full-scan.py" {
		t.Errorf("active script %q, want the full scan", got)
	}
}

func TestFfufParsesResults(t *testing.T) {
	raw := []byte(`{"results":[
	  {"input":{"FUZZ":"admin"},"url":"https://x/admin","status":401,"length":12},
	  {"input":{"FUZZ":"backup"},"url":"https://x/backup","status":200,"length":900}
	]}`)
	f := NewFfuf(Config{Target: "https://x"})
	findings, err := f.parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("parsed %d, want 2", len(findings))
	}
	// A guarded path (401) is low; a plain 200 is info.
	var admin, backup *model.Finding
	for i := range findings {
		switch {
		case strings.Contains(findings[i].File, "/admin"):
			admin = &findings[i]
		case strings.Contains(findings[i].File, "/backup"):
			backup = &findings[i]
		}
	}
	if admin == nil || admin.Severity != model.Low {
		t.Errorf("admin: %+v", admin)
	}
	if backup == nil || backup.Severity != model.Info {
		t.Errorf("backup: %+v", backup)
	}
}

func TestFfufRefusesWithoutActiveOrWordlist(t *testing.T) {
	// The gate is honest: a selected ffuf that cannot run says why, so it shows as a
	// coverage gap rather than a silent nothing. The binary-missing reason wins when
	// ffuf is not installed, so the net-active reason is only asserted when it is.
	noActive := NewFfuf(Config{Target: "https://x", NetActive: false, Wordlist: "/tmp/w.txt"})
	if noActive.Available() {
		t.Error("ffuf ran without --net-active")
	}
	if proc.Which("ffuf") != "" {
		if !strings.Contains(noActive.UnavailableReason(), "net-active") {
			t.Errorf("with ffuf present, the reason should name --net-active: %q", noActive.UnavailableReason())
		}
		noWordlist := NewFfuf(Config{Target: "https://x", NetActive: true})
		if proc.Which("ffuf") != "" && noWordlist.wordlist() == "" {
			if noWordlist.Available() {
				t.Error("ffuf ran with no wordlist")
			}
			if !strings.Contains(noWordlist.UnavailableReason(), "wordlist") {
				t.Errorf("reason should name the wordlist: %q", noWordlist.UnavailableReason())
			}
		}
	}
}
