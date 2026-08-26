package runner

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/model"
)

// LLMRecon points a language model at a live address and asks it, in effect, where
// it would look for weakness by hand. It reasons over what the site serves - the
// headers, the page, the robots list - rather than sending anything an attacker
// would; its findings are leads to check, not confirmed holes, and it says so.
//
// It is opt-in and spends the caller's money, the same as the filesystem AI pass.
type LLMRecon struct {
	config  Config
	backend ai.Backend
	model   string
	notes   []string
	costUSD float64
	turns   int
}

// NewLLMRecon builds the runner, resolving the backend up front so an unknown
// provider fails here rather than mid-scan. The target is a URL, so the backend's
// working directory is a scratch dir, not the target.
func NewLLMRecon(config Config) (Runner, error) {
	backend, err := ai.New(config.AIProvider, config.WorkDir, config.WorkDir)
	if err != nil {
		return nil, err
	}
	chosen := config.AIModel
	if chosen == "" {
		chosen = backend.DefaultModel()
	}
	return &LLMRecon{config: config, backend: backend, model: chosen}, nil
}

func (l *LLMRecon) Name() string { return "llm-recon" }

func (l *LLMRecon) Available() bool {
	ok, _ := l.backend.Available()
	return ok
}

func (l *LLMRecon) UnavailableReason() string {
	_, reason := l.backend.Available()
	if reason == "" {
		reason = "the AI backend is not available"
	}
	return reason
}

func (l *LLMRecon) Version() string {
	return fmt.Sprintf("%s · %s", l.backend.Name(), l.model)
}

func (l *LLMRecon) Scan(progress func(string)) (Outcome, error) {
	progress("collecting what " + l.config.Target + " serves")
	context := l.observe()

	progress(fmt.Sprintf("recon pass on %s · %s", l.backend.Name(), l.model))
	answer, err := l.backend.Ask(ai.Request{
		Prompt:   reconPrompt(l.config.Target),
		Model:    l.model,
		Timeout:  l.timeout(),
		Context:  context,
		Progress: progress,
	})
	if err != nil {
		return Outcome{}, err
	}
	_ = WriteFile(filepath.Join(l.config.WorkDir, "llm-recon.txt"), answer.Text)
	l.costUSD += answer.CostUSD
	l.turns += answer.Turns
	l.notes = append(l.notes, answer.Notes...)

	findings, parseErr := l.parse(answer.Text)
	if parseErr != nil {
		return Outcome{}, parseErr
	}
	return Outcome{
		Findings: findings,
		Command:  fmt.Sprintf("%s recon on %s (reasoning over the served surface)", l.backend.Name(), l.model),
		Note:     l.note(),
	}, nil
}

// observe fetches what an ordinary visitor sees and hands it to the model as
// context. Nothing here probes: it is one GET of the page and one of robots.txt,
// the same reading the surface pass does.
func (l *LLMRecon) observe() string {
	client := &http.Client{Timeout: 20 * time.Second}
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n\n", l.config.Target)

	if response, err := client.Get(l.config.Target); err == nil {
		defer response.Body.Close()
		fmt.Fprintf(&b, "HTTP %s\n", response.Status)
		fmt.Fprintln(&b, "Response headers:")
		for name, values := range response.Header {
			fmt.Fprintf(&b, "  %s: %s\n", name, strings.Join(values, ", "))
		}
		if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
			cert := response.TLS.PeerCertificates[0]
			fmt.Fprintf(&b, "TLS: %s, cert for %v expires %s\n",
				tlsName(response.TLS.Version), cert.DNSNames, cert.NotAfter.Format("2006-01-02"))
		}
	} else {
		fmt.Fprintf(&b, "Could not fetch the page: %v\n", err)
	}

	if base, err := url.Parse(l.config.Target); err == nil {
		base.Path, base.RawQuery = "/robots.txt", ""
		if response, err := client.Get(base.String()); err == nil {
			defer response.Body.Close()
			if response.StatusCode == http.StatusOK {
				fmt.Fprintln(&b, "\nrobots.txt is present.")
			}
		}
	}
	return b.String()
}

func (l *LLMRecon) parse(text string) ([]model.Finding, error) {
	data := ExtractJSON(text)
	if data == nil {
		return nil, fmt.Errorf("could not parse JSON from the recon pass; the raw answer is in %s",
			l.config.WorkDir)
	}
	raw, _ := data["findings"].([]any)
	findings := make([]model.Finding, 0, len(raw))
	for _, entry := range raw {
		item, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		description := model.Truncate(asString(item["description"]), 4000)
		if check := model.Truncate(asString(item["how_to_check"]), 2000); check != "" {
			description = strings.TrimSpace(description + "\n\nHow to check: " + check)
		}
		finding := model.Finding{
			Tool:            "llm-recon",
			Severity:        model.ParseSeverity(asString(item["severity"]), model.Info),
			Title:           model.Truncate(orText(asString(item["title"]), "Unnamed lead"), 140),
			Description:     description,
			ScannerCategory: "recon/" + asString(item["category"]),
			RuleID:          "llm-recon",
			File:            orText(asString(item["endpoint"]), l.config.Target),
			CWE:             asStringList(item["cwe"]),
			Remediation:     model.Truncate(asString(item["remediation"]), 2000),
			Confidence:      orText(asString(item["confidence"]), "tentative"),
			Provider:        ai.Vendor[l.backend.Name()],
			Model:           l.model,
			Pass:            "recon",
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	return findings, nil
}

func (l *LLMRecon) timeout() time.Duration {
	if l.config.AITimeout > 0 {
		return l.config.AITimeout
	}
	return 10 * time.Minute
}

func (l *LLMRecon) note() string {
	parts := []string{
		"llm-recon reasons over what the site serves; its findings are leads to verify by hand, not confirmed vulnerabilities",
	}
	if !l.backend.Agentic() {
		parts = append(parts, "the backend saw only the surface we collected, not the live site")
	}
	if l.costUSD > 0 {
		parts = append(parts, fmt.Sprintf("cost about $%.2f", l.costUSD))
	}
	parts = append(parts, l.notes...)
	return strings.Join(parts, "; ")
}

// reconPrompt asks for leads in the strict-JSON shape parse expects. It is
// deliberately about observation and reasoning, not exploitation.
func reconPrompt(target string) string {
	return "You are a security reviewer looking at a public web address: " + target + ".\n" +
		"You are given only what the site serves to an ordinary visitor (headers, TLS, the page, robots.txt).\n" +
		"Do NOT suggest sending attacks. Reason about where a human tester should look for weakness, " +
		"based on what is observable and on what the technology stack implies.\n\n" +
		"Return ONLY JSON of this shape:\n" +
		`{"findings":[{"title":"","severity":"critical|high|medium|low|info",` +
		`"category":"","endpoint":"","description":"","how_to_check":"",` +
		`"remediation":"","cwe":[],"confidence":"tentative|likely"}]}` + "\n" +
		"Every finding is a lead to verify, so prefer low/info severity and 'tentative' confidence " +
		"unless what you can see is itself conclusive."
}
