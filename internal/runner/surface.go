package runner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
)

// Surface reads what a server volunteers to an ordinary visitor: its TLS, its
// response headers, its cookies, its robots.txt. It sends nothing an attacker
// would send - only the GETs a browser makes - so it is safe to run against any
// address you are allowed to look at, and it says as much in its note.
type Surface struct {
	config Config
	client *http.Client
}

// NewSurface builds the runner. The client refuses to follow a redirect off the
// original host, so a scan of one site cannot wander onto another.
func NewSurface(config Config) *Surface {
	timeout := config.SurfaceTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	origin, _ := url.Parse(config.Target)
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if origin != nil && req.URL.Host != origin.Host {
				return http.ErrUseLastResponse
			}
			if len(via) >= 8 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return &Surface{config: config, client: client}
}

func (s *Surface) Name() string { return "surface" }

// Available is always true: this runner is Go, not a binary on PATH. What it
// cannot do is reach a target that is down, and that surfaces as an error, not as
// absence.
func (s *Surface) Available() bool           { return true }
func (s *Surface) UnavailableReason() string { return "" }
func (s *Surface) Version() string           { return "surface (built in)" }

func (s *Surface) Scan(progress func(string)) (Outcome, error) {
	progress("fetching " + s.config.Target)
	request, err := http.NewRequest(http.MethodGet, s.config.Target, nil)
	if err != nil {
		return Outcome{}, err
	}
	request.Header.Set("User-Agent", "whatsrisky-surface")
	response, err := s.client.Do(request)
	if err != nil {
		return Outcome{}, fmt.Errorf("could not reach %s: %w", s.config.Target, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))

	var findings []model.Finding
	findings = append(findings, s.tls(response)...)
	findings = append(findings, s.headers(response)...)
	findings = append(findings, s.cookies(response)...)

	// The check helpers return findings without the shared fields; stamp them in
	// one place so no helper can forget.
	for i := range findings {
		findings[i].Tool = "surface"
		if findings[i].File == "" {
			findings[i].File = s.config.Target
		}
		findings[i].Normalize()
	}

	progress("checking robots.txt")
	findings = append(findings, s.robots()...)

	return Outcome{
		Findings: findings,
		Command:  "GET " + s.config.Target + " (surface: observational, GET only)",
		Note:     "surface reads only what the server serves to a visitor; it sends no attack traffic",
	}, nil
}

// tls reports on the transport: no encryption at all, an old protocol, an expired
// or nearly-expired certificate.
func (s *Surface) tls(response *http.Response) []model.Finding {
	var out []model.Finding
	state := response.TLS
	if state == nil {
		if strings.HasPrefix(s.config.Target, "http://") {
			out = append(out, model.Finding{
				Severity:    model.High,
				Title:       "Served over plain HTTP, without TLS",
				Description: "The address responds without encryption, so anything sent to it — credentials, session cookies, form data — travels in clear text and can be read or changed on the network path.",
				RuleID:      "surface:no-tls",
				CWE:         []string{"CWE-319"},
				Remediation: "Serve the site over HTTPS and redirect HTTP to it.",
			})
		}
		return out
	}
	if state.Version < tls.VersionTLS12 {
		out = append(out, model.Finding{
			Severity:    model.Medium,
			Title:       "Obsolete TLS version negotiated",
			Description: fmt.Sprintf("The connection negotiated %s, which is deprecated and has known weaknesses.", tlsName(state.Version)),
			RuleID:      "surface:old-tls",
			CWE:         []string{"CWE-327"},
			Remediation: "Require TLS 1.2 or newer and disable older protocol versions.",
		})
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if left := time.Until(cert.NotAfter); left < 0 {
			out = append(out, model.Finding{
				Severity:    model.High,
				Title:       "TLS certificate has expired",
				Description: fmt.Sprintf("The certificate expired on %s. Visitors see a security warning, and some clients refuse the connection.", cert.NotAfter.Format("2006-01-02")),
				RuleID:      "surface:cert-expired",
				CWE:         []string{"CWE-295"},
				Remediation: "Renew the certificate and automate its renewal.",
			})
		} else if left < 14*24*time.Hour {
			out = append(out, model.Finding{
				Severity:    model.Low,
				Title:       "TLS certificate expires soon",
				Description: fmt.Sprintf("The certificate expires on %s, in under two weeks.", cert.NotAfter.Format("2006-01-02")),
				RuleID:      "surface:cert-expiring",
				Remediation: "Renew the certificate before it lapses; automate renewal so this does not recur.",
			})
		}
	}
	return out
}

// securityHeader is one header a site is expected to set, and why.
type securityHeader struct {
	name        string
	title       string
	description string
	severity    model.Severity
	httpsOnly   bool
}

var expectedHeaders = []securityHeader{
	{"Strict-Transport-Security", "HSTS is not set",
		"Without Strict-Transport-Security a visitor's first request can be downgraded to HTTP and intercepted.",
		model.Medium, true},
	{"Content-Security-Policy", "No Content-Security-Policy",
		"A CSP is the main defence against cross-site scripting; without one, an injected script runs unrestricted.",
		model.Medium, false},
	{"X-Content-Type-Options", "X-Content-Type-Options is not set",
		"Without nosniff, a browser may treat a file as a type it was not meant to be, which can turn an upload into a script.",
		model.Low, false},
	{"X-Frame-Options", "No clickjacking protection",
		"Neither X-Frame-Options nor a frame-ancestors CSP is set, so the page can be framed by another site for clickjacking.",
		model.Low, false},
	{"Referrer-Policy", "No Referrer-Policy",
		"Without a Referrer-Policy the full URL, which may carry tokens, is sent to other sites the user navigates to.",
		model.Info, false},
}

// headers reports the security headers that are missing and the ones that leak
// what software is running.
func (s *Surface) headers(response *http.Response) []model.Finding {
	var out []model.Finding
	https := response.TLS != nil
	for _, header := range expectedHeaders {
		if header.httpsOnly && !https {
			continue
		}
		if response.Header.Get(header.name) != "" {
			continue
		}
		out = append(out, model.Finding{
			Severity:        header.severity,
			Title:           header.title,
			Description:     header.description,
			RuleID:          "surface:header:" + strings.ToLower(header.name),
			ScannerCategory: "header",
			CWE:             []string{"CWE-693"},
			Remediation:     "Set the " + header.name + " response header.",
		})
	}
	for _, leaky := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		value := response.Header.Get(leaky)
		if value == "" || !strings.ContainsAny(value, "0123456789") {
			continue
		}
		out = append(out, model.Finding{
			Severity:        model.Info,
			Title:           "Software version disclosed in a header",
			Description:     fmt.Sprintf("The %s header reads %q, which tells an attacker exactly what to look up known vulnerabilities for.", leaky, value),
			RuleID:          "surface:version-leak:" + strings.ToLower(leaky),
			ScannerCategory: "header",
			CWE:             []string{"CWE-200"},
			Remediation:     "Remove or blank the " + leaky + " header.",
		})
	}
	return out
}

// cookies reports cookies set without the flags that keep them from theft.
func (s *Surface) cookies(response *http.Response) []model.Finding {
	var out []model.Finding
	https := response.TLS != nil
	for _, cookie := range response.Cookies() {
		var missing []string
		if !cookie.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if https && !cookie.Secure {
			missing = append(missing, "Secure")
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, model.Finding{
			Severity:        model.Low,
			Title:           fmt.Sprintf("Cookie %q is missing %s", cookie.Name, strings.Join(missing, " and ")),
			Description:     "A cookie without HttpOnly can be read by injected JavaScript; without Secure it is sent over plain HTTP. Both make session theft easier.",
			RuleID:          "surface:cookie:" + cookie.Name,
			ScannerCategory: "cookie",
			CWE:             []string{"CWE-1004"},
			Remediation:     "Set the " + strings.Join(missing, " and ") + " attribute(s) on this cookie.",
		})
	}
	return out
}

// robots fetches robots.txt and notes the paths it asks crawlers to avoid: a
// Disallow list is a map of what the operator would rather not be found.
func (s *Surface) robots() []model.Finding {
	base, err := url.Parse(s.config.Target)
	if err != nil {
		return nil
	}
	base.Path = "/robots.txt"
	base.RawQuery = ""
	response, err := s.client.Get(base.String())
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	var disallowed []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(strings.ToLower(line), "disallow:"); ok {
			if path := strings.TrimSpace(rest); path != "" && path != "/" {
				disallowed = append(disallowed, path)
			}
		}
	}
	if len(disallowed) == 0 {
		return nil
	}
	shown := disallowed
	if len(shown) > 12 {
		shown = shown[:12]
	}
	f := model.Finding{
		Tool:            "surface",
		File:            base.String(),
		Severity:        model.Info,
		Title:           fmt.Sprintf("robots.txt names %d path(s) to avoid", len(disallowed)),
		Description:     "robots.txt asks crawlers not to visit these paths, which tells anyone reading it where the operator would rather not be found:\n  " + strings.Join(shown, "\n  "),
		RuleID:          "surface:robots",
		ScannerCategory: "information-disclosure",
		CWE:             []string{"CWE-200"},
		Remediation:     "Do not rely on robots.txt to hide anything; protect sensitive paths with authentication.",
	}
	f.Normalize()
	return []model.Finding{f}
}

func tlsName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionSSL30:
		return "SSL 3.0"
	}
	return fmt.Sprintf("0x%04x", version)
}
