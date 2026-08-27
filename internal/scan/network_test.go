package scan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A live server with none of the security headers set and an insecure cookie, so
// the surface pass has real things to find.
func bareServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("<html>hi</html>"))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /internal\n"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestASurfaceScanFindsWhatTheServerVolunteers(t *testing.T) {
	server := bareServer(t)
	options := NewOptions()
	options.Target = server.URL
	options.Authorized = true
	options.Tools = []string{"surface"}
	options.Formats = []string{"json"}
	options.Compare = false
	options.OutDir = t.TempDir()

	outcome, err := Run(options, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	titles := map[string]bool{}
	for _, f := range outcome.Report.Findings {
		titles[f.Title] = true
	}
	// Missing CSP, a version-leaking Server header, an insecure cookie, and the
	// robots.txt Disallow list — all things a plain GET reveals.
	wants := []string{"Content-Security-Policy", "version disclosed", "session", "robots.txt"}
	for _, want := range wants {
		found := false
		for title := range titles {
			if strings.Contains(title, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("surface did not report %q; got %v", want, keys(titles))
		}
	}

	// The report is honest about the target and about coverage.
	if outcome.Report.ProjectPath != server.URL {
		t.Errorf("report target %q", outcome.Report.ProjectPath)
	}
}

func TestANetworkScanRefusesWithoutAuthorization(t *testing.T) {
	options := NewOptions()
	options.Target = "https://example.com"
	options.Tools = []string{"surface"}
	options.Formats = []string{"json"}
	// Authorized deliberately left false.

	if _, err := Run(options, nil); err == nil {
		t.Fatal("a network scan started without authorization")
	} else if !strings.Contains(err.Error(), "authoriz") {
		t.Errorf("the refusal does not name authorization: %v", err)
	}
}

func TestTheNetworkEquivalentCommandIsHonest(t *testing.T) {
	options := NewOptions()
	options.Target = "https://example.com"
	options.Tools = append([]string(nil), DefaultNetTools...)
	got := options.Normalized().CommandLine()
	if !strings.Contains(got, "https://example.com") {
		t.Errorf("the command omits the target: %s", got)
	}
	if !strings.Contains(got, "--i-am-authorized") {
		t.Errorf("a network scan needs authorization and the command should show it: %s", got)
	}

	options.Tools = without(DefaultNetTools, "llm-recon")
	if got := options.Normalized().CommandLine(); !strings.Contains(got, "--no-llm") {
		t.Errorf("dropping the recon pass should read as --no-llm: %s", got)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestTheDefaultNetworkPassesLeaveOutTheHeavyOptIns(t *testing.T) {
	// zap (Java/Docker) and ffuf (needs a wordlist, active) are opt-in via --passes,
	// not part of a plain network scan. This was the bug behind "zap and ffuf ran
	// though I did not tick them": the default set wrongly included them, so a scan
	// with no --passes ran them.
	for _, unwanted := range []string{"zap", "ffuf"} {
		for _, name := range DefaultNetTools {
			if name == unwanted {
				t.Errorf("%s is opt-in and must not be in DefaultNetTools", unwanted)
			}
		}
	}
	// And the observational passes are there.
	for _, want := range []string{"surface", "testssl", "nuclei", "llm-recon"} {
		found := false
		for _, name := range DefaultNetTools {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s should be a default network pass", want)
		}
	}
}
