package perimeter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smagew/whatsrisky/internal/model"
)

func TestFanOutScansEveryAliveAssetIntoOneReport(t *testing.T) {
	// Two bare servers stand in for two discovered assets. The fan-out runs the
	// surface pass on each and rolls the findings into one report, each carrying the
	// asset it came from.
	one := bare(t)
	two := bare(t)
	assets := []Asset{
		{Host: "one.example.com", URL: one.URL, Status: 200, Alive: true},
		{Host: "two.example.com", URL: two.URL, Status: 200, Alive: true},
		{Host: "dead.example.com", Alive: false},
	}

	report := Scan(Config{Domain: "example.com", Passes: []string{"surface"}, WorkDir: t.TempDir()},
		assets, []string{"dnsx not installed: names were not pre-resolved"})

	if report.ProjectName != "example.com" {
		t.Errorf("report is for %q", report.ProjectName)
	}
	// Findings from both live assets are present, tagged by their URL.
	fromOne, fromTwo := false, false
	for _, f := range report.Findings {
		if strings.HasPrefix(f.File, one.URL) {
			fromOne = true
		}
		if strings.HasPrefix(f.File, two.URL) {
			fromTwo = true
		}
	}
	if !fromOne || !fromTwo {
		t.Errorf("findings did not come from both assets: one=%v two=%v", fromOne, fromTwo)
	}

	// The inventory is a tool of its own, and it carries the discovery note so a
	// missing PD tool is visible in the report, not just on the terminal.
	var discovery *model.ToolResult
	for i := range report.Tools {
		if report.Tools[i].Name == "discovery" {
			discovery = &report.Tools[i]
		}
	}
	if discovery == nil {
		t.Fatal("no discovery tool result")
	}
	if !strings.Contains(discovery.Message, "3 asset(s) found, 2 alive") {
		t.Errorf("discovery summary: %q", discovery.Message)
	}
	if !strings.Contains(discovery.Message, "dnsx not installed") {
		t.Errorf("discovery does not carry the gap note: %q", discovery.Message)
	}
}

func TestFanOutOverNothingIsHonest(t *testing.T) {
	report := Scan(Config{Domain: "example.com", Passes: []string{"surface"}, WorkDir: t.TempDir()},
		nil, []string{"httpx not installed: nothing was probed"})
	if report.Status != model.StatusPartial {
		t.Errorf("a scan that found no assets should be partial, got %q", report.Status)
	}
	var discovery model.ToolResult
	for _, tool := range report.Tools {
		if tool.Name == "discovery" {
			discovery = tool
		}
	}
	if discovery.OK() {
		t.Error("discovery with zero assets should not read as OK")
	}
}

func bare(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("hi"))
	}))
	t.Cleanup(server.Close)
	return server
}
