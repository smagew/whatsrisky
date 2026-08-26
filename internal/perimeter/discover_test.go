package perimeter

import (
	"strings"
	"testing"
)

func TestParseSubfinder(t *testing.T) {
	out := `{"host":"api.example.com","source":"crtsh"}
{"host":"www.example.com","source":"dns"}
not json
{"host":"","source":"x"}`
	got := parseSubfinder(out)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "api.example.com" || got[1] != "www.example.com" {
		t.Errorf("hosts %v", got)
	}
}

func TestParseDNSx(t *testing.T) {
	out := `{"host":"api.example.com","a":["1.2.3.4","1.2.3.5"]}
{"host":"dead.example.com"}`
	got := parseDNSx(out)
	if len(got["api.example.com"]) != 2 {
		t.Errorf("api IPs: %v", got["api.example.com"])
	}
	if _, ok := got["dead.example.com"]; !ok {
		t.Error("a name with no A record should still appear as resolved-with-none")
	}
}

func TestParseHTTPx(t *testing.T) {
	out := `{"input":"api.example.com","url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx","PHP"]}
{"input":"admin.example.com","url":"https://admin.example.com","status_code":401,"tech":["Apache"]}
{"input":"nothing.example.com"}`
	got := parseHTTPx(out)
	if len(got) != 2 {
		t.Fatalf("got %d live hosts, want 2", len(got))
	}
	if got[0].Host != "api.example.com" || got[0].Status != 200 || len(got[0].Tech) != 2 {
		t.Errorf("first: %+v", got[0])
	}
}

func TestAliveURLsAndOrdering(t *testing.T) {
	assets := []Asset{
		{Host: "dead.example.com", Alive: false},
		{Host: "www.example.com", URL: "https://www.example.com", Alive: true},
	}
	urls := AliveURLs(assets)
	if len(urls) != 1 || urls[0] != "https://www.example.com" {
		t.Errorf("alive URLs %v", urls)
	}

	// sortAssets puts the live ones first.
	sorted := sortAssets(map[string]*Asset{
		"dead.example.com": {Host: "dead.example.com", Alive: false},
		"a.example.com":    {Host: "a.example.com", URL: "https://a.example.com", Alive: true},
	})
	if !sorted[0].Alive {
		t.Errorf("the live asset should sort first: %v", sorted)
	}
}

func TestDiscoverNeedsADomain(t *testing.T) {
	if _, _, err := Discover("   ", 0, nil); err == nil {
		t.Error("an empty domain should be refused")
	}
}

func TestDiscoverWithoutToolsNotesTheGaps(t *testing.T) {
	// On a machine without the PD tools, discovery must not fail silently: it says
	// what it could not run, per the project's coverage-honesty rule. (Skipped if
	// the tools happen to be installed here.)
	assets, notes, err := Discover("example.com", 0, nil)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(notes) == 0 && len(assets) == 0 {
		t.Error("with no tools and no assets, there should be notes explaining why")
	}
	_ = strings.Join(notes, ";")
}
