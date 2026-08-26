package perimeter

import "testing"

func TestCrawlWithoutKatanaReturnsTheSeed(t *testing.T) {
	// No katana here, so Crawl degrades to just the seed rather than failing.
	got := Crawl("https://example.com", 50, 0, nil)
	if len(got) != 1 || got[0] != "https://example.com" {
		t.Errorf("crawl without katana: %v", got)
	}
}

func TestHostOf(t *testing.T) {
	if hostOf("https://a.example.com/x?y=1") != "a.example.com" {
		t.Errorf("hostOf: %q", hostOf("https://a.example.com/x?y=1"))
	}
}
