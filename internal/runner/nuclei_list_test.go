package runner

import (
	"strings"
	"testing"
)

func TestNucleiUsesTargetOrListByExtras(t *testing.T) {
	// No extras: nuclei scans the one target.
	plain := NewNuclei(Config{Target: "https://x"})
	if !strings.Contains(strings.Join(plain.argv(), " "), "-target https://x") {
		t.Errorf("plain argv: %v", plain.argv())
	}
	if strings.Contains(strings.Join(plain.argv(), " "), "-list") {
		t.Error("no extras should not use -list")
	}

	// With crawl endpoints: the seed and the endpoints, de-duplicated, one -list.
	crawled := NewNuclei(Config{Target: "https://x", ExtraTargets: []string{"https://x", "https://x/a", "https://x/b"}})
	if got := crawled.allTargets(); len(got) != 3 {
		t.Errorf("allTargets deduped to %v", got)
	}
	if !strings.Contains(strings.Join(crawled.argvWith("/tmp/l.txt"), " "), "-list /tmp/l.txt") {
		t.Errorf("list argv: %v", crawled.argvWith("/tmp/l.txt"))
	}
}
