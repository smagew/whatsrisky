package perimeter

import (
	"bufio"
	"bytes"
	"net/url"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/proc"
)

// CrawlTool is katana: it spiders a site and lists the endpoints it reaches, so
// nuclei can be pointed at the pages a site actually has rather than only its
// front door. Crawling is a lot of ordinary GETs — not attacks, but heavier than
// the observational passes — so it is opt-in with --crawl.
const CrawlTool = "katana"

// Crawl returns the endpoints katana finds under a URL, the seed included, capped
// so one sprawling site cannot swamp the scan. A missing katana yields just the
// seed and a note handled by the caller.
func Crawl(seed string, max int, timeout time.Duration, progress Progress) []string {
	if proc.Which(CrawlTool) == "" {
		return []string{seed}
	}
	if max <= 0 {
		max = 200
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	progress.say("katana: crawling " + seed)
	// -jc follows same-domain links; -silent prints one endpoint per line.
	result, _ := proc.Run([]string{CrawlTool, "-u", seed, "-silent", "-jc", "-d", "2"},
		proc.Options{Timeout: timeout})

	seen := map[string]bool{seed: true}
	endpoints := []string{seed}
	host := hostOf(seed)
	scanner := bufio.NewScanner(bytes.NewReader([]byte(result.Stdout)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] || !strings.HasPrefix(line, "http") {
			continue
		}
		// Stay on the asset's own host: a crawl that wanders off-site turns one
		// asset's scan into someone else's.
		if hostOf(line) != host {
			continue
		}
		seen[line] = true
		endpoints = append(endpoints, line)
		if len(endpoints) >= max {
			break
		}
	}
	progress.say(fmtCount("katana", len(endpoints), "endpoint"))
	return endpoints
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return raw
}
