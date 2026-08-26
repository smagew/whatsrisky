package perimeter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/proc"
)

// Tools is the discovery chain, in order. Each is a ProjectDiscovery binary on
// PATH; a missing one is reported, not fatal, because a partial map beats none.
var Tools = []string{"subfinder", "dnsx", "httpx"}

// Progress is a no-op-safe callback.
type Progress func(string)

func (p Progress) say(message string) {
	if p != nil {
		p(message)
	}
}

// Discover runs subfinder → dnsx → httpx and returns the assets, most-alive
// first. Each stage that cannot run is noted in the returned notes rather than
// stopping the chain: without subfinder it still probes the bare domain, without
// httpx it still returns what resolved.
func Discover(domain string, timeout time.Duration, progress Progress) ([]Asset, []string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, nil, fmt.Errorf("no domain")
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	var notes []string

	// 1. subfinder: subdomains. The domain itself is always in the set.
	hosts := map[string]bool{domain: true}
	if proc.Which("subfinder") == "" {
		notes = append(notes, "subfinder not installed: only the bare domain was checked, not its subdomains")
	} else {
		progress.say("subfinder: enumerating subdomains of " + domain)
		result, err := proc.Run([]string{"subfinder", "-d", domain, "-silent", "-oJ"},
			proc.Options{Timeout: timeout})
		if err != nil && strings.TrimSpace(result.Stdout) == "" {
			notes = append(notes, "subfinder failed: "+firstLine(result.Stderr))
		}
		for _, host := range parseSubfinder(result.Stdout) {
			hosts[host] = true
		}
		progress.say(fmt.Sprintf("subfinder: %d name(s)", len(hosts)))
	}

	names := sortedKeys(hosts)

	// 2. dnsx: which names resolve, and to what. Skipped cleanly if absent.
	resolved := map[string][]string{}
	if proc.Which("dnsx") == "" {
		notes = append(notes, "dnsx not installed: names were not pre-resolved (httpx still resolves as it probes)")
		for _, name := range names {
			resolved[name] = nil
		}
	} else {
		progress.say("dnsx: resolving " + fmt.Sprintf("%d name(s)", len(names)))
		listFile, cleanup, listErr := writeList(names)
		if listErr != nil {
			return nil, notes, listErr
		}
		result, err := proc.Run([]string{"dnsx", "-silent", "-json", "-a", "-resp", "-l", listFile},
			proc.Options{Timeout: timeout})
		cleanup()
		if err != nil && strings.TrimSpace(result.Stdout) == "" {
			notes = append(notes, "dnsx failed: "+firstLine(result.Stderr))
			for _, name := range names {
				resolved[name] = nil
			}
		} else {
			resolved = parseDNSx(result.Stdout)
			progress.say(fmt.Sprintf("dnsx: %d name(s) resolved", len(resolved)))
		}
	}

	// 3. httpx: which are alive over HTTP(S), and what they run.
	assets := map[string]*Asset{}
	for host, ips := range resolved {
		assets[host] = &Asset{Host: host, IPs: ips}
	}
	if proc.Which("httpx") == "" {
		notes = append(notes, "httpx not installed: nothing was probed over HTTP, so no URLs to scan")
	} else {
		probe := sortedKeys(resolved)
		if len(probe) == 0 {
			probe = names
		}
		progress.say("httpx: probing " + fmt.Sprintf("%d name(s)", len(probe)))
		listFile, cleanup, listErr := writeList(probe)
		if listErr != nil {
			return nil, notes, listErr
		}
		result, err := proc.Run([]string{"httpx", "-silent", "-json", "-title", "-tech-detect",
			"-status-code", "-l", listFile}, proc.Options{Timeout: timeout})
		cleanup()
		if err != nil && strings.TrimSpace(result.Stdout) == "" {
			notes = append(notes, "httpx failed: "+firstLine(result.Stderr))
		}
		for _, live := range parseHTTPx(result.Stdout) {
			asset := assets[live.Host]
			if asset == nil {
				asset = &Asset{Host: live.Host}
				assets[live.Host] = asset
			}
			asset.URL, asset.Status, asset.Title, asset.Tech = live.URL, live.Status, live.Title, live.Tech
			asset.Alive = true
		}
		progress.say(fmt.Sprintf("httpx: %d alive", countAlive(assets)))
	}

	return sortAssets(assets), notes, nil
}

// --- parsers, each against the tool's real JSONL ---------------------

func parseSubfinder(output string) []string {
	var out []string
	forEachJSONLine(output, func(line []byte) {
		var entry struct {
			Host string `json:"host"`
		}
		if json.Unmarshal(line, &entry) == nil && entry.Host != "" {
			out = append(out, entry.Host)
		}
	})
	return out
}

func parseDNSx(output string) map[string][]string {
	out := map[string][]string{}
	forEachJSONLine(output, func(line []byte) {
		var entry struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
		}
		if json.Unmarshal(line, &entry) == nil && entry.Host != "" {
			out[entry.Host] = entry.A
		}
	})
	return out
}

type liveHost struct {
	Host   string
	URL    string
	Status int
	Title  string
	Tech   []string
}

func parseHTTPx(output string) []liveHost {
	var out []liveHost
	forEachJSONLine(output, func(line []byte) {
		var entry struct {
			Input      string   `json:"input"`
			Host       string   `json:"host"`
			URL        string   `json:"url"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"`
		}
		if json.Unmarshal(line, &entry) != nil || entry.URL == "" {
			return
		}
		host := entry.Input
		if host == "" {
			host = entry.Host
		}
		out = append(out, liveHost{Host: host, URL: entry.URL,
			Status: entry.StatusCode, Title: entry.Title, Tech: entry.Tech})
	})
	return out
}

// --- helpers ---------------------------------------------------------

func forEachJSONLine(output string, fn func([]byte)) {
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) > 0 && line[0] == '{' {
			fn(line)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func countAlive(assets map[string]*Asset) int {
	n := 0
	for _, a := range assets {
		if a.Alive {
			n++
		}
	}
	return n
}

// sortAssets puts the live assets first, then by host, so the inventory reads with
// the things worth scanning at the top.
func sortAssets(assets map[string]*Asset) []Asset {
	out := make([]Asset, 0, len(assets))
	for _, a := range assets {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alive != out[j].Alive {
			return out[i].Alive
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// AliveURLs is the list of addresses worth handing to the scanners.
func AliveURLs(assets []Asset) []string {
	var out []string
	for _, a := range assets {
		if a.Alive && a.URL != "" {
			out = append(out, a.URL)
		}
	}
	return out
}

// writeList puts host names in a temp file for the -l flag of dnsx and httpx,
// which read their input from a file rather than from stdin here.
func writeList(names []string) (path string, cleanup func(), err error) {
	file, err := os.CreateTemp("", "whatsrisky-hosts-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	_, _ = file.WriteString(strings.Join(names, "\n"))
	_ = file.Close()
	return file.Name(), func() { _ = os.Remove(file.Name()) }, nil
}

func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return strings.TrimSpace(text[:i])
	}
	return strings.TrimSpace(text)
}
