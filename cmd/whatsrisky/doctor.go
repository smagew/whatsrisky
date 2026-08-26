package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/smagew/whatsrisky/internal/perimeter"
	"github.com/smagew/whatsrisky/internal/proc"
	"github.com/smagew/whatsrisky/internal/runner"
	"github.com/smagew/whatsrisky/internal/scan"
)

// toolStatus is the machine-readable form of a probe, for the desktop UI.
type toolStatus struct {
	Name    string   `json:"name"`
	Found   bool     `json:"found"`
	Version string   `json:"version"`
	Covers  string   `json:"covers"`
	Hint    string   `json:"hint"`
	Install string   `json:"install"` // the command to install it, or "" if we cannot
	Modes   []string `json:"modes"`   // which UI tabs use it: folder / address / domain
	Detail  string   `json:"detail"`  // a fuller "what it does", for a "more" panel
}

// toolDetail is the fuller "what does this do" for each tool, shown behind a "more"
// in the UI. The one-line summary is covers (from the runner vocabularies); this is
// the paragraph. Kept here because it is UI copy, not scan behaviour.
// perimeterCovers is the one-line summary for the discovery tools, which are not
// runners and so have no ToolCoverage entry.
var perimeterCovers = map[string]string{
	"subfinder": "Finds subdomains (optional)",
	"dnsx":      "Resolves the names found (optional)",
	"httpx":     "Finds which hosts are alive over HTTP (optional)",
	"gowitness": "Screenshots each live asset (optional)",
	"katana":    "Crawls each asset for endpoints (optional)",
}

var toolDetail = map[string]string{
	"semgrep":   "Static analysis of your own source code: injection, unsafe calls and risky patterns, matched by rules. Fast, and it never leaves your machine.",
	"trivy":     "Checks your dependencies and infrastructure-as-code against known-vulnerability databases (CVEs) and misconfiguration rules. A finding here is usually fixed by a version bump or a config change.",
	"gitleaks":  "Looks for secrets — API keys, tokens, passwords — in the working tree and across the whole git history, so a key committed and later deleted is still found.",
	"ai":        "A language model reads the code for the flaws a rule cannot see: broken authorization, data flow across files, business-rule mistakes. It sends your code to the provider and spends money, so it is opt-out, and the report records which model found what.",
	"surface":   "Reads only what a server serves an ordinary visitor — TLS, the security headers it is missing, version leaks, insecure cookies, the robots.txt disallow list. It sends nothing an attacker would, so it is safe on any address you may look at.",
	"testssl":   "Deep TLS analysis with testssl.sh: cipher suites, protocol versions, the certificate chain, and the named transport vulnerabilities (Heartbleed, ROBOT, downgrade). It only completes handshakes.",
	"nuclei":    "Runs ProjectDiscovery's community templates for known CVEs, misconfigurations and exposures. By default it excludes the templates that send payloads; --net-active includes the fuzzing and injection ones.",
	"zap":       "OWASP ZAP through its scan scripts: a passive baseline that spiders the site and observes, or — with --net-active — the full active scan that sends attack rules. The scripts ship with the ZAP Docker image.",
	"ffuf":      "Brute-forces paths from a wordlist to find endpoints the site does not link to — forgotten admin panels, left-over files. That is attack-shaped traffic, so it needs --net-active and a wordlist.",
	"llm-recon": "A language model reads the served surface and points out where a human should look by hand, based on what is observable. Its findings are leads to verify, not confirmed holes, and it spends money.",
	"subfinder": "Enumerates the subdomains of the target domain from public sources, so the scan covers the estate and not just the front door.",
	"dnsx":      "Resolves the discovered names and keeps the ones that answer DNS, trimming the list before anything is probed.",
	"httpx":     "Probes which hosts answer over HTTP or HTTPS, and what stack each one advertises — the live assets worth scanning.",
	"gowitness": "Loads each live asset in a headless browser and saves a screenshot, so a forgotten panel is obvious at a glance in the report.",
	"katana":    "Crawls each asset and hands the endpoints it finds to nuclei, so nuclei checks the pages a site actually has. Enabled with --crawl.",
}

// modesFor says which UI tabs a tool belongs to, from the engine's own
// vocabularies, so the desktop never hardcodes a grouping that could drift. A tool
// used by more than one tab lists them all.
func modesFor(name string) []string {
	var modes []string
	if contains(scan.AllTools, name) {
		modes = append(modes, "folder")
	}
	if contains(scan.NetTools, name) {
		modes = append(modes, "address")
	}
	// The domain tab runs the perimeter default passes plus discovery and extras.
	domain := append(append([]string(nil), perimeter.DefaultPasses...), perimeter.Tools...)
	domain = append(domain, perimeter.ScreenshotTool, perimeter.CrawlTool)
	if contains(domain, name) {
		modes = append(modes, "domain")
	}
	return modes
}

// doctorJSON prints the tool status as a JSON array, the surface the desktop reads
// to show what will run and to offer installs.
func doctorJSON(probes []probe, stdout *os.File) int {
	out := make([]toolStatus, 0, len(probes))
	for _, entry := range probes {
		out = append(out, toolStatus{
			Name: entry.name, Found: entry.found, Version: entry.version,
			Covers: entry.covers, Hint: entry.hint,
			Install: installCommand(entry.name, entry.found),
			Modes:   modesFor(entry.name),
			Detail:  toolDetail[entry.name],
		})
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}

// installOne installs a single tool by name, so the desktop can offer a button per
// missing tool. It runs the same package manager doctor --install uses.
func installOne(name string, stdout, stderr *os.File) int {
	if !installableNames[name] {
		fmt.Fprintf(stderr, "whatsrisky cannot install %q for you\n", name)
		return 1
	}
	command := installCommand(name, false)
	if command == "" {
		fmt.Fprintf(stderr, "no known install command for %q on this platform\n", name)
		return 1
	}
	if _, err := exec.LookPath("brew"); err != nil {
		fmt.Fprintln(stderr, "Homebrew not found; install it, or install the tool yourself.")
		return 1
	}
	fmt.Fprintf(stdout, "running: %s\n", command)
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return 1
	}
	fmt.Fprintf(stdout, "installed %s\n", name)
	return 0
}

// probe is what doctor reports about one scanner.
type probe struct {
	name    string
	found   bool
	version string
	hint    string
	covers  string
}

// brewPackage is the Homebrew spec for a tool where it differs from the tool's own
// name, so a one-click install runs the right formula or cask.
var brewPackage = map[string]string{
	"testssl": "brew install testssl",
}

// installCommand is how to install a tool on this platform, or "" when whatsrisky
// cannot do it for you (a non-Homebrew system, or a thing like an API key).
func installCommand(name string, found bool) string {
	if found || runtime.GOOS != "darwin" {
		return ""
	}
	if spec, ok := brewPackage[name]; ok {
		return spec
	}
	// Everything else installs as its own name.
	if _, known := installableNames[name]; known {
		return "brew install " + name
	}
	return ""
}

// installableNames is the set whatsrisky knows how to install: the scanners and the
// perimeter tools, all Homebrew formulae. "ai" is not here — you cannot brew a key.
var installableNames = map[string]bool{
	"semgrep": true, "trivy": true, "gitleaks": true,
	"testssl": true, "nuclei": true, "ffuf": true,
	"subfinder": true, "dnsx": true, "httpx": true, "gowitness": true, "katana": true,
}

func probeTools() []probe {
	config := runner.Config{Target: ".", WorkDir: os.TempDir(), AIProvider: "claude-cli"}
	// The filesystem scanners, then the network passes: doctor should say what is
	// installed for both kinds of scan.
	names := append(append([]string(nil), scan.AllTools...), scan.NetTools...)
	out := make([]probe, 0, len(names))
	for _, name := range names {
		covers := scan.ToolCoverage[name]
		if covers == "" {
			covers = scan.NetToolCoverage[name]
		}
		entry := probe{name: name, covers: covers}
		built, err := runner.New(name, config)
		switch {
		case err != nil:
			entry.hint = err.Error()
		case runner.Present(built):
			entry.found = true
			entry.version = built.Version()
		default:
			// Only ask why when it is actually missing: probing a healthy backend
			// for a failure reason produces a misleading string.
			entry.hint = built.UnavailableReason()
		}
		out = append(out, entry)
	}
	// The perimeter discovery tools are not runners (they feed the fan-out, they do
	// not produce findings), so they are probed directly. They are optional: a
	// perimeter scan degrades and says what it could not run.
	perimeterTools := append(append([]string(nil), perimeter.Tools...), perimeter.ScreenshotTool, perimeter.CrawlTool)
	for _, name := range perimeterTools {
		entry := probe{name: name, covers: perimeterCovers[name]}
		if path := proc.Which(name); path != "" {
			entry.found = true
			entry.version = proc.Version(name, "-version")
		} else {
			entry.hint = "`" + name + "` not found in PATH — used by `whatsrisky perimeter`"
		}
		out = append(out, entry)
	}
	return out
}

func cmdDoctor(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	install := flags.Bool("install", false, "install the missing scanners with the platform package manager")
	asJSON := flags.Bool("json", false, "print the tool status as JSON (for the desktop UI)")
	installTool := flags.String("install-tool", "", "install one named tool and exit (for the desktop UI)")
	if err := flags.Parse(args); err != nil {
		return 1
	}

	if *installTool != "" {
		return installOne(*installTool, stdout, stderr)
	}

	probes := probeTools()
	if *asJSON {
		return doctorJSON(probes, stdout)
	}
	fmt.Fprintln(stdout, "scanner    found  version / how to get it")
	var missing []probe
	for _, entry := range probes {
		mark := "no "
		detail := entry.hint
		if entry.found {
			mark = "yes"
			detail = entry.version
		} else {
			missing = append(missing, entry)
		}
		fmt.Fprintf(stdout, "%-10s %-6s %s\n", entry.name, mark, detail)
	}
	if len(missing) == 0 {
		fmt.Fprintln(stdout, "\nAll scanners present.")
		return 0
	}

	// Only the binaries can be installed for you; a missing API key cannot.
	var installable []string
	for _, entry := range missing {
		if strings.Contains(entry.hint, "not found in PATH") {
			installable = append(installable, entry.name)
		}
	}
	if *install && len(installable) > 0 {
		if runtime.GOOS != "darwin" {
			fmt.Fprintln(stderr, "\n--install only knows Homebrew; install these yourself:")
			for _, entry := range missing {
				fmt.Fprintf(stderr, "  %s: %s\n", entry.name, entry.hint)
			}
			return 1
		}
		if _, err := exec.LookPath("brew"); err != nil {
			fmt.Fprintln(stderr, "\nHomebrew not found; install the scanners manually.")
			return 1
		}
		fmt.Fprintf(stdout, "\nInstalling: %s\n", strings.Join(installable, " "))
		command := exec.Command("brew", append([]string{"install"}, installable...)...)
		command.Stdout, command.Stderr = stdout, stderr
		if err := command.Run(); err != nil {
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout)
	for _, entry := range missing {
		fmt.Fprintf(stdout, "%s: %s\n", entry.name, entry.hint)
	}
	return 1
}
