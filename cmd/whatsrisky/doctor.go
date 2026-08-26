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
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Version string `json:"version"`
	Covers  string `json:"covers"`
	Hint    string `json:"hint"`
	Install string `json:"install"` // the command to install it, or "" if we cannot
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
		covers := "perimeter discovery (optional)"
		if name == perimeter.ScreenshotTool {
			covers = "perimeter screenshots (optional)"
		}
		if name == perimeter.CrawlTool {
			covers = "perimeter crawl for --crawl (optional)"
		}
		entry := probe{name: name, covers: covers}
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
