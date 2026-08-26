package main

import (
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

// probe is what doctor reports about one scanner.
type probe struct {
	name    string
	found   bool
	version string
	hint    string
	covers  string
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
		case built.Available():
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
	for _, name := range perimeter.Tools {
		entry := probe{name: name, covers: "perimeter discovery (optional)"}
		if path := proc.Which(name); path != "" {
			entry.found = true
			entry.version = proc.Version(name, "-version")
		} else {
			entry.hint = "`" + name + "` not found in PATH — needed for `whatsrisky perimeter`"
		}
		out = append(out, entry)
	}
	return out
}

func cmdDoctor(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	install := flags.Bool("install", false, "install the missing scanners with the platform package manager")
	if err := flags.Parse(args); err != nil {
		return 1
	}

	probes := probeTools()
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
