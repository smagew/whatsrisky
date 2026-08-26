package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/config"
	"github.com/smagew/whatsrisky/internal/report"
	"github.com/smagew/whatsrisky/internal/scan"
	"github.com/smagew/whatsrisky/internal/ui"
)

func cmdUI(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("ui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profileName := flags.String("profile", "", "start from a saved profile (default: the active one)")
	positional, err := parseInterleaved(flags, args)
	if err != nil {
		return 1
	}

	// Where we are is what we scan, unless a path was given. Everything else
	// follows from that folder, not from whatever was scanned last.
	target := ""
	if len(positional) > 0 {
		target = positional[0]
	}
	if target == "" {
		if cwd, err := os.Getwd(); err == nil {
			target = cwd
		}
	}
	if absolute, err := filepath.Abs(target); err == nil {
		target = absolute
	}

	// A named profile is asked for explicitly, so it wins. Otherwise the folder's
	// own settings, and otherwise the defaults - never the last run in some other
	// project.
	var options scan.Options
	profile := *profileName
	if profile != "" {
		loaded, ok := config.LoadProfile(profile)
		if !ok {
			fmt.Fprintf(stderr, "no such profile: %s (have: %s)\n",
				profile, orNone(strings.Join(config.ProfileNames(), ", ")))
			return 1
		}
		options = loaded
	} else {
		options, profile = config.StartupOptions(target)
	}
	options.Path = target

	report.Version = Version
	code, err := ui.Run(Version, options, profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return code
}
