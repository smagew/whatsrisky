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

	// The active profile decides what the form starts from - a profile you saved is
	// what you meant to come back to - with the last run as the fallback.
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
		_ = config.SetActiveProfile(profile)
		if last, hadLast := config.LoadLast(); hadLast {
			options.Path = last.Path
		}
	} else {
		options, profile = config.StartupOptions()
	}
	if len(positional) > 0 {
		options.Path = positional[0]
	}
	if options.Path == "" {
		if cwd, err := os.Getwd(); err == nil {
			options.Path = cwd
		}
	}
	if absolute, err := filepath.Abs(options.Path); err == nil {
		options.Path = absolute
	}

	report.Version = Version
	code, err := ui.Run(Version, options, profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return code
}
