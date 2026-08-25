package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/smagew/whatsrisky/internal/config"
)

func cmdProfiles(args []string, stdout, stderr *os.File) int {
	flags := flag.NewFlagSet("profiles", flag.ContinueOnError)
	flags.SetOutput(stderr)
	remove := flags.String("delete", "", "profile name to remove")
	if err := flags.Parse(args); err != nil {
		return 1
	}

	if *remove != "" {
		if config.DeleteProfile(*remove) {
			fmt.Fprintf(stdout, "deleted %s\n", *remove)
			return 0
		}
		fmt.Fprintf(stderr, "no such profile: %s\n", *remove)
		return 1
	}

	names := config.ProfileNames()
	if len(names) == 0 {
		fmt.Fprintln(stdout, "No saved profiles. Create one in the UI (`whatsrisky ui`) "+
			"or with --save-profile.")
		return 0
	}
	active := config.ActiveProfile()
	fmt.Fprintf(stdout, "profiles in %s\n\n", config.Path())
	for _, name := range names {
		marker := " "
		if name == active {
			marker = "*"
		}
		line := "-"
		if options, ok := config.LoadProfile(name); ok {
			line = options.CommandLine()
		}
		fmt.Fprintf(stdout, "%s %s\n    %s\n", marker, name, line)
	}
	if active != "" {
		fmt.Fprintf(stdout, "\n* the active profile: a launch starts from it\n")
	}
	return 0
}
