// Command whatsrisky answers one question about a codebase: what's risky here?
package main

import (
	"fmt"
	"os"
)

// Version is the package version, and the one stamped into every report. It is
// the only place it is written; -ldflags can override it for a build.
var Version = "0.3.2"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	command := "scan"
	rest := args
	switch {
	case len(args) == 0:
		command = "ui"
		rest = nil
	case args[0] == "scan" || args[0] == "ui" || args[0] == "doctor" || args[0] == "profiles" || args[0] == "version":
		command, rest = args[0], args[1:]
	case args[0] == "-h" || args[0] == "--help" || args[0] == "help":
		usage(stdout)
		return 0
	case args[0] == "--version":
		fmt.Fprintf(stdout, "whatsrisky %s\n", Version)
		return 0
	}

	switch command {
	case "scan":
		return cmdScan(rest, stdout, stderr)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	case "profiles":
		return cmdProfiles(rest, stdout, stderr)
	case "ui":
		return cmdUI(rest, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "whatsrisky %s\n", Version)
		return 0
	}
	usage(stderr)
	return 1
}

func usage(out *os.File) {
	fmt.Fprint(out, `whatsrisky — what's risky in this project?

Usage:
  whatsrisky <path> [flags]     scan a project
  whatsrisky ui [path]          interactive settings UI (the default with no arguments)
  whatsrisky doctor [--install] check that the scanners are installed
  whatsrisky profiles           list or delete saved setting profiles
  whatsrisky --version

Run "whatsrisky scan --help" for every scan flag.
`)
}
