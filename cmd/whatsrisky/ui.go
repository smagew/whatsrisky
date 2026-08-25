package main

import (
	"fmt"
	"os"
)

// cmdUI is phase 5 of docs/go-rewrite.md. Until then it says so and points at the
// flags, rather than opening an empty window.
func cmdUI(args []string, stdout, stderr *os.File) int {
	fmt.Fprintln(stderr, "the terminal UI is not ported yet (phase 5 of docs/go-rewrite.md).")
	fmt.Fprintln(stderr, "Scan from the command line meanwhile:")
	fmt.Fprintln(stderr, "  whatsrisky <path> [--ai] [--diff HEAD~1..HEAD] [--open]")
	fmt.Fprintln(stderr, "  whatsrisky scan --help")
	return 1
}
