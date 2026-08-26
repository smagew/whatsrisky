package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/smagew/whatsrisky/internal/ai"
)

// cmdModels prints the models each AI provider is usually asked for, as JSON, so a
// front end offers the same names the CLI and TUI do rather than a hardcoded list
// that could drift. An id not listed is still accepted by the scan.
func cmdModels(_ []string, stdout, _ *os.File) int {
	out := map[string][]string{}
	for _, provider := range ai.Providers {
		out[provider] = ai.Models(provider)
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, string(body))
	return 0
}
