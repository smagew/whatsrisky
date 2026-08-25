// Package ai holds the backends that can run the review pass.
//
// Two kinds, and the difference is not cosmetic:
//
//   - An agentic backend (the claude CLI) explores the repository itself with read
//     tools. It decides what to open and follows data flow across files.
//   - An API backend sees only the context we hand it. It cannot go looking, so
//     the quality ceiling is set by our file selection.
//
// Those are different analyses of different strength, so Agentic is part of the
// contract and reaches the report: a reader must be able to tell which one
// produced a finding.
package ai

import (
	"fmt"
	"time"
)

// Answer is what a backend returns: the model's text plus what it cost.
type Answer struct {
	Text    string
	CostUSD float64
	Turns   int
	Notes   []string
}

// Request is one pass.
type Request struct {
	Prompt   string
	Model    string
	Timeout  time.Duration
	Context  string // empty for an agentic backend, which does its own reading
	Progress func(string)
}

// Backend runs the model.
type Backend interface {
	Name() string
	// Agentic reports whether the backend reads the repository itself.
	Agentic() bool
	DefaultModel() string
	// Available returns (usable, reason when not).
	Available() (bool, string)
	Version() string
	Ask(Request) (Answer, error)
}

// Vendor is who runs the model behind each backend, for the report's
// detector.provider.
var Vendor = map[string]string{
	"claude-cli": "anthropic",
	"openai":     "openai",
}

// Providers is every backend name, in the order they are offered.
var Providers = []string{"claude-cli", "openai"}

// New builds a backend. cwd is the project being scanned; workDir is where raw
// transcripts are kept.
func New(provider, cwd, workDir string) (Backend, error) {
	switch provider {
	case "claude-cli":
		return &ClaudeCLI{cwd: cwd, workDir: workDir}, nil
	case "openai":
		return NewOpenAI(cwd, workDir)
	}
	return nil, fmt.Errorf("unknown ai provider %q; known: claude-cli, openai", provider)
}

func progressOf(callback func(string)) func(string) {
	if callback == nil {
		return func(string) {}
	}
	return callback
}
