// Package runner holds one scanner per file. Each returns findings already on the
// shared severity scale, and each maps its own tool's levels explicitly - there is
// no generic translation, because there is no generic meaning.
package runner

import (
	"fmt"
	"runtime"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// Config is everything a runner needs to know about this scan.
type Config struct {
	Target  string
	WorkDir string

	// Scope: when set, only these paths are scanned (resolved from a git range).
	ScopePaths []string
	DiffRange  string
	Exclude    []string

	SemgrepConfigs []string
	SemgrepTimeout time.Duration

	TrivyScanners string
	TrivyTimeout  time.Duration
	TrivyOffline  bool

	GitleaksMode    string
	GitleaksTimeout time.Duration

	AIProvider     string
	AIModel        string
	AIMode         string
	AITimeout      time.Duration
	AIMaxFindings  int
	AIContextBytes int

	// Network scans. Target carries the URL; NetActive lets a pass send
	// attack-shaped traffic rather than only reading what is served.
	SurfaceTimeout time.Duration
	NucleiTimeout  time.Duration
	NetActive      bool
	Wordlist       string // path list for ffuf content discovery
}

// Outcome is what a scan produced, plus the things a report has to say about how
// it was produced.
type Outcome struct {
	Findings []model.Finding
	Command  string
	Stderr   string
	// Note is the honest remark: Trivy saying it ignored --diff, an API backend
	// saying it was handed a fixed context. It reaches the report.
	Note string
}

// Runner is one scanner.
type Runner interface {
	Name() string
	// Available reports whether this runner can do anything at all. Not every
	// runner is a binary on PATH: the AI pass asks its backend.
	Available() bool
	UnavailableReason() string
	Version() string
	Scan(progress func(string)) (Outcome, error)
}

// Progress is a no-op-safe progress callback.
func Progress(callback func(string)) func(string) {
	if callback == nil {
		return func(string) {}
	}
	return func(message string) {
		if text := model.CleanText(message); text != "" {
			if len(text) > 160 {
				text = text[:160]
			}
			callback(text)
		}
	}
}

// Run executes a runner and turns whatever happened into a ToolResult. A broken
// scanner must not kill the scan, so a failure is a status, not a panic.
func Run(runner Runner, progress func(string)) model.ToolResult {
	result := model.ToolResult{Name: runner.Name()}
	if !runner.Available() {
		result.Status = model.ToolMissing
		result.Message = runner.UnavailableReason()
		return result
	}
	result.Version = model.CleanText(runner.Version())

	started := time.Now()
	outcome, err := runner.Scan(Progress(progress))
	result.DurationS = time.Since(started).Seconds()
	if err != nil {
		result.Status = model.ToolError
		result.Message = model.CleanText(err.Error())
		return result
	}
	result.Status = model.ToolOK
	result.Findings = outcome.Findings
	result.Command = outcome.Command
	result.StderrTail = proc.Tail(outcome.Stderr, 12)
	result.Message = outcome.Note
	return result
}

// installHints are per-platform: telling a Linux user to run brew is not help.
type installHints map[string]string

func (h installHints) resolve() string {
	key := "linux"
	switch runtime.GOOS {
	case "darwin":
		key = "darwin"
	case "windows":
		key = "windows"
	}
	if hint, ok := h[key]; ok && hint != "" {
		return hint
	}
	return h["default"]
}

// binaryRunner is the shared part of a runner that is a binary on PATH.
type binaryRunner struct {
	binary string
	hints  installHints
	config Config
}

func (b binaryRunner) Available() bool { return proc.Which(b.binary) != "" }

func (b binaryRunner) UnavailableReason() string {
	return fmt.Sprintf("`%s` not found in PATH. Install: %s", b.binary, b.hints.resolve())
}

// InstallHint is what doctor prints for a missing scanner.
func (b binaryRunner) InstallHint() string { return b.hints.resolve() }

// New builds the runner for a scanner name.
func New(name string, config Config) (Runner, error) {
	switch name {
	case "semgrep":
		return NewSemgrep(config), nil
	case "trivy":
		return NewTrivy(config), nil
	case "gitleaks":
		return NewGitleaks(config), nil
	case "ai":
		return NewAI(config)
	case "surface":
		return NewSurface(config), nil
	case "testssl":
		return NewTestSSL(config), nil
	case "nuclei":
		return NewNuclei(config), nil
	case "zap":
		return NewZAP(config), nil
	case "ffuf":
		return NewFfuf(config), nil
	case "llm-recon":
		return NewLLMRecon(config)
	}
	return nil, fmt.Errorf("unknown scanner %q", name)
}

// gitProbeTimeout bounds the "is this a git repo" question.
const gitProbeTimeout = 15 * time.Second
