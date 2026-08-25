package ai

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/proc"
)

// ClaudeCLI runs the review through the Claude Code CLI, which explores the
// repository itself. Headless, with a read-only tool allowlist, so it cannot
// modify the project being scanned.
type ClaudeCLI struct {
	cwd     string
	workDir string
}

// readOnlyTools is the allowlist. Anything not named here is refused, and in
// headless mode a refused tool is simply not used - which is what keeps a scan
// from editing the project it is scanning.
var readOnlyTools = strings.Join([]string{
	"Read", "Grep", "Glob", "Skill", "TodoWrite",
	"Bash(git log:*)", "Bash(git diff:*)", "Bash(git status:*)", "Bash(git show:*)",
	"Bash(git branch:*)", "Bash(git rev-parse:*)", "Bash(git merge-base:*)",
	"Bash(git ls-files:*)", "Bash(rg:*)", "Bash(ls:*)", "Bash(find:*)",
	"Bash(cat:*)", "Bash(head:*)", "Bash(wc:*)",
}, ",")

func (c *ClaudeCLI) Name() string         { return "claude-cli" }
func (c *ClaudeCLI) Agentic() bool        { return true }
func (c *ClaudeCLI) DefaultModel() string { return "opus" }

func (c *ClaudeCLI) Available() (bool, string) {
	if proc.Which("claude") != "" {
		return true, ""
	}
	return false, "`claude` not found in PATH. Install: npm install -g @anthropic-ai/claude-code"
}

func (c *ClaudeCLI) Version() string { return "claude " + proc.Version("claude") }

type streamEvent struct {
	Type    string `json:"type"`
	Message struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Text  string          `json:"text"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	} `json:"message"`
	Result       string  `json:"result"`
	IsError      bool    `json:"is_error"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	NumTurns     int     `json:"num_turns"`
}

// describeToolUse turns a tool_use block into something worth reading: "Read
// app.py" beats a raw payload, and it is the difference between watching a
// spinner and seeing which files the reviewer is opening.
func describeToolUse(name string, input json.RawMessage) string {
	var args map[string]any
	if json.Unmarshal(input, &args) != nil {
		return name
	}
	for _, field := range []string{"file_path", "path", "pattern", "command", "query", "notebook_path"} {
		if value, ok := args[field]; ok {
			text := fmt.Sprint(value)
			if text != "" {
				if len(text) > 120 {
					text = text[:120]
				}
				return name + ": " + text
			}
		}
	}
	return name
}

func (c *ClaudeCLI) Ask(request Request) (Answer, error) {
	progress := progressOf(request.Progress)
	var final *streamEvent

	onLine := func(line string) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			return
		}
		var event streamEvent
		if json.Unmarshal([]byte(line), &event) != nil {
			return
		}
		switch event.Type {
		case "assistant":
			for _, block := range event.Message.Content {
				switch block.Type {
				case "tool_use":
					progress(describeToolUse(block.Name, block.Input))
				case "text":
					if head := firstLine(block.Text); head != "" && !strings.HasPrefix(head, "{") && !strings.HasPrefix(head, "[") {
						progress(head)
					}
				}
			}
		case "result":
			copied := event
			final = &copied
		}
	}

	argv := []string{
		"claude", "-p", request.Prompt, "--model", request.Model,
		// stream-json reports each step as it happens; json would only speak at the end.
		"--output-format", "stream-json", "--verbose",
		"--allowed-tools", readOnlyTools,
	}
	result, err := proc.Run(argv, proc.Options{
		Dir: c.cwd, Timeout: request.Timeout, OnStdout: onLine,
	})
	if err != nil {
		return Answer{}, err
	}
	_ = writeRaw(filepath.Join(c.workDir, "ai-claude-cli.raw.jsonl"), result.Stdout)
	if result.TimedOut {
		return Answer{}, fmt.Errorf("the claude CLI timed out after %s", request.Timeout)
	}

	if final != nil {
		if final.IsError {
			return Answer{}, fmt.Errorf("the claude CLI failed: %s", model.Truncate(final.Result, 400))
		}
		if strings.TrimSpace(final.Result) == "" {
			return Answer{}, fmt.Errorf("the claude CLI returned an empty answer after %d turn(s)", final.NumTurns)
		}
		return Answer{Text: final.Result, CostUSD: final.TotalCostUSD, Turns: final.NumTurns}, nil
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return Answer{Text: result.Stdout}, nil
	}
	return Answer{}, fmt.Errorf("the claude CLI returned nothing (exit %d): %s",
		result.ExitCode, model.Truncate(result.Stderr, 400))
}

func firstLine(text string) string {
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
