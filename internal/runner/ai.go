package runner

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/smagew/whatsrisky/internal/ai"
	"github.com/smagew/whatsrisky/internal/model"
	"github.com/smagew/whatsrisky/internal/scan"
)

// AI is the review pass. Which model runs it is a backend's business; this owns
// the prompts, the strict-JSON contract with the model, repairing the JSON it
// gets back, and turning the answer into findings on the shared severity scale.
type AI struct {
	config      Config
	backend     ai.Backend
	model       string
	summary     string
	coverage    string
	contextText string
	contextNote string
	costUSD     float64
	turns       int
	notes       []string
}

// NewAI builds the runner, resolving the backend up front so an unknown provider
// is an error here rather than a surprise mid-scan.
func NewAI(config Config) (Runner, error) {
	backend, err := ai.New(config.AIProvider, config.Target, config.WorkDir)
	if err != nil {
		return nil, err
	}
	chosen := config.AIModel
	if chosen == "" {
		chosen = backend.DefaultModel()
	}
	return &AI{config: config, backend: backend, model: chosen}, nil
}

func (a *AI) Name() string { return "ai" }

func (a *AI) Available() bool {
	ok, _ := a.backend.Available()
	return ok
}

func (a *AI) UnavailableReason() string {
	_, reason := a.backend.Available()
	if reason == "" {
		return fmt.Sprintf("the %s backend is unavailable", a.backend.Name())
	}
	return reason
}

func (a *AI) Version() string {
	return a.backend.Version() + " · model " + a.model
}

// prepareContext builds what a non-agentic backend gets to see. An agentic one
// needs none, and asking for one would be a lie about how it works.
func (a *AI) prepareContext(progress func(string)) {
	if a.backend.Agentic() {
		return
	}
	excluded := func(rel string) bool { return scan.PathExcluded(rel, a.config.Exclude) }
	text, included, skipped := ai.BuildContext(
		a.config.Target, excluded, a.config.ScopePaths, a.config.AIContextBytes)
	a.contextText = text
	a.contextNote = fmt.Sprintf(
		"the %s backend cannot read the repository itself, so it saw %d file(s)",
		a.backend.Name(), len(included))
	if skipped > 0 {
		a.contextNote += fmt.Sprintf(" and %d were left out for size", skipped)
	}
	a.notes = append(a.notes, a.contextNote)
	progress(fmt.Sprintf("prepared %d file(s) of context", len(included)))
}

func (a *AI) ask(prompt, label string, progress func(string)) (string, string, error) {
	progress(fmt.Sprintf("%s pass on %s · %s", label, a.backend.Name(), a.model))
	answer, err := a.backend.Ask(ai.Request{
		Prompt: prompt, Model: a.model, Timeout: a.config.AITimeout,
		Context: a.contextText, Progress: progress,
	})
	if err != nil {
		return "", "", err
	}
	_ = WriteFile(filepath.Join(a.config.WorkDir, "ai-"+label+".txt"), answer.Text)
	a.costUSD += answer.CostUSD
	a.turns += answer.Turns
	a.notes = append(a.notes, answer.Notes...)
	return answer.Text, fmt.Sprintf("%s:%s model=%s", a.backend.Name(), label, a.model), nil
}

func (a *AI) passFull(progress func(string)) ([]model.Finding, []string, error) {
	prompt := strings.ReplaceAll(fullPrompt, "{max_findings}", strconv.Itoa(a.config.AIMaxFindings))
	if len(a.config.Exclude) > 0 {
		prompt += "\nIgnore these paths entirely: " + strings.Join(limit(a.config.Exclude, 40), ", ") + "\n"
	}
	if len(a.config.ScopePaths) > 0 {
		listed := "- " + strings.Join(limit(a.config.ScopePaths, 200), "\n- ")
		prompt += fmt.Sprintf("\nScope: audit ONLY these files (changed by `%s`), reading whatever "+
			"else you need for context:\n%s\n", a.config.DiffRange, listed)
	}

	text, command, err := a.ask(prompt, "full", progress)
	if err != nil {
		return nil, nil, err
	}
	commands := []string{command}
	if parsed := ExtractJSON(text); parsed == nil || parsed["findings"] == nil {
		// The audit ran but the JSON is unusable - reshape it instead of losing it.
		convert := strings.ReplaceAll(convertPrompt, "{review_text}", model.Truncate(text, 60000))
		reshaped, second, convertErr := a.ask(convert, "full-convert", progress)
		if convertErr != nil {
			return nil, commands, convertErr
		}
		text = reshaped
		commands = append(commands, second)
	}
	findings, err := a.parse(text, "full")
	return findings, commands, err
}

func (a *AI) passReview(progress func(string)) ([]model.Finding, []string, error) {
	if !a.backend.Agentic() {
		// Refuse rather than return a confident empty answer.
		return nil, nil, fmt.Errorf("the %s backend cannot review a diff: it has no access to git. "+
			"Use --ai-mode full, or --ai-provider claude-cli", a.backend.Name())
	}
	target := "the pending changes on the current branch (the diff against its merge base)"
	if a.config.DiffRange != "" {
		target = fmt.Sprintf("the diff `%s`", a.config.DiffRange)
	}
	prompt := strings.ReplaceAll(reviewPrompt, "{diff_target}", target)

	text, command, err := a.ask(prompt, "review", progress)
	if err != nil {
		return nil, nil, err
	}
	commands := []string{command}
	if parsed := ExtractJSON(text); parsed == nil || parsed["findings"] == nil {
		convert := strings.ReplaceAll(convertPrompt, "{review_text}", model.Truncate(text, 60000))
		reshaped, second, convertErr := a.ask(convert, "review-convert", progress)
		if convertErr != nil {
			return nil, commands, convertErr
		}
		text = reshaped
		commands = append(commands, second)
	}
	findings, err := a.parse(text, "security-review")
	return findings, commands, err
}

func (a *AI) Scan(progress func(string)) (Outcome, error) {
	a.prepareContext(progress)

	var modes []string
	switch a.config.AIMode {
	case "review":
		modes = []string{"review"}
	case "both":
		modes = []string{"full", "review"}
	default:
		modes = []string{"full"}
	}

	var findings []model.Finding
	var commands []string
	seen := map[string]bool{}
	for _, mode := range modes {
		var (
			got  []model.Finding
			cmds []string
			err  error
		)
		if mode == "full" {
			got, cmds, err = a.passFull(progress)
		} else {
			got, cmds, err = a.passReview(progress)
		}
		commands = append(commands, cmds...)
		if err != nil {
			return Outcome{}, err
		}
		for _, finding := range got {
			if seen[finding.Fingerprint()] {
				continue
			}
			seen[finding.Fingerprint()] = true
			findings = append(findings, finding)
		}
	}
	return Outcome{
		Findings: findings,
		Command:  strings.Join(commands, " && "),
		Note:     a.note(),
	}, nil
}

// note is what the report says about how the model saw the project. An agentic
// backend read it; an API backend was handed a slice. Those are not the same
// analysis, and a reader must not have to guess which happened.
func (a *AI) note() string {
	how := "was given a fixed context"
	if a.backend.Agentic() {
		how = "explored the repository itself"
	}
	lines := []string{fmt.Sprintf("%s · %s · %s", a.backend.Name(), a.model, how)}
	seen := map[string]bool{lines[0]: true}
	for _, note := range append(a.notes, a.summary) {
		if note != "" && !seen[note] {
			seen[note] = true
			lines = append(lines, note)
		}
	}
	if a.costUSD > 0 {
		lines = append(lines, fmt.Sprintf("[cost $%.2f, %d turns]", a.costUSD, a.turns))
	}
	return strings.Join(lines, "\n\n")
}

// parse turns the model's JSON into findings.
func (a *AI) parse(text, source string) ([]model.Finding, error) {
	data := ExtractJSON(text)
	if data == nil {
		return nil, fmt.Errorf("could not parse JSON from the %s pass; the raw answer is in %s",
			source, a.config.WorkDir)
	}
	if summary := asString(data["summary"]); summary != "" {
		a.summary = strings.TrimSpace(a.summary + "\n\n" + summary)
	}
	if coverage := asString(data["coverage"]); coverage != "" {
		a.coverage = strings.TrimSpace(a.coverage + "\n\n" + coverage)
	}

	raw, _ := data["findings"].([]any)
	findings := make([]model.Finding, 0, len(raw))
	for _, entry := range raw {
		item, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		description := model.Truncate(asString(item["description"]), 4000)
		if attack := model.Truncate(asString(item["attack_scenario"]), 2000); attack != "" {
			description = strings.TrimSpace(description + "\n\nAttack scenario: " + attack)
		}
		file := Relative(a.config.Target, asString(item["file"]))
		line := asInt(item["line"])
		category := asString(item["category"])
		if category == "" {
			category = source
		}

		finding := model.Finding{
			Tool:            "ai",
			Severity:        model.ParseSeverity(asString(item["severity"]), model.Medium),
			Title:           model.Truncate(orText(asString(item["title"]), "Unnamed finding"), 140),
			Description:     description,
			ScannerCategory: "AI/" + category,
			RuleID:          "ai:" + source,
			File:            file,
			Line:            line,
			CWE:             asStringList(item["cwe"]),
			Remediation:     model.Truncate(asString(item["remediation"]), 2000),
			Confidence:      asString(item["confidence"]),
			Snippet:         ReadSnippet(a.config.Target, file, line, 2),
			Provider:        ai.Vendor[a.backend.Name()],
			Model:           a.model,
			Pass:            passName(source),
			Raw:             map[string]string{"source": source},
		}
		finding.Normalize()
		findings = append(findings, finding)
	}
	return findings, nil
}

func passName(source string) string {
	if source == "full" {
		return "full"
	}
	return "review"
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func asInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		if number, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return number
		}
	}
	return 0
}

func asStringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range items {
		if text := strings.TrimSpace(asString(item)); text != "" {
			out = append(out, text)
		}
	}
	return out
}
