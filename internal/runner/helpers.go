package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
)

// Relative turns a scanner's path into one relative to the scanned project.
func Relative(root, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		if rel, err := filepath.Rel(root, path); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(path), "./")
}

const (
	maxSnippetBytes = 4_000_000
	maxSnippetChars = 1200
)

// ReadSnippet reads a few source lines around line for report context, marking
// the finding's own line. The marker is what lets an identity key ignore the
// context: see model.EvidenceOf.
func ReadSnippet(root, relFile string, line, context int) string {
	if relFile == "" || line < 1 {
		return ""
	}
	target := filepath.Join(root, relFile)
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	absoluteTarget, err := filepath.Abs(target)
	if err != nil || !strings.HasPrefix(absoluteTarget, absoluteRoot) {
		return ""
	}
	info, err := os.Stat(absoluteTarget)
	if err != nil || info.IsDir() || info.Size() > maxSnippetBytes {
		return ""
	}
	file, err := os.Open(absoluteTarget)
	if err != nil {
		return ""
	}
	defer file.Close()

	first, last := line-context, line+context
	if first < 1 {
		first = 1
	}
	var out []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for number := 1; scanner.Scan() && number <= last; number++ {
		if number < first {
			continue
		}
		marker := " "
		if number == line {
			marker = ">"
		}
		out = append(out, fmt.Sprintf("%s %5d | %s", marker, number, strings.TrimRight(scanner.Text(), " \t")))
	}
	text := strings.Join(out, "\n")
	if len(text) > maxSnippetChars {
		text = text[:maxSnippetChars]
	}
	return text
}

// asStrings accepts what scanners actually put in metadata: a string, a list of
// strings, or nothing.
func asStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return []string{single}
	}
	return nil
}

func limit(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}

// WriteFile writes a file the runner generates (a scanner config, a raw log).
func WriteFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

// ReadJSONFile parses a report a scanner wrote to disk.
func ReadJSONFile(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return fmt.Errorf("%s is empty", filepath.Base(path))
	}
	return json.Unmarshal(raw, into)
}

// ExtractJSON pulls the first plausible JSON object out of an LLM's answer, then
// repairs the mistakes LLMs actually make. Declared here because both the AI
// runner and its backends need it.
func ExtractJSON(text string) map[string]any {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	candidates := []string{text}
	if start := strings.Index(text, "{"); start >= 0 {
		if end := strings.LastIndex(text, "}"); end > start {
			candidates = append(candidates, text[start:end+1])
		}
	}
	for _, candidate := range candidates {
		var parsed map[string]any
		if json.Unmarshal([]byte(candidate), &parsed) == nil {
			return parsed
		}
		if json.Unmarshal([]byte(model.RepairJSON(candidate)), &parsed) == nil {
			return parsed
		}
	}
	return nil
}
