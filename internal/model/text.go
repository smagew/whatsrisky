package model

import (
	"regexp"
	"strings"
)

var (
	ansi    = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	control = regexp.MustCompile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

	// Evidence as we render it carries a line-number gutter and, for context, the
	// neighbouring lines. Neither may enter an identity key: the gutter changes
	// when a line drifts and the neighbours change when the code moves, and both
	// would make the same finding look like a different one.
	snippetGutter = regexp.MustCompile(`^[>\s]*\d+\s*\|\s?`)
	markedLine    = regexp.MustCompile(`^\s*>`)
)

// CleanText strips ANSI escapes and control characters. Scanner stderr carries
// both, and they are not printable anywhere we send them.
func CleanText(value string) string {
	value = ansi.ReplaceAllString(value, "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return control.ReplaceAllString(value, "")
}

// EvidenceOf reduces a snippet to the offending code itself.
//
// A marked snippet (our own reader marks the finding's line with ">") reduces to
// the marked lines. An unmarked one is already just the match - that is what the
// scanners hand us - so it is kept whole.
func EvidenceOf(snippet string) string {
	lines := strings.Split(snippet, "\n")
	if snippet == "" {
		lines = nil
	}
	var marked []string
	for _, line := range lines {
		if markedLine.MatchString(line) {
			marked = append(marked, line)
		}
	}
	chosen := marked
	if len(chosen) == 0 {
		chosen = lines
	}
	parts := make([]string, 0, len(chosen))
	for _, line := range chosen {
		collapsed := strings.Join(strings.Fields(snippetGutter.ReplaceAllString(line, "")), " ")
		parts = append(parts, collapsed)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// Truncate shortens text for a report field, marking that it was cut.
func Truncate(text string, limit int) string {
	text = strings.TrimSpace(CleanText(text))
	if len([]rune(text)) <= limit {
		return text
	}
	return strings.TrimRight(string([]rune(text)[:limit-1]), " ") + "…"
}
