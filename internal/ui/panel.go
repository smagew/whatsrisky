package ui

import (
	"fmt"
	"strings"

	"github.com/smagew/whatsrisky/internal/exclude"
	"github.com/smagew/whatsrisky/internal/scan"
)

// panelText is what the screen implies, written out: which scanners are actually
// installed, the command these settings amount to, and anything worth saying
// before a scan rather than after it.
func (u *UI) panelText(options scan.Options, width int) string {
	inner := maxInt(16, width-2)
	var out strings.Builder

	out.WriteString(titleTag + "Scanners on this machine" + resetTag + "\n")
	if u.probing {
		out.WriteString(dimTag + "checking…" + resetTag + "\n")
	}
	for _, entry := range u.probes {
		if entry.found {
			out.WriteString(fmt.Sprintf("%s✓%s %-9s %s%s%s\n", passTag, resetTag, entry.name,
				dimTag, shorten(entry.detail, maxInt(12, inner-12)), resetTag))
			continue
		}
		// The reason a scanner is missing gets its own wrapped lines rather than
		// being truncated: "not found in PATH. Install: ..." is the actionable
		// half, and it is the half an ellipsis eats.
		out.WriteString(fmt.Sprintf("%s✗%s %s\n", flagTag, resetTag, entry.name))
		for _, line := range wrapLines(entry.detail, inner-2) {
			out.WriteString("  " + dimTag + line + resetTag + "\n")
		}
	}

	out.WriteString("\n" + titleTag + "Same thing, as a command" + resetTag + "\n")
	// Wrapped between arguments, never inside one: a command that reads as
	// broken is worse than no panel at all.
	out.WriteString(commandTag + wrapArguments(options.CommandLine(), inner) + resetTag + "\n")

	out.WriteString("\n" + titleTag + "What we do not look at" + resetTag + "\n")
	if options.UseDefaultExcludes {
		out.WriteString(fmt.Sprintf("%s%d folders and files we always skip%s\n",
			dimTag, len(exclude.Defaults), resetTag))
		out.WriteString(markTag + "ctrl+i" + resetTag + dimTag + " shows the list" + resetTag + "\n")
	} else {
		out.WriteString(dimTag + "nothing, unless you named it above" + resetTag + "\n")
	}
	if yours := splitCommas(u.values.ignorePaths); len(yours) > 0 {
		out.WriteString(fmt.Sprintf("%splus yours: %s%s\n", dimTag,
			shorten(strings.Join(yours, ", "), inner-12), resetTag))
	}

	if warnings := u.warnings(options); len(warnings) > 0 {
		out.WriteString("\n" + titleTag + "Before you run" + resetTag + "\n")
		for _, warning := range warnings {
			for index, wrapped := range wrapLines(warning, inner-2) {
				if index == 0 {
					out.WriteString(markTag + "• " + resetTag + wrapped + "\n")
					continue
				}
				out.WriteString("  " + wrapped + "\n")
			}
		}
	}

	if names := profileNames(); len(names) > 0 {
		out.WriteString("\n" + titleTag + "Saved settings" + resetTag + "\n")
		out.WriteString(dimTag + shorten(strings.Join(names, ", "), inner) + resetTag + "\n")
	}
	return out.String()
}

// wrapArguments breaks a command line between arguments, never inside one. A
// token that cannot fit is truncated with an ellipsis, because a silently split
// path looks like a command you could copy, and is not.
func wrapArguments(command string, width int) string {
	return strings.Join(wrapFields(strings.Fields(command), width), "\n")
}

func wrapLines(text string, width int) []string {
	return wrapFields(strings.Fields(text), width)
}

func wrapFields(tokens []string, width int) []string {
	if width < 8 {
		width = 8
	}
	var lines []string
	current := ""
	for _, token := range tokens {
		switch {
		case current == "":
			current = token
		case len([]rune(current))+1+len([]rune(token)) <= width:
			current += " " + token
		default:
			lines = append(lines, current)
			current = token
		}
		if len([]rune(current)) > width {
			lines = append(lines, shorten(current, width))
			current = ""
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func shorten(text string, limit int) string {
	text = strings.ReplaceAll(text, "\n", " ")
	if len([]rune(text)) <= limit {
		return text
	}
	return string([]rune(text)[:maxInt(1, limit-1)]) + "…"
}
