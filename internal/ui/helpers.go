package ui

import "strings"

func commaList(values []string) string { return strings.Join(values, ",") }

func splitCommas(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
