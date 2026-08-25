package scan

import (
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultExcludes is vendored, generated and build output. Scanning it produces
// findings nobody can act on, in code nobody in the project wrote.
var DefaultExcludes = []string{
	".git", ".hg", ".svn",
	"node_modules", "bower_components", "jspm_packages",
	"vendor", "third_party", "thirdparty", "Pods", "Carthage",
	".venv", "venv", "env", "virtualenv", "site-packages",
	"dist", "build", "out", "target", "bin", "obj",
	".next", ".nuxt", ".svelte-kit", ".output", ".parcel-cache", ".turbo",
	"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
	".gradle", ".m2", ".cargo", ".terraform", ".serverless",
	"coverage", "htmlcov", ".nyc_output",
	"*.min.js", "*.min.css", "*.map", "*.lock.json",
	".idea", ".vscode", ".DS_Store",
	"whatsrisky-reports",
}

const globChars = "*?["

// NormalizePattern trims the shapes people actually type.
func NormalizePattern(pattern string) string {
	pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
	return strings.Trim(pattern, "/")
}

func hasGlob(pattern string) bool { return strings.ContainsAny(pattern, globChars) }

// PathExcluded reports whether a project-relative path falls under one of the
// exclusions.
//
// A bare name (`node_modules`) matches that path segment anywhere; a pattern with
// a slash (`src/generated`) matches that subtree; a glob (`*.min.js`) matches the
// whole path, the basename, or any single segment.
func PathExcluded(relPath string, patterns []string) bool {
	path := strings.Trim(strings.ReplaceAll(relPath, "\\", "/"), "/")
	if path == "" {
		return false
	}
	segments := strings.Split(path, "/")
	base := segments[len(segments)-1]

	for _, raw := range patterns {
		pattern := NormalizePattern(raw)
		if pattern == "" {
			continue
		}
		switch {
		case hasGlob(pattern):
			if match(pattern, path) || match(pattern, base) {
				return true
			}
			for _, segment := range segments {
				if match(pattern, segment) {
					return true
				}
			}
		case strings.Contains(pattern, "/"):
			if path == pattern || strings.HasPrefix(path, pattern+"/") {
				return true
			}
		default:
			for _, segment := range segments {
				if segment == pattern {
					return true
				}
			}
		}
	}
	return false
}

func match(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

// PatternToRegex renders an exclusion as a Go-flavoured regex, which is what
// gitleaks needs: it has no exclude flag, so paths are excluded through a
// generated config allowlist.
func PatternToRegex(pattern string) string {
	pattern = NormalizePattern(pattern)
	if pattern == "" {
		return ""
	}
	var escaped strings.Builder
	for _, char := range pattern {
		switch char {
		case '*':
			escaped.WriteString("[^/]*")
		case '?':
			escaped.WriteString("[^/]")
		default:
			escaped.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	return "(^|/)" + escaped.String() + "(/|$)"
}
