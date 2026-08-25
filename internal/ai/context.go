package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Context for backends that cannot explore the repository themselves.
//
// An API backend sees only what we send, so what we send decides what it can
// find. The selection is deliberate and stated in the report: the files most
// likely to hold an exploitable flaw first, within a byte budget. This is a weaker
// analysis than an agentic backend doing its own reading, and the report says so
// rather than presenting the two as equivalent.

type priority struct {
	pattern *regexp.Regexp
	weight  int
}

// Where flaws live, in the order we would read them ourselves.
var priorities = []priority{
	{regexp.MustCompile(`(?i)(^|/)(auth|authn|authz|login|session|permission|acl|rbac)`), 100},
	{regexp.MustCompile(`(?i)(^|/)(route|routes|handler|handlers|controller|controllers|api|views?|endpoints?)`), 90},
	{regexp.MustCompile(`(?i)(^|/)(middleware|filters?|guards?|interceptors?)`), 85},
	{regexp.MustCompile(`(?i)(^|/)(models?|schema|db|database|repository|dao|queries)`), 70},
	{regexp.MustCompile(`(?i)(^|/)(upload|file|download|export|import|template|render)`), 65},
	{regexp.MustCompile(`(?i)(^|/)(config|settings|env|secrets?)`), 60},
	{regexp.MustCompile(`(?i)(^|/)(util|utils|helpers?|lib)`), 40},
	{regexp.MustCompile(`(?i)(^|/)(tests?|spec|fixtures?|examples?|docs?)`), -50},
}

var codeExtensions = map[string]bool{
	".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true,
	".jsx": true, ".go": true, ".rb": true, ".php": true, ".java": true, ".kt": true,
	".cs": true, ".rs": true, ".scala": true, ".swift": true, ".c": true, ".cc": true,
	".cpp": true, ".h": true, ".hpp": true, ".sh": true, ".bash": true, ".sql": true,
	".tf": true, ".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".env": true, ".conf": true, ".ini": true,
}

var alwaysInteresting = regexp.MustCompile(
	`(?i)(^|/)(dockerfile|containerfile|makefile|requirements[^/]*\.txt|package\.json|go\.mod|pom\.xml|build\.gradle)$`)

const (
	maxCandidateBytes = 400_000
	smallFileBytes    = 40_000
	largeFileBytes    = 120_000
)

// Candidate is a file that could be sent, with the score that ordered it.
type Candidate struct {
	Path string
	Size int64
}

func score(rel string, size int64) int {
	total := 0
	for _, entry := range priorities {
		if entry.pattern.MatchString(rel) {
			total += entry.weight
		}
	}
	if alwaysInteresting.MatchString(rel) {
		total += 80
	}
	// A 4 KB handler is likelier to be readable and relevant than a 400 KB blob.
	switch {
	case size > largeFileBytes:
		total -= 60
	case size < smallFileBytes:
		total += 10
	}
	return total
}

// Candidates lists the files worth sending, best first. excluded decides what is
// off limits; scope, when set, is the diff's changed files.
func Candidates(root string, excluded func(string) bool, scope []string) []Candidate {
	var found []Candidate
	if len(scope) > 0 {
		for _, rel := range scope {
			if info, err := os.Stat(filepath.Join(root, rel)); err == nil && !info.IsDir() {
				found = append(found, Candidate{Path: rel, Size: info.Size()})
			}
		}
	} else {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable directory is not fatal
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if entry.IsDir() {
				if rel != "." && excluded != nil && excluded(rel) {
					return filepath.SkipDir
				}
				return nil
			}
			if excluded != nil && excluded(rel) {
				return nil
			}
			if !codeExtensions[strings.ToLower(filepath.Ext(rel))] && !alwaysInteresting.MatchString(rel) {
				return nil
			}
			info, statErr := entry.Info()
			if statErr != nil || info.Size() == 0 || info.Size() > maxCandidateBytes {
				return nil
			}
			found = append(found, Candidate{Path: rel, Size: info.Size()})
			return nil
		})
	}
	sort.SliceStable(found, func(i, j int) bool {
		left, right := score(found[i].Path, found[i].Size), score(found[j].Path, found[j].Size)
		if left != right {
			return left > right
		}
		return found[i].Path < found[j].Path
	})
	return found
}

// BuildContext returns the context text, the files it includes, and how many were
// left out. The caller must report the skipped count: a reader has to know the
// model was shown part of the project, not all of it.
func BuildContext(root string, excluded func(string) bool, scope []string, budget int) (string, []string, int) {
	ranked := Candidates(root, excluded, scope)
	var parts, chosen []string
	used := 0
	for _, candidate := range ranked {
		if used+int(candidate.Size) > budget {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, candidate.Path))
		if err != nil {
			continue
		}
		parts = append(parts, "===== "+candidate.Path+" =====\n"+numbered(string(body)))
		chosen = append(chosen, candidate.Path)
		used += int(candidate.Size)
	}
	return strings.Join(parts, "\n\n"), chosen, len(ranked) - len(chosen)
}

// numbered prefixes each line, because a finding has to cite a line number.
func numbered(body string) string {
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	out := make([]string, 0, len(lines))
	for index, line := range lines {
		out = append(out, fmt.Sprintf("%5d | %s", index+1, line))
	}
	return strings.Join(out, "\n")
}
