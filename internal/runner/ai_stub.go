package runner

import "fmt"

// NewAI is phase 3 of docs/go-rewrite.md. Until then the scanner exists and says
// so, rather than being silently absent from the tool list.
func NewAI(config Config) (Runner, error) {
	return nil, fmt.Errorf("the ai runner is not ported yet (phase 3 of docs/go-rewrite.md)")
}
