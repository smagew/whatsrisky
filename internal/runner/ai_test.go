package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smagew/whatsrisky/internal/model"
)

const modelAnswer = `{
  "summary": "Every route takes unsanitized input into a dangerous sink.",
  "coverage": "Read the files that were sent.",
  "findings": [
    {"severity":"CRITICAL","title":"SQL injection in /user","category":"Injection",
     "file":"app.py","line":20,"description":"name is interpolated into the query.",
     "attack_scenario":"?name=' OR 1=1 --","remediation":"Use a parameterised query.",
     "cwe":["CWE-89"],"confidence":"HIGH"},
    {"severity":"HIGH","title":"World-writable uploads","category":"Access control",
     "file":"upload.py","line":12,"description":"chmod 0o777 on an upload.",
     "remediation":"Use 0o640.","cwe":["CWE-732"],"confidence":"MEDIUM"}
  ]
}`

func stubOpenAI(t *testing.T, content string) *[]map[string]any {
	t.Helper()
	var seen []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message":       map[string]string{"content": content},
				"finish_reason": "stop",
			}},
			"usage": map[string]int{"prompt_tokens": 4200, "completion_tokens": 610},
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("OPENAI_API_KEY", "stub")
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")
	return &seen
}

func aiConfig(t *testing.T, root string) Config {
	t.Helper()
	return Config{
		Target: root, WorkDir: t.TempDir(),
		AIProvider: "openai", AIModel: "gpt-5", AIMode: "full",
		AITimeout: 30 * time.Second, AIMaxFindings: 40, AIContextBytes: 240000,
	}
}

func TestTheAIPassProducesNormalizedFindings(t *testing.T) {
	seen := stubOpenAI(t, modelAnswer)
	root := vulnApp(t)
	runner, err := NewAI(aiConfig(t, root))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	result := Run(runner, nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(result.Findings))
	}

	first := result.Findings[0]
	if first.Detector() != (model.Detector{Tool: "ai", Provider: "openai", Model: "gpt-5", Pass: "full"}) {
		t.Errorf("detector: %+v", first.Detector())
	}
	if first.Category != model.CatInjectionSQL {
		t.Errorf("category %q, want %q (from CWE-89)", first.Category, model.CatInjectionSQL)
	}
	if !strings.Contains(first.Description, "Attack scenario:") {
		t.Error("the attack scenario must survive into the description")
	}
	if result.Findings[1].Category != model.CatMisconfiguration {
		t.Errorf("CWE-732 maps to %q", result.Findings[1].Category)
	}

	// The report has to say the model was handed a slice, not the repository.
	if !strings.Contains(result.Message, "was given a fixed context") ||
		!strings.Contains(result.Message, "cannot read the repository itself") {
		t.Errorf("the note hides how the model saw the project: %q", result.Message)
	}
	if !strings.Contains(result.Message, "tokens in/out: 4200/610") {
		t.Errorf("the cost belongs in the note too: %q", result.Message)
	}

	body := (*seen)[0]
	messages, _ := body["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	user, _ := last["content"].(string)
	if strings.Count(user, "===== ") < 3 {
		t.Errorf("the fixture's files should all be in the context, got %d", strings.Count(user, "===== "))
	}
}

func TestAnAPIBackendRefusesToPretendItCanReviewADiff(t *testing.T) {
	stubOpenAI(t, modelAnswer)
	config := aiConfig(t, t.TempDir())
	config.AIMode = "review"
	runner, err := NewAI(config)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	result := Run(runner, nil)
	if result.Status != model.ToolError {
		t.Fatalf("status %s, want an error", result.Status)
	}
	// A refusal with the reason and the two ways out, not a confident empty answer.
	for _, want := range []string{"cannot review a diff", "no access to git", "--ai-mode full", "claude-cli"} {
		if !strings.Contains(result.Message, want) {
			t.Errorf("the refusal must mention %q: %s", want, result.Message)
		}
	}
}

func TestAlmostJSONIsRepairedNotLost(t *testing.T) {
	// "line": 15-38 is a mistake LLMs actually make; an audit must not be lost to it.
	broken := `{"summary":"s","findings":[{"severity":"HIGH","title":"t","file":"app.py",` +
		`"line": 15-38,"description":"d","cwe":["CWE-89"],}]}`
	stubOpenAI(t, broken)
	runner, err := NewAI(aiConfig(t, t.TempDir()))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	result := Run(runner, nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if len(result.Findings) != 1 || result.Findings[0].Line != 15 {
		t.Errorf("got %d findings, first line %v", len(result.Findings), findingLine(result.Findings))
	}
}

func TestAnUnparsableAnswerIsReshapedByASecondCall(t *testing.T) {
	// Prose instead of JSON: the audit ran, so reshape it rather than lose it.
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		content := "I found a SQL injection in app.py line 20."
		if calls > 1 {
			content = modelAnswer
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": content}}},
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("OPENAI_API_KEY", "stub")
	t.Setenv("OPENAI_BASE_URL", server.URL+"/v1")

	runner, err := NewAI(aiConfig(t, t.TempDir()))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	result := Run(runner, nil)
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if calls != 2 {
		t.Errorf("expected a reshaping call, got %d call(s)", calls)
	}
	if len(result.Findings) != 2 {
		t.Errorf("got %d findings after reshaping", len(result.Findings))
	}
}

func TestAMissingKeyIsReportedAsMissingNotBroken(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_BASE_URL", "")
	runner, err := NewAI(aiConfig(t, t.TempDir()))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	result := Run(runner, nil)
	if result.Status != model.ToolMissing {
		t.Errorf("status %s, want %s", result.Status, model.ToolMissing)
	}
	if !strings.Contains(result.Message, "OPENAI_API_KEY") {
		t.Errorf("the reason must name what to set: %q", result.Message)
	}
}

func TestTheRawAnswerIsAlwaysKept(t *testing.T) {
	stubOpenAI(t, modelAnswer)
	config := aiConfig(t, t.TempDir())
	runner, err := NewAI(config)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	Run(runner, nil)
	for _, name := range []string{"ai-full.txt", "ai-openai.raw.json"} {
		if _, err := os.Stat(filepath.Join(config.WorkDir, name)); err != nil {
			t.Errorf("%s was not kept: %v", name, err)
		}
	}
}

func findingLine(findings []model.Finding) []int {
	var out []int
	for _, finding := range findings {
		out = append(out, finding.Line)
	}
	return out
}

// TestTheClaudeCLIBackendLive is the one thing a stub cannot cover: the real CLI's
// behaviour. Opt-in, because it spends tokens.
//
//	WHATSRISKY_LIVE_AI=1 WHATSRISKY_LIVE_MODEL=sonnet go test ./internal/runner/ -run Live -v
func TestTheClaudeCLIBackendLive(t *testing.T) {
	if os.Getenv("WHATSRISKY_LIVE_AI") != "1" {
		t.Skip("set WHATSRISKY_LIVE_AI=1 to run the live AI pass (it spends tokens)")
	}
	requireBinary(t, "claude")
	root := vulnApp(t)
	config := aiConfig(t, root)
	config.AIProvider = "claude-cli"
	config.AIModel = os.Getenv("WHATSRISKY_LIVE_MODEL")
	if config.AIModel == "" {
		config.AIModel = "sonnet"
	}
	config.AITimeout = 10 * time.Minute

	runner, err := NewAI(config)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	var steps []string
	result := Run(runner, func(message string) { steps = append(steps, message) })
	if result.Status != model.ToolOK {
		t.Fatalf("status %s: %s", result.Status, result.Message)
	}
	if len(result.Findings) == 0 {
		t.Fatal("the live pass found nothing in a deliberately vulnerable app")
	}
	// The agentic backend must report what it is reading, not just spin.
	if len(steps) == 0 {
		t.Error("no progress was reported")
	}
	if !strings.Contains(result.Message, "explored the repository itself") {
		t.Errorf("the note must say it read the repo: %q", result.Message)
	}
	for _, finding := range result.Findings {
		if finding.Provider != "anthropic" || finding.Model != config.AIModel {
			t.Errorf("detector: %+v", finding.Detector())
		}
	}
	t.Logf("%d findings; progress steps: %d; first: %s", len(result.Findings), len(steps), steps[0])
	for _, finding := range result.Findings[:min(3, len(result.Findings))] {
		t.Logf("  %-8s %-18s %s — %s", finding.Severity, finding.Category, finding.Location(), finding.Title)
	}
}
