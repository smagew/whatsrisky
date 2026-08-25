package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The OpenAI backend is exercised against a stub speaking the chat-completions
// shape. That covers request construction, context injection, parsing and every
// error path - everything except the real service's behaviour, which no test here
// can claim.

const answerJSON = `{"summary":"s","coverage":"c","findings":[{"severity":"CRITICAL",` +
	`"title":"SQL injection in /user","file":"app.py","line":4,"cwe":["CWE-89"]}]}`

type recorded struct {
	path string
	auth string
	body map[string]any
}

func stubServer(t *testing.T, status int, payload any) (*httptest.Server, *[]recorded) {
	t.Helper()
	var seen []recorded
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, recorded{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: body})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload == nil {
			payload = map[string]any{
				"choices": []any{map[string]any{
					"message":       map[string]string{"content": answerJSON},
					"finish_reason": "stop",
				}},
				"usage": map[string]int{"prompt_tokens": 900, "completion_tokens": 120},
			}
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	t.Setenv(envOpenAIKey, "test-key")
	t.Setenv(envOpenAIBase, server.URL+"/v1")
	return server, &seen
}

func TestBackendsDeclareWhatTheyAre(t *testing.T) {
	t.Setenv(envOpenAIBase, "")
	cli, err := New("claude-cli", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("claude-cli: %v", err)
	}
	api, err := New("openai", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("openai: %v", err)
	}
	// The distinction that matters: one reads the repository, the other cannot.
	if !cli.Agentic() || api.Agentic() {
		t.Errorf("agentic flags are wrong: claude-cli=%v openai=%v", cli.Agentic(), api.Agentic())
	}
	if cli.DefaultModel() == "" || api.DefaultModel() == "" {
		t.Error("every backend needs a default model")
	}
	if Vendor["claude-cli"] != "anthropic" || Vendor["openai"] != "openai" {
		t.Errorf("vendor map: %v", Vendor)
	}
	if _, err := New("nope", t.TempDir(), t.TempDir()); err == nil {
		t.Error("an unknown provider must be an error")
	}
}

func TestOpenAIWithoutAKeySaysSo(t *testing.T) {
	t.Setenv(envOpenAIKey, "")
	t.Setenv(envOpenAIBase, "")
	backend, err := New("openai", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	ready, reason := backend.Available()
	if ready || !strings.Contains(reason, envOpenAIKey) {
		t.Errorf("ready=%v reason=%q", ready, reason)
	}
}

func TestTheBaseURLCannotSmuggleAScheme(t *testing.T) {
	// A URL library speaks file:// too, so an env var must not become arbitrary IO.
	for _, bad := range []string{
		"file:///etc/passwd", "ftp://example.invalid/x", "/etc/passwd", "not a url", "",
	} {
		t.Setenv(envOpenAIBase, bad)
		if _, err := New("openai", t.TempDir(), t.TempDir()); err == nil && bad != "" {
			t.Errorf("%q was accepted as a base URL", bad)
		}
	}
	t.Setenv(envOpenAIBase, "https://proxy.example.invalid/v1/")
	backend, err := New("openai", t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("a valid https URL was rejected: %v", err)
	}
	if got := backend.(*OpenAI).BaseURL(); got != "https://proxy.example.invalid/v1" {
		t.Errorf("base URL %q - the trailing slash should be trimmed", got)
	}
}

func TestOpenAICallShapeAndParsing(t *testing.T) {
	workDir := t.TempDir()
	_, seen := stubServer(t, http.StatusOK, nil)
	backend, err := New("openai", t.TempDir(), workDir)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	var steps []string
	answer, err := backend.Ask(Request{
		Prompt: "Find the bugs.", Model: "gpt-5", Timeout: 10 * time.Second,
		Context: "===== a.py =====", Progress: func(s string) { steps = append(steps, s) },
	})
	if err != nil {
		t.Fatalf("asking: %v", err)
	}
	if !strings.Contains(answer.Text, "SQL injection in /user") {
		t.Errorf("answer text: %q", answer.Text)
	}
	if answer.Turns != 1 || len(answer.Notes) == 0 || !strings.Contains(answer.Notes[0], "900/120") {
		t.Errorf("token accounting missing: %+v", answer)
	}
	if len(steps) == 0 {
		t.Error("the pass must report progress")
	}

	request := (*seen)[len(*seen)-1]
	if !strings.HasSuffix(request.path, "/chat/completions") {
		t.Errorf("endpoint %q", request.path)
	}
	if request.auth != "Bearer test-key" {
		t.Errorf("authorization %q", request.auth)
	}
	if request.body["model"] != "gpt-5" {
		t.Errorf("model %v", request.body["model"])
	}
	format, _ := request.body["response_format"].(map[string]any)
	if format["type"] != "json_object" {
		t.Errorf("response_format %v", request.body["response_format"])
	}
	messages, _ := request.body["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	user, _ := last["content"].(string)
	if !strings.Contains(user, "===== a.py =====") {
		t.Error("the context must reach the model")
	}
	if !strings.Contains(user, "cannot open files yourself") {
		t.Error("and it must know it cannot go looking")
	}
	if _, err := os.Stat(filepath.Join(workDir, "ai-openai.raw.json")); err != nil {
		t.Errorf("the raw response must be kept: %v", err)
	}
}

func TestOpenAIFailuresAreReportedNotSwallowed(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		payload  any
		expected string
	}{
		{"bad key", http.StatusUnauthorized, map[string]any{"error": "bad key"}, "openai returned 401"},
		{"cut off", http.StatusOK, map[string]any{"choices": []any{map[string]any{
			"message": map[string]string{"content": ""}, "finish_reason": "length"}}}, "empty answer"},
		{"no choices", http.StatusOK, map[string]any{"choices": []any{}}, "empty answer"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			stubServer(t, testCase.status, testCase.payload)
			backend, err := New("openai", t.TempDir(), t.TempDir())
			if err != nil {
				t.Fatalf("building: %v", err)
			}
			_, err = backend.Ask(Request{Prompt: "x", Model: "gpt-5", Timeout: 10 * time.Second})
			if err == nil || !strings.Contains(err.Error(), testCase.expected) {
				t.Errorf("got %v, want an error mentioning %q", err, testCase.expected)
			}
		})
	}
}

func TestContextRanksWhatMattersAndRespectsTheBudget(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "import sqlite3\n\n\ndef get(name):\n    return name\n")
	write("auth/session.py", "SECRET = 'x'\n")
	write("tests/test_app.py", "def test_ok():\n    assert True\n")
	write("node_modules/dep.js", "var a = 1;\n")

	excluded := func(rel string) bool { return strings.HasPrefix(rel, "node_modules") }
	ranked := Candidates(root, excluded, nil)
	var paths []string
	for _, candidate := range ranked {
		paths = append(paths, candidate.Path)
	}
	joined := strings.Join(paths, " ")
	if strings.Contains(joined, "node_modules") {
		t.Error("an excluded path must never be sent to a model")
	}
	if indexOf(paths, "auth/session.py") > indexOf(paths, "tests/test_app.py") {
		t.Errorf("auth code must outrank tests: %v", paths)
	}

	text, included, skipped := BuildContext(root, excluded, nil, 1<<20)
	if len(included) != 3 || skipped != 0 {
		t.Errorf("included %v, skipped %d", included, skipped)
	}
	if !strings.Contains(text, "===== app.py =====") {
		t.Error("each file must be delimited")
	}
	if !strings.Contains(text, "    4 | def get(name):") {
		t.Error("line numbers must survive; findings cite them")
	}

	_, few, left := BuildContext(root, excluded, nil, 20)
	if len(few) >= len(included) || left == 0 {
		t.Errorf("the budget was ignored: kept %d, skipped %d", len(few), left)
	}
}

func TestScopeLimitsTheContextToTheDiff(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.py", "b.py"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x = 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	text, included, _ := BuildContext(root, nil, []string{"a.py"}, 1<<20)
	if len(included) != 1 || included[0] != "a.py" {
		t.Errorf("included %v", included)
	}
	if strings.Contains(text, "b.py") {
		t.Error("a file outside the diff was sent")
	}
}

func indexOf(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return len(values)
}
