package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
)

// OpenAI as an API backend. The model cannot read the repository, so what we send
// decides what it can find - and the report says how much of the project that was.
type OpenAI struct {
	cwd     string
	workDir string
	baseURL string
}

const (
	openAIDefaultBaseURL = "https://api.openai.com/v1"
	envOpenAIKey         = "OPENAI_API_KEY"
	envOpenAIBase        = "OPENAI_BASE_URL"
)

// NewOpenAI validates the endpoint before anything else can use it.
func NewOpenAI(cwd, workDir string) (*OpenAI, error) {
	base, err := validatedBaseURL(firstSet(os.Getenv(envOpenAIBase), openAIDefaultBaseURL))
	if err != nil {
		return nil, err
	}
	return &OpenAI{cwd: cwd, workDir: workDir, baseURL: base}, nil
}

// validatedBaseURL accepts only http(s) endpoints with a host.
//
// Left unchecked, "point it at a compatible endpoint" also means "read a local
// file": a URL library will happily follow file:// or ftp://. An environment
// variable must not become arbitrary scheme handling. Our own scan found this.
func validatedBaseURL(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("%s must be an http(s) URL with a host; got %q", envOpenAIBase, raw)
	}
	return trimmed, nil
}

func (o *OpenAI) Name() string         { return "openai" }
func (o *OpenAI) Agentic() bool        { return false }
func (o *OpenAI) DefaultModel() string { return "gpt-5" }

func (o *OpenAI) Available() (bool, string) {
	if os.Getenv(envOpenAIKey) != "" {
		return true, ""
	}
	return false, envOpenAIKey + " is not set; export it to use the openai backend"
}

func (o *OpenAI) Version() string {
	if parsed, err := url.Parse(o.baseURL); err == nil {
		return "openai api (" + parsed.Host + ")"
	}
	return "openai api"
}

// BaseURL is exported for the tests that point it at a stub.
func (o *OpenAI) BaseURL() string { return o.baseURL }

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (o *OpenAI) Ask(request Request) (Answer, error) {
	key := os.Getenv(envOpenAIKey)
	if key == "" {
		return Answer{}, fmt.Errorf("%s is not set", envOpenAIKey)
	}
	progressOf(request.Progress)("asking " + request.Model + " over the api")

	user := request.Prompt
	if request.Context != "" {
		user += "\n\nYou cannot open files yourself, so the relevant sources are below " +
			"with line numbers. Cite those line numbers.\n\n" + request.Context
	}
	payload, err := json.Marshal(map[string]any{
		"model": request.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a senior application security engineer. " +
				"You answer only with the JSON object the user asks for - no prose, no markdown fences."},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return Answer{}, err
	}

	httpRequest, err := http.NewRequest(http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return Answer{}, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+key)
	httpRequest.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: request.Timeout}
	response, err := client.Do(httpRequest)
	if err != nil {
		return Answer{}, fmt.Errorf("cannot reach %s: %w", o.baseURL, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Answer{}, fmt.Errorf("reading the response: %w", err)
	}
	_ = writeRaw(filepath.Join(o.workDir, "ai-openai.raw.json"), string(body))

	if response.StatusCode >= 400 {
		return Answer{}, fmt.Errorf("openai returned %d: %s",
			response.StatusCode, model.Truncate(string(body), 400))
	}
	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Answer{}, fmt.Errorf("openai returned something that is not JSON: %w", err)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		reason := "no content"
		if len(parsed.Choices) > 0 && parsed.Choices[0].FinishReason != "" {
			reason = parsed.Choices[0].FinishReason
		}
		return Answer{}, fmt.Errorf("openai returned an empty answer (%s)", reason)
	}

	var notes []string
	if parsed.Usage.PromptTokens > 0 || parsed.Usage.CompletionTokens > 0 {
		notes = append(notes, fmt.Sprintf("tokens in/out: %d/%d",
			parsed.Usage.PromptTokens, parsed.Usage.CompletionTokens))
	}
	return Answer{Text: parsed.Choices[0].Message.Content, Turns: 1, Notes: notes}, nil
}

func firstSet(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeRaw(path, body string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o600)
}
