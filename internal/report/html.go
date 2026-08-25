package report

import (
	"embed"
	"encoding/json"
	"strings"

	"github.com/smagew/whatsrisky/internal/model"
)

// The viewer is one file - CSS, JS and all - and it is embedded rather than
// generated, so the page a user reads is the page in the repository.
//
//go:embed templates/viewer.html
var templates embed.FS

const (
	titlePlaceholder = "__TITLE__"
	jsonPlaceholder  = "__REPORT_JSON__"

	// A literal </script> inside a JSON string would close the tag that carries
	// it. Escaping the slash is inert inside JSON and safe in HTML.
	closeTag        = "</"
	closeTagEscaped = "<\\/"
)

// Viewer is the template, for the tests that check it is the same file.
func Viewer() (string, error) {
	body, err := templates.ReadFile("templates/viewer.html")
	return string(body), err
}

// RenderHTML produces the self-contained page: the viewer with the report inlined.
// The page is both the view and the data - ExtractJSON recovers exactly what
// WriteJSON would have written.
func RenderHTML(report model.Report) (string, error) {
	template, err := Viewer()
	if err != nil {
		return "", err
	}
	// Compact, because this file is rewritten on every scanner transition.
	document, err := json.Marshal(Document(report))
	if err != nil {
		return "", err
	}
	title := report.ProjectName + " — whatsrisky"
	page := strings.ReplaceAll(template, titlePlaceholder, escapeForHTML(title))
	return strings.ReplaceAll(page, jsonPlaceholder, escapeForHTML(string(document))), nil
}

func escapeForHTML(payload string) string {
	return strings.ReplaceAll(payload, closeTag, closeTagEscaped)
}

// WriteHTML writes the page atomically, for the same reason as the JSON.
func WriteHTML(report model.Report, path string) error {
	page, err := RenderHTML(report)
	if err != nil {
		return err
	}
	return writeAtomic(path, []byte(page))
}

// ExtractJSON recovers the report from a rendered page - the round trip the viewer
// promises.
func ExtractJSON(page string) (map[string]any, error) {
	const marker = `<script id="report-data" type="application/json">`
	start := strings.Index(page, marker)
	if start < 0 {
		return nil, errNoData
	}
	start += len(marker)
	end := strings.Index(page[start:], "</script>")
	if end < 0 {
		return nil, errNoData
	}
	body := strings.ReplaceAll(page[start:start+end], closeTagEscaped, closeTag)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

type htmlError string

func (e htmlError) Error() string { return string(e) }

const errNoData htmlError = "the page carries no report data"
