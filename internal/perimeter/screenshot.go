package perimeter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smagew/whatsrisky/internal/proc"
)

// ScreenshotTool is gowitness: it loads each live asset in a headless browser and
// saves a picture. A forgotten admin panel is obvious in a screenshot in a way it
// is not in a status code, which is the whole point.
const ScreenshotTool = "gowitness"

// Screenshot runs gowitness over the live assets and records, on each, the
// relative path to its picture. It is observational — a headless browser loading a
// page a visitor could load — so it needs no --net-active. A missing gowitness is a
// stated gap, returned as a note, not a failure.
//
// It mutates assets in place: the screenshot belongs to the asset, and the report
// already has the field.
func Screenshot(assets []Asset, outDir, subdir string, timeout time.Duration, progress Progress) (string, error) {
	urls := AliveURLs(assets)
	if len(urls) == 0 {
		return "", nil
	}
	if proc.Which(ScreenshotTool) == "" {
		return "gowitness not installed: no screenshots taken (brew install gowitness)", nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	shotDir := filepath.Join(outDir, subdir)
	if err := os.MkdirAll(shotDir, 0o755); err != nil {
		return "", err
	}
	listFile, cleanup, err := writeList(urls)
	if err != nil {
		return "", err
	}
	defer cleanup()

	progress.say(fmt.Sprintf("gowitness: screenshotting %d asset(s)", len(urls)))
	// v3: scan a file of URLs, write screenshots to a directory, keep no database.
	_, _ = proc.Run([]string{ScreenshotTool, "scan", "file", "-f", listFile,
		"--screenshot-path", shotDir, "--write-none"}, proc.Options{Timeout: timeout})

	shots, err := os.ReadDir(shotDir)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(shots))
	for _, entry := range shots {
		if !entry.IsDir() && isImage(entry.Name()) {
			names = append(names, entry.Name())
		}
	}

	matched := 0
	for i := range assets {
		if !assets[i].Alive || assets[i].URL == "" {
			continue
		}
		if file := matchShot(assets[i].URL, names); file != "" {
			assets[i].Screenshot = filepath.Join(subdir, file)
			matched++
		}
	}
	progress.say(fmt.Sprintf("gowitness: %d screenshot(s) matched to assets", matched))
	if matched == 0 {
		return "gowitness ran but no screenshots could be matched to assets", nil
	}
	return "", nil
}

// matchShot finds the screenshot file for a URL. gowitness's filename convention
// has changed across versions, so rather than reconstruct it this reduces both the
// URL and each filename to their alphanumeric core and takes the file whose core
// contains the URL's — robust to dots, dashes or a leading scheme.
func matchShot(rawURL string, files []string) string {
	key := shotKey(rawURL)
	if len(key) < 4 {
		return ""
	}
	// Prefer the shortest containing filename: it is the closest match rather than
	// a longer name that merely happens to include the host.
	best := ""
	for _, file := range files {
		if strings.Contains(shotKey(file), key) {
			if best == "" || len(file) < len(best) {
				best = file
			}
		}
	}
	return best
}

// shotKey reduces a URL or a filename to its comparable core: lowercase, scheme and
// image extension removed, then only the letters and digits kept — so
// "https://api.example.com/" and "https-api-example-com.jpeg" both reduce to
// "apiexamplecom".
func shotKey(s string) string {
	s = strings.ToLower(s)
	for _, ext := range []string{".png", ".jpeg", ".jpg"} {
		s = strings.TrimSuffix(s, ext)
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	core := b.String()
	// Drop a leading scheme token so a URL key (no scheme) matches a filename key
	// that kept one.
	for _, scheme := range []string{"https", "http"} {
		core = strings.TrimPrefix(core, scheme)
	}
	return core
}

func isImage(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpeg") ||
		strings.HasSuffix(lower, ".jpg")
}
