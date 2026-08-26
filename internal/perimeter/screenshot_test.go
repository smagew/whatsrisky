package perimeter

import "testing"

func TestMatchShotAcrossFilenameConventions(t *testing.T) {
	// The same URL, matched against the different names gowitness has used across
	// versions: scheme-prefixed with dashes, dotted, and a plain host.
	files := []string{
		"https-api-example-com.jpeg",
		"http-www-example-com.png",
		"login.example.com.png",
	}
	cases := map[string]string{
		"https://api.example.com":   "https-api-example-com.jpeg",
		"http://www.example.com/":   "http-www-example-com.png",
		"https://login.example.com": "login.example.com.png",
	}
	for url, want := range cases {
		if got := matchShot(url, files); got != want {
			t.Errorf("%s → %q, want %q", url, got, want)
		}
	}
}

func TestMatchShotPrefersTheClosestAndRefusesAStranger(t *testing.T) {
	files := []string{"https-example-com.png", "https-admin-example-com.png"}
	// api.example.com is not among them: no false match.
	if got := matchShot("https://api.example.com", files); got != "" {
		t.Errorf("an absent host matched %q", got)
	}
	// example.com should take the shorter, exact-host file, not the admin one.
	if got := matchShot("https://example.com", files); got != "https-example-com.png" {
		t.Errorf("example.com matched %q", got)
	}
}
