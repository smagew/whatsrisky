package main

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestInstallableToolsHaveACommandOnMac(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("install commands are Homebrew, checked on macOS")
	}
	for name := range installableNames {
		if cmd := installCommand(name, false); !strings.HasPrefix(cmd, "brew") {
			t.Errorf("%s has no brew install command: %q", name, cmd)
		}
		// A found tool never offers an install.
		if cmd := installCommand(name, true); cmd != "" {
			t.Errorf("%s offers an install while present: %q", name, cmd)
		}
	}
	// A thing whatsrisky cannot install (a key) has no command.
	if cmd := installCommand("ai", false); cmd != "" {
		t.Errorf("ai should not be installable, got %q", cmd)
	}
	// testssl differs from its tool name; it is the one special case left.
	if installCommand("testssl", false) != "brew install testssl" {
		t.Errorf("testssl: %q", installCommand("testssl", false))
	}
	// zap is deliberately not one-click: the cask does not provide zap-baseline.py.
	if installCommand("zap", false) != "" {
		t.Errorf("zap should not offer a one-click install: %q", installCommand("zap", false))
	}
}

func TestDoctorJSONIsWellFormed(t *testing.T) {
	stdout, read := captureStdout(t)
	code := cmdDoctor([]string{"--json"}, stdout, stdout)
	body := read()
	if code != 0 {
		t.Fatalf("doctor --json exited %d", code)
	}
	var tools []toolStatus
	if err := json.Unmarshal([]byte(body), &tools); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	if len(tools) == 0 {
		t.Fatal("no tools reported")
	}
	// surface is built in: always found, never installable.
	for _, tool := range tools {
		if tool.Name == "surface" {
			if !tool.Found || tool.Install != "" {
				t.Errorf("surface: found=%v install=%q", tool.Found, tool.Install)
			}
		}
	}
}
