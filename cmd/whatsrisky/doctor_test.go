package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallCommandsAreRealAndProgramGated(t *testing.T) {
	// Every command names a program that is actually present on this machine — a
	// button that runs a missing brew or go helps no one.
	for name, command := range installCommands {
		program := strings.Fields(command)[0]
		if program != "brew" && program != "go" {
			t.Errorf("%s installs via an unexpected program: %q", name, command)
		}
		// installCommand only offers it when that program is on PATH.
		got := installCommand(name, false)
		if _, err := exec.LookPath(program); err == nil {
			if got != command {
				t.Errorf("%s: with %s present, expected %q, got %q", name, program, command, got)
			}
		} else if got != "" {
			t.Errorf("%s: %s absent, should offer nothing, got %q", name, program, got)
		}
		// A found tool never offers an install.
		if installCommand(name, true) != "" {
			t.Errorf("%s offers an install while present", name)
		}
	}
	// gowitness is a go install, not a formula.
	if installCommands["gowitness"] != "go install github.com/sensepost/gowitness@latest" {
		t.Errorf("gowitness: %q", installCommands["gowitness"])
	}
	// Things whatsrisky cannot install for you have no command at all.
	for _, name := range []string{"ai", "zap", "surface", "llm-recon"} {
		if _, ok := installCommands[name]; ok {
			t.Errorf("%s should not be one-click installable", name)
		}
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
