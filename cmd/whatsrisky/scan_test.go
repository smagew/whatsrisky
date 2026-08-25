package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlagsMayFollowThePath(t *testing.T) {
	// `whatsrisky <path> --flag` is the documented form, and the standard flag
	// package stops at the first non-flag argument. A flag written after the path
	// used to be silently ignored - which is how --out-dir and --no-compare were
	// found to be doing nothing.
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	outDir := flags.String("out-dir", "", "")
	noCompare := flags.Bool("no-compare", false, "")
	model := flags.String("model", "", "")
	var excludes stringList
	flags.Var(&excludes, "exclude", "")

	positional, err := parseInterleaved(flags, []string{
		"/some/project", "--out-dir", "/tmp/r", "--no-compare",
		"--model", "sonnet", "--exclude", "legacy", "second-positional",
	})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(positional) != 2 || positional[0] != "/some/project" || positional[1] != "second-positional" {
		t.Errorf("positional args: %v", positional)
	}
	if *outDir != "/tmp/r" || !*noCompare || *model != "sonnet" {
		t.Errorf("flags after the path were dropped: out-dir=%q no-compare=%v model=%q",
			*outDir, *noCompare, *model)
	}
	if len(excludes) != 1 || excludes[0] != "legacy" {
		t.Errorf("repeatable flag: %v", excludes)
	}
}

func TestDocxIsRefusedWithAReason(t *testing.T) {
	// A dropped feature that fails quietly is worse than one that fails loudly.
	stderr, read := captureStderr(t)
	code := cmdScan([]string{t.TempDir(), "--format", "docx,json"}, os.Stdout, stderr)
	message := read()
	if code == 0 {
		t.Error("asking for a removed format must fail")
	}
	for _, want := range []string{"DOCX was removed in 0.3.0", "HTML report", "v0.2.0"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal must mention %q, got: %s", want, message)
		}
	}
}

func TestShowExcludesNamesTheOrigin(t *testing.T) {
	stdout, read := captureStdout(t)
	code := cmdScan([]string{t.TempDir(), "--show-excludes", "--exclude", "mydir"}, stdout, os.Stderr)
	output := read()
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(output, "mydir  (user)") {
		t.Errorf("a user pattern must be marked as such:\n%s", output)
	}
	if !strings.Contains(output, "node_modules  (default)") {
		t.Errorf("and a default one too:\n%s", output)
	}
}

func TestAMissingPathIsRefused(t *testing.T) {
	stderr, read := captureStderr(t)
	if code := cmdScan([]string{"/definitely/not/here"}, os.Stdout, stderr); code == 0 {
		t.Error("scanning a nonexistent directory must fail")
	}
	if !strings.Contains(read(), "Not a directory") {
		t.Error("and say why")
	}
}

func TestAnUnknownAIProviderIsRefusedBeforeScanning(t *testing.T) {
	stderr, read := captureStderr(t)
	if code := cmdScan([]string{t.TempDir(), "--ai-provider", "nope"}, os.Stdout, stderr); code == 0 {
		t.Error("an unknown provider must fail")
	}
	if message := read(); !strings.Contains(message, "unknown ai provider") {
		t.Errorf("got: %s", message)
	}
}

// captureStdout / captureStderr swap in a pipe, because the commands take *os.File.
func captureStdout(t *testing.T) (*os.File, func() string) { return capture(t) }
func captureStderr(t *testing.T) (*os.File, func() string) { return capture(t) }

func capture(t *testing.T) (*os.File, func() string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "captured")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the capture file: %v", err)
	}
	t.Cleanup(func() { file.Close() })
	return file, func() string {
		file.Sync()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading the capture: %v", err)
		}
		return string(body)
	}
}
