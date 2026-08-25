package proc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputIsStreamedLineByLine(t *testing.T) {
	var stderrLines, stdoutLines []string
	script := `import sys
print("out 1"); print("out 2")
print("step 1", file=sys.stderr); print("step 2", file=sys.stderr)`
	result, err := Run([]string{"python3", "-c", script}, Options{
		Timeout:  30 * time.Second,
		OnStdout: func(line string) { stdoutLines = append(stdoutLines, line) },
		OnStderr: func(line string) { stderrLines = append(stderrLines, line) },
	})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit %d: %s", result.ExitCode, result.Stderr)
	}
	if got := strings.Join(stderrLines, "|"); got != "step 1|step 2" {
		t.Errorf("stderr arrived as %q, want the lines in order", got)
	}
	if got := strings.Join(stdoutLines, "|"); got != "out 1|out 2" {
		t.Errorf("stdout arrived as %q", got)
	}
	if result.Stdout != "out 1\nout 2" {
		t.Errorf("buffered stdout: %q", result.Stdout)
	}
}

func TestStdoutCanGoStraightToAFile(t *testing.T) {
	// The scanners that write a JSON report leave both streams free for progress.
	path := filepath.Join(t.TempDir(), "out.txt")
	result, err := Run([]string{"python3", "-c", `print("captured")`}, Options{
		Timeout: 30 * time.Second, StdoutPath: path,
	})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit %d", result.ExitCode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if strings.TrimSpace(string(body)) != "captured" {
		t.Errorf("file holds %q", body)
	}
}

func TestATimeoutIsReportedAndNotFatal(t *testing.T) {
	result, err := Run([]string{"python3", "-c", "import time; time.sleep(30)"},
		Options{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("a timeout is a result, not an error: %v", err)
	}
	if !result.TimedOut || result.ExitCode != exitCodeTimedOut {
		t.Errorf("timed out=%v exit=%d", result.TimedOut, result.ExitCode)
	}
	if !strings.Contains(result.Stderr, "timed out after") {
		t.Errorf("the reason must reach the report: %q", result.Stderr)
	}
}

func TestAMissingBinaryIsAResultNotAnError(t *testing.T) {
	result, err := Run([]string{"definitely-not-a-real-binary-xyz"}, Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("a missing binary must not fail the scan: %v", err)
	}
	if result.ExitCode != 127 {
		t.Errorf("exit %d, want 127", result.ExitCode)
	}
}

func TestANonZeroExitIsNormal(t *testing.T) {
	// Scanners exit non-zero when they find things; that is not a failure.
	result, err := Run([]string{"python3", "-c", "import sys; sys.exit(1)"},
		Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 1 {
		t.Errorf("exit %d, want 1", result.ExitCode)
	}
}

func TestALongSingleLineSurvives(t *testing.T) {
	// A whole JSON report can arrive as one line; the default 64 KiB cap would cut it.
	script := `print("x" * 500000)`
	result, err := Run([]string{"python3", "-c", script}, Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if len(result.Stdout) != 500000 {
		t.Errorf("stdout is %d bytes, want 500000 — the line was truncated", len(result.Stdout))
	}
}

func TestTailKeepsTheEnd(t *testing.T) {
	if got := Tail("a\n\nb\nc\n", 2); got != "b\nc" {
		t.Errorf("got %q", got)
	}
	if got := Tail("only", 5); got != "only" {
		t.Errorf("got %q", got)
	}
}
