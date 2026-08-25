// Package proc runs the scanners.
//
// The one thing that matters here is streaming: a scanner describes what it is
// doing on stderr, and surfacing that live is the difference between a progress
// display and a spinner. The Python original needed a watchdog thread and two
// pump threads with careful joins; here it is a context and two goroutines.
package proc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Result is what a finished command left behind.
type Result struct {
	Argv     []string
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
}

// Command is the human-readable invocation, for the report's "commands executed".
func (r Result) Command() string { return strings.Join(r.Argv, " ") }

// Options configures one run. OnStdout and OnStderr receive complete lines as
// they arrive; either may be nil. StdoutPath sends stdout to a file instead of
// buffering it, which is how the scanners that write a JSON report are handled.
type Options struct {
	Dir        string
	Timeout    time.Duration
	Env        []string
	OnStdout   func(string)
	OnStderr   func(string)
	StdoutPath string
}

// exitCodeTimedOut mirrors the shell convention for "killed after a timeout",
// and the reference implementation's choice.
const exitCodeTimedOut = 124

// Run executes argv, streaming its output. It returns an error only when the
// command could not be started at all; a non-zero exit is a Result, not an error,
// because a scanner exiting 1 because it found something is normal.
func Run(argv []string, options Options) (Result, error) {
	started := time.Now()
	result := Result{Argv: argv}
	if len(argv) == 0 {
		return result, errors.New("no command given")
	}

	ctx := context.Background()
	cancel := func() {}
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
	}
	defer cancel()

	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir = options.Dir
	if len(options.Env) > 0 {
		command.Env = append(os.Environ(), options.Env...)
	}

	var outFile *os.File
	if options.StdoutPath != "" {
		file, err := os.Create(options.StdoutPath)
		if err != nil {
			return result, err
		}
		outFile = file
		command.Stdout = file
	}

	var stdoutPipe, stderrPipe io.ReadCloser
	var err error
	if outFile == nil {
		if stdoutPipe, err = command.StdoutPipe(); err != nil {
			return result, err
		}
	}
	if stderrPipe, err = command.StderrPipe(); err != nil {
		return result, err
	}

	if err := command.Start(); err != nil {
		if outFile != nil {
			outFile.Close()
		}
		result.Duration = time.Since(started)
		result.ExitCode = 127 // "command not found", as a shell would report it
		result.Stderr = err.Error()
		return result, nil
	}

	var wait sync.WaitGroup
	var stdout, stderr strings.Builder
	pump := func(reader io.Reader, sink *strings.Builder, callback func(string)) {
		defer wait.Done()
		scanner := bufio.NewScanner(reader)
		// Scanner's default 64 KiB line cap is too small for a JSON payload on one line.
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			sink.WriteString(line)
			sink.WriteString("\n")
			if callback != nil && strings.TrimSpace(line) != "" {
				callback(line)
			}
		}
	}
	if stdoutPipe != nil {
		wait.Add(1)
		go pump(stdoutPipe, &stdout, options.OnStdout)
	}
	wait.Add(1)
	go pump(stderrPipe, &stderr, options.OnStderr)

	waitErr := command.Wait()
	wait.Wait()
	if outFile != nil {
		outFile.Close()
	}

	result.Stdout = strings.TrimSuffix(stdout.String(), "\n")
	result.Stderr = strings.TrimSuffix(stderr.String(), "\n")
	result.Duration = time.Since(started)

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		result.ExitCode = exitCodeTimedOut
		if result.Stderr != "" {
			result.Stderr += "\n"
		}
		result.Stderr += "[whatsrisky] timed out after " + options.Timeout.String()
		return result, nil
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
			result.Stderr = strings.TrimSpace(result.Stderr + "\n" + waitErr.Error())
		}
	}
	return result, nil
}

// Which reports the absolute path of a binary on PATH, or "".
func Which(binary string) string {
	if binary == "" {
		return ""
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return ""
	}
	return path
}

// Version asks a tool for its version and returns the first line.
func Version(binary string, args ...string) string {
	if Which(binary) == "" {
		return ""
	}
	if len(args) == 0 {
		args = []string{"--version"}
	}
	result, err := Run(append([]string{binary}, args...), Options{Timeout: 30 * time.Second})
	if err != nil {
		return ""
	}
	text := result.Stdout
	if strings.TrimSpace(text) == "" {
		text = result.Stderr
	}
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// Tail is the last n non-blank lines, for a diagnostics field.
func Tail(text string, n int) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
