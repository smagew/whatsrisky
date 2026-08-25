# Rewriting in Go — specification

Status: **phases 1-2 done**, see the checklists. DOCX is dropped; see the cost below.

## Why

Not because Python cannot do the work — it does, and 77% of the current code is
plain orchestration that would translate line for line. Because of how the tool is
*delivered*.

The evidence is in our own CI. It installs Trivy and gitleaks in one line each —

```
curl -sSLf …/gitleaks_8.30.1_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
```

— and then took two failed iterations to set up its own runtime: a uv-managed
interpreter refuses `--system`, and `setup-uv` had already created the `.venv`
that `uv venv` then refused to overwrite. Those are not exotic; they are the
normal texture of shipping a Python CLI. Every scanner we orchestrate is a single
Go binary, and the orchestrator is the one thing with a runtime prerequisite.

Three things make that cost concrete rather than aesthetic:

1. **The Claude Code plugin** (the next step on the roadmap) invokes this tool. A
   binary means the plugin has no prerequisites. Python means "install 3.10+ and a
   package" before anything works.
2. **The desktop UI** bundles a binary trivially and a Python environment
   painfully.
3. **Windows** is a real target for a security tool and Python's story there is
   the weakest.

The concurrency is a bonus, not a reason: `run_streaming` is 91 lines of watchdog
thread plus two pump threads, and it is `exec.Cmd` + `context.WithTimeout` +
`bufio.Scanner` in goroutines — about twenty.

## What is dropped, and what that costs

**DOCX goes.** It was the original headline deliverable, so this is a real loss,
not a tidy-up:

- `python-docx` plus hand-written OOXML (cell shading, `TOC`/`PAGE` field codes,
  keep-with-next) has no equivalent in Go under a permissive licence. The mature
  option's licence is not MIT-compatible for our use; the permissive ones do
  template substitution only.
- Anyone who needs a Word file today can print the HTML report from a browser, or
  run the tagged Python release (`v0.2.0`).
- The door stays open: the JSON schema does not change, so a DOCX side-car — in
  any language — can be added later without touching the scanner.

What is *not* lost: the HTML report is 599 lines of HTML/CSS/JS with the JSON
inlined, and moves across untouched via `go:embed`.

## What must not change

These are contracts with users, machines and the files already on their disks:

- **The report schema** stays at version 3, field for field.
- **`~/.config/whatsrisky/config.json`** stays readable, version 3, profiles and
  all. Nobody re-creates their profiles because we changed language.
- **The CLI surface** stays, minus `docx` in `--format`.
- **Exit codes** stay: 0, 1 for a bad invocation, 2 for `--fail-on`.
- **Output filenames** stay `<project>-<YYYYMMDD-HHMMSS>.<ext>`.
- **The viewer** is the same file.

## Layout

```
cmd/whatsrisky/          the CLI entry point and subcommand dispatch
internal/model/          Severity, Finding, Report, the category vocabulary
internal/scan/           ScanOptions, run, exclusions, diff scoping, live writing
internal/runner/         one file per scanner + the AI runner
internal/ai/             backend contract, claude-cli, openai, context building
internal/compare/        rescan correlation
internal/config/         profiles and the last-run memory
internal/report/         json, html (go:embed viewer.html), markdown
internal/progress/       the shared progress model
internal/ui/             the terminal UI
```

## Dependencies

The Python version held itself to three. The Go version holds itself to the Bubble
Tea trio — `bubbletea`, `bubbles`, `lipgloss` — and the standard library for
everything else: `os/exec`, `net/http`, `encoding/json`, `embed`, `flag` with
manual subcommand dispatch. No CLI framework, no HTTP client library, no JSON
library.

## Parity is a differential test, not a claim

The Python implementation is the specification. During the rewrite, both run on
the same fixture and their reports are compared field by field, ignoring the
fields that must differ (timestamps, durations, scan ids, absolute paths).

`make diff-parity` does this, and as of phase 2 it reports 28 findings identical
in both implementations - tool, rule, file, line, severity, category, source and
fingerprint. A finding that one implementation reports and the
other does not is a failure, and so is a differing severity, category, source,
detector or identity key. This is what turns "we rewrote it faithfully" into
something a machine checks.

## Done =

### Phase 1 — the logic that has no I/O
- [ ] `internal/model`: Severity with the same ordering and weights, Finding with
      the three identity keys producing **the same digests** as Python for the same
      input, Report with the same counts/verdict/risk-score semantics.
- [ ] `internal/model` categories: the same 149 CWE mappings, the same precedence
      (scanner class → strong rule token → artifact → CWE → weak keyword), and a
      table test per vocabulary entry.
- [ ] `internal/compare`: the same statuses, the same correlation order, resolved
      carried for one generation, ambiguity not resolved arbitrarily.
- [ ] Golden files: the Python implementation's output for a set of inputs, checked
      into `testdata/`, asserted by the Go tests.

### Phase 2 — running the scanners
- [x] Streaming process runner with per-tool timeout and a progress callback.
- [x] semgrep, trivy, gitleaks: the same arguments, the same parsing, the same
      severity mapping, the same honest notes (Trivy still says it ignores `--diff`).
- [x] Exclusions: the same pattern semantics, the generated gitleaks allowlist, the
      post-filter with a count, and never scanning our own output.
- [x] Integration tests against the real binaries, as now.

### Phase 3 — the AI pass
- [ ] The backend contract with `agentic`, claude-cli via stream-json, OpenAI over
      the API, context selection for non-agentic backends.
- [ ] The same refusal when a backend cannot do what was asked.
- [ ] The stub-server tests, ported.

### Phase 4 — output and the CLI
- [ ] JSON identical to Python's under `make diff-parity`.
- [ ] The viewer embedded and byte-identical to the current file.
- [ ] Markdown writer.
- [ ] Every flag, `doctor`, `profiles`, `--show-excludes`, `--json-stdout`, `--quiet`.
- [ ] `--format docx` is refused with a reason ("removed in 0.3.0; print the HTML
      report, or use the tagged v0.2.0"), never silently ignored. A dropped feature
      that fails quietly is worse than one that fails loudly.
- [ ] Live report written before the first scanner and after each one.

### Phase 5 — the terminal UI
- [ ] Settings screen: profile picker first, every option, the live equivalent
      command, scanner probing, warnings.
- [ ] Run screen: per-scanner progress with elapsed time and current activity,
      View report available from the first second.
- [ ] Tests, headless.

### Phase 6 — shipping
- [ ] `go build` produces one static binary; `make build-all` cross-compiles for
      darwin/linux/windows on amd64/arm64.
- [ ] A release workflow attaches the binaries to a GitHub release.
- [ ] `install.sh` in the README, the way Trivy and gitleaks are installed.
- [ ] The Python tree is deleted and `v0.2.0-python` is tagged so it stays
      retrievable.

## Version

0.3.0. Pre-1.0, and dropping `--format docx` is a breaking change to the CLI even
though the schema and the config file are untouched.
