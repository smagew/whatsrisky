# Contributing

Bug reports and patches are welcome. A few things that will save us both time.

## Getting set up

```bash
make check       # gofmt + vet + tests + the self-scan gate
make test        # -short: runs on a machine with no scanners installed
make test-all    # everything, against the real semgrep, trivy and gitleaks
```

`make check` before every push. CI runs the same things on Linux, macOS and
Windows, plus a cross-compile of every release platform.

## What a good patch looks like

- **A parser change comes with an integration test.** The tests in
  `internal/runner` exist to catch a scanner changing its JSON shape. If you touch
  a runner, assert against the real output, not a mock.
- **New settings go through `scan.Options`.** It is the single source of truth for
  the CLI, the UI and the library API. Add the field, the flag, the form row, and
  the `CommandLine()` case together — a setting that exists in only one of the
  three is a bug, and the UI's equivalent-command panel is what exposes it.
- **JSON changes bump `model.SchemaVersion`.** Other tools consume the report;
  `schema/report.schema.json` is a contract, not documentation.
- **Never commit credentials, even fake ones.** `internal/fixture` derives them from
  a hash stream for this reason. A literal `ghp_…` in the repository trips GitHub
  push protection and every secret scanner pointed at us.
- **Say what you did not do.** The project's stance is that unscanned is not the
  same as clean; the same applies to patches.

## Adding a scanner

Add a file to `internal/runner`, implement the `Runner` interface, register it in
`New()` and in `scan.AllTools`, and map its severities onto the shared scale
explicitly — do not invent a new one. If the scanner cannot honour `--diff`, say so
in the `Outcome.Note` (see Trivy) instead of silently scanning everything.

## Adding an AI backend

Add a file to `internal/ai` implementing `Backend`, and be honest about `Agentic`:
whether it reads the repository itself decides what it can be asked to do, what the
report says about its findings, and whether it must refuse `--ai-mode review`.
