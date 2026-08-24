# Contributing

Bug reports and patches are welcome. A few things that will save us both time.

## Getting set up

```bash
uv venv && uv pip install -e ".[dev]"
python -m pytest tests -q
python -m pyflakes whatsrisky tests
```

`python -m pytest -m "not integration"` skips the tests that need `semgrep`, `trivy` or `gitleaks`
installed. CI runs both.

## What a good patch looks like

- **A parser change comes with an integration test.** The tests in `tests/test_runners.py` exist to
  catch a scanner changing its JSON shape. If you touch `whatsrisky/runners/`, assert on the real
  output, not on a mock.
- **New settings go through `ScanOptions`.** It is the single source of truth for the CLI, the UI and
  the library API. Add the field, add the flag, add the widget, extend `command_line()` — a setting
  that only exists in one of the three is a bug.
- **JSON changes bump `SCHEMA_VERSION`.** Other tools consume the report; `schema/report.schema.json`
  is a contract, not documentation.
- **Never commit credentials, even fake ones.** The test fixture assembles its tokens at runtime for
  this reason. A literal `ghp_…` in the repository trips GitHub push protection and every secret
  scanner pointed at us.
- **Say what you did not do.** The project's stance is that unscanned is not the same as clean; the
  same applies to patches.

## Adding a scanner

Subclass `Runner` in `whatsrisky/runners/`, implement `scan()` returning normalized `Finding`
objects, register it in `ALL_RUNNERS`, and map its severities onto the shared scale explicitly — do
not invent a new one. If the scanner cannot honour `--diff`, say so in the runner (see Trivy's
`scope_note`) instead of silently scanning everything.
