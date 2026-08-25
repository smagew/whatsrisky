# CLAUDE.md — working on whatsrisky

whatsrisky answers one question about a codebase: **what's risky here?** It runs
Semgrep, Trivy and gitleaks (and, opt-in, an LLM reviewer), normalizes every
finding onto one severity scale, and produces a report a person can act on —
prioritized, with evidence, remediation, and an explicit statement of what was
*not* scanned. See `README.md` for the product surface and `CHANGELOG.md` for the
release history.

Sibling project: [whydiff](https://github.com/smagew/whydiff) — same author, same
conventions, same design language. A change here that diverges from whydiff's
practices is a bug unless the divergence is deliberate and written down.

## Commands

```bash
uv venv && uv pip install -e ".[dev]"   # dev environment
make check       # lint + unit tests + the self-scan gate
make test-all    # adds the integration tests (needs the scanner binaries)
make check-ci    # runs the CI job steps against a clean export of HEAD
```

`make check` before every push, `make check-ci` before touching the workflow.

## Architecture

A scan is a pipeline: options → scanners in parallel → normalized findings → report writers.

- `whatsrisky/core.py` — `ScanOptions` (every knob, serializable) and `run_scan()`.
  No terminal, no UI, no rich. This is the library API and the single source of
  truth for defaults, exclusions and diff scoping.
- `whatsrisky/runners/` — one module per scanner. Each returns normalized
  `Finding` objects and maps its native severities onto the shared scale
  explicitly. `base.Runner` gives them availability probing, per-platform install
  hints and the progress channel.
- `whatsrisky/ai/` — who runs the AI pass. `base.py` defines the contract,
  including `agentic`: whether the backend reads the repository itself. `claude_cli.py`
  is agentic, `openai_api.py` is not, `context.py` chooses what a non-agentic
  backend gets to see. `runners/ai.py` owns the prompts and the JSON contract with
  the model and knows nothing about who answers.
- `whatsrisky/compare.py` — rescan correlation. `whatsrisky/categories.py` — CWE to
  a closed category vocabulary. `whatsrisky/report/templates/viewer.html` — the
  whole HTML viewer in one file.
- `whatsrisky/models.py` — `Severity`, `Finding`, `ToolResult`, `ScanReport`, and
  `SCHEMA_VERSION`. The severity mapping rationale lives here.
- `whatsrisky/report/` — output writers (DOCX, Markdown). They read the model and
  never re-derive severity or scope logic.
- `whatsrisky/progress.py` — one progress model, rendered by both front ends.
- `whatsrisky/cli.py` — argparse + rich. `whatsrisky/ui.py` — the Textual settings
  and progress UI. `whatsrisky/settings.py` — persisted profiles.
- `schema/report.schema.json` — the machine contract for other tools. Everything
  the JSON report carries is documented there.

## Delivery flow

Adopted from whydiff, for the same reason: it stops half-baked work shipping.
For any non-trivial change, in order:

1. **Spec first — an acceptance checklist.** Write `Done =` as concrete, checkable
   outcomes and get it agreed before coding. That list is the contract.
2. **Standard before invention.** Find the correct or standard approach first
   (SARIF's shape, CWE mappings, a real streaming API) instead of trial-and-error
   on a solved problem.
3. **Behaviour → tests.** Every mechanisable acceptance item becomes a test.
4. **Self-review the whole artifact before showing it.** Generate the complete
   output — every section of the report, every screen — and inspect all of it
   against the checklist as a harsh reviewer. The reviewer who finds the flaws
   must be me, not the user.
5. **"Done" means the checklist is fully met.** Green tests are not done. If the
   list is not fully met, say "partial — X and Y still open".

## Conventions (enforced — do not relearn them the hard way)

- **A missing scanner is not a clean result.** Coverage gaps are reported as
  gaps, in the document and in `tools[].status`. Never let absence read as safety.
- **Never silently drop a finding.** Exclusions, severity floors and per-severity
  caps are all *counted* in the report. A number the user can see, not a quieter
  report.
- **A scanner must not scan its own output.** Report directories carry
  `.whatsrisky-output` and are skipped. Our JSON quotes the secrets it found.
- **Honest scoping.** If a scanner cannot honour an option, it says so in the
  report (see Trivy and `--diff`) instead of pretending. Fake precision is worse
  than a stated limitation.
- **The AI pass is opt-in, always.** It spends the caller's money and sends code
  to a third party. It is never in a default set, and the report records which
  model produced which finding.
- **An agentic backend and an API backend are not the same analysis.** One reads
  the repository, the other sees the slice we chose. The report says which ran and
  how much it was shown; a backend that cannot do something refuses with the reason
  instead of returning a confident empty answer.
- **Testing discipline.** (1) Bug → failing test first. (2) Assert the invariant,
  not a proxy — a test must fail when the feature is actually wrong; parser tests
  run against real scanner output, not mocks. (3) Reproduce the failing variant
  before claiming a fix works.
- **No credentials in this repository, real or fake.** The vulnerable fixture is
  derived from a seed at test time. A literal `ghp_…` trips GitHub push protection
  and every secret scanner pointed at us — and CPython folds a split literal back
  together in the `.pyc`.
- **English-only source.** All shipped text — code, comments, docs, schema
  descriptions, prompts, commit messages — is English. Other languages appear only
  as an interface locale in a viewer, never in the source.
- **Every setting goes through `ScanOptions`.** Add the field, the flag, the
  widget, and the `command_line()` case together. A setting that exists in only
  one front end is a bug: the UI's "equivalent command" panel is what keeps the
  CLI and the UI honest.
- **Two independent versions, both contracts.** `whatsrisky/__init__.py` holds the
  package version and nothing else does — `pyproject.toml` reads it through
  `[tool.hatch.version]`, so a wheel cannot disagree with the reports it writes.
  `SCHEMA_VERSION` in `models.py` versions the JSON report and moves on its own
  schedule. A change that ships bumps the package version and closes a CHANGELOG
  section in the same PR; `tests/test_version.py` fails when either is missing.
- **JSON changes bump `SCHEMA_VERSION`.** Other tools consume the report;
  `schema/report.schema.json` is a contract, not documentation.
- **Design system** (when a viewer exists): the same rules as whydiff, because the
  two windows sit side by side — hex colours only in the token block on
  `:root`/`[data-p=…]`, `border-radius` ≤ 5px, `font-size` ≥ 13px, no
  `text-transform: uppercase`, shadows only on overlays, one level of box nesting
  in the reading column. A test enforces it.
- **Git identity.** Personal repo (`github.com/smagew/whatsrisky`): commit and
  push as **smagew** over SSH. The `gh` CLI here is signed in as the work account
  (`alishervertex`) — use it for reads only, never for PRs, releases or branch
  settings.
- **Branching.** Trunk-based: short branches named by intent (`feat/…`, `fix/…`,
  `chore/…`), one PR each, deleted after merge. Conventional commit subjects
  (`feat(core):`, `fix(ui):`, `chore(release):`).

## Release

1. Bump `__version__` in `whatsrisky/__init__.py` (semver: a report-schema change or
   a new pass is a minor, a fix is a patch).
2. Rename the CHANGELOG's `[Unreleased]` heading to `[X.Y.Z] - YYYY-MM-DD` and open a
   fresh empty `[Unreleased]` above it.
3. `python -m pytest tests -q` — the version tests check both.
4. Merge, then tag `vX.Y.Z` on main.

## Gotchas

Hard-won; check before touching the area. Add to this list whenever a surprise
costs time.

- **`claude -p "/slash-command"` is a no-op in headless mode** — zero turns, empty
  result. Drive the skill by name instead ("Use the security-review skill to …")
  with `Skill` in `--allowed-tools`.
- **LLMs emit almost-JSON.** `"line": 15-38`, trailing commas, Python literals.
  `util.repair_json_text` fixes the known shapes; a second cheap call reshapes the
  rest. Never lose an audit to a formatting slip.
- **Scanner output carries control characters.** ANSI escapes and NULs from stderr
  make `python-docx` raise `ValueError`. Everything is sanitized in
  `Finding.__post_init__` and at each DOCX insertion point.
- **gitleaks has no exclude flag.** Paths are excluded through a generated config
  with `[extend] useDefault = true` + `[[allowlists]] paths` (verified on 8.30.1).
- **CI failures here have been about the runner, not the commands.** `uv pip
  install --system` fails on the uv-managed interpreter setup-uv provides, and
  `uv venv` fails because setup-uv has already created one — so every job needs
  `--allow-existing` and `uv run`. `make check-ci` reproduces both preconditions
  against a clean export; `tests/test_design.py` guards them.
- **A stub server is how the API backends are tested.** `tests/test_ai.py` runs a
  local `ThreadingHTTPServer` speaking the chat-completions shape, so request
  construction, context injection and every error path are covered without a key.
  What it cannot cover is the real service's behaviour — say so, do not imply it.
- **`semgrep --config auto` needs the network and metrics.** With `--offline` it
  falls back to `p/security-audit`; `--metrics off` breaks `auto`.
- **Semgrep suppressions anchor on the call site**, not on the flagged argument's
  line: `# nosemgrep: rule-id` goes on the line the finding reports. It must also be
  the line *immediately* before it — a two-line comment pushes the marker out of
  range and the suppression silently does nothing. Put the reason on the first
  line and `# nosemgrep: rule-id` alone on the last.
