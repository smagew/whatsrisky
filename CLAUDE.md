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
make check       # gofmt + vet + tests + the self-scan gate
make test        # -short: no scanner binaries needed
make test-all    # everything, against the real scanners
make build-all   # every release archive into dist/
make live-ai     # the AI pass against the real claude CLI (spends tokens)
```

`make check` before every push.

## Architecture

A scan is a pipeline: options → scanners in parallel → normalized findings → report writers.

- `cmd/whatsrisky` — the CLI and its subcommands. No logic beyond argument
  handling and rendering.
- `internal/model` — severity, findings, the category vocabulary, the report and its
  verdict rules. `SchemaVersion` lives here.
- `internal/scan` — `Options` (every setting, serializable) and `Run()`. No
  terminal, no UI: this is the library API and the single source of truth for the
  defaults, the exclusions and the diff scoping.
- `internal/runner` — one file per scanner. Each maps its own severities onto the
  shared scale explicitly, and each keeps its own honesty (Trivy states that it
  ignored `--diff`).
- `internal/ai` — who runs the AI pass. `Agentic` is part of the contract: one
  backend reads the repository, the other sees the slice we chose.
- `internal/compare` — rescan correlation. `internal/report` — JSON, HTML
  (`templates/viewer.html`, embedded with go:embed), Markdown. `internal/ui` — the
  Bubble Tea interface. `internal/config` — profiles and the last-run memory.
- `schema/report.schema.json` — the machine contract for other tools.
- `testdata/parity` — what the Python implementation computed, frozen. The tests
  still check against it; see docs/go-rewrite.md.

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
- **No credentials in this repository, real or fake.** The vulnerable fixture
  (`internal/fixture`) derives them from a hash stream at test time. A literal
  `ghp_…` trips GitHub push protection and every secret scanner pointed at us, and
  splitting one across two string parts does not help: the halves are still
  high-entropy strings.
- **English-only source.** All shipped text — code, comments, docs, schema
  descriptions, prompts, commit messages — is English. Other languages appear only
  as an interface locale in a viewer, never in the source.
- **Every setting goes through `scan.Options`.** Add the field, the flag, the
  widget, and the `command_line()` case together. A setting that exists in only
  one front end is a bug: the UI's "equivalent command" panel is what keeps the
  CLI and the UI honest.
- **Two independent versions, both contracts.** `cmd/whatsrisky/main.go` holds the
  package version and nothing else does — the Makefile reads it out of the source
  and the release workflow refuses to publish when the tag disagrees.
  `model.SchemaVersion` versions the JSON report and moves on its own schedule. A
  change that ships bumps the package version and closes a CHANGELOG section in the
  same PR; `cmd/whatsrisky/version_test.go` fails when either is missing.
- **JSON changes bump `model.SchemaVersion`.** Other tools consume the report;
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

Releases are automatic; the only manual part is the bump, and CI refuses a pull
request without it.

1. Bump `Version` in `cmd/whatsrisky/main.go` (semver: a report-schema change or a
   new pass is a minor, a fix is a patch).
2. Rename the CHANGELOG's `[Unreleased]` heading to `[X.Y.Z] - YYYY-MM-DD` and open a
   fresh empty `[Unreleased]` above it.
3. `make check`.
4. Merge. The release workflow sees a version with no release behind it, runs the
   tests, cross-compiles, creates the tag and publishes the archives with
   checksums. A merge that did not bump the version does nothing.

Do the bump in the same pull request as the change. Merging first and bumping
after is how 0.3.1 reached main still calling itself 0.3.0.

## Gotchas

- **Bubble Tea is a framework, not a widget set.** It gives an event loop and a
  renderer; `bubbles` gives primitives. Reaching for it to build a form means
  writing the form yourself, which is how a hand-rolled 1,379-line field/focus/
  scroll layer shipped and had to be replaced by `huh`. Check whether the widget
  exists before writing one.
- **A Bubble Tea model must not drop unknown messages.** huh answers a keypress
  with a command, and the message that command returns is what moves the focus.
  A `switch` with no default silently breaks all navigation.
- **huh's `WithWidth` does not re-wrap.** It moves the frame and leaves the field
  descriptions wrapped for the old width. Rebuild the form on resize; fields bind
  to variables, so nothing typed is lost.
- **Never copy `theme.Focused` into `theme.Blurred`.** The focus bar is how the
  user knows where they are; copying puts it on every field at once.
- **A huh `Note` must not be the first field in a group.** Focus starting on a
  skipped note renders the entire group as blank space.
- **Testing a Bubble Tea model means running its commands.** Dropping them reports
  a form that cannot be navigated. Running all of them waits on cursor-blink and
  tick timers - this suite went to 578 seconds before those were bounded, so run
  only what answers immediately.
- **`git tag` rejects `-F` with `-m`**, and it strips `#` lines from a message
  file as comments - so CHANGELOG notes reach a tag with every heading missing.
  `--cleanup=verbatim` with the subject line prepended into the file is the whole
  fix. Both cost a release: the workflow ran the tests, cross-compiled five
  platforms, and died on the tag.
- **A tag pushed by `GITHUB_TOKEN` does not trigger other workflows.** GitHub
  blocks that recursion, so a tag-then-release split would silently never release.
  The release workflow creates the tag and publishes in one job for this reason.
- **A terminal UI must be measured, not eyeballed.** The form drew 39 lines with
  nothing clamping it, so at 100x30 the whole Tuning section and the key bindings
  were off-screen — and the user reported it before any test did. The height tests
  in `internal/ui` now assert the view fits 80x24 through 200x60, that the action
  and the keys never scroll away, and that the equivalent command survives a narrow
  terminal.
- **`make build` targets `dist/`, never `./whatsrisky`.** That name was the Python
  package directory, and building over it deleted the tree once, three phases
  before the plan said it should go.
- **Go's flag package stops at the first non-flag argument**, so `whatsrisky <path>
  --out-dir X` would ignore the flag. `parseInterleaved` handles it; a test guards
  it.
- **Go's JSON encoder escapes `<` by default**, so a finding whose text contains
  `</script>` cannot break the HTML page. The manual escaping is belt-and-braces.

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
- **A stub server is how the API backends are tested.** `tests/test_ai.py` runs a
  local `ThreadingHTTPServer` speaking the chat-completions shape, so request
  construction, context injection and every error path are covered without a key.
  What it cannot cover is the real service's behaviour — say so, do not imply it.
- **`semgrep --config auto` needs the network and metrics.** With `--offline` it
  falls back to `p/security-audit`; `--metrics off` breaks `auto`.
- **`math/rand` is flagged on sight, and reasonably.** Where determinism is the
  requirement, derive the bytes from a hash stream instead of silencing the rule.
- **Semgrep suppressions anchor on the call site**, not on the flagged argument's
  line: `# nosemgrep: rule-id` goes on the line the finding reports. It must also be
  the line *immediately* before it — a two-line comment pushes the marker out of
  range and the suppression silently does nothing. Put the reason on the first
  line and `# nosemgrep: rule-id` alone on the last.
