# CLAUDE.md — working on whatsrisky

whatsrisky answers one question about a codebase: **what's risky here?** It runs
Semgrep, Trivy, gitleaks and an LLM reviewer (`--no-ai` drops it), normalizes every
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
- **The AI pass runs by default, and everything around it has to earn that.**
  Changed deliberately in 0.4.0, by the project owner, after the case against was
  put: it spends the caller's money and sends code to a third party. What the
  decision therefore obliges:
  `--no-ai` exists, has the last word over every way of asking for the pass
  (including naming a model), and is what the equivalent command prints; the
  screen warns about the cost before a run, not after; and the report still
  records which model produced which finding. A default that spends money is only
  acceptable while it is this easy to see and to refuse.
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

- **Reach for the widget set, not the event loop.** Bubble Tea gives a loop and a
  renderer; building a form on it means writing the form. That produced a
  1,379-line field/focus/scroll layer, then a `huh` rewrite that fought huh's
  page model, and finally tview - which had the widgets all along. Check what
  exists before writing one.
- **Measure the chrome, do not count it.** The settings form needs five rows
  around it, not the three the header, notice and key line suggest: tview's Form
  pads a row at each end. The arrangement is chosen from the measured number, and
  a test renders at every size from 80x24 to 200x60 to keep it true.
- **A tview `Form` does not scroll.** Whatever does not fit is simply not drawn,
  so the layout has to fit by construction - one column when the height allows,
  two when it does not.
- **A heading belongs in a form item's label, not its text.** `AddTextView` puts
  text in the value column, which lands a section heading under the values.
- **tview draws an unchecked box as an empty cell**, which reads as "no widget
  here" rather than "no". A single yes/no setting is a two-option list; a checkbox
  is for a list of things you tick.
- **`Application.SetInputCapture` runs before the focused widget**, and tview's
  fields bind neither ctrl+r nor ctrl+s. Function keys were never needed.
- **Render onto a `tcell.SimulationScreen` to test a screen.** Draw the primitive
  directly - `root.SetRect(...)` then `root.Draw(screen)`. Going through
  `Application` races its own first frame, which produced an 80-column preview of
  a 120-column layout and made the layout look broken.
- **Settings are per-project, and a launch reads nothing else.**
  `.whatsrisky.json` in the scanned folder, or the defaults. A remembered last run
  is what made whatsrisky open in one project showing another's folder and profile;
  restoring anything global on launch brings that back. Named profiles stay global
  because they are asked for by name. A per-run field - path, out, diff, baseline -
  must never be written into the file.
- **An overlay must swallow what it does not use.** `Pages` keeps the page
  underneath live, so a click the overlay ignores reaches the screen behind it -
  and if it lands on a drop-down, that drop-down opens *behind* the overlay and
  then captures every mouse event through `mouseCapturingPrimitive`. It looks
  exactly like a freeze. Wrap an overlay in a layer whose MouseHandler consumes
  anything its children did not.
- **Handle `MouseLeftDoubleClick` or map it to a click.** tview coalesces two quick
  clicks into it, and a widget that ignores it drops every other click a user makes.
- **Test the interface through `Application`, not through its handlers.** Calling
  MouseHandler directly passed while three mouse bugs shipped: the double-click
  coalescing, the click-through and the focus all live in the Application's own
  dispatch. `internal/ui/live_test.go` runs the real app on a SimulationScreen and
  injects real events; `SetSize` before `Run` does not reach it, so the size has to
  be delivered as an event.
- **An overlay needs a backdrop, not a `Box`.** A plain `tview.Box` takes the
  focus when clicked and then answers nothing, so one click beside an overlay
  leaves the whole interface unresponsive. The margins around anything that opens
  must dismiss it and must never take focus.
- **`Pages.AddPage` does not move the keyboard.** Whatever opens has to ask for
  focus, or its arrows go to the screen behind it.
- **In a tview `List`, take the index from the handler, never from
  `GetCurrentItem`.** A click runs the clicked item's handler before moving the
  cursor, so reading the cursor acts on the previous selection.
- **A row of chips is for a fixed few, a list is for however many.** The four
  scanners fit on a line and read well there. The project's own folders do not:
  the same widget reused for them stopped at what fitted, and then at a count of
  what it hid, before becoming what it should have been - a vertical list behind a
  summary row. Match the widget to whether you control the length.
- **`tcell.ColorDefault` is not a background, it is a hole.** It means "whatever
  the terminal has", and a translucent terminal then shows the desktop through the
  text. Set a real ground, set `tview.Styles` too - a drop-down's list and a page's
  frame take theirs from there - and never use a `nil` Flex item as a margin,
  because nil paints nothing.
- **tview paints a field's whole width**, so a field sized to the terminal is a
  bar of background, not a field. Cap each one at what its contents need.
- **tview reads `[` as the start of a colour tag.** A literal `[x]` is swallowed;
  `tview.Escape` is the fix. Found by writing the chip row and seeing every ticked
  chip render bare.
- **A form item's label sets the alignment for the whole form.** Putting a section
  description in the label made it the widest label and pushed every value on the
  screen out to its width; descriptions belong in the value column.
- **Python's Textual has no equal in Go.** It is a full app framework - CSS, a
  layout engine, reactive state - and the Go ecosystem has widget toolkits
  (tview) and event loops (bubbletea) but nothing with a styling language. Bordered
  fields and chip rows come free there and are hand-written here. Worth knowing
  before promising a screen will look like the 0.2.0 one did.
- **A squash merge plus a long-lived branch is a conflict machine.** Squashing
  leaves main with the content but not the commits, so the branch it came from is
  not an ancestor of anything. Keep committing to that branch and every later
  merge replays work main already has, conflicting on every file touched twice -
  four times in a row here, in the same files. Branch fresh from main for each
  pull request, which is what the branching rule above already says.
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
