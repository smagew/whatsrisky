# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-08-26

### Added — desktop

- **A desktop window (`desktop/`), built on Tauri.** It drives the `whatsrisky`
  binary rather than reimplementing anything: pick a mode — folder, address, or
  domain — set the options, and it shows the exact command it will run, runs it,
  streams the progress, and opens the report the binary wrote (the same HTML
  viewer the CLI produces). The command on screen *is* the argument list that runs,
  so it cannot drift from the scan. Tauri over Electron to keep the footprint to a
  system webview and a thin Rust shell, in the spirit of the single Go binary.
  It shows a **tool inventory** (from `doctor --json`): what is installed, and an
  **Install** button for each missing tool that runs the package manager for you
  (`doctor --install-tool`). During a scan it shows **per-tool progress** — which
  passes will run, which is running, and how long each took — parsed from a new
  `scan --events` NDJSON stream. The tool inventory is filtered to the active tab —
  Folder shows the source scanners, Address the network passes, Domain the
  discovery and screenshot tools — from a `modes` field `doctor --json` now
  reports, so the grouping comes from the engine, not the window. Not launched here (no display); the Rust shell
  compiles against Tauri v2 and the frontend is plain checked JS. Native folder
  picker and embedded report view are the next steps.

### Changed

- **`model.SchemaVersion` is 4.** The JSON report gained an `assets` array — the
  estate a perimeter scan mapped, each host with whether it resolved, whether it
  answered HTTP, its URL, status and stack. It is `[]` for a single-target or
  filesystem scan, so an existing consumer that ignores the field is unaffected.
  `schema/report.schema.json` and the Markdown report carry it too.

### Added

- **Perimeter mode: scan a whole estate, not one address.**
  `whatsrisky perimeter example.com --i-am-authorized` discovers the live web
  assets under a domain and runs the observational passes across every one of
  them, into a single report.
  - **Discovery** is the ProjectDiscovery chain — subfinder (subdomains) → dnsx
    (resolve) → httpx (which are alive, and their stack). Each tool is optional: a
    missing one is a stated gap, not a stop, and the chain still returns what it
    could find. The inventory is printed live and recorded in the report as its own
    `discovery` tool result, so an absent tool is visible there too.
  - **Fan-out** runs surface, testssl and nuclei on each alive asset; every finding
    carries the asset it came from. llm-recon is left out by default — a paid model
    call per asset across an estate is a cost to ask for with `--passes`.
  - Authorization is required and sharper than for a single target: you are stating
    you may scan the domain and every host under it.
  - **gowitness screenshots.** Each live asset is loaded in a headless browser and
    pictured; the shot is matched back to its asset and shown in the HTML report's
    new estate panel, so a forgotten admin panel is obvious at a glance.
    Observational — a browser loading the page — so no `--net-active`. The estate
    report is a page plus a screenshots directory beside it, rather than one file.
  - **katana crawl (`--crawl`).** Each asset is spidered and the endpoints it finds
    are handed to nuclei, so nuclei checks the pages a site actually has, not only
    its front door. The crawl stays on the asset's own host and is capped; it is a
    lot of ordinary GETs, so it is opt-in. The other passes still look at the asset
    itself.
  - `doctor` now reports the discovery, screenshot and crawl tools too, and gains
  `--json` (machine-readable status with an install command per tool) and
  `--install-tool NAME` (install one tool), which the desktop window uses.
- `scan --events` emits progress as JSON lines, so a front end can show which pass
  is running and how long each took.

### Notes

- Perimeter is an orchestrator over the single-target scan, in this repo by design:
  the severity scale, the report and the honesty rules are shared, not
  reimplemented. gowitness screenshots, a katana crawl feeding nuclei, and a proper
  per-asset section in the JSON report (a schema change) are the next steps.


## [0.5.0] - 2026-08-26

### Added

- **A network scan: point whatsrisky at a live address, not just a folder.**
  `whatsrisky https://example.com --i-am-authorized` runs three passes and
  normalises their findings onto the same severity scale as the code scan.
  - **surface** — pure Go, fully observational: TLS and certificate, the security
    headers a site is missing, version-leaking headers, insecure cookies, and the
    paths robots.txt asks crawlers to avoid. It sends only the GETs a browser
    makes.
  - **testssl** — deep TLS analysis via [testssl.sh](https://github.com/testssl/testssl.sh):
    cipher suites, protocol versions, the certificate chain, and the named TLS CVEs
    (Heartbleed, ROBOT, downgrade). Observational — it only completes handshakes.
    surface keeps a shallow TLS check as a baseline for when testssl is not
    installed.
  - **nuclei** — ProjectDiscovery's template scanner for known CVEs, misconfig and
    exposures. By default it excludes the templates that send payloads (fuzzing,
    injection); `--net-active` includes them, and the report says which ran.
  - **zap** — OWASP ZAP through its packaged scan scripts. The baseline spiders the
    site and reports what its passive rules see (it crawls but sends no attacks) and
    is the default when zap is chosen; `--net-active` runs the full active scan. Not
    in the default set — it is a heavyweight, asked for with `--passes`.
  - **ffuf** — content discovery: it brute-forces paths from a wordlist, which is how
    a forgotten admin panel turns up. Brute-force is attack traffic, so it runs only
    with `--net-active` and a `--wordlist`; without either it reports itself as a
    coverage gap with the reason. Opt-in via `--passes`.
  - **llm-recon** — a language model reads what the site serves and reasons about
    where to look by hand. Its findings are leads to verify, not confirmed holes,
    and it says so. Opt-in and paid, like the code AI pass; `--no-llm` drops it.
- **Authorization is required and stated.** A network scan refuses to start without
  `--i-am-authorized`; the target and the fact of authorization are recorded, and
  the equivalent command always shows the flag. Pointing this tool at an address
  you do not control is the caller's responsibility, stated rather than assumed.
- `doctor` now reports the network passes too, so you can see whether `nuclei` is
  installed before you rely on it.

### Notes

- The two scan kinds keep separate vocabularies: the code scanners never run
  against a URL and the network passes never run against a folder, each refusing
  with the reason rather than pretending. Observational is the default throughout;
  anything that sends attack-shaped traffic is behind `--net-active`.


## [0.4.0] - 2026-08-26

### Changed

- **Settings belong to the project, not to whoever ran the tool last.** A launch
  reads `.whatsrisky.json` from the folder being scanned; without one, the
  defaults. Nothing else is consulted. Previously the settings lived in one shared
  file, so running whatsrisky in a second project came up showing the first
  project's folder and the first project's profile.
  The file can be committed, which is how a team shares one way of scanning. It
  never stores a path, a diff range or a baseline — those belong to one invocation,
  and a file that carried them would hand the next reader someone else's run.
  `ctrl+s` writes it. `--profile NAME` still wins, because a name is asked for
  explicitly, and a flag on the line wins over both. The CLI says
  `using .whatsrisky.json from …` when it reads one: settings that did not come
  from the command line have to be visible.
- **The AI review pass now runs by default.** A deliberate decision by the project
  owner, taken after the case against it was put: it spends the caller's money and
  sends code to a third party. What the decision obliges is in place — `--no-ai`
  drops it and has the last word over every other way of asking for the pass,
  including naming a model; the equivalent command prints `--no-ai` rather than a
  list of the other three; the screen warns about the cost before the run; and the
  report still records which model produced which finding.

- **The interface is rebuilt on [tview](https://github.com/rivo/tview).** tview is a
  widget toolkit, so the checkboxes, lists, fields, focus handling and mouse are
  the library's rather than ours. Bubble Tea, which the last two versions used, is
  an event loop: with it the form had to be written by hand, and every defect
  reported in the interface was in that hand-written code.
- **Every setting is on the screen at once.** No pages and no scrolling: the
  arrangement is chosen by whether the settings actually fit — one column beside
  the panel when the terminal is tall enough, two columns when it is not.
- **The mouse works throughout.** A click ticks a scanner, opens a list, picks
  from it, or puts the cursor in a field. Only text is still typed.
- **No jargon on the screen.** "pattern", "exclusion" and "glob" are gone. The
  section is called *what we do not look at*, and a test fails if any of those
  words comes back.
- Labels say what a setting is for: *project folder*, *only these changes*, *hide
  anything below*, *fail the build at*.

### Added

- **`--no-ai`**, because a default that spends money has to be one flag to refuse,
  not a list of the three scanners you do want.
- **The folders of the project are picked from a list, not typed.** The row says
  what is skipped — `6 folders here, none skipped` — and opens the full list
  vertically, with a tick against each and no length at which it starts hiding
  things. Typing the name of a folder you are looking at is dictation, not a
  choice. The ones already in the usual noise are not offered twice, and a folder
  that is both ticked and typed reaches the scanners once.
- **The model is a list.** `ai.Models` names what each provider is usually asked
  for — opus, sonnet, haiku for the CLI; gpt-5 and friends for the API — and the
  field completes from it. An id we have never heard of still goes through: a
  provider's catalogue moves faster than our list, and a field that refuses a
  valid model is worse than one that only suggests.
- **The scanners and the output formats are each a row of chips** —
  `[x] semgrep [x] trivy [x] gitleaks [ ] ai` — instead of one checkbox per row.
  tview has no such item, so this is the one widget written by hand here: it
  implements the form-item contract, moves with left and right, toggles with
  space, and lands a click on the chip pointed at rather than on the row. Five
  rows saved, which is what decides whether a terminal gets one column of
  settings or two.
- **An empty field says what belongs in it** — `main..HEAD`,
  `build, *.min.js`, `blank = the default` — and each section says what it is
  for, on the heading line so it costs no vertical room.
- **A run button you can click.** A key hint is not a button.
- **The 49 folders and files we always skip are listed, not just counted**
  (`ctrl+i`). The list is read from `internal/exclude.Defaults`, so it cannot
  drift from the one that does the skipping, and it says how to scan one of them
  anyway: point whatsrisky straight at it.
- **A scanner that is switched on but not installed is a warning before the run**,
  worded as what goes unchecked rather than as a tool name — "gitleaks is not
  installed, so secrets, including the ones in git history, will not be checked".
  Absence must not read as safety on this screen either.
- `ctrl+p` shows the panel where there is no room for it beside the form.

### Fixed

- **ZAP runs via Docker, so it is usable without a fiddly install.** whatsrisky
  calls zap-baseline.py / zap-full-scan.py, which the Homebrew cask and the desktop
  app do not put on PATH — the scripts ship inside the ZAP Docker image. ZAP now
  runs the script directly when it is on PATH and otherwise through
  `ghcr.io/zaproxy/zaproxy`, mounting the work directory so the report comes back
  either way. With Docker present it reads as installed ("via Docker") and the image
  auto-pulls on first run; without Docker the hint says to install it. This replaces
  the earlier honest-but-dead-end "run the Docker image" note.
- **A tool the window cannot install for you reads cleanly.** A missing,
  non-one-click tool shows the description, a plain "not installed", and its
  how-to-get-it on its own line, with the "not found in PATH. Install:" boilerplate
  stripped.
- **Network findings now have a source of their own.** A finding's *source* — the
  axis the report groups and filters by — is inferred from its tool, and every tool
  added this release (surface, testssl, nuclei, zap, ffuf, llm-recon) fell through
  to `source-code`, so a TLS or header problem on a live address read as a code
  problem. They are now `live-target`. *found by* was already correct — it shows the
  tool that reported the finding. No other stale mapping was found: the report's
  category, source and detector filters are all built from the findings, not a
  hardcoded list.
- **The install button runs the right command.** gowitness is not a Homebrew
  formula (`brew install gowitness` fails); it is `go install
  github.com/sensepost/gowitness@latest`. The install commands are now an explicit
  map — brew or go — and a command is offered only when the program it needs (brew
  or go) is actually on PATH.
- **The desktop window shows a scan as finished even after the AI pass.** It knew a
  run had ended by the stdout stream reaching EOF, but the agentic AI backend can
  leave a descendant holding that pipe open, so EOF never came and the window sat
  there though the scan was long done and the report written. It now ends on the
  process exiting, draining the last output first, and runs the child with no stdin
  so the agentic CLI cannot block waiting for input.
- **The desktop window finds tools a GUI's minimal PATH hides.** A macOS app
  inherits a bare PATH, so a Homebrew or `go install` tool was present on disk but
  invisible to the scan the window launched. The window now runs the binary with
  the usual install locations (`~/go/bin`, the Homebrew dirs) prepended to PATH.
- **Ticking a folder no longer un-ticks the one before it.** tview runs a clicked
  item's handler without moving the cursor first, so a handler that read the cursor
  toggled whichever folder had been ticked previously. The index comes from the
  handler now.
- **The arrows walk the list.** `Pages` shows a page without moving the keyboard
  focus, so the arrows were still going to the form behind the overlay.
- **A click can no longer fall through an overlay onto the screen behind it.**
  This is what "everything breaks as soon as I click" was. The settings page stayed
  live under the list, so a click the list did not want reached the form beneath —
  and landing on a drop-down opened it *behind* the overlay, where it then captured
  every further mouse event. The interface was not frozen; it was answering a
  widget nobody could see. An overlay is a modal layer now: it swallows what it
  does not use.
- **A double click does what a single click does.** tview turns two clicks inside
  its double-click interval into one `MouseLeftDoubleClick`, and nothing handled
  that — not this code, not tview's own list. Clicking about at a normal pace, every
  other click landed on nothing.
- **Clicking beside an overlay closes it instead of freezing everything.** The
  space around it was a plain `Box`, and a `Box` takes the focus when clicked while
  being able to do nothing with it — one click beside the list left the interface
  dead to keys and clicks alike. The backdrop now dismisses and never takes focus,
  and it applies to all three overlays.
- **The interface paints its own ground.** It was `tcell.ColorDefault`, which is
  the terminal's own background - so on a translucent terminal the desktop showed
  through the text and none of it could be read. At 209x33 that was 6,532 cells.
  A test counts them and fails at one, overlays included; the margins around an
  overlay were `nil` items, which paint nothing at all.
- **Fields are as wide as their contents need, not as wide as the terminal.**
  tview paints a field's whole width, so one sized to a 200-column terminal was
  sixty-five characters of background running off to the right - which reads as a
  redaction bar rather than as somewhere to type. A path gets 44 columns, a model
  name 22.
- A section's description sits in the value column, not the label. In the label
  it was the widest label in the form, and every value on the screen lined up
  after it.
- A ticked chip keeps its tick: tview reads square brackets as colour markup, so
  an unescaped `[x]` was swallowed.
- **No folder is hidden, at any count.** The folders were first a horizontal row
  that stopped at ten in silence, then one that counted what it hid. Both were the
  wrong shape: a row of chips suits four fixed scanners, and a project has as many
  folders as it has. It is a list now, and a list scrolls.
- A problem that blocks a scan — a path that is not a directory — is on the
  always-visible line, not only in a panel a small terminal hides.
- A scanner that did not run no longer has "0 findings" written next to it in the
  log. That phrase describes a clean pass, and this was not one.
- The reason a scanner is missing is wrapped onto its own lines instead of being
  truncated: "not found in PATH. Install: …" is the actionable half, and the
  ellipsis ate exactly that half.

### Removed

- `bubbletea`, `bubbles`, `lipgloss` and `huh`. The interface has one dependency
  now, plus the terminal library under it.


## [0.3.2] - 2026-08-26

### Changed

- The settings form is now built with [huh](https://github.com/charmbracelet/huh)
  instead of by hand. Bubble Tea is a framework, not a widget set, so the previous
  form was 1,379 lines of our own field, focus and scrolling code — and every
  defect reported in it was in that code. What replaces it is real widgets:
  checkboxes that say whether they are ticked, selects that show the whole option,
  descriptions under the field instead of in the value column, and a viewport that
  scrolls rather than a form that draws past the bottom of the terminal.
- The panel is given its width before the form, not after. Starving it is what
  made the equivalent command break inside an argument and the warnings break
  mid-phrase.

### Fixed

- The model dropped every message it did not recognise, and huh answers a
  keypress with a command whose message is what moves the focus. The form could
  not be navigated at all.
- A resize widened the frame and left every description wrapped for the old
  width, so the form kept its narrow text. The form is rebuilt on resize; the
  fields bind to the same variables, so nothing typed is lost.
- Exactly one field looks focused. The blurred styles were a copy of the focused
  ones, which put the focus bar on all twenty fields at once.
- A section heading can no longer be the first field: huh renders the whole group
  as blank space when focus starts on one.
- The scanner list in the panel no longer both wraps and gets an ellipsis.

### Removed

- Click-to-focus and wheel scrolling. Both existed to compensate for a form that
  was hard to navigate by keyboard; the keyboard now works, and a fake click
  target is worse than none. The key hint that outlived the mouse is gone with it.


## [0.3.1] - 2026-08-25

Never published as a release: the release job cross-compiled everything and then
died on `git tag`, which rejects `-F` with `-m`. These changes ship in 0.3.2.

### Fixed

- The settings form fits the terminal. It drew 39 lines with nothing clamping them,
  so on a 100x30 terminal the whole Tuning section and the key bindings were simply
  cut off — a form with no visible way to act. It scrolls now, keeping the focused
  row in view, with the primary action and the key help pinned below it and a
  `↓ N more` indicator. Tested from 80x24 to 200x60.
- The equivalent command survives a narrow terminal. Below 100 columns the side
  panel cannot sit beside the form; it used to disappear entirely, taking with it
  the thing that makes the UI worth using. The command and the first warning are
  stacked underneath instead.
- A cycling field looks like one: choices and toggles keep their `‹ … ›` brackets
  when unfocused, so half the form no longer reads as static text.
- The mouse works: click a row to focus it, wheel to scroll. Stepping through
  twenty rows with the arrows was the only way to reach anything.

## [0.3.0] - 2026-08-25

Rewritten in Go. One binary, no runtime, installed the way the scanners it
orchestrates are installed. See [docs/go-rewrite.md](docs/go-rewrite.md) for why,
what it cost, and what it had to preserve.

### Changed

- **whatsrisky is a single static binary.** `curl -sSfL …/install.sh | sh`, or a
  release archive per platform for darwin, linux and windows on amd64 and arm64.
  No Python, no virtualenv, no interpreter that reports itself externally managed.
  The Claude Code plugin and the desktop UI on the roadmap now have no
  prerequisites beyond the scanners themselves.
- **The report schema, the config file and the CLI are unchanged.** Schema stays at
  version 3 field for field; `~/.config/whatsrisky/config.json` is read as the
  Python version wrote it, migrations and all, so nobody re-creates their profiles
  because the tool changed language; every flag still means what it meant.
- The terminal UI is a Bubble Tea model rather than a Textual app. Same form, same
  live equivalent-command panel, same warnings before the scan rather than after.

### Removed

- **The DOCX report.** `python-docx` plus hand-written OOXML has no equivalent in
  Go under a permissive licence, and the HTML report had already become the working
  view. `--format docx` fails with the reason and the two ways to get a Word file
  rather than being ignored in silence. The Python implementation stays retrievable
  at the `v0.2.0-python` tag.

### Verified

Parity was a differential test, not a claim: both implementations scanned the same
project and every field of every finding had to agree — **28 findings and 17
contract fields identical**, fingerprints included, because without matching
digests a Go scan could not correlate against a baseline a Python scan wrote. The
frozen record of what the reference computed stays in `testdata/parity/`.

### Fixed on the way

- Flags may follow the path. Go's flag package stops at the first non-flag
  argument, so `whatsrisky <path> --out-dir X` silently ignored the flag.
- A missing scanner's progress row no longer reports "0 findings", which says
  nothing about a scanner that never ran; it carries the reason.

### Added

- `Makefile` with `check`, `test-all`, `selfscan` and `check-ci`. The last one replays the CI job
  steps against a clean export of HEAD *with the runner's preconditions* — a uv-managed interpreter
  and a `.venv` that setup-uv has already created — because both CI failures so far were about those
  rather than about the commands.

### Fixed

- A saved profile is what the next launch starts from. Saving one records it as active, the picker
  opens on it and the window title names it; previously the UI always reopened on the last run and a
  profile had to be found and re-chosen by hand.
- The profile picker is the first block in the form instead of the last block of the side panel, the
  blank entry means "not in a profile" rather than doing nothing, and re-picking the active profile
  reloads it.
- A profile no longer carries the project path, the git range, the baseline or an explicit output
  file. Those are per-invocation; storing them meant a profile reused elsewhere dragged the old
  project with it. Existing profiles are cleaned up by a config migration.
- "View report" opens the page or nothing. It used to fall back to the JSON file when a run wrote no
  HTML, which looked like a broken button. Profiles saved before the HTML view existed had
  `formats: ["json"]` and hit exactly that; the migration adds `html` back to them.
- A CLI run no longer overwrites what the UI remembers, so a scripted `--out-dir /tmp/x` cannot end
  up as the interactive default.

## [0.2.0] - 2026-08-25

### Added

- The AI pass is provider-neutral (`schema_version: 3`). `whatsrisky/ai/` holds the backends and
  `--ai-provider` picks one: `claude-cli` as before, or `openai` over the API with the key from the
  environment (`OPENAI_API_KEY`, `OPENAI_BASE_URL` to point elsewhere). `--model` is free-form and
  defaults to the backend's own; the tool is now called `ai` rather than `claude`, with `claude`
  accepted as an alias.
- The report states how the model saw the project. An agentic backend explores the repository
  itself; an API backend is handed a context we choose, and the tool note says so along with how many
  files it was shown. `detector` carries the provider and the model on every finding.
- Context selection for non-agentic backends (`whatsrisky/ai/context.py`): auth, routes, middleware
  and config first, tests and docs last, within `--ai-context-bytes`. Excluded paths are never sent,
  a `--diff` scope limits it to the changed files, and the skipped count is reported.
- An API backend refuses what it cannot do instead of returning a confident empty answer: asking
  `openai` for `--ai-mode review` fails with the reason and the two ways to fix it.

- Self-contained HTML report (`report.html`, on by default). One file, no network: the viewer with
  the report JSON inlined, so the artifact is both the view and the data and the round trip is
  exact. Groups by severity, category, source, who found it, directory or status; filters compose
  and live in the URL hash so a filtered view is a link. Coverage gaps sit with the counts rather
  than in an appendix, resolved findings are one click away and never inflate the open counts, and
  the palettes are whydiff's so the two windows read as one family.
- The report can be opened while the scan runs. It exists before the first scanner starts, says
  `scanning — 1 of 3 done` and names the pending scanners. The TUI enables **View report** (`v`)
  from the first second; **Open DOCX** (`d`) stays disabled until the DOCX exists and says why.

- Rescan comparison (`schema_version: 2`). A scan correlates itself against the previous report and
  labels every finding `new`, `open`, `resolved`, `reintroduced` or `accepted`. Resolved findings are
  carried into the report for one generation, because showing them is the point. Three identity keys
  — exact location, the evidence itself, the location without the line — mean code that moves keeps
  its history instead of being reported as a fix plus a regression. `--baseline`, `--no-compare`, and
  automatic discovery of the latest report otherwise.
- Grouping axes on every finding: a normalized `category` from a closed vocabulary derived from CWE,
  a `source` (source code, dependency manifest, git history, IaC, container, CI config), and a
  `detector` object recording tool, provider, model and pass — so "who found it" is a real axis and
  another AI provider is a seam rather than a rewrite.
- The JSON report is written from the first second of a scan and rewritten atomically after each
  scanner, with `status: running` and per-scanner `pending`/`running`, so a viewer can open it
  mid-scan.
- Resolved and accepted findings are excluded from the counts, the risk score, the verdict and the
  exit code — history and decisions are not open work — and get their own section in the DOCX.

- Default skip list for vendored, generated and build directories, with `--exclude`,
  `--no-default-excludes` and `--show-excludes`. Exclusions now reach every scanner: gitleaks gets a
  generated allowlist config (it has no exclude flag), the AI pass is told which paths to ignore, and
  a post-filter drops anything that slips through — counted in the report, not hidden.
- Directory picker in the settings UI: the project's own directories as checkboxes, so skipping a
  folder no longer means typing a pattern.
- Live progress. Scanner output is streamed instead of captured, so each tool reports what it is
  doing as it happens; the AI pass runs with `--output-format stream-json` and shows which files the
  reviewer is reading. Shared `ProgressModel` renders in both the CLI (rich Live) and the TUI, with
  plain lines on a non-terminal.

### Fixed

- A running scan no longer reports "CLEAN". Absence of findings before the scanners have finished is
  not safety, which is the rule this project applies to everything else.
- A verdict no longer sounds more confident than its coverage: with a scanner missing it reads
  `MODERATE - plan remediation · partial coverage (trivy did not run)`.
- Category precedence: an unambiguous rule-id token now outranks the CWE, because scanner CWE tagging
  is unreliable — semgrep tags its own `injection.tainted-sql-string` rule with CWE-915, which filed
  SQL injections under deserialization. Findings in Dockerfiles, IaC and CI config fall back to
  `misconfiguration` instead of `other`. On the fixture project `other` went from 2% to 0%.
- A scan no longer discovers its own reports. Output directories are marked, so a second run does not
  re-report the secrets quoted in the first run's report.
- `OPENAI_BASE_URL` is validated as an http(s) URL with a host. `urlopen` speaks `file://` too, so an
  unchecked environment variable turned "point it at a compatible endpoint" into reading a local
  file. Found by scanning ourselves.

## [0.1.0] - 2026-08-24

First release.

### Added

- Orchestration of Semgrep, Trivy and gitleaks with findings normalized onto one severity scale.
- Optional Claude Code review pass (`--ai`) in two modes: whole-project audit, or the branch diff via
  the `security-review` skill. Malformed model JSON is repaired locally, then reshaped by a cheap
  follow-up call rather than lost.
- Prioritized DOCX report: verdict, executive summary with per-severity SLAs, coverage gaps, findings
  CRITICAL→INFO with evidence and remediation. Markdown and JSON outputs alongside it.
- `--diff <range>` to scope a scan to files changed in a git range (Semgrep, gitleaks and the AI pass
  honour it; Trivy states that it cannot).
- Textual settings UI with a live equivalent-command panel, scanner probing, and named profiles
  shared with the CLI.
- Versioned JSON contract (`schema/report.schema.json`) plus `--json-stdout` and `--quiet` for
  embedding in other tools.
- `doctor` with per-platform install hints.
