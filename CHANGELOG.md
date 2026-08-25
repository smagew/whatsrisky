# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
