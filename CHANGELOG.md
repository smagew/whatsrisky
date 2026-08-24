# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
