# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
