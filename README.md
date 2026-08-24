# whatsrisky

**What's risky in this project?** Point it at a path, get one prioritized security report — DOCX for people, JSON for machines.

Four scanners, one severity scale, one document:

| Scanner | Covers |
| --- | --- |
| **Semgrep** | First-party source code (SAST) |
| **Trivy** | Dependency CVEs, IaC / container misconfiguration, optionally secrets |
| **gitleaks** | Hardcoded secrets in the working tree *and* in git history |
| **Claude Code** | LLM review of logic, authn/authz and data flow — whole-project audit or the branch diff |

The report is the point. Not a wall of tool output: a document that says what to fix first, why it
is exploitable, where it is, and — the part scanners usually hide — **what was not scanned at all**.

![settings UI](docs/tui-settings.png)

## Install

```bash
uv tool install whatsrisky        # or: pipx install whatsrisky
whatsrisky doctor --install       # checks the scanners, offers to install the missing ones
```

From a clone:

```bash
git clone https://github.com/smagew/whatsrisky && cd whatsrisky
uv tool install --editable .
```

The three scanners are separate binaries (`semgrep`, `trivy`, `gitleaks`) — `doctor` tells you what
is missing and how to get it on your platform. The Claude pass additionally needs the `claude` CLI
(`npm i -g @anthropic-ai/claude-code`) and is **off by default**: it spends tokens on your account.

## Use

```bash
whatsrisky ~/www/app                      # semgrep + trivy + gitleaks, reports in ./whatsrisky-reports
whatsrisky ~/www/app --ai                 # add the Claude review pass (costs tokens)
whatsrisky ~/www/app --diff HEAD~1..HEAD  # only what this range changed
whatsrisky ~/www/app --min-severity HIGH --open
whatsrisky ~/www/app --fail-on high       # exit 2 for CI when HIGH+ exists
whatsrisky                                # no arguments: the settings UI
```

### Settings UI

`whatsrisky ui` (or the bare command) opens a form for every option, with a live **Equivalent
command** panel — you always see the flags your choices produce, so the UI is a way to *learn* the
CLI rather than an alternative to it. It also shows which scanners are actually installed, warns
before you run (bad path, offline + `auto`, "the AI pass spends tokens"), and disables Run when the
settings cannot work.

`r` runs the scan on a live-progress screen; `ctrl+s` saves the current form as a named **profile**.

![run screen](docs/tui-run.png)

Profiles work from the CLI too, so the UI and CI can share one configuration:

```bash
whatsrisky ~/www/app --profile ci-fast              # run a saved profile
whatsrisky ~/www/app --profile ci-fast --ai         # profile, then override
whatsrisky ~/www/app --save-profile nightly        # save while scanning
whatsrisky profiles                                 # list  ·  --delete NAME to remove
```

Everything lives in `~/.config/whatsrisky/config.json`; the last run is remembered.

### Flags that matter

- `--ai` — add the Claude pass. Naming `--model` or `--claude-mode` implies it.
- `--model opus|sonnet|haiku|<model-id>` — default `opus`. `sonnet` is several times cheaper.
- `--claude-mode full|review|both` — audit the whole project, review the diff, or both.
- `--diff HEAD~1..HEAD` — scope to a git range (see the honesty note below).
- `--tools semgrep,trivy` / `--skip gitleaks` — pick scanners.
- `--min-severity HIGH`, `--max-per-severity 25` — trim the document (JSON keeps everything).
- `--fail-on critical|high|…` — exit 2 for CI.
- `--exclude node_modules --exclude dist` — repeatable.
- `--offline` — no network; Trivy skips its DB update and Semgrep falls back to `p/security-audit`.
- `--quiet` / `--json-stdout` — machine-readable output, see **Embedding** below.

## The report

1. **Cover** — project, path, git commit, verdict, risk score.
2. **Executive summary** — counts per severity with what each level means and its SLA, counts per
   scanner, top 10 priorities.
3. **Scope and methodology** — what each scanner covered, the exact commands run, and **coverage
   gaps**: a scanner that did not run means that area is *unscanned*, not clean.
4. **Findings by priority** — CRITICAL → INFO, each with a coloured badge, `file:line`, rule id,
   CWE/OWASP/CVSS, what is wrong, code evidence, how to fix, references, and a stable id.
5. **Appendix** — AI reviewer summary and scanner diagnostics.

`--format docx,md,json` picks the outputs; all three by default.

## Embedding

`core.py` holds the whole scan: `ScanOptions` (every knob, serializable) and `run_scan(options,
on_event)` which reports progress through a callback and never touches a terminal. The CLI and the
UI are thin shells over it, which is also why `ScanOptions.command_line()` can render the exact
equivalent command.

As a library:

```python
from whatsrisky.core import ScanOptions, run_scan

outcome = run_scan(ScanOptions(path="/srv/app", diff="main...HEAD", formats=["json"]))
print(outcome.report.risk_score(), outcome.exit_code)
for finding in outcome.report.sorted_findings():
    print(finding.severity, finding.location, finding.title)
```

As a subprocess — one JSON document on stdout, nothing else:

```bash
whatsrisky /srv/app --diff main...HEAD --json-stdout > findings.json
```

The shape is a versioned contract: [`schema/report.schema.json`](schema/report.schema.json).
`schema_version` is bumped on any breaking change, and every finding carries a stable `fingerprint`
suitable as a suppression key.

## Honesty notes

These are deliberate, not oversights:

- **`--diff` does not scope Trivy.** A dependency CVE is a property of the manifest, not of the
  changed lines: a lockfile untouched by your range can still be vulnerable. Trivy scans the whole
  tree and the report says so, instead of quietly reporting "0 findings" for a diff.
- **A missing scanner is not a clean result.** Section 2 of the report lists coverage gaps for
  exactly this reason, and the JSON `tools[].status` tells a machine the same thing.
- **The risk score ranks, it does not measure.** `100·(1−e^(−Σweights/120))` saturates by design.
- **Automated scanning is a floor.** It does not replace threat modelling, authenticated dynamic
  testing, or a human reading the business logic.

## Severity model

Tool-native severities are mapped onto one scale (`whatsrisky/models.py`):

- Semgrep `ERROR` → HIGH, promoted to CRITICAL when the rule metadata says high impact and high
  confidence; `WARNING` → MEDIUM; `INFO` → LOW.
- Trivy severities map 1:1.
- gitleaks has no severity: provider-specific rules → CRITICAL, generic/entropy rules → HIGH, and
  matches under test/fixture/example paths drop one notch.
- Claude is given an explicit rubric in the prompt and returns the severity directly.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
python -m pytest tests -q                        # unit + integration (integration skips without binaries)
python -m pytest tests -q -m "not integration"   # unit only
python -m pyflakes whatsrisky tests
```

The vulnerable sample project used by the integration tests is generated at test time
(`tests/conftest.py`) — this repository contains no credentials, real or fake, so it does not trip
secret scanners or GitHub push protection.

## Layout

- `whatsrisky/core.py` — `ScanOptions`, `run_scan()`, tool probing. No terminal, no UI.
- `whatsrisky/runners/` — one module per scanner, each returning normalized `Finding` objects.
- `whatsrisky/report/` — DOCX and Markdown writers.
- `whatsrisky/ui.py` — Textual settings + progress UI. `whatsrisky/settings.py` — persisted profiles.
- `schema/report.schema.json` — the JSON contract for other tools.

## License

MIT — see [LICENSE](LICENSE). The scanners are separate programs invoked as subprocesses; their own
licenses (Semgrep LGPL-2.1, Trivy Apache-2.0, gitleaks MIT) are unaffected by this one. The Claude
pass depends on Anthropic's proprietary `claude` CLI and is therefore optional.
