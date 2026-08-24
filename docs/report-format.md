# Report format and viewer — specification

Status: **proposed**, awaiting agreement. Nothing here is built yet.

## Why a format at all

Today a scan writes three unrelated artifacts: a DOCX for people, a Markdown
mirror, and a JSON dump. That is enough to *read* a scan once and no more. Four
things it cannot do:

1. **Reopen a report later** in a viewer, with the same fidelity it had when written.
2. **Regroup the same findings** by category (secret leak, SQL injection…), by
   source, or by who found them — not only by severity.
3. **Say what changed since last time**: which findings a rescan resolved, which
   are new, which came back.
4. **Be looked at while the scan is still running.** The report view should open
   the moment there is anything to show, not after the last scanner exits.

All four are properties of the *data*, so the format is the foundation. The
viewer, the Claude plugin and the eventual desktop UI are readers of it.

## Decision: JSON is the contract, HTML is the artifact

- **`report.json`** — the contract, `schema/report.schema.json`, `schema_version: 2`.
  Machine-readable, diffable, greppable, and what every reader consumes.
- **`report.html`** — one self-contained file with the JSON inlined in a `<script>`
  block, the same pattern whydiff's viewer uses. Double-click opens it in any
  browser with no tooling; a reader can also recover the exact JSON from it.
  This is the file the "View report" button opens.
- **DOCX / Markdown** stay as they are: the deliverable you hand to someone, not
  the working view.

### On the `.wrsk` zip

Deferred, deliberately, with a stated trigger. A zip with a custom extension buys
one thing: bundling files that are *not* the report — raw scanner output, an SBOM,
patches, screenshots. We have none of those in the report today, and a zip costs
greppability, diffability, and a double-click that works.

The trigger to introduce it: **the desktop app, or the first real attachment.**
When it comes, `.wrsk` is a zip containing `report.json` + `report.html` +
`attachments/`, so renaming it to `.zip` and opening the HTML always works. The
extension is worth it when an OS association makes double-click open *our* app —
not before.

## Finding identity, and how a rescan knows what was fixed

Three keys per finding, cheapest first:

| Key | Composition | Survives |
| --- | --- | --- |
| `fingerprint` | tool + rule + file + line + package + version | nothing; exact match |
| `content_key` | tool + rule + hash(normalized evidence) | the code moving within or between files |
| `match_key` | tool + rule + file + package | the line drifting |

Correlation against a baseline report, in order: exact `fingerprint` →
`content_key` (same file) → `content_key` (any file, records a move) →
`match_key` when the occurrence is unambiguous. What is left over is either new
or resolved.

`status` per finding:

- `new` — absent from the baseline.
- `open` — present in both.
- `resolved` — in the baseline, gone now. **Carried into the new report** so the
  viewer can show it; that is the point of the feature.
- `reintroduced` — was `resolved` in the baseline, present again.
- `accepted` — a human decided to live with it (see Baseline below).

Plus `first_seen` and `last_seen` (scan ids), and `moved_from` when the code moved.

The baseline is the most recent report in the output directory, overridable with
`--baseline <path>` and disabled with `--no-compare`. Report-level `comparison`
carries the baseline's scan id and the counts, so a reader does not recompute it.

This also gives us suppression for free: a finding marked `accepted` in a baseline
stays `accepted`, which is the missing answer to "semgrep is wrong about this one".

## Normalized categories

`category` is free-form per tool today (`SAST/security`, `Dependency/pip`,
`AI/Injection`) — useless for grouping. Add `category`, a closed vocabulary,
derived in this order:

1. **CWE**, when the finding has one. This is the reliable signal and it is
   already in the data: CWE-89 → `injection.sql`, CWE-798 → `secret`,
   CWE-22 → `path-traversal`, CWE-502 → `deserialization`, CWE-918 → `ssrf`,
   CWE-79 → `xss`, CWE-862/863/306 → `access-control`, CWE-327/328/330 → `crypto`.
2. The scanner's own class — a Trivy vulnerability is `dependency`, a Trivy
   misconfiguration is `misconfiguration`, a gitleaks hit is `secret`.
3. Rule-id keywords, as a last resort.
4. `other` — and `other` staying large is a bug in the mapping, not a category.

Vocabulary: `secret`, `injection.sql`, `injection.command`, `injection.code`,
`xss`, `path-traversal`, `deserialization`, `ssrf`, `xxe`, `access-control`,
`authentication`, `crypto`, `dependency`, `misconfiguration`, `supply-chain`,
`dos`, `info-disclosure`, `input-validation`, `race`, `memory`, `logging`,
`other`. `category_label` carries the human name for display.

## Who found it, and being ready for other providers

`detector` replaces the bare `tool` string:

```json
"detector": {
  "tool": "ai",              "provider": "anthropic",
  "model": "claude-opus-5",  "pass": "full"
}
```

Local scanners report `{"tool": "semgrep", "provider": null, "model": null,
"pass": "code"}`. This is what makes "group by who found it" a real axis, and it
is also the seam for other providers: the AI runner becomes `ai` with pluggable
backends — `claude-cli` (today), and API backends for Anthropic, OpenAI and Google
selected with `--ai-provider`, keyed from the environment.

One honesty note that must reach the report, not just this document: the
`claude-cli` backend *explores the repository itself* with read tools, while a
plain API backend can only see the context we hand it. Those are different
analyses of different strength, and `detector.pass` plus a note on the tool result
must say which one ran.

## Source axis

`source` — the kind of artifact a finding lives in, for filtering: `source-code`,
`dependency-manifest`, `git-history`, `iac`, `container`, `ci-config`. Derived
from the runner and the path; it is what makes "show me only the dependency
problems" one click instead of a mental filter over tool names.

## Live reports

The report is written from the first moment, not at the end.

- Report-level `status`: `running` → `complete`, or `partial` when a scanner
  errored. `tools[].status` gains `pending` and `running`.
- `report.json` and `report.html` are rewritten after every scanner finishes, and
  once at scan start so the artifact exists immediately. DOCX is written once, at
  the end: it is the deliverable, not the live view.
- The viewer shows what is still running, so a half-empty report reads as
  in-progress rather than as clean.
- **"View report" is enabled as soon as the artifact exists** — from the first
  seconds of a scan, not after the last scanner exits.

## Grouping and filtering the viewer must support

Group by any of: severity, category, detector (tool / model), source, directory,
status. Filter by: severity floor, category, detector, source, status (hide
resolved / show only new), free text over title, file and rule.

Defaults: group by severity, sorted CRITICAL → INFO, resolved hidden but counted
in a chip that reveals them.

## Done =

### 1. Format and comparison (`schema_version: 2`)
- [ ] `report.json` carries `detector`, `category`, `category_label`, `source`,
      `status`, `content_key`, `match_key`, `first_seen`, `last_seen`.
- [ ] CWE → category mapping is table-driven and unit-tested per vocabulary entry;
      `other` is under 10% of findings on the fixture project.
- [ ] A rescan of an unchanged project reports every finding `open`, zero `new`,
      zero `resolved`.
- [ ] Fixing one finding and rescanning reports exactly that one `resolved`, still
      present in the output, and the rest `open`.
- [ ] Moving vulnerable code to another line — and to another file — keeps it
      `open`, not `resolved` + `new`, and records `moved_from`.
- [ ] Reintroducing a fixed finding reports `reintroduced`.
- [ ] `--baseline`, `--no-compare` and auto-detection of the latest report all work,
      and a missing baseline is not an error.
- [ ] `schema/report.schema.json` validates every field, and the self-scan output
      validates against it in CI.

### 2. HTML viewer
- [ ] One self-contained file, no network, opens by double-click.
- [ ] The embedded JSON round-trips: extracting it yields the same document as
      `report.json`.
- [ ] Grouping by severity, category, detector and source, each with counts.
- [ ] Filters compose (severity + category + status + text) and are reflected in the
      URL hash, so a filtered view can be shared.
- [ ] Resolved findings are visible on demand and never inflate the open counts.
- [ ] A `running` report renders as in-progress, naming which scanners are pending.
- [ ] Coverage gaps are as prominent as findings — a missing scanner must not read
      as a clean result.
- [ ] Design system: the whydiff rules, enforced by a test (tokens on `:root`,
      radius ≤ 5px, type ≥ 13px, no uppercase, shadows only on overlays).

### 3. Live view in the existing UIs
- [ ] `report.html` exists within a second of the scan starting.
- [ ] The TUI's "View report" opens it at any moment, including mid-scan.
- [ ] Rewritten after each scanner; reloading the browser shows the newer state.
- [ ] "Open DOCX" stays disabled until the DOCX is actually written, and says why.

### 4. Provider abstraction
- [ ] `--ai-provider claude-cli|anthropic|openai|google`, `--model` free-form.
- [ ] `claude-cli` behaviour is unchanged from today, tests included.
- [ ] One API backend implemented end to end, with keys from the environment and a
      clear error when absent.
- [ ] `detector` records provider and model for every AI finding.
- [ ] The report states which backend explored the repository and which was handed
      a fixed context.

### 5. Claude Code plugin
- [ ] `.claude-plugin/plugin.json` + `marketplace.json`, repo as its own marketplace.
- [ ] `/whatsrisky [path]` runs a scan and opens the report.
- [ ] Version bumped in `pyproject.toml`, `plugin.json` and `marketplace.json` in the
      same PR — the plugin cache is keyed by version.
- [ ] Works when the Python package is not installed, or says exactly what to install.

## Order of work

1. Format + comparison — everything else reads it.
2. HTML viewer + live writing — this is what the user actually looks at.
3. Provider abstraction — before the plugin, so the plugin is not Anthropic-only.
4. Plugin.

Each step is its own branch and PR, with the checklist above as the contract.
