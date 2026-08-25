# Security policy

## Reporting a vulnerability

Email **alisher@vertex.lt** with the details. Please do not open a public issue for a vulnerability
in whatsrisky itself. Expect an acknowledgement within a few days.

## What to keep in mind when using this tool

- **Reports contain findings, and findings contain evidence.** The generated HTML, Markdown and JSON
  quote source code and, for secret findings, redacted matches. Treat the output directory as
  sensitive and keep it out of version control (`whatsrisky-reports/` is in `.gitignore`).
- **The AI pass sends code to a third party.** `--ai` transmits the code the model reads — to
  Anthropic with `--ai-provider claude-cli`, to OpenAI with `openai`, and to whatever
  `OPENAI_BASE_URL` points at if you override it, which is validated as an http(s) URL for exactly
  that reason. It is off by default. Do not use it on code you may not share.
- **The installer verifies what it downloads.** `install.sh` checks the release checksum before
  installing; a security tool that installs itself unverified is not much of an argument.
- **Scanner output is untrusted input.** Findings are sanitized before being written into reports,
  but they originate in the scanned repository.
- **Secrets found are already compromised.** If a credential appears in the report, rotate it. The
  report tells you this too, and it means it.

## Scope

whatsrisky invokes third-party scanners as subprocesses. Vulnerabilities in Semgrep, Trivy, gitleaks
or Claude Code should be reported to their maintainers.
