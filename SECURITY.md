# Security policy

## Reporting a vulnerability

Email **alisher@vertex.lt** with the details. Please do not open a public issue for a vulnerability
in whatsrisky itself. Expect an acknowledgement within a few days.

## What to keep in mind when using this tool

- **Reports contain findings, and findings contain evidence.** Generated DOCX/MD/JSON files quote
  source code and, for secret findings, redacted matches. Treat the output directory as sensitive
  and keep it out of version control (`whatsrisky-reports/` is in `.gitignore`).
- **The AI pass sends code to Anthropic.** `--ai` runs the `claude` CLI over the project, which
  transmits the code it reads. It is off by default for this reason. Do not use it on code you may
  not share with a third party.
- **Scanner output is untrusted input.** Findings are sanitized before being written into reports,
  but they originate in the scanned repository.
- **Secrets found are already compromised.** If a credential appears in the report, rotate it. The
  report tells you this too, and it means it.

## Scope

whatsrisky invokes third-party scanners as subprocesses. Vulnerabilities in Semgrep, Trivy, gitleaks
or Claude Code should be reported to their maintainers.
