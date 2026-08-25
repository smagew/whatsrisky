package runner

// The prompts are ported verbatim from the reference implementation. They are the
// analysis: paraphrasing them would change what the model looks for without
// meaning to. The placeholders are substituted at run time.

const fullPrompt = `You are a senior application security engineer performing a full security audit of the codebase in the current working directory.

Method:
1. Map the project: entry points (HTTP routes/handlers, CLI, queue consumers, webhooks), authn/authz layers, data stores, external calls, deserialization, file/path handling, template rendering, subprocess/eval usage, crypto and secret handling, and the CI/CD or IaC config.
2. Follow untrusted input from every entry point to every dangerous sink. Read the actual code - never guess.
3. Report only findings you can point at in real code with a file and line. No generic advice, no "consider reviewing X" filler.
4. Prefer depth over breadth: the exploitable bugs first.

Severity rubric (be strict, do not inflate):
- CRITICAL: remotely exploitable without auth, or leads directly to RCE / full data breach / auth bypass / leaked live credential.
- HIGH: exploitable by an authenticated or adjacent attacker with serious impact (privilege escalation, IDOR on sensitive data, SQLi behind auth, stored XSS).
- MEDIUM: real weakness needing preconditions or with limited impact (CSRF on non-critical action, missing rate limit, weak crypto parameters, SSRF to internal metadata behind auth).
- LOW: defense-in-depth gaps and hardening (missing security headers, verbose errors, permissive CORS on public data).
- INFO: hygiene/observations with no direct security impact.

Output rules:
- Your FINAL message must be ONLY a single JSON object, no prose before or after, no markdown fences.
- Cap the list at {max_findings} findings, highest severity first.
- "line" must be a single integer (the most relevant line), never a range, never a string.
- If you find nothing exploitable, return an empty findings array and say so in "summary".

JSON shape:
{
  "summary": "2-4 sentence security posture summary of this codebase",
  "coverage": "what you actually inspected and what you deliberately skipped",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "short imperative title",
      "category": "e.g. Authentication, Injection, Access Control, Crypto, SSRF, Secrets, Deserialization, Supply Chain, Logging",
      "file": "path/relative/to/project/root",
      "line": 123,
      "description": "what the flaw is and why it is exploitable, referencing the concrete code",
      "attack_scenario": "concrete steps an attacker takes, with the impact",
      "remediation": "specific fix, ideally with the code shape to use instead",
      "cwe": ["CWE-89"],
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ]
}
`

const reviewPrompt = `Use the security-review skill to perform a security review of {{diff_target}}. Follow that skill's instructions to find the vulnerabilities, then report them to me as JSON.

Severity rubric (be strict, do not inflate):
- CRITICAL: remotely exploitable without auth, or leads directly to RCE / full data breach / auth bypass / leaked live credential.
- HIGH: exploitable by an authenticated or adjacent attacker with serious impact (privilege escalation, IDOR on sensitive data, SQLi behind auth, stored XSS).
- MEDIUM: real weakness needing preconditions or with limited impact (CSRF on non-critical action, missing rate limit, weak crypto parameters, SSRF to internal metadata behind auth).
- LOW: defense-in-depth gaps and hardening (missing security headers, verbose errors, permissive CORS on public data).
- INFO: hygiene/observations with no direct security impact.

Output rules:
- Your FINAL message must be ONLY a single JSON object, no prose before or after, no markdown fences.
- Report only findings that are in the changed code, with a real file and line.
- "line" must be a single integer, never a range, never a string.
- "summary" should state what the branch changes and the security impact.

JSON shape:
{
  "summary": "2-4 sentence security posture summary of this codebase",
  "coverage": "what you actually inspected and what you deliberately skipped",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "short imperative title",
      "category": "e.g. Authentication, Injection, Access Control, Crypto, SSRF, Secrets, Deserialization, Supply Chain, Logging",
      "file": "path/relative/to/project/root",
      "line": 123,
      "description": "what the flaw is and why it is exploitable, referencing the concrete code",
      "attack_scenario": "concrete steps an attacker takes, with the impact",
      "remediation": "specific fix, ideally with the code shape to use instead",
      "cwe": ["CWE-89"],
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ]
}
`

const convertPrompt = `Convert the security review below into a single JSON object. Do not re-analyze, do not add findings that are not in the text, do not drop any. Keep file paths and line numbers exactly as written.

Severity rubric (be strict, do not inflate):
- CRITICAL: remotely exploitable without auth, or leads directly to RCE / full data breach / auth bypass / leaked live credential.
- HIGH: exploitable by an authenticated or adjacent attacker with serious impact (privilege escalation, IDOR on sensitive data, SQLi behind auth, stored XSS).
- MEDIUM: real weakness needing preconditions or with limited impact (CSRF on non-critical action, missing rate limit, weak crypto parameters, SSRF to internal metadata behind auth).
- LOW: defense-in-depth gaps and hardening (missing security headers, verbose errors, permissive CORS on public data).
- INFO: hygiene/observations with no direct security impact.

Output ONLY the JSON object, no fences, no prose.

JSON shape:
{
  "summary": "2-4 sentence security posture summary of this codebase",
  "coverage": "what you actually inspected and what you deliberately skipped",
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "short imperative title",
      "category": "e.g. Authentication, Injection, Access Control, Crypto, SSRF, Secrets, Deserialization, Supply Chain, Logging",
      "file": "path/relative/to/project/root",
      "line": 123,
      "description": "what the flaw is and why it is exploitable, referencing the concrete code",
      "attack_scenario": "concrete steps an attacker takes, with the impact",
      "remediation": "specific fix, ideally with the code shape to use instead",
      "cwe": ["CWE-89"],
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ]
}

--- SECURITY REVIEW TEXT ---
{{review_text}}
--- END ---
`
