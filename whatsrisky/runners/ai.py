"""The AI review pass, normalized into findings.

Which model runs it is a backend choice (`whatsrisky/ai/`), not this module's
business. What this module owns: the prompts, the strict-JSON contract with the
model, repairing the JSON it gets back, and turning the answer into findings that
sit on the same severity scale as every scanner's.

Two passes:
  * full   - whole-project audit driven by our own prompt
  * review - the branch diff, via the security-review skill on an agentic backend
Both must answer with JSON; a malformed answer is repaired locally, then reshaped
by one cheap follow-up call rather than lost.
"""

from __future__ import annotations

from ..ai import VENDOR, make_backend
from ..ai import context as ai_context
from ..models import Finding, Severity, ToolResult
from ..util import extract_json, read_snippet, relative, truncate
from .base import Runner

SCHEMA_BLOCK = """{
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
}"""

SEVERITY_RUBRIC = """Severity rubric (be strict, do not inflate):
- CRITICAL: remotely exploitable without auth, or leads directly to RCE / full data breach / auth bypass / leaked live credential.
- HIGH: exploitable by an authenticated or adjacent attacker with serious impact (privilege escalation, IDOR on sensitive data, SQLi behind auth, stored XSS).
- MEDIUM: real weakness needing preconditions or with limited impact (CSRF on non-critical action, missing rate limit, weak crypto parameters, SSRF to internal metadata behind auth).
- LOW: defense-in-depth gaps and hardening (missing security headers, verbose errors, permissive CORS on public data).
- INFO: hygiene/observations with no direct security impact."""

FULL_PROMPT = f"""You are a senior application security engineer performing a full security audit of the codebase in the current working directory.

Method:
1. Map the project: entry points (HTTP routes/handlers, CLI, queue consumers, webhooks), authn/authz layers, data stores, external calls, deserialization, file/path handling, template rendering, subprocess/eval usage, crypto and secret handling, and the CI/CD or IaC config.
2. Follow untrusted input from every entry point to every dangerous sink. Read the actual code - never guess.
3. Report only findings you can point at in real code with a file and line. No generic advice, no "consider reviewing X" filler.
4. Prefer depth over breadth: the exploitable bugs first.

{SEVERITY_RUBRIC}

Output rules:
- Your FINAL message must be ONLY a single JSON object, no prose before or after, no markdown fences.
- Cap the list at {{max_findings}} findings, highest severity first.
- "line" must be a single integer (the most relevant line), never a range, never a string.
- If you find nothing exploitable, return an empty findings array and say so in "summary".

JSON shape:
{SCHEMA_BLOCK}
"""

REVIEW_PROMPT = f"""Use the security-review skill to perform a security review of {{diff_target}}. Follow that skill's instructions to find the vulnerabilities, then report them to me as JSON.

{SEVERITY_RUBRIC}

Output rules:
- Your FINAL message must be ONLY a single JSON object, no prose before or after, no markdown fences.
- Report only findings that are in the changed code, with a real file and line.
- "line" must be a single integer, never a range, never a string.
- "summary" should state what the branch changes and the security impact.

JSON shape:
{SCHEMA_BLOCK}
"""

CONVERT_PROMPT = f"""Convert the security review below into a single JSON object. Do not re-analyze, do not add findings that are not in the text, do not drop any. Keep file paths and line numbers exactly as written.

{SEVERITY_RUBRIC}

Output ONLY the JSON object, no fences, no prose.

JSON shape:
{SCHEMA_BLOCK}

--- SECURITY REVIEW TEXT ---
{{review_text}}
--- END ---
"""


class AiRunner(Runner):
    name = "ai"
    binary = ""            # availability is the backend's business, not a PATH lookup
    category = "AI review"
    install_hints = {"default": "see the --ai-provider options"}

    def __init__(self, config, on_progress=None):
        super().__init__(config, on_progress)
        self.backend = make_backend(config.ai_provider, config.target, config.work_dir)
        self.model = config.ai_model or self.backend.default_model
        self.summary = ""
        self.coverage = ""
        self.cost_usd = 0.0
        self.turns = 0
        self.context_note = ""
        self._context_text = ""
        self.notes: list[str] = []

    # --- availability -------------------------------------------------
    def available(self) -> bool:
        return self.backend.available()[0]

    def unavailable_reason(self) -> str:
        return self.backend.available()[1] or f"the {self.backend.name} backend is unavailable"

    def version(self) -> str:
        return f"{self.backend.version()} · model {self.model}"

    # --- asking the model ---------------------------------------------
    def _prepare_context(self) -> str:
        """Build the context once; agentic backends need none."""
        if self.backend.agentic:
            return ""
        cfg = self.config
        text, included, skipped = ai_context.build(
            cfg.target, cfg.exclude, cfg.scope_paths or None, cfg.ai_context_bytes
        )
        self.context_note = (
            f"the {self.backend.name} backend cannot read the repository itself, so it saw "
            f"{len(included)} file(s)"
            + (f" and {skipped} were left out for size" if skipped else "")
        )
        self.notes.append(self.context_note)
        self.progress(f"prepared {len(included)} file(s) of context")
        return text

    def _invoke(self, prompt: str, label: str) -> tuple[str, str]:
        """Run one pass. Returns (answer text, a description of the call)."""
        cfg = self.config
        self.progress(f"{label} pass on {self.backend.name} · {self.model}")
        answer = self.backend.ask(
            prompt,
            model=self.model,
            timeout=cfg.ai_timeout,
            on_progress=self.progress,
            context=self._context_text,
        )
        (cfg.work_dir / f"ai-{label}.txt").write_text(answer.text, encoding="utf-8")
        self.cost_usd += answer.cost_usd
        self.turns += answer.turns
        self.notes += answer.notes
        return answer.text, f"{self.backend.name}:{label} model={self.model}"

    # --- passes -------------------------------------------------------
    def _pass_full(self) -> tuple[list[Finding], list[str], list[str]]:
        cfg = self.config
        prompt = FULL_PROMPT.replace("{max_findings}", str(cfg.ai_max_findings))
        if cfg.exclude:
            prompt += "\nIgnore these paths entirely: " + ", ".join(cfg.exclude[:40]) + "\n"
        if cfg.scope_paths:
            listed = "\n".join(f"- {p}" for p in cfg.scope_paths[:200])
            prompt += (
                f"\nScope: audit ONLY these files (changed by `{cfg.diff_range}`), reading "
                f"whatever else you need for context:\n{listed}\n"
            )
        text, command = self._invoke(prompt, "full")
        commands = [command]
        parsed = extract_json(text)
        if not (isinstance(parsed, dict) and "findings" in parsed):
            # The audit ran but the JSON is unusable - reshape it instead of losing it.
            convert = CONVERT_PROMPT.replace("{review_text}", truncate(text, 60000))
            text, command2 = self._invoke(convert, "full-convert")
            commands.append(command2)
        return self._parse(text, "full"), commands, []

    def _pass_review(self) -> tuple[list[Finding], list[str], list[str]]:
        cfg = self.config
        if not self.backend.agentic:
            raise RuntimeError(
                f"the {self.backend.name} backend cannot review a diff: it has no access to git. "
                "Use --ai-mode full, or --ai-provider claude-cli."
            )
        target = (
            f"the diff `{cfg.diff_range}`"
            if cfg.diff_range
            else "the pending changes on the current branch (the diff against its merge base)"
        )
        prompt = REVIEW_PROMPT.replace("{diff_target}", target)
        text, command = self._invoke(prompt, "review")
        commands = [command]

        parsed = extract_json(text)
        if not (isinstance(parsed, dict) and "findings" in parsed):
            convert = CONVERT_PROMPT.replace("{review_text}", truncate(text, 60000))
            text, command2 = self._invoke(convert, "review-convert")
            commands.append(command2)
        return self._parse(text, "security-review"), commands, []

    def scan(self):
        cfg = self.config
        self._context_text = self._prepare_context()
        modes = {"full": ["full"], "review": ["review"], "both": ["full", "review"]}.get(
            cfg.ai_mode, ["full"]
        )
        findings: list[Finding] = []
        commands: list[str] = []
        stderrs: list[str] = []
        seen: set[str] = set()
        for mode in modes:
            got, cmds, errs = self._pass_full() if mode == "full" else self._pass_review()
            commands += cmds
            stderrs += errs
            for f in got:
                if f.fingerprint in seen:
                    continue
                seen.add(f.fingerprint)
                findings.append(f)
        return findings, " && ".join(commands), "\n".join(stderrs)

    # --- parsing ------------------------------------------------------
    def _parse(self, text: str, source: str) -> list[Finding]:
        data = extract_json(text)
        if not isinstance(data, dict):
            raise RuntimeError(
                f"could not parse JSON from the claude {source} pass; raw output kept in "
                f"{self.config.work_dir}"
            )
        summary = str(data.get("summary") or "").strip()
        coverage = str(data.get("coverage") or "").strip()
        if summary:
            self.summary = (self.summary + "\n\n" + summary).strip()
        if coverage:
            self.coverage = (self.coverage + "\n\n" + coverage).strip()

        out: list[Finding] = []
        for item in data.get("findings") or []:
            if not isinstance(item, dict):
                continue
            rel = relative(str(item.get("file") or ""), self.config.target)
            line = item.get("line")
            line = int(line) if isinstance(line, (int, float)) or str(line).isdigit() else None
            description = truncate(str(item.get("description") or ""), 4000)
            attack = truncate(str(item.get("attack_scenario") or ""), 2000)
            if attack:
                description = f"{description}\n\nAttack scenario: {attack}".strip()
            out.append(
                Finding(
                    tool=self.name,
                    severity=Severity.parse(item.get("severity"), Severity.MEDIUM),
                    title=truncate(str(item.get("title") or "Unnamed finding"), 140),
                    description=description,
                    category=f"AI/{item.get('category') or source}",
                    rule_id=f"claude:{source}",
                    file=rel,
                    line=line,
                    cwe=[str(c) for c in (item.get("cwe") or []) if str(c).strip()],
                    remediation=truncate(str(item.get("remediation") or ""), 2000),
                    confidence=str(item.get("confidence") or ""),
                    snippet=read_snippet(self.config.target, rel, line),
                    provider=VENDOR.get(self.backend.name, self.backend.name),
                    model=self.model,
                    pass_name="full" if source == "full" else "review",
                    raw={"source": source},
                )
            )
        return out

    def run(self) -> ToolResult:
        result = super().run()
        notes: list[str] = []
        # How the model saw the project belongs in the report: an agentic backend
        # read it, an API backend was handed a slice, and those are not the same
        # analysis.
        notes.append(
            f"{self.backend.name} · {self.model} · "
            + ("explored the repository itself" if self.backend.agentic else "was given a fixed context")
        )
        notes += [n for n in self.notes if n and n != self.context_note or n == self.context_note]
        if self.summary:
            notes.append(self.summary)
        if self.cost_usd:
            notes.append(f"[cost ${self.cost_usd:.2f}, {self.turns} turns]")
        if result.ok and notes:
            result.message = "\n\n".join(dict.fromkeys(notes))
        return result
