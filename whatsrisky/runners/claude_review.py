"""Claude Code as a security reviewer (headless), normalized into findings.

Two passes are available:
  * full   - whole-project security audit driven by our own audit prompt
  * review - the built-in `/security-review` slash command (diff of the branch)
Both are asked to emit strict JSON; `review` output is structured by a second,
cheaper conversion call because the slash command answers in prose.
"""

from __future__ import annotations

import json

from ..models import Finding, Severity, ToolResult
from ..util import extract_json, read_snippet, relative, run_streaming, truncate
from .base import Runner

READ_ONLY_TOOLS = ",".join(
    [
        "Read",
        "Grep",
        "Glob",
        "Skill",
        "TodoWrite",
        "Bash(git merge-base:*)",
        "Bash(git ls-files:*)",
        "Bash(git log:*)",
        "Bash(git diff:*)",
        "Bash(git status:*)",
        "Bash(git show:*)",
        "Bash(git branch:*)",
        "Bash(git rev-parse:*)",
        "Bash(rg:*)",
        "Bash(ls:*)",
        "Bash(find:*)",
        "Bash(cat:*)",
        "Bash(head:*)",
        "Bash(wc:*)",
    ]
)

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


def _describe_tool_use(block: dict) -> str:
    """`Read app.py` reads better than a raw tool_use payload."""
    name = block.get("name") or "tool"
    args = block.get("input") or {}
    for key in ("file_path", "path", "pattern", "command", "query", "notebook_path"):
        value = args.get(key)
        if value:
            return f"{name}: {str(value)[:120]}"
    return name


def _final_result(stream: str) -> dict | None:
    """Pick the terminal `result` event out of a stream-json transcript."""
    payload: dict | None = None
    for line in (stream or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("type") == "result":
            payload = event
    return payload


class ClaudeRunner(Runner):
    name = "claude"
    binary = "claude"
    category = "AI review"
    install_hints = {"default": "npm install -g @anthropic-ai/claude-code"}

    def __init__(self, config):
        super().__init__(config)
        self.summary = ""
        self.coverage = ""
        self.cost_usd = 0.0
        self.turns = 0

    def version(self) -> str:
        from ..util import tool_version

        return f"claude {tool_version(self.binary)} (model: {self.config.claude_model})"

    # --- claude invocation --------------------------------------------
    def _stream_line(self, line: str) -> None:
        """Turn one stream-json event into a progress message."""
        line = line.strip()
        if not line.startswith("{"):
            return
        try:
            event = json.loads(line)
        except ValueError:
            return
        if event.get("type") != "assistant":
            return
        for block in event.get("message", {}).get("content", []) or []:
            kind = block.get("type")
            if kind == "tool_use":
                self.progress(_describe_tool_use(block))
            elif kind == "text":
                text = (block.get("text") or "").strip().splitlines()
                if text and not text[0].lstrip().startswith(("{", "[")):
                    self.progress(text[0])

    def _invoke(self, prompt: str, model: str, label: str) -> tuple[str, str, str]:
        cfg = self.config
        argv = [
            self.binary,
            "-p",
            prompt,
            "--model",
            model,
            # stream-json reports each step as it happens; json would only speak at the end.
            "--output-format",
            "stream-json",
            "--verbose",
            "--allowed-tools",
            READ_ONLY_TOOLS,
        ]
        self.progress(f"{label} pass: starting {model}")
        res = run_streaming(
            argv,
            cwd=cfg.target,
            timeout=cfg.claude_timeout,
            on_stdout=self._stream_line,
        )
        raw_path = cfg.work_dir / f"claude-{label}.raw.jsonl"
        raw_path.write_text(res.stdout or "", encoding="utf-8")
        if res.timed_out:
            raise RuntimeError(f"claude {label} pass timed out after {cfg.claude_timeout}s")

        payload = _final_result(res.stdout)
        if isinstance(payload, dict) and "result" in payload:
            if payload.get("is_error"):
                raise RuntimeError(f"claude {label} pass failed: {truncate(str(payload.get('result')), 400)}")
            self.cost_usd += float(payload.get("total_cost_usd") or 0.0)
            self.turns += int(payload.get("num_turns") or 0)
            text = str(payload.get("result") or "")
            if not text.strip():
                raise RuntimeError(
                    f"claude {label} pass returned an empty answer after "
                    f"{payload.get('num_turns', 0)} turn(s)"
                )
        else:
            text = res.stdout or ""
            if not text.strip():
                raise RuntimeError(
                    f"claude {label} pass returned nothing (exit {res.returncode}): "
                    f"{truncate(res.stderr, 400)}"
                )
        return text, res.command, res.stderr

    # --- passes -------------------------------------------------------
    def _pass_full(self) -> tuple[list[Finding], list[str], list[str]]:
        cfg = self.config
        prompt = FULL_PROMPT.replace("{max_findings}", str(cfg.claude_max_findings))
        if cfg.exclude:
            prompt += "\nIgnore these paths entirely: " + ", ".join(cfg.exclude[:40]) + "\n"
        if cfg.scope_paths:
            listed = "\n".join(f"- {p}" for p in cfg.scope_paths[:200])
            prompt += (
                f"\nScope: audit ONLY these files (changed by `{cfg.diff_range}`), reading "
                f"whatever else you need for context:\n{listed}\n"
            )
        text, command, stderr = self._invoke(prompt, cfg.claude_model, "full")
        (cfg.work_dir / "claude-full.txt").write_text(text, encoding="utf-8")
        commands, stderrs = [command], [stderr]
        parsed = extract_json(text)
        if not (isinstance(parsed, dict) and "findings" in parsed):
            # The audit ran but the JSON is unusable - reshape it instead of losing it.
            convert = CONVERT_PROMPT.replace("{review_text}", truncate(text, 60000))
            text, command2, stderr2 = self._invoke(convert, "sonnet", "full-convert")
            commands.append(command2)
            stderrs.append(stderr2)
        return self._parse(text, "full"), commands, stderrs

    def _pass_review(self) -> tuple[list[Finding], list[str], list[str]]:
        cfg = self.config
        target = (
            f"the diff `{cfg.diff_range}`"
            if cfg.diff_range
            else "the pending changes on the current branch (the diff against its merge base)"
        )
        prompt = REVIEW_PROMPT.replace("{diff_target}", target)
        text, command, stderr = self._invoke(prompt, cfg.claude_model, "review")
        (cfg.work_dir / "claude-review.md").write_text(text, encoding="utf-8")
        commands, stderrs = [command], [stderr]

        parsed = extract_json(text)
        if not (isinstance(parsed, dict) and "findings" in parsed):
            convert = CONVERT_PROMPT.replace("{review_text}", truncate(text, 60000))
            text2, command2, stderr2 = self._invoke(convert, "sonnet", "review-convert")
            commands.append(command2)
            stderrs.append(stderr2)
            text = text2
        return self._parse(text, "security-review"), commands, stderrs

    def scan(self):
        cfg = self.config
        modes = {"full": ["full"], "review": ["review"], "both": ["full", "review"]}.get(
            cfg.claude_mode, ["full"]
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
                    raw={"source": source},
                )
            )
        return out

    def run(self) -> ToolResult:
        result = super().run()
        notes = []
        if self.summary:
            notes.append(self.summary)
        if self.cost_usd:
            notes.append(f"[cost ${self.cost_usd:.2f}, {self.turns} turns]")
        if result.ok and notes:
            result.message = "\n\n".join(notes)
        return result
