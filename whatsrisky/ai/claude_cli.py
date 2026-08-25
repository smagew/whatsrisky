"""The Claude Code CLI as an agentic backend.

It explores the repository itself with read tools, which is why it needs no
context from us and why its findings are stronger than an API backend's. Run
headless with a read-only tool allowlist, so it cannot modify the project.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..util import run_streaming, tool_version, truncate, which
from .base import Answer

READ_ONLY_TOOLS = ",".join(
    [
        "Read", "Grep", "Glob", "Skill", "TodoWrite",
        "Bash(git log:*)", "Bash(git diff:*)", "Bash(git status:*)", "Bash(git show:*)",
        "Bash(git branch:*)", "Bash(git rev-parse:*)", "Bash(git merge-base:*)",
        "Bash(git ls-files:*)", "Bash(rg:*)", "Bash(ls:*)", "Bash(find:*)",
        "Bash(cat:*)", "Bash(head:*)", "Bash(wc:*)",
    ]
)


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


class ClaudeCliBackend:
    name = "claude-cli"
    agentic = True
    default_model = "opus"
    binary = "claude"

    def __init__(self, cwd: Path, work_dir: Path):
        self.cwd = cwd
        self.work_dir = work_dir

    def available(self) -> tuple[bool, str]:
        if which(self.binary):
            return True, ""
        return False, "`claude` not found in PATH. Install: npm install -g @anthropic-ai/claude-code"

    def version(self) -> str:
        return f"claude {tool_version(self.binary)}"

    def ask(self, prompt, model, timeout, on_progress=None, context="") -> Answer:
        def stream_line(line: str) -> None:
            line = line.strip()
            if not on_progress or not line.startswith("{"):
                return
            try:
                event = json.loads(line)
            except ValueError:
                return
            if event.get("type") != "assistant":
                return
            for block in event.get("message", {}).get("content", []) or []:
                if block.get("type") == "tool_use":
                    on_progress(_describe_tool_use(block))
                elif block.get("type") == "text":
                    head = (block.get("text") or "").strip().splitlines()
                    if head and not head[0].lstrip().startswith(("{", "[")):
                        on_progress(head[0])

        argv = [
            self.binary, "-p", prompt, "--model", model,
            # stream-json reports each step as it happens; json would only speak at the end.
            "--output-format", "stream-json", "--verbose",
            "--allowed-tools", READ_ONLY_TOOLS,
        ]
        res = run_streaming(argv, cwd=self.cwd, timeout=timeout, on_stdout=stream_line)
        (self.work_dir / "ai-claude-cli.raw.jsonl").write_text(res.stdout or "", encoding="utf-8")
        if res.timed_out:
            raise RuntimeError(f"the claude CLI timed out after {timeout}s")

        payload = _final_result(res.stdout)
        if isinstance(payload, dict) and "result" in payload:
            if payload.get("is_error"):
                raise RuntimeError(f"the claude CLI failed: {truncate(str(payload.get('result')), 400)}")
            text = str(payload.get("result") or "")
            if not text.strip():
                raise RuntimeError(
                    f"the claude CLI returned an empty answer after {payload.get('num_turns', 0)} turn(s)"
                )
            return Answer(
                text=text,
                cost_usd=float(payload.get("total_cost_usd") or 0.0),
                turns=int(payload.get("num_turns") or 0),
            )
        if (res.stdout or "").strip():
            return Answer(text=res.stdout)
        raise RuntimeError(
            f"the claude CLI returned nothing (exit {res.returncode}): {truncate(res.stderr, 400)}"
        )
