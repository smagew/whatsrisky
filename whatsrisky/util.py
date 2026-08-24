"""Process, git and file helpers."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CmdResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False

    @property
    def command(self) -> str:
        return " ".join(shlex_quote(a) for a in self.argv)


def shlex_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(
    argv: list[str],
    cwd: str | Path | None = None,
    timeout: int = 900,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> CmdResult:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=full_env,
            input=stdin_text,
        )
        return CmdResult(argv, proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        return CmdResult(
            argv,
            124,
            _as_text(exc.stdout),
            _as_text(exc.stderr) + f"\n[whatsrisky] timed out after {timeout}s",
            time.monotonic() - started,
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return CmdResult(argv, 127, "", str(exc), time.monotonic() - started)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def tool_version(binary: str, args: list[str] | None = None) -> str:
    if not which(binary):
        return ""
    res = run([binary] + (args or ["--version"]), timeout=30)
    text = (res.stdout or res.stderr).strip().splitlines()
    return text[0].strip() if text else ""


def git_info(path: Path) -> tuple[str, str]:
    """Return (commit, branch) or ("", "") when the path is not a git repo."""
    if not (path / ".git").exists():
        res = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=path, timeout=15)
        if res.returncode != 0 or res.stdout.strip() != "true":
            return "", ""
    commit = run(["git", "rev-parse", "--short", "HEAD"], cwd=path, timeout=15)
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=path, timeout=15)
    return (
        commit.stdout.strip() if commit.returncode == 0 else "",
        branch.stdout.strip() if branch.returncode == 0 else "",
    )


def is_git_repo(path: Path) -> bool:
    res = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=path, timeout=15)
    return res.returncode == 0 and res.stdout.strip() == "true"


def relative(path_str: str, root: Path) -> str:
    if not path_str:
        return ""
    try:
        p = Path(path_str)
        if p.is_absolute():
            return str(p.relative_to(root))
    except (ValueError, OSError):
        pass
    return str(path_str).lstrip("./")


def read_snippet(root: Path, rel_file: str, line: int | None, context: int = 2, max_chars: int = 1200) -> str:
    """Read a few source lines around `line` for report context."""
    if not rel_file or not line or line < 1:
        return ""
    target = (root / rel_file).resolve()
    try:
        root_resolved = root.resolve()
        if not str(target).startswith(str(root_resolved)):
            return ""
        if not target.is_file() or target.stat().st_size > 4_000_000:
            return ""
        with target.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    out = []
    for idx in range(start, end):
        marker = ">" if idx == line - 1 else " "
        out.append(f"{marker} {idx + 1:>5} | {lines[idx].rstrip()}")
    text = clean_text("\n".join(out))
    return text[:max_chars]


_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value) -> str:
    """Strip ANSI escapes and control characters (DOCX/XML rejects them)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = _ANSI.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub("", text)


def truncate(text: str, limit: int) -> str:
    text = clean_text(text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def tail(text: str, lines: int = 12) -> str:
    parts = [l for l in clean_text(text).splitlines() if l.strip()]
    return "\n".join(parts[-lines:])


_RANGE = re.compile(r'(:\s*)(\d+)\s*[-\u2013]\s*\d+(\s*[,}\]])')
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
_PY_LITERALS = re.compile(r"(:\s*)(None|True|False|NaN|Infinity)(\s*[,}\]])")
_PY_MAP = {"None": "null", "True": "true", "False": "false", "NaN": "null", "Infinity": "null"}


def repair_json_text(text: str) -> str:
    """Fix the JSON mistakes LLMs actually make: numeric ranges, trailing
    commas, Python literals. Everything else is left to the parser."""
    text = _RANGE.sub(r"\1\2\3", text)
    text = _TRAILING_COMMA.sub(r"\1", text)
    text = _PY_LITERALS.sub(lambda m: m.group(1) + _PY_MAP[m.group(2)] + m.group(3), text)
    return text


def extract_json(text: str):
    """Pull the first plausible JSON object/array out of an LLM answer."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    fenced = re.findall(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    candidates = [f.strip() for f in fenced]
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])
    for cand in candidates:
        try:
            return json.loads(cand)
        except (ValueError, TypeError):
            pass
        try:
            return json.loads(repair_json_text(cand))
        except (ValueError, TypeError):
            continue
    try:
        return json.loads(repair_json_text(text))
    except (ValueError, TypeError):
        return None


def open_file(path) -> bool:
    """Open a file in the OS default application. Returns False when it cannot."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=False)
        elif system == "Windows":
            os.startfile(str(path))  # type: ignore[attr-defined]  # noqa: S606 - Windows only
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
        return True
    except (OSError, AttributeError):
        return False


def platform_key() -> str:
    return {"Darwin": "darwin", "Windows": "windows"}.get(platform.system(), "linux")


def changed_files(root: Path, diff_range: str) -> list[str]:
    """Files touched by a git range, relative to root, existing on disk.

    Deleted files are dropped - there is nothing left to scan in them.
    """
    res = run(["git", "diff", "--name-only", "--diff-filter=d", diff_range], cwd=root, timeout=60)
    if res.returncode != 0:
        raise ValueError(
            f"cannot resolve git range {diff_range!r} in {root}: {tail(res.stderr, 3) or 'git failed'}"
        )
    out: list[str] = []
    for line in res.stdout.splitlines():
        rel = line.strip()
        if rel and (root / rel).is_file():
            out.append(rel)
    return out


def slugify(value: str) -> str:
    out = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")
    return out or "project"
