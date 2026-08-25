"""Context for backends that cannot explore the repository themselves.

An API backend sees only what we send, so what we send decides what it can find.
The selection is deliberate and stated in the report: files most likely to hold
an exploitable flaw first, within a byte budget.

This is a weaker analysis than an agentic backend performing its own reading, and
the report says so rather than presenting the two as equivalent.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..util import path_excluded

# Where flaws live, in the order we would read them ourselves.
_PRIORITY: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"(^|/)(auth|authn|authz|login|session|permission|acl|rbac)", re.I), 100),
    (re.compile(r"(^|/)(route|routes|handler|handlers|controller|controllers|api|views?|endpoints?)", re.I), 90),
    (re.compile(r"(^|/)(middleware|filters?|guards?|interceptors?)", re.I), 85),
    (re.compile(r"(^|/)(models?|schema|db|database|repository|dao|queries)", re.I), 70),
    (re.compile(r"(^|/)(upload|file|download|export|import|template|render)", re.I), 65),
    (re.compile(r"(^|/)(config|settings|env|secrets?)", re.I), 60),
    (re.compile(r"(^|/)(util|utils|helpers?|lib)", re.I), 40),
    (re.compile(r"(^|/)(tests?|spec|fixtures?|examples?|docs?)", re.I), -50),
)

_CODE = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".kt",
    ".cs", ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".sh", ".bash",
    ".sql", ".tf", ".yaml", ".yml", ".json", ".toml", ".env", ".conf", ".ini",
}
_ALWAYS = re.compile(r"(^|/)(dockerfile|containerfile|makefile|requirements[^/]*\.txt|package\.json|go\.mod|pom\.xml|build\.gradle)$", re.I)


def _score(rel: str, size: int) -> int:
    score = 0
    for pattern, weight in _PRIORITY:
        if pattern.search(rel):
            score += weight
    if _ALWAYS.search(rel):
        score += 80
    # A 4 KB handler is likelier to be readable and relevant than a 400 KB blob.
    if size > 120_000:
        score -= 60
    elif size < 40_000:
        score += 10
    return score


def candidates(root: Path, excludes: list[str], scope: list[str] | None = None) -> list[tuple[str, int]]:
    """Repo-relative candidate files with sizes, best first."""
    if scope:
        found = [(rel, (root / rel).stat().st_size) for rel in scope if (root / rel).is_file()]
    else:
        found = []
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                continue
            if path_excluded(rel, excludes):
                continue
            if path.suffix.lower() not in _CODE and not _ALWAYS.search(rel):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > 400_000:
                continue
            found.append((rel, size))
    return sorted(found, key=lambda item: (-_score(item[0], item[1]), item[0]))


def build(root: Path, excludes: list[str], scope: list[str] | None = None, budget: int = 240_000):
    """Return (context text, files included, files skipped).

    The caller must report the skipped count: a reader has to know the model was
    shown part of the project, not all of it.
    """
    chosen: list[str] = []
    parts: list[str] = []
    used = 0
    ranked = candidates(root, excludes, scope)
    for rel, size in ranked:
        if used + size > budget:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        numbered = "\n".join(f"{n:>5} | {line}" for n, line in enumerate(text.splitlines(), 1))
        parts.append(f"===== {rel} =====\n{numbered}")
        chosen.append(rel)
        used += size
    return "\n\n".join(parts), chosen, len(ranked) - len(chosen)
