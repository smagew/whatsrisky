"""The AI review pass, independent of who runs the model.

Two kinds of backend, and the difference is not cosmetic:

* An **agentic** backend (the `claude` CLI) explores the repository itself with
  read tools. It decides what to open, follows data flow across files, and its
  analysis is as deep as its budget.
* An **API** backend (OpenAI, and later others) sees only the context we hand it.
  It cannot go looking, so the quality ceiling is set by our file selection.

Those are different analyses of different strength, so `Backend.agentic` is part
of the contract and lands in the report: a reader must be able to tell which one
produced a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol


@dataclass
class Answer:
    """What a backend returns: the model's text plus what it cost."""

    text: str
    cost_usd: float = 0.0
    turns: int = 0
    notes: list[str] = field(default_factory=list)


class Backend(Protocol):
    name: str
    agentic: bool
    default_model: str

    def available(self) -> tuple[bool, str]:
        """(usable, reason when not)."""

    def version(self) -> str:
        ...

    def ask(
        self,
        prompt: str,
        model: str,
        timeout: int,
        on_progress: Callable[[str], None] | None = None,
        context: str = "",
    ) -> Answer:
        """Run one review pass and return the model's final answer."""
