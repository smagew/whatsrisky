"""Shared progress state.

One model, two front ends: the CLI wraps it in a rich Live, the TUI renders the
same table into a widget. Keeping the bookkeeping here is what stops the two
from drifting apart.
"""

from __future__ import annotations

import time

from rich.table import Table
from rich.text import Text

STATUS_STYLE = {"ok": "green", "missing": "yellow", "error": "red", "skipped": "dim", "running": "cyan"}
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class ProgressModel:
    """Per-scanner status: elapsed time and what it is doing right now."""

    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}
        self.order: list[str] = []
        self.frame = 0
        self.header: str = ""

    # --- state ---
    def handle(self, kind: str, payload: dict) -> None:
        tool = payload.get("tool", "")
        if kind == "info":
            self.header = payload.get("message", "")
        elif kind == "tool_start":
            self.rows[tool] = {
                "status": "running",
                "message": "starting",
                "findings": 0,
                "started": time.monotonic(),
                "duration": 0.0,
            }
            if tool not in self.order:
                self.order.append(tool)
        elif kind == "tool_progress" and tool in self.rows:
            self.rows[tool]["message"] = payload.get("message", "")
        elif kind == "tool_done" and tool in self.rows:
            self.rows[tool].update(
                status=payload["status"],
                findings=payload["findings"],
                duration=payload["duration"],
                message=payload.get("message") or "",
            )

    @property
    def running(self) -> bool:
        return any(row["status"] == "running" for row in self.rows.values())

    def elapsed(self, tool: str) -> float:
        row = self.rows[tool]
        return row["duration"] or (time.monotonic() - row["started"])

    def line(self, tool: str) -> str:
        row = self.rows[tool]
        return (
            f"{tool} {row['status']} · {row['findings']} findings · {self.elapsed(tool):.0f}s"
        )

    # --- rendering ---
    def render_table(self) -> Table:
        self.frame += 1
        table = Table.grid(padding=(0, 1))
        table.add_column(width=1)
        table.add_column(width=9)
        table.add_column(width=6, justify="right")
        table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
        for tool in self.order:
            row = self.rows[tool]
            running = row["status"] == "running"
            mark = SPINNER[self.frame % len(SPINNER)] if running else "▪"
            style = STATUS_STYLE.get(row["status"], "white")
            detail = row["message"] if running else f"{row['findings']} findings · {row['status']}"
            table.add_row(
                Text(mark, style=style),
                Text(tool, style=style),
                Text(f"{self.elapsed(tool):.0f}s", style="dim"),
                Text(detail or "", style="dim" if running else style),
            )
        return table
