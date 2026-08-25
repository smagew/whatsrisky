"""Comparing a scan against the previous one.

The question a rescan has to answer is "what did we fix?", and the only hard part
is telling a fixed finding from one whose code moved. Three identity keys make
that decidable: the exact location, then the evidence itself, then the location
without the line. Anything still unmatched is genuinely new or genuinely gone.

Resolved findings are carried into the new report - showing them is the whole
point - for one generation. A finding already resolved in the baseline and still
absent drops off, so reports do not accumulate history forever.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, ScanReport, Status, finding_from_dict


@dataclass
class Comparison:
    baseline_path: str = ""
    baseline_scan_id: str = ""
    baseline_at: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    moved: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_path": self.baseline_path,
            "baseline_scan_id": self.baseline_scan_id,
            "baseline_at": self.baseline_at,
            "counts": self.counts,
            "moved": self.moved,
        }


def load_report(path: str | Path) -> dict | None:
    """Read a report JSON, or None when it is not one of ours."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    generator = (data.get("generator") or {}).get("name")
    if generator not in (None, "whatsrisky"):
        return None
    return data


def find_baseline(out_dir: str | Path, exclude: set[str] | None = None) -> Path | None:
    """The most recent report in the output directory, if there is one."""
    directory = Path(out_dir)
    if not directory.is_dir():
        return None
    excluded = {str(Path(p).resolve()) for p in (exclude or set())}
    candidates = [
        path
        for path in directory.glob("*.json")
        if str(path.resolve()) not in excluded and load_report(path) is not None
    ]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


class _Baseline:
    """Baseline findings, consumable: a match claims its entry so two current
    findings can never both correlate to the same one."""

    def __init__(self, entries: list[dict]):
        self.entries = [e for e in entries if isinstance(e, dict)]
        self.taken: set[int] = set()
        self.by_fingerprint: dict[str, list[int]] = {}
        self.by_content: dict[str, list[int]] = {}
        self.by_match: dict[str, list[int]] = {}
        for position, entry in enumerate(self.entries):
            for key, index in (
                (entry.get("fingerprint"), self.by_fingerprint),
                (entry.get("content_key"), self.by_content),
                (entry.get("match_key"), self.by_match),
            ):
                if key:
                    index.setdefault(str(key), []).append(position)

    def _free(self, index: dict[str, list[int]], key: str) -> list[int]:
        return [p for p in index.get(key, []) if p not in self.taken]

    def claim(self, position: int) -> dict:
        self.taken.add(position)
        return self.entries[position]

    def match(self, finding: Finding) -> tuple[dict | None, bool]:
        """Correlate one current finding. Returns (baseline entry, moved)."""
        exact = self._free(self.by_fingerprint, finding.fingerprint)
        if exact:
            return self.claim(exact[0]), False

        # The evidence is the same, so this is the same finding in a new place.
        # Prefer a candidate in the same file: a copy-paste elsewhere should not
        # capture the original's history.
        content = self._free(self.by_content, finding.content_key)
        if content:
            same_file = [p for p in content if (self.entries[p].get("file") or "") == finding.file]
            position = (same_file or content)[0]
            entry = self.claim(position)
            moved = (entry.get("file") or "") != finding.file or entry.get("line") != finding.line
            return entry, moved

        # Same rule, same file, line drifted - only trustworthy when unambiguous.
        by_match = self._free(self.by_match, finding.match_key)
        if len(by_match) == 1:
            entry = self.claim(by_match[0])
            return entry, entry.get("line") != finding.line

        return None, False

    def unclaimed(self) -> list[dict]:
        return [entry for position, entry in enumerate(self.entries) if position not in self.taken]


def _origin(entry: dict) -> str:
    file = entry.get("file") or ""
    line = entry.get("line")
    return f"{file}:{line}" if file and line else file


def correlate(report: ScanReport, baseline: dict, baseline_path: str = "") -> Comparison:
    """Assign a status to every finding in `report`, relative to `baseline`.

    Mutates `report`: statuses and seen-timestamps are filled in, and findings the
    baseline had but this scan does not are appended with status `resolved`.
    """
    index = _Baseline(baseline.get("findings") or [])
    scan_id = report.scan_id or report.started_at
    baseline_id = str(baseline.get("scan_id") or baseline.get("started_at") or "")
    moved = 0

    for finding in report.findings:
        entry, was_moved = index.match(finding)
        finding.last_seen = scan_id
        if entry is None:
            finding.status = Status.NEW
            finding.first_seen = scan_id
            continue
        previous = str(entry.get("status") or Status.OPEN)
        if previous == Status.RESOLVED:
            finding.status = Status.REINTRODUCED
        elif previous == Status.ACCEPTED:
            finding.status = Status.ACCEPTED  # a human decision outlives a rescan
        else:
            finding.status = Status.OPEN
        finding.first_seen = str(entry.get("first_seen") or baseline_id or scan_id)
        if was_moved:
            moved += 1
            finding.moved_from = _origin(entry)

    # What the baseline had and this scan does not. Already-resolved entries drop
    # off instead of trailing through every future report.
    for entry in index.unclaimed():
        if str(entry.get("status") or Status.OPEN) == Status.RESOLVED:
            continue
        resolved = finding_from_dict(entry)
        resolved.status = Status.RESOLVED
        resolved.first_seen = str(entry.get("first_seen") or baseline_id)
        resolved.last_seen = str(entry.get("last_seen") or baseline_id)
        report.findings.append(resolved)

    counts = {status: 0 for status in Status.ALL}
    for finding in report.findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1

    comparison = Comparison(
        baseline_path=str(baseline_path),
        baseline_scan_id=baseline_id,
        baseline_at=str(baseline.get("finished_at") or baseline.get("started_at") or ""),
        counts=counts,
        moved=moved,
    )
    report.comparison = comparison.to_dict()
    return comparison
