"""Self-contained HTML report.

One file: the viewer template with the report JSON inlined. No network, no
tooling - double-click and read it. The JSON is the same document `report.json`
carries, so the artifact is both the view and the data.

Written repeatedly while a scan runs, so it must stay cheap: read the template,
substitute twice, write atomically.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanReport

TEMPLATE = Path(__file__).with_name("templates") / "viewer.html"

# A literal </script> inside a JSON string would close the tag that holds it.
# Escaping the slash is inert inside JSON strings and safe in HTML.
_CLOSE = "</"
_CLOSE_ESCAPED = "<\\/"


def _escape_for_html(payload: str) -> str:
    return payload.replace(_CLOSE, _CLOSE_ESCAPED)


def render(report: ScanReport) -> str:
    template = TEMPLATE.read_text(encoding="utf-8")
    document = json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))
    title = f"{report.project_name} — whatsrisky"
    return template.replace("__TITLE__", _escape_for_html(title)).replace(
        "__REPORT_JSON__", _escape_for_html(document)
    )


def write_html(report: ScanReport, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = out_path.with_suffix(".html.part")
    temporary.write_text(render(report), encoding="utf-8")
    temporary.replace(out_path)  # atomic: a reader never sees half a page
    return out_path


def extract_json(html: str) -> dict:
    """Recover the report from a rendered page - the round trip the viewer promises."""
    start = html.index('<script id="report-data" type="application/json">')
    start = html.index(">", start) + 1
    end = html.index("</script>", start)
    return json.loads(html[start:end].replace(_CLOSE_ESCAPED, _CLOSE))
