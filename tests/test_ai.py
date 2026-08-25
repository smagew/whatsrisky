"""The AI pass and its backends.

The OpenAI backend is exercised against a local stub that speaks the
chat-completions shape. That covers request construction, context injection,
parsing and every error path - everything except the real service's behaviour,
which no test here can claim.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from whatsrisky.ai import PROVIDER_CHOICES, VENDOR, make_backend
from whatsrisky.ai import context as ai_context
from whatsrisky.core import ScanOptions, run_scan
from whatsrisky.runners import AiRunner
from whatsrisky.runners.base import ScanConfig

ANSWER = {
    "summary": "One route concatenates user input into SQL.",
    "coverage": "Read the two files that were sent.",
    "findings": [
        {
            "severity": "CRITICAL",
            "title": "SQL injection in /user",
            "category": "Injection",
            "file": "app.py",
            "line": 4,
            "description": "The name parameter is interpolated into the query.",
            "attack_scenario": "?name=' OR 1=1 --",
            "remediation": "Use a parameterised query.",
            "cwe": ["CWE-89"],
            "confidence": "HIGH",
        }
    ],
}


class _Stub(BaseHTTPRequestHandler):
    """Records the request, replies like the chat-completions endpoint."""

    seen: list[dict] = []
    status = 200
    payload: object = None

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).seen.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        )
        raw = (
            json.dumps(type(self).payload).encode()
            if type(self).payload is not None
            else json.dumps(
                {
                    "choices": [{"message": {"content": json.dumps(ANSWER)}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 900, "completion_tokens": 120},
                }
            ).encode()
        )
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        return


@pytest.fixture
def stub(monkeypatch):
    _Stub.seen = []
    _Stub.status = 200
    _Stub.payload = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", f"http://127.0.0.1:{server.server_address[1]}/v1")
    yield _Stub
    server.shutdown()


@pytest.fixture
def project(tmp_path) -> Path:
    root = tmp_path / "app"
    (root / "auth").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "app.py").write_text(
        "import sqlite3\n\n\ndef get(name):\n"
        "    return sqlite3.connect('a.db').execute(\"select * from u where n='%s'\" % name)\n",
        encoding="utf-8",
    )
    (root / "auth" / "session.py").write_text("SECRET = 'x'\n", encoding="utf-8")
    (root / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("var a = 1;\n", encoding="utf-8")
    return root


# --- the registry -----------------------------------------------------
def test_backends_declare_what_they_are(tmp_path):
    assert set(PROVIDER_CHOICES) == {"claude-cli", "openai"}
    cli = make_backend("claude-cli", tmp_path, tmp_path)
    api = make_backend("openai", tmp_path, tmp_path)
    # The distinction that matters: one reads the repository, the other cannot.
    assert cli.agentic is True and api.agentic is False
    assert VENDOR["claude-cli"] == "anthropic" and VENDOR["openai"] == "openai"
    assert cli.default_model and api.default_model
    with pytest.raises(ValueError, match="unknown ai provider"):
        make_backend("nope", tmp_path, tmp_path)


def test_openai_without_a_key_says_so(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    ready, why = make_backend("openai", tmp_path, tmp_path).available()
    assert not ready and "OPENAI_API_KEY" in why

    config = ScanConfig(target=tmp_path, work_dir=tmp_path, ai_provider="openai")
    result = AiRunner(config).run()
    assert result.status == "missing" and "OPENAI_API_KEY" in result.message


# --- the context an api backend is given ------------------------------
def test_context_ranks_what_matters_and_respects_the_budget(project):
    excludes = ScanOptions(path=str(project)).effective_excludes()
    ranked = [rel for rel, _ in ai_context.candidates(project, excludes)]
    assert "node_modules/dep.js" not in ranked, "excluded paths must not be sent to a model"
    assert ranked.index("auth/session.py") < ranked.index("tests/test_app.py")

    text, included, skipped = ai_context.build(project, excludes)
    assert "auth/session.py" in included and "===== app.py =====" in text
    assert "    4 | def get(name):" in text, "line numbers must survive, findings cite them"
    assert skipped == 0

    _, few, left_out = ai_context.build(project, excludes, budget=40)
    assert len(few) < len(included) and left_out > 0


def test_scope_limits_the_context_to_the_diff(project):
    text, included, _ = ai_context.build(project, [], scope=["app.py"])
    assert included == ["app.py"] and "auth/session.py" not in text


# --- the openai backend against a stub --------------------------------
def test_openai_call_shape_and_parsing(stub, tmp_path):
    backend = make_backend("openai", tmp_path, tmp_path)
    assert backend.available()[0]
    steps: list[str] = []
    answer = backend.ask(
        "Find the bugs.", model="gpt-5", timeout=10, on_progress=steps.append, context="===== a.py ====="
    )

    assert json.loads(answer.text)["findings"][0]["title"] == "SQL injection in /user"
    assert answer.turns == 1 and any("tokens in/out: 900/120" in n for n in answer.notes)
    assert steps, "the pass must report progress"

    sent = stub.seen[-1]
    assert sent["path"].endswith("/chat/completions")
    assert sent["auth"] == "Bearer test-key"
    assert sent["body"]["model"] == "gpt-5"
    assert sent["body"]["response_format"] == {"type": "json_object"}
    user = sent["body"]["messages"][-1]["content"]
    assert "===== a.py =====" in user, "the context must reach the model"
    assert "cannot open files yourself" in user, "and it must know it cannot go looking"


@pytest.mark.parametrize(
    "status,payload,expected",
    [
        (401, {"error": {"message": "bad key"}}, "openai returned 401"),
        (200, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}, "empty answer"),
        (200, {"choices": []}, "empty answer"),
    ],
)
def test_openai_failures_are_reported_not_swallowed(stub, tmp_path, status, payload, expected):
    stub.status = status
    stub.payload = payload
    backend = make_backend("openai", tmp_path, tmp_path)
    with pytest.raises(RuntimeError, match=expected):
        backend.ask("x", model="gpt-5", timeout=10)


def test_an_api_backend_refuses_to_pretend_it_can_review_a_diff(stub, project):
    config = ScanConfig(
        target=project, work_dir=project, ai_provider="openai", ai_mode="review"
    )
    result = AiRunner(config).run()
    assert result.status == "error"
    assert "cannot review a diff" in result.message and "claude-cli" in result.message


def test_a_scan_through_the_openai_backend(stub, project, tmp_path):
    outcome = run_scan(
        ScanOptions(
            path=str(project), tools=["ai"], formats=["json"], out_dir=str(tmp_path / "out"),
            ai_provider="openai", model="gpt-5", compare=False,
        )
    )
    findings = outcome.report.findings
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == {
        "tool": "ai", "provider": "openai", "model": "gpt-5", "pass": "full"
    }
    assert finding.norm_category == "injection.sql"      # from CWE-89
    assert "attack scenario" in finding.description.lower()

    note = outcome.report.tools[0].message
    # The report has to say the model was handed a slice, not the repository.
    assert "was given a fixed context" in note
    assert "cannot read the repository itself" in note


def test_the_base_url_cannot_smuggle_a_scheme(tmp_path, monkeypatch):
    """urlopen speaks file:// too, so an env var must not become arbitrary IO."""
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    for bad in ("file:///etc/passwd", "ftp://example.invalid/x", "/etc/passwd", "not a url"):
        monkeypatch.setenv("OPENAI_BASE_URL", bad)
        with pytest.raises(ValueError, match="must be an http"):
            make_backend("openai", tmp_path, tmp_path)

    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example.invalid/v1/")
    backend = make_backend("openai", tmp_path, tmp_path)
    assert backend.base_url == "https://proxy.example.invalid/v1"   # trailing slash trimmed


def test_a_dynamic_url_rule_is_categorised_as_ssrf():
    from whatsrisky.categories import classify

    assert classify(rule_id="python.lang.security.audit.dynamic-urllib-use-detected") == "ssrf"
