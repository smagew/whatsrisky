"""OpenAI as an API backend.

No SDK: one HTTPS POST with the standard library, so the tool keeps its three
dependencies. The model cannot read the repository, so `context.build()` decides
what it sees - and the report says how much of the project that was.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from ..util import truncate
from .base import Answer

DEFAULT_BASE_URL = "https://api.openai.com/v1"
ENV_KEY = "OPENAI_API_KEY"
ENV_BASE = "OPENAI_BASE_URL"


class OpenAiBackend:
    name = "openai"
    agentic = False
    default_model = "gpt-5"

    def __init__(self, cwd: Path, work_dir: Path):
        self.cwd = cwd
        self.work_dir = work_dir
        self.base_url = (os.environ.get(ENV_BASE) or DEFAULT_BASE_URL).rstrip("/")

    def available(self) -> tuple[bool, str]:
        if os.environ.get(ENV_KEY):
            return True, ""
        return False, f"{ENV_KEY} is not set; export it to use the openai backend"

    def version(self) -> str:
        host = self.base_url.split("//", 1)[-1].split("/", 1)[0]
        return f"openai api ({host})"

    def ask(self, prompt, model, timeout, on_progress=None, context="") -> Answer:
        key = os.environ.get(ENV_KEY)
        if not key:
            raise RuntimeError(f"{ENV_KEY} is not set")
        if on_progress:
            on_progress(f"asking {model} over the api")

        user = prompt if not context else (
            prompt
            + "\n\nYou cannot open files yourself, so the relevant sources are below with line "
            "numbers. Cite those line numbers.\n\n"
            + context
        )
        body = json.dumps(
            {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a senior application security engineer. You answer only with the "
                            "JSON object the user asks for - no prose, no markdown fences."
                        ),
                    },
                    {"role": "user", "content": user},
                ],
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoint
                payload = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            detail = truncate(exc.read().decode("utf-8", "replace"), 400)
            raise RuntimeError(f"openai returned {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"cannot reach {self.base_url}: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError(f"openai returned something that is not JSON: {exc}") from exc

        (self.work_dir / "ai-openai.raw.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        choices = payload.get("choices") or []
        text = ""
        if choices:
            text = str((choices[0].get("message") or {}).get("content") or "")
        if not text.strip():
            reason = (choices[0].get("finish_reason") if choices else None) or "no content"
            raise RuntimeError(f"openai returned an empty answer ({reason})")

        usage = payload.get("usage") or {}
        notes = []
        if usage:
            notes.append(
                f"tokens in/out: {usage.get('prompt_tokens', '?')}/{usage.get('completion_tokens', '?')}"
            )
        return Answer(text=text, turns=1, notes=notes)
