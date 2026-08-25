from pathlib import Path

from .base import Answer, Backend
from .claude_cli import ClaudeCliBackend
from .openai_api import OpenAiBackend

BACKENDS = {
    ClaudeCliBackend.name: ClaudeCliBackend,
    OpenAiBackend.name: OpenAiBackend,
}
PROVIDER_CHOICES = tuple(BACKENDS)

# Which vendor is behind each backend, for the report's detector.provider.
VENDOR = {ClaudeCliBackend.name: "anthropic", OpenAiBackend.name: "openai"}


def make_backend(provider: str, cwd: Path, work_dir: Path) -> Backend:
    try:
        factory = BACKENDS[provider]
    except KeyError:
        raise ValueError(
            f"unknown ai provider {provider!r}; known: {', '.join(PROVIDER_CHOICES)}"
        ) from None
    return factory(cwd, work_dir)


__all__ = ["Answer", "Backend", "BACKENDS", "PROVIDER_CHOICES", "VENDOR", "make_backend"]
