from .base import Runner, ScanConfig
from .semgrep import SemgrepRunner
from .trivy import TrivyRunner
from .gitleaks import GitleaksRunner
from .claude_review import ClaudeRunner

ALL_RUNNERS: dict[str, type[Runner]] = {
    SemgrepRunner.name: SemgrepRunner,
    TrivyRunner.name: TrivyRunner,
    GitleaksRunner.name: GitleaksRunner,
    ClaudeRunner.name: ClaudeRunner,
}

__all__ = [
    "Runner",
    "ScanConfig",
    "SemgrepRunner",
    "TrivyRunner",
    "GitleaksRunner",
    "ClaudeRunner",
    "ALL_RUNNERS",
]
