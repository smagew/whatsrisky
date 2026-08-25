from .ai import AiRunner
from .base import Runner, ScanConfig
from .gitleaks import GitleaksRunner
from .semgrep import SemgrepRunner
from .trivy import TrivyRunner

ALL_RUNNERS: dict[str, type[Runner]] = {
    SemgrepRunner.name: SemgrepRunner,
    TrivyRunner.name: TrivyRunner,
    GitleaksRunner.name: GitleaksRunner,
    AiRunner.name: AiRunner,
}

__all__ = [
    "Runner",
    "ScanConfig",
    "SemgrepRunner",
    "TrivyRunner",
    "GitleaksRunner",
    "AiRunner",
    "ALL_RUNNERS",
]
