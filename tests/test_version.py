"""The version is a release contract.

whydiff enforces this with a pre-push hook because a plugin cache keyed by
version means users never see an unbumped change. Here the risk is the same in a
different shape: the version is stamped into every report, so a stale one makes a
report claim it came from software that never wrote it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import whatsrisky

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


def test_the_version_is_semver():
    assert SEMVER.match(whatsrisky.__version__), whatsrisky.__version__


def test_the_installed_package_reports_the_same_version():
    """pyproject reads it through hatch, so a mismatch means the build is stale."""
    metadata = pytest.importorskip("importlib.metadata")
    try:
        installed = metadata.version("whatsrisky")
    except metadata.PackageNotFoundError:  # running from a source tree, not installed
        pytest.skip("whatsrisky is not installed in this environment")
    assert installed == whatsrisky.__version__


def test_pyproject_does_not_carry_a_second_copy():
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert '[tool.hatch.version]' in text
    assert not re.search(r'^version\s*=', text, re.MULTILINE), (
        "a literal version in pyproject.toml can drift from the package's"
    )


def test_the_changelog_documents_this_version():
    text = Path("CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{whatsrisky.__version__}]" in text, (
        f"CHANGELOG.md has no section for {whatsrisky.__version__}"
    )
    assert "## [Unreleased]" in text, "keep an Unreleased section open for the next change"


def test_the_version_reaches_every_surface():
    """A report, a page and a screen must all be able to say which build made them."""
    from whatsrisky.models import ScanReport

    report = ScanReport(project_path="/p", project_name="p", started_at="now")
    assert report.to_dict()["generator"] == {"name": "whatsrisky", "version": whatsrisky.__version__}

    viewer = Path("whatsrisky/report/templates/viewer.html").read_text(encoding="utf-8")
    assert "R.generator.version" in viewer, "the viewer must show which build wrote the report"

    ui = Path("whatsrisky/ui.py").read_text(encoding="utf-8")
    assert "__version__" in ui and 'id="version"' in ui
