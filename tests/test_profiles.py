"""Profiles and the report the UI opens.

Three complaints from real use, each turned into a test that fails on the code
that produced them:

1. A saved profile is not there on the next launch.
2. With several profiles saved there is no way to start from one.
3. "View report" opened a JSON file instead of the page.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from textual.widgets import Button, Input, Select

from whatsrisky import settings
from whatsrisky.core import ScanOptions
from whatsrisky.ui import RunScreen, SettingsScreen, WhatsriskyApp


@pytest.fixture(autouse=True)
def config_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    return tmp_path / "cfg"


def test_a_saved_profile_comes_back_on_the_next_launch(tmp_path):
    """Complaint 1: saving a profile and restarting lost it."""
    saved = ScanOptions(path=str(tmp_path), tools=["semgrep"], min_severity="HIGH", fail_on="high")
    settings.save_profile("nightly", saved)

    restored = settings.startup_options()
    assert restored.min_severity == "HIGH", "the profile just saved must be what the next launch uses"
    assert restored.tools == ["semgrep"]
    assert settings.active_profile() == "nightly"


def test_the_last_run_is_used_when_no_profile_is_active(tmp_path):
    settings.save_last(ScanOptions(path=str(tmp_path), jobs=2))
    assert settings.active_profile() == ""
    assert settings.startup_options().jobs == 2


def test_a_profile_does_not_carry_the_target_or_the_diff(tmp_path):
    """A profile says HOW to scan; what to scan is per-invocation.

    Reusing a profile on another project used to drag the old path, git range and
    output file along with it.
    """
    settings.save_profile(
        "ci",
        ScanOptions(path="/old/project", out="/old/report.docx", diff="HEAD~1..HEAD",
                    baseline="/old/b.json", out_dir="/reports", min_severity="HIGH"),
    )
    loaded = settings.load_profile("ci")
    assert loaded.path == "" and loaded.out == "" and loaded.diff == "" and loaded.baseline == ""
    assert loaded.out_dir == "/reports"      # where reports go is a setting
    assert loaded.min_severity == "HIGH"


def test_old_configs_gain_the_html_format(config_home):
    """Complaint 3, root cause: profiles written before the HTML view had none.

    A profile with json only leaves the View button with nothing to open, so the
    migration adds the view back rather than leaving a broken button.
    """
    config_home.mkdir(parents=True, exist_ok=True)
    (config_home / "whatsrisky").mkdir(parents=True, exist_ok=True)
    (config_home / "whatsrisky" / "config.json").write_text(
        json.dumps(
            {
                "last": {"path": "/p", "formats": ["docx", "md", "json"]},
                "profiles": {"os": {"path": "/p", "formats": ["json"]}},
            }
        ),
        encoding="utf-8",
    )
    assert "html" in settings.load_profile("os").formats
    assert "html" in (settings.load_last() or ScanOptions()).formats
    # …and the migration is recorded, so it happens once
    stored = json.loads((config_home / "whatsrisky" / "config.json").read_text())
    assert stored["version"] >= 2


# --- the UI -----------------------------------------------------------
def _drive(coro):
    asyncio.run(coro())


def test_the_ui_offers_the_profiles_and_starts_from_one(tmp_path):
    """Complaint 2: several profiles saved, no way to pick one."""
    settings.save_profile("fast", ScanOptions(tools=["semgrep"], min_severity="HIGH"))
    settings.save_profile("full", ScanOptions(tools=["semgrep", "trivy", "gitleaks"]))

    async def drive():
        app = WhatsriskyApp(settings.startup_options(), profile="fast")
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SettingsScreen)
            picker = screen.query_one("#profile-load", Select)
            listed = {v for _, v in picker._options if isinstance(v, str) and v}
            assert listed == {"fast", "full"}
            assert picker.value == "fast", "the active profile must be selected, not blank"
            assert screen.collect().min_severity == "HIGH"
            assert app.sub_title.startswith("fast"), "the screen must say which profile is active"

            picker.value = "full"
            await pilot.pause()
            assert screen.collect().tools == ["semgrep", "trivy", "gitleaks"]
            assert screen.query_one("#profile-name", Input).value == "full"

            # Choosing the blank entry detaches from the profile without changing
            # the settings on screen - it is a state, not a dead option.
            picker.clear()
            await pilot.pause()
            assert screen.active_profile == ""
            assert settings.active_profile() == ""
            assert screen.collect().tools == ["semgrep", "trivy", "gitleaks"]
            assert app.sub_title.startswith("no profile")

    _drive(drive)


def test_loading_a_profile_keeps_the_project_you_are_looking_at(tmp_path):
    settings.save_profile("p", ScanOptions(min_severity="HIGH"))

    async def drive():
        app = WhatsriskyApp(ScanOptions(path=str(tmp_path)))
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one("#profile-load", Select).value = "p"
            await pilot.pause()
            assert screen.collect().path == str(tmp_path), "a profile must not replace the target"
            assert screen.collect().min_severity == "HIGH"

    _drive(drive)


def test_view_report_never_opens_the_json_instead_of_the_page(tmp_path, monkeypatch):
    """Complaint 3: the button opened a JSON file."""
    opened: list[str] = []
    monkeypatch.setattr("whatsrisky.ui.open_file", lambda path: opened.append(str(path)) or True)

    async def drive():
        options = ScanOptions(path=str(tmp_path), tools=["semgrep"], formats=["json"])
        app = WhatsriskyApp(options)
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause()
            screen = RunScreen(options)
            app.push_screen(screen)
            await pilot.pause()
            # the scan announces its live artifacts; this run has no page
            screen._handle_event("live", {"html": "", "json": str(tmp_path / "r.json")})
            await pilot.pause()
            assert screen.query_one("#view", Button).disabled, "nothing to view means no live button"
            screen.action_view_report()
            assert opened == [], "a JSON file is not the report view"

            screen._handle_event("live", {"html": str(tmp_path / "r.html"), "json": ""})
            await pilot.pause()
            assert not screen.query_one("#view", Button).disabled
            screen.action_view_report()
            assert opened == [str(tmp_path / "r.html")]

    _drive(drive)
