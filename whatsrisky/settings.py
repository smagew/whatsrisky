"""Persisted scan settings: the last run, named profiles, and which one is active.

A profile answers "how do I scan", not "what do I scan". The target path, the git
range, the baseline and an explicit output file are per-invocation and are
deliberately not stored: reusing a profile on another project used to drag the old
project's path along with it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .core import FORMAT_CHOICES, ScanOptions

CONFIG_VERSION = 3

# Settings that belong to one invocation rather than to a way of scanning.
PER_RUN_FIELDS = ("path", "out", "diff", "baseline")


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "whatsrisky" / "config.json"


def _add_html(options: dict) -> None:
    """The HTML view did not exist in v1, so stored formats have none - which
    leaves the "View report" button with nothing to open."""
    formats = options.get("formats")
    if isinstance(formats, list) and "html" not in formats:
        options["formats"] = [f for f in FORMAT_CHOICES if f in formats or f == "html"]


def _strip_per_run(options: dict) -> None:
    """v1 and v2 profiles stored the project path and the git range, which then
    followed the profile onto every other project."""
    for field in PER_RUN_FIELDS:
        if isinstance(options.get(field), str):
            options[field] = ""


def _migrate(data: dict) -> tuple[dict, bool]:
    """Bring an older config forward, one step at a time. Returns (data, changed)."""
    version = int(data.get("version") or 1)
    if version >= CONFIG_VERSION:
        return data, False

    profiles = [p for p in (data.get("profiles") or {}).values() if isinstance(p, dict)]
    last = data.get("last") if isinstance(data.get("last"), dict) else None

    if version < 2:
        for options in profiles + ([last] if last else []):
            _add_html(options)
    if version < 3:
        for options in profiles:
            _strip_per_run(options)

    data["version"] = CONFIG_VERSION
    return data, True


def _load_raw() -> dict:
    path = config_path()
    if not path.is_file():
        return {"version": CONFIG_VERSION}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": CONFIG_VERSION}
    if not isinstance(data, dict):
        return {"version": CONFIG_VERSION}
    data, changed = _migrate(data)
    if changed:
        _save_raw(data)   # migrate once, not on every read
    return data


def _save_raw(data: dict) -> None:
    data["version"] = CONFIG_VERSION
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


# --- the last run -----------------------------------------------------
def load_last() -> ScanOptions | None:
    raw = _load_raw().get("last")
    return ScanOptions.from_json(raw) if isinstance(raw, dict) else None


def save_last(options: ScanOptions) -> None:
    data = _load_raw()
    data["last"] = options.to_json()
    _save_raw(data)


# --- profiles ---------------------------------------------------------
def profile_names() -> list[str]:
    profiles = _load_raw().get("profiles")
    return sorted(profiles) if isinstance(profiles, dict) else []


def load_profile(name: str) -> ScanOptions | None:
    profiles = _load_raw().get("profiles")
    if not isinstance(profiles, dict):
        return None
    raw = profiles.get(name)
    return ScanOptions.from_json(raw) if isinstance(raw, dict) else None


def save_profile(name: str, options: ScanOptions) -> None:
    """Store the way of scanning, and make it the one the next launch starts from."""
    stored = options.to_json()
    for field in PER_RUN_FIELDS:
        stored[field] = "" if isinstance(stored.get(field), str) else stored.get(field)
    data = _load_raw()
    profiles = data.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        profiles = data["profiles"] = {}
    profiles[name] = stored
    data["active_profile"] = name
    data["last"] = options.to_json()
    _save_raw(data)


def delete_profile(name: str) -> bool:
    data = _load_raw()
    profiles = data.get("profiles")
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        if data.get("active_profile") == name:
            data["active_profile"] = ""
        _save_raw(data)
        return True
    return False


def active_profile() -> str:
    name = str(_load_raw().get("active_profile") or "")
    return name if name in profile_names() else ""


def set_active_profile(name: str) -> None:
    data = _load_raw()
    data["active_profile"] = name
    _save_raw(data)


def startup_options() -> ScanOptions:
    """What a fresh launch should start from.

    The active profile wins: a profile you saved is what you meant to come back
    to. Without one, the last run. Without that, the defaults.
    """
    name = active_profile()
    if name:
        profile = load_profile(name)
        if profile is not None:
            last = load_last()
            if last is not None:
                # keep where you were pointing, take how you wanted to scan
                for field in PER_RUN_FIELDS:
                    setattr(profile, field, getattr(last, field))
            return profile
    return load_last() or ScanOptions()
