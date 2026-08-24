"""Persisted scan settings: the last used options plus named profiles."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .core import ScanOptions


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "whatsrisky" / "config.json"


def _load_raw() -> dict:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_raw(data: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load_last() -> ScanOptions | None:
    raw = _load_raw().get("last")
    return ScanOptions.from_json(raw) if isinstance(raw, dict) else None


def save_last(options: ScanOptions) -> None:
    data = _load_raw()
    data["last"] = options.to_json()
    _save_raw(data)


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
    data = _load_raw()
    profiles = data.setdefault("profiles", {})
    if not isinstance(profiles, dict):
        profiles = data["profiles"] = {}
    profiles[name] = options.to_json()
    _save_raw(data)


def delete_profile(name: str) -> bool:
    data = _load_raw()
    profiles = data.get("profiles")
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        _save_raw(data)
        return True
    return False
