"""Configuration loading (TOML) with defaults."""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path

DEFAULTS: dict = {
    "general": {"state_dir": "~/.local/state/hsm", "host": "", "retention_days": 90},
    "rules": {"files": ["rules/default.toml"]},
    "mail": {"min_severity": "medium"},
    "journald": {"enabled": True, "first_run_lookback": "1h"},
    "docker": {"enabled": True},
    "tailscale": {"enabled": True},
    "ports": {"enabled": True},
    "fim": {"enabled": True, "paths": []},
}


def _merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def find_config(explicit: str | None) -> Path | None:
    for candidate in (explicit, os.environ.get("HSM_CONFIG"), "config.toml"):
        if candidate and Path(candidate).expanduser().is_file():
            return Path(candidate).expanduser()
    return None


def load_config(path: Path | None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    base_dir = Path.cwd()
    if path is not None:
        with open(path, "rb") as handle:
            _merge(cfg, tomllib.load(handle))
        base_dir = path.resolve().parent
    cfg["_base_dir"] = base_dir
    cfg["general"]["state_dir"] = Path(cfg["general"]["state_dir"]).expanduser()
    if not cfg["general"]["host"]:
        cfg["general"]["host"] = os.uname().nodename
    return cfg
