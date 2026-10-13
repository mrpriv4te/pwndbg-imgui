"""Persistent settings (~/.config/pwndbg-imgui/settings.json)."""

from __future__ import annotations

import json
import os

from . import APP_NAME


def config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


class Settings:
    DEFAULTS = {
        "theme": "Pwn Night",
        "ui_size": 15.0,
        "code_size": 15.0,
        "font": "",
        "fps_idle": 20.0,
        "viewports": True,
        "custom_titlebar": True,
        "remember_bps": True,
        "decomp_autoconnect": True,
        "autofit": True,
        "io_raw": True,
        "io_echo": True,
        "io_newline": True,
        "console_history": [],
        "io_history": [],
        "binaries": {},
        "views": [],
        "visible": {},
    }

    def __init__(self) -> None:
        self.path = os.path.join(config_dir(), "settings.json")
        self.data = json.loads(json.dumps(self.DEFAULTS))
        try:
            with open(self.path) as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value) -> None:
        self.data[key] = value

    def binary(self, path: str | None) -> dict:
        key = os.path.abspath(path) if path else "<none>"
        return self.data["binaries"].setdefault(key, {})

    def save(self) -> None:
        self.data["console_history"] = self.data["console_history"][-500:]
        self.data["io_history"] = self.data["io_history"][-200:]
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self.data, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass
