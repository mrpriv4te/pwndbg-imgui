"""Persistent settings (~/.config/pwndbg-imgui/settings.json)."""

from __future__ import annotations

import copy
import json
import os

from . import APP_NAME

_MISSING = object()


def config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def merge(disk, base, ours, append_only: bool = False):
    """Three-way merge of one saved value, so two windows don't overwrite each other.

    `base` is what this instance last loaded or saved, `ours` its current value and
    `disk` what the file holds now (maybe saved meanwhile by another instance). What we
    changed since `base` wins; everything else keeps the disk's version. Dicts merge key
    by key (deleting a key counts as a change); `append_only` lists keep the disk's
    entries plus the ones we appended."""
    if isinstance(ours, dict) and isinstance(base, dict) and isinstance(disk, dict):
        out = dict(disk)
        for k in base.keys() | ours.keys():
            b, o = base.get(k, _MISSING), ours.get(k, _MISSING)
            if o is _MISSING:
                out.pop(k, None)  # we deleted it
            elif b is _MISSING:  # we added it; another instance may have added it too
                d = disk.get(k, _MISSING)
                out[k] = merge(d, {}, o) if isinstance(d, dict) and isinstance(o, dict) else o
            else:
                out[k] = merge(disk.get(k, b), b, o)
        return out
    if append_only and isinstance(ours, list) and isinstance(base, list) and isinstance(disk, list):
        if ours[:len(base)] == base:
            return disk + ours[len(base):]
    return ours if ours != base else disk


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
        "persist_pwndbg_config": True,
        # pwndbg parameters changed in the Config pane, re-applied each run; the defaults here
        # are a starting point (registers in compact columns, flags shown)
        "pwndbg_config": {"show-compact-regs": "hardcut", "show-compact-regs-columns": "3", "show-flags": "on"},
        "decomp_autoconnect": True,
        "autofit": True,
        "io_raw": True,
        "io_echo": True,
        "io_newline": True,
        "console_history": [],
        "io_history": [],
        "binaries": {},
        "views": [],
        "user_layout": None,  # "Save current layout as default": {ini, visible}
        "visible": {},
    }
    HISTORY_LIMITS = {"console_history": 500, "io_history": 200}  # append-only, capped on disk

    def __init__(self) -> None:
        self.path = os.path.join(config_dir(), "settings.json")
        self.data = copy.deepcopy(self.DEFAULTS)
        self.data.update(self._read())
        self._base = copy.deepcopy(self.data)  # our view of the file, to tell what we changed

    def _read(self) -> dict:
        try:
            with open(self.path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value) -> None:
        self.data[key] = value

    def binary(self, path: str | None) -> dict:
        key = os.path.abspath(path) if path else "<none>"
        return self.data["binaries"].setdefault(key, {})

    def save(self) -> None:
        """Write our changes, merged over whatever another instance saved meanwhile.
        A no-op when nothing changed since the last save."""
        if self.data == self._base:
            return
        disk = self._read()
        out = {k: merge(disk.get(k, self._base.get(k)), self._base.get(k), v,
                        append_only=k in self.HISTORY_LIMITS)
               for k, v in self.data.items()}
        out.update({k: v for k, v in disk.items() if k not in out})  # keys a newer version added
        for k, limit in self.HISTORY_LIMITS.items():
            out[k] = out[k][-limit:]
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(out, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            return
        self._base = copy.deepcopy(self.data)
