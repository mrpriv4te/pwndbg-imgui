"""Font discovery (fontconfig)."""

from __future__ import annotations

import os


def find_mono_fonts() -> list[tuple[str, str]]:
    """Return [(family, regular_path)] of monospace fonts, preferred first."""
    import subprocess

    preferred = [
        "JetBrains Mono", "JetBrainsMono Nerd Font", "Fira Code", "Cascadia Code", "Hack",
        "Iosevka", "Source Code Pro", "Ubuntu Sans Mono", "Ubuntu Mono", "DejaVu Sans Mono",
        "Noto Sans Mono", "Liberation Mono", "Go Mono",
    ]
    found: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["fc-list", ":spacing=mono", "family", "style", "file"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    for line in out.splitlines():
        try:
            path, rest = line.split(": ", 1)
        except ValueError:
            continue
        if not path.lower().endswith((".ttf", ".otf")):
            continue
        family = rest.split(":")[0].split(",")[0].strip()
        style = rest.split("style=")[-1] if "style=" in rest else ""
        styles = [s.strip() for s in style.split(",")]
        if "Regular" in styles or "Book" in styles or "[wght]" in path:
            if family not in found or "[wght]" not in path:
                found.setdefault(family, path)
    order = [f for f in preferred if f in found] + sorted(f for f in found if f not in preferred)
    return [(f, found[f]) for f in order]


FALLBACK_CHARS = "►◂▸◆—─│┃╎├└↓↑→←⚠✔✘✗•●○▲▼…⋯⤷"


def find_fallback_fonts(exclude: tuple[str, ...] = ()) -> list[str]:
    """Fonts that provide the glyphs in FALLBACK_CHARS (DejaVu Sans Mono first)."""
    import subprocess

    def match(pattern: str) -> str:
        try:
            return subprocess.run(["fc-match", "-f", "%{file}", pattern],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    files: list[str] = []
    for pattern in ["DejaVu Sans Mono"] + [f":charset={ord(c):x}" for c in FALLBACK_CHARS]:
        path = match(pattern)
        if path and path.lower().endswith((".ttf", ".otf")) and path not in files and path not in exclude:
            files.append(path)
    return files


def find_bold_variant(path: str) -> str | None:
    if "[wght]" in path or "Variable" in path:
        return None
    d, base = os.path.split(path)
    for a, b in (("Regular", "Bold"), ("-Book", "-Bold"), (".ttf", "-Bold.ttf"), (".otf", "-Bold.otf")):
        if a in base:
            cand = os.path.join(d, base.replace(a, b, 1))
            if os.path.exists(cand):
                return cand
    return None
