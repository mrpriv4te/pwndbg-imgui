"""Color helpers and themes (UI colors + terminal palette)."""

from __future__ import annotations

def hex_rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return int(h[0:2], 16) / 255, int(h[2:4], 16) / 255, int(h[4:6], 16) / 255


def mix(a, b, t: float):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def luminance(c) -> float:
    def ch(v):
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    return 0.2126 * ch(c[0]) + 0.7152 * ch(c[1]) + 0.0722 * ch(c[2])


def contrast(a, b) -> float:
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def u32(c, a: float = 1.0) -> int:
    r, g, b = (int(max(0.0, min(1.0, v)) * 255 + 0.5) for v in c[:3])
    return (int(max(0.0, min(1.0, a)) * 255 + 0.5) << 24) | (b << 16) | (g << 8) | r


class Theme:
    def __init__(self, name, dark, bg, panel, border, fg, dim, accent, term_bg, ansi, accent2=None):
        self.name = name
        self.dark = dark
        self.bg = hex_rgb(bg)
        self.panel = hex_rgb(panel)
        self.border = hex_rgb(border)
        self.fg = hex_rgb(fg)
        self.dim = hex_rgb(dim)
        self.accent = hex_rgb(accent)
        self.accent2 = hex_rgb(accent2 or accent)
        self.term_bg = hex_rgb(term_bg)
        self.ansi = [hex_rgb(c) for c in ansi]
        # semantic colors used across the UI (pwndbg legend colors)
        self.red, self.green, self.yellow = self.ansi[1], self.ansi[2], self.ansi[3]
        self.blue, self.magenta, self.cyan = self.ansi[4], self.ansi[5], self.ansi[6]
        self._cache: dict[int, int] = {}

    def xterm(self, n: int):
        if n < 16:
            return self.ansi[n]
        if n < 232:
            n -= 16
            steps = (0, 95, 135, 175, 215, 255)
            return steps[n // 36] / 255, steps[(n // 6) % 6] / 255, steps[n % 6] / 255
        v = (8 + (n - 232) * 10) / 255
        return v, v, v

    def readable(self, c):
        """Push a color towards the foreground until it's readable on the terminal bg."""
        if contrast(c, self.term_bg) >= 3.0:
            return c
        target = self.fg
        for t in (0.25, 0.45, 0.65, 0.85):
            m = mix(c, target, t)
            if contrast(m, self.term_bg) >= 3.0:
                return m
        return target

    def color(self, code: int, a: float = 1.0) -> int:
        """Resolve a terminal color code (see Term) to an ImU32."""
        key = (code << 8) | int(a * 255)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        if code < 0:
            c = self.fg
        elif code < 256:
            c = self.readable(self.xterm(code))
        else:
            v = code & 0xFFFFFF
            c = self.readable(((v >> 16) / 255, ((v >> 8) & 255) / 255, (v & 255) / 255))
        self._cache[key] = u32(c, a)
        return self._cache[key]

    def kind_color(self, kind: str):
        return {
            "stack": self.yellow,
            "heap": self.blue,
            "code": self.red,
            "wx": self.red,
            "data": self.magenta,
            "rodata": self.fg,
            "guard": self.dim,
        }.get(kind, self.fg)


def _theme_list() -> list[Theme]:
    T = Theme
    return [
        T("Pwn Night", True, "#14161b", "#1b1e25", "#2b303b", "#d5d9e0", "#7c8493", "#f0565a", "#101216",
          ["#2a2e38", "#f0565a", "#8fd16a", "#f2c45c", "#5fa8f5", "#c67bf0", "#4fd2d8", "#cfd3da",
           "#5c6370", "#ff7a7d", "#a8e38a", "#ffd97a", "#82bfff", "#d9a0ff", "#7ae6eb", "#ffffff"], "#5fa8f5"),
        T("Dracula", True, "#21222c", "#282a36", "#3b3d4f", "#f8f8f2", "#7a7fa5", "#bd93f9", "#1d1e26",
          ["#21222c", "#ff5555", "#50fa7b", "#f1fa8c", "#bd93f9", "#ff79c6", "#8be9fd", "#f8f8f2",
           "#6272a4", "#ff6e6e", "#69ff94", "#ffffa5", "#d6acff", "#ff92df", "#a4ffff", "#ffffff"], "#ff79c6"),
        T("Catppuccin Mocha", True, "#181825", "#1e1e2e", "#313244", "#cdd6f4", "#7f849c", "#cba6f7", "#11111b",
          ["#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de",
           "#585b70", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8"], "#89b4fa"),
        T("Tokyo Night", True, "#16161e", "#1a1b26", "#292e42", "#c0caf5", "#565f89", "#7aa2f7", "#13131a",
          ["#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6",
           "#414868", "#ff899d", "#9fe044", "#faba4a", "#8db0ff", "#c7a9ff", "#a4daff", "#c0caf5"], "#bb9af7"),
        T("Nord", True, "#2b303b", "#2e3440", "#434c5e", "#d8dee9", "#7b88a1", "#88c0d0", "#272c36",
          ["#3b4252", "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#88c0d0", "#e5e9f0",
           "#4c566a", "#bf616a", "#a3be8c", "#ebcb8b", "#81a1c1", "#b48ead", "#8fbcbb", "#eceff4"], "#81a1c1"),
        T("Gruvbox Dark", True, "#1d2021", "#282828", "#3c3836", "#ebdbb2", "#928374", "#fe8019", "#1a1c1d",
          ["#282828", "#fb4934", "#b8bb26", "#fabd2f", "#83a598", "#d3869b", "#8ec07c", "#d5c4a1",
           "#665c54", "#fb4934", "#b8bb26", "#fabd2f", "#83a598", "#d3869b", "#8ec07c", "#fbf1c7"], "#fabd2f"),
        T("One Dark", True, "#1e2127", "#282c34", "#3a3f4b", "#abb2bf", "#5c6370", "#61afef", "#1b1d23",
          ["#282c34", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#abb2bf",
           "#5c6370", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#ffffff"], "#c678dd"),
        T("Monokai", True, "#1e1f1c", "#272822", "#3e3d32", "#f8f8f2", "#75715e", "#a6e22e", "#1a1b18",
          ["#272822", "#f92672", "#a6e22e", "#f4bf75", "#66d9ef", "#ae81ff", "#a1efe4", "#f8f8f2",
           "#75715e", "#f92672", "#a6e22e", "#f4bf75", "#66d9ef", "#ae81ff", "#a1efe4", "#f9f8f5"], "#f92672"),
        T("Solarized Dark", True, "#002b36", "#073642", "#0e4a58", "#93a1a1", "#586e75", "#268bd2", "#00232c",
          ["#073642", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198", "#eee8d5",
           "#586e75", "#cb4b16", "#859900", "#b58900", "#6c71c4", "#d33682", "#2aa198", "#fdf6e3"], "#2aa198"),
        T("Hacker Green", True, "#050805", "#0a100a", "#163016", "#9cff9c", "#3f7f3f", "#33ff66", "#030503",
          ["#0a100a", "#ff5f5f", "#33ff66", "#e5ff66", "#4fc3ff", "#d48cff", "#5fffd7", "#b8ffb8",
           "#3f7f3f", "#ff8787", "#7dff9a", "#f2ff99", "#87d7ff", "#e0aaff", "#87ffe0", "#eaffea"], "#5fffd7"),
        T("GitHub Light", False, "#f6f8fa", "#ffffff", "#d0d7de", "#1f2328", "#6e7781", "#0969da", "#ffffff",
          ["#24292f", "#cf222e", "#116329", "#9a6700", "#0969da", "#8250df", "#1b7c83", "#6e7781",
           "#57606a", "#a40e26", "#1a7f37", "#7d4e00", "#218bff", "#a475f9", "#3192aa", "#8c959f"], "#8250df"),
        T("Catppuccin Latte", False, "#e6e9ef", "#eff1f5", "#bcc0cc", "#4c4f69", "#8c8fa1", "#8839ef", "#eff1f5",
          ["#5c5f77", "#d20f39", "#40a02b", "#df8e1d", "#1e66f5", "#ea76cb", "#179299", "#acb0be",
           "#6c6f85", "#d20f39", "#40a02b", "#df8e1d", "#1e66f5", "#ea76cb", "#179299", "#bcc0cc"], "#1e66f5"),
        T("Solarized Light", False, "#eee8d5", "#fdf6e3", "#d6cfb8", "#586e75", "#93a1a1", "#268bd2", "#fdf6e3",
          ["#073642", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198", "#93a1a1",
           "#586e75", "#cb4b16", "#859900", "#b58900", "#6c71c4", "#d33682", "#2aa198", "#002b36"], "#d33682"),
    ]


THEMES = {t.name: t for t in _theme_list()}
