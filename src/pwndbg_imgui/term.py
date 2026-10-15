"""A small line-oriented terminal emulator (ANSI SGR colors, CR/BS, erase)."""

from __future__ import annotations

import re
import threading


# ── Terminal buffer / ANSI parser ───────────────────────────────────────────
# A style is (fg, bg, flags). fg/bg: -1 = default, 0..255 = xterm palette,
# 0x1000000 | rgb = truecolor. Styles are interned into small integers.
BOLD, DIM, ITALIC, UNDER, INVERSE, STRIKE, CTRL, ECHO = 1, 2, 4, 8, 16, 32, 64, 128
_STYLES: list[tuple[int, int, int]] = [(-1, -1, 0)]
_STYLE_IDS: dict[tuple[int, int, int], int] = {(-1, -1, 0): 0}
_STYLE_LOCK = threading.Lock()


def style_id(fg: int, bg: int, flags: int) -> int:
    key = (fg, bg, flags)
    sid = _STYLE_IDS.get(key)
    if sid is None:
        with _STYLE_LOCK:
            sid = _STYLE_IDS.get(key)
            if sid is None:
                sid = len(_STYLES)
                _STYLES.append(key)
                _STYLE_IDS[key] = sid
    return sid


_TOKEN_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC
    r"|\x1b[()*+][0-9A-Za-z]"  # charset designation
    r"|\x1b[^\[\]()*+]"  # other two-byte escapes
    r"|[\x00-\x1f\x7f\udc80-\udcff]"  # control characters / undecodable bytes
)
_PARTIAL_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*|\][^\x07\x1b]*\x1b?|[()*+])?$")


class Line:
    __slots__ = ("chars", "styles", "_spans", "_text")

    def __init__(self) -> None:
        self.chars: list[str] = []
        self.styles: list[int] = []
        self._spans = None
        self._text = None

    def touch(self) -> None:
        self._spans = None
        self._text = None

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = "".join(self.chars)
        return self._text

    @property
    def spans(self) -> list[tuple[int, str, int]]:
        if self._spans is None:
            spans = []
            chars, styles = self.chars, self.styles
            n = len(chars)
            i = 0
            while i < n:
                s = styles[i]
                j = i + 1
                while j < n and styles[j] == s:
                    j += 1
                spans.append((i, "".join(chars[i:j]), s))
                i = j
            self._spans = spans
        return self._spans


class Term:
    """A small line-oriented terminal emulator: enough for gdb, pwndbg and
    most CLI programs (SGR colors, CR/BS overwrite, erase line/screen)."""

    def __init__(self, max_lines: int = 20000, show_ctrl: bool = False) -> None:
        self.lock = threading.RLock()
        self.max_lines = max_lines
        self.show_ctrl = show_ctrl
        self.clear()

    def clear(self) -> None:
        with self.lock:
            self.lines: list[Line] = [Line()]
            self.row = 0
            self.col = 0
            self.fg, self.bg, self.flags = -1, -1, 0
            self.style = 0
            self.pending = ""
            self.version = getattr(self, "version", 0) + 1
            self.width = 0
            self.trimmed = 0

    def set_text(self, text: str) -> None:
        with self.lock:
            self.clear()
            self.feed(text)

    def plain(self) -> str:
        with self.lock:
            return "\n".join(line.text for line in self.lines)

    # -- low level ------------------------------------------------------
    def _line(self) -> Line:
        while self.row >= len(self.lines):
            self.lines.append(Line())
        return self.lines[self.row]

    def _put(self, text: str, style: int | None = None) -> None:
        line = self._line()
        n = len(text)
        col = self.col
        if col > len(line.chars):
            pad = col - len(line.chars)
            line.chars.extend(" " * pad)
            line.styles.extend([0] * pad)
        line.chars[col:col + n] = text
        line.styles[col:col + n] = [self.style if style is None else style] * n
        line.touch()
        self.col = col + n
        if len(line.chars) > self.width:
            self.width = len(line.chars)

    def _newline(self) -> None:
        self.row += 1
        self.col = 0
        self._line()
        if len(self.lines) > self.max_lines:
            drop = max(1, self.max_lines // 10)
            del self.lines[:drop]
            self.row -= drop
            self.trimmed += drop

    def _ctrl(self, text: str) -> None:
        if self.show_ctrl:
            self._put(text, style_id(self.fg, self.bg, self.flags | CTRL))

    def feed(self, data: str, style_flags: int = 0) -> None:
        with self.lock:
            data = self.pending + data.replace("\ufe0f", "").replace("\u200d", "")
            self.pending = ""
            m = _PARTIAL_RE.search(data)
            if m and m.start() < len(data):
                self.pending = data[m.start():]
                data = data[: m.start()]
            saved = self.flags
            if style_flags:
                self.flags |= style_flags
                self._restyle()
            pos = 0
            for m in _TOKEN_RE.finditer(data):
                if m.start() > pos:
                    self._put(data[pos:m.start()])
                self._token(m.group())
                pos = m.end()
            if pos < len(data):
                self._put(data[pos:])
            if style_flags:
                self.flags = saved
                self._restyle()
            self.version += 1

    def _token(self, tok: str) -> None:
        c = tok[0]
        if c == "\n":
            self._newline()
        elif c == "\r":
            self.col = 0
        elif c == "\b":
            self.col = max(0, self.col - 1)
        elif c == "\t":
            self._put(" " * (8 - self.col % 8))
        elif c == "\x1b":
            if len(tok) > 2 and tok[1] == "[":
                self._csi(tok[2:-1], tok[-1])
            elif tok == "\x1bc":
                self.clear()
        elif "\udc80" <= c <= "\udcff":
            self._ctrl(f"\\x{ord(c) - 0xDC00:02x}")
        elif c in "\x01\x02\x07":
            pass
        else:
            self._ctrl(f"\\x{ord(c):02x}")

    def _csi(self, params: str, final: str) -> None:
        if final == "m":
            self._sgr(params)
            return
        private = params[:1] in "?<=>" and params != ""
        if private:
            return
        nums = [int(p) if p.isdigit() else 0 for p in params.split(";")] if params else []
        n = nums[0] if nums else 0
        line = self._line()
        if final == "K":
            if n == 0:
                del line.chars[self.col:]
                del line.styles[self.col:]
            elif n == 1:
                k = min(self.col + 1, len(line.chars))
                line.chars[:k] = " " * k
                line.styles[:k] = [0] * k
            else:
                line.chars.clear()
                line.styles.clear()
            line.touch()
        elif final == "J":
            if n in (2, 3):
                self.lines = [Line()]
                self.row = self.col = 0
                self.width = 0
            elif n == 0:
                del line.chars[self.col:]
                del line.styles[self.col:]
                line.touch()
                del self.lines[self.row + 1:]
        elif final in "Hf":
            r = max(1, nums[0] if nums else 1) - 1
            c = max(1, nums[1] if len(nums) > 1 else 1) - 1
            self.row = min(r, len(self.lines) - 1) if len(self.lines) > 1 else 0
            self.col = c
        elif final == "A":
            self.row = max(0, self.row - max(1, n))
        elif final == "S":
            # scroll up: equivalent to opening blank lines below the cursor
            k = max(1, n)
            self.lines[self.row + 1:self.row + 1] = [Line() for _ in range(k)]
            self.row += k
        elif final == "B":
            self.row += max(1, n)
        elif final == "C":
            self.col += max(1, n)
        elif final == "D":
            self.col = max(0, self.col - max(1, n))
        elif final == "G":
            self.col = max(1, n) - 1
        elif final == "P":
            del line.chars[self.col:self.col + max(1, n)]
            del line.styles[self.col:self.col + max(1, n)]
            line.touch()
        elif final == "@":
            k = max(1, n)
            line.chars[self.col:self.col] = " " * k
            line.styles[self.col:self.col] = [0] * k
            line.touch()
        elif final == "X":
            k = max(1, n)
            end = min(len(line.chars), self.col + k)
            line.chars[self.col:end] = " " * (end - self.col)
            line.styles[self.col:end] = [0] * (end - self.col)
            line.touch()

    def _sgr(self, params: str) -> None:
        parts = [int(p) if p.isdigit() else 0 for p in params.replace(":", ";").split(";")] if params else [0]
        i = 0
        while i < len(parts):
            p = parts[i]
            if p == 0:
                self.fg, self.bg, self.flags = -1, -1, 0
            elif p == 1:
                self.flags |= BOLD
            elif p == 2:
                self.flags |= DIM
            elif p == 3:
                self.flags |= ITALIC
            elif p == 4:
                self.flags |= UNDER
            elif p == 7:
                self.flags |= INVERSE
            elif p == 9:
                self.flags |= STRIKE
            elif p in (21, 22):
                self.flags &= ~(BOLD | DIM)
            elif p == 23:
                self.flags &= ~ITALIC
            elif p == 24:
                self.flags &= ~UNDER
            elif p == 27:
                self.flags &= ~INVERSE
            elif p == 29:
                self.flags &= ~STRIKE
            elif 30 <= p <= 37:
                self.fg = p - 30
            elif 40 <= p <= 47:
                self.bg = p - 40
            elif 90 <= p <= 97:
                self.fg = p - 90 + 8
            elif 100 <= p <= 107:
                self.bg = p - 100 + 8
            elif p == 39:
                self.fg = -1
            elif p == 49:
                self.bg = -1
            elif p in (38, 48) and i + 1 < len(parts):
                if parts[i + 1] == 5 and i + 2 < len(parts):
                    color = parts[i + 2] & 255
                    i += 2
                elif parts[i + 1] == 2 and i + 4 < len(parts):
                    r, g, b = (v & 255 for v in parts[i + 2:i + 5])
                    color = 0x1000000 | (r << 16) | (g << 8) | b
                    i += 4
                else:
                    color = -1
                    i += 1
                if p == 38:
                    self.fg = color
                else:
                    self.bg = color
            i += 1
        self._restyle()

    def _restyle(self) -> None:
        self.style = style_id(self.fg, self.bg, self.flags)


def strip_ansi(text: str) -> str:
    return _TOKEN_RE.sub(lambda m: "\n" if m.group() == "\n" else ("\t" if m.group() == "\t" else ""), text)
