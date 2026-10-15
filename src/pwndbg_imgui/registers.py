"""Locate register cells in pwndbg's `regs` context text (one or several columns)."""

from __future__ import annotations

import re

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def register_cells(text: str, names) -> list[tuple[int, int, str]]:
    """Return (start, end, name) for each register cell on a line of the regs pane.

    pwndbg prints a cell as `<change marker or spaces><NAME padded> <value>`; with
    `show-compact-regs` several cells share a line, aligned in columns. A cell starts at
    an uppercase register name (from `names`, lowercase) that begins the line or follows
    whitespace or the change marker, and is followed by whitespace / the wrap mark; it
    spans to the next cell. `start` includes the change marker, `end` excludes the
    separating spaces."""
    starts: list[tuple[int, str]] = []
    for m in _WORD_RE.finditer(text):
        word = m.group()
        if word != word.upper() or word.lower() not in names:
            continue  # registers are printed uppercase; values like "mov rdi, rax" are not
        after = text[m.end():m.end() + 1]
        if after and not after.isspace() and after != "⏎":
            continue
        s = m.start()
        while s > 0 and not text[s - 1].isspace():
            s -= 1  # include the change marker (default "*", configurable)
        marker = text[s:m.start()]
        if len(marker) > 3 or any(c.isalnum() for c in marker):
            continue  # glued to other text: part of a value, not a cell
        starts.append((s, word.lower()))
    cells = []
    for i, (s, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        cells.append((s, len(text[:end].rstrip()), name))
    return cells
