"""
pty_manager.py

Crée un pseudo-terminal (PTY) par section de contexte pwndbg.
Chaque PTY a un côté "master" qu'on lit depuis Python (non-bloquant)
et un côté "slave" dont on donne le chemin (/dev/pts/N) à pwndbg via
la commande `contextoutput <section> <tty> True`.

Le contenu brut (avec séquences ANSI) est accumulé dans un buffer
circulaire (liste de lignes) par section, thread-safe.
"""

from __future__ import annotations

import os
import pty
import time
import threading

from typing import Dict, Optional, Literal

from stransi.ansi import Text, Ansi
from stransi.clear import SetClear, Clear
from stransi.instruction import Instruction


Banner = Literal["both", "top", "bottom", "none"]

# Toutes les sections de contexte pwndbg disponibles
# name, clearing, banner, width, height
PWNDBG_SECTIONS: list[tuple[str, bool, Banner, Optional[int], Optional[int]]] = [
    ("regs", True, "none", None, None),
    ("disasm", True, "none", None, None),
    ("code", True, "none", None, None),
    ("stack", True, "none", None, None),
    ("expressions", True, "none", None, None),
    ("backtrace", True, "none", None, None),
    ("threads", True, "none", None, None),
    ("heap_tracker", True, "none", None, None),
    ("last_signal", True, "none", None, None),
]


class SectionPTY:
    """Représente le PTY associé à une section pwndbg."""

    def __init__(
        self,
        name: str,
        clearing: bool = False,
        banner: Literal["both", "top", "bottom", "none"] = "none",
        width: Optional[int] = None,
        height: Optional[int] = None,
    ):
        self.name = name
        self.clearing = clearing
        self.banner = banner
        self.width = width
        self.height = height

        self.master_fd, self.slave_fd = pty.openpty()
        self.slave_path = os.ttyname(self.slave_fd)

        # Rend le master non-bloquant pour pouvoir le poller depuis
        # la boucle de rendu sans freezer l'UI.
        os.set_blocking(self.master_fd, False)

        self.lines_instructions: list[list[Instruction | Text]] = []
        self.has_change: bool = False
        self.data: bytes = b""
        self._lock = threading.Lock()

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._reader_loop, name=f"pty-reader-{name}", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------
    def _reader_loop(self) -> None:
        """Boucle de lecture tournant dans un thread séparé."""
        while not self._stop.is_set():
            try:
                data = os.read(self.master_fd, 65536)
            except BlockingIOError:
                if self.data:

                    lines = (
                        self.data.decode("utf-8")
                        .replace("\r\n", "\n")
                        .replace("\r", "\n")
                        .replace("\x1b[?2004h", "")
                        .replace("\x1b[?2004l\n", "")
                        .split("\n")
                    )

                    self.data = b""

                    if not lines:
                        continue

                    with self._lock:
                        self.has_change = True

                        new_lines_instructions: list[list[Instruction | Text]] = []
                        for l, line in enumerate(lines):
                            line_insts = list(Ansi(line).instructions())
                            for i, inst in reversed(list(enumerate(line_insts))):
                                if isinstance(inst, SetClear) and inst.region == Clear.SCREEN:
                                    self.lines_instructions.clear()
                                    new_lines_instructions.clear()
                                    line_insts = line_insts[i + 1 :] if i < (len(line_insts) - 1) else None
                                    break
                            if line_insts is None:
                                continue
                            new_lines_instructions.append(line_insts)

                        if self.lines_instructions and self.lines_instructions[-1] and new_lines_instructions and new_lines_instructions[0]:
                            partial = []
                            if isinstance(self.lines_instructions[-1][-1], Text) and isinstance(new_lines_instructions[0][0], Text):
                                partial = list(Ansi(self.lines_instructions[-1][-1] + new_lines_instructions[0][0]).instructions())
                                self.lines_instructions[-1] = self.lines_instructions[-1][:-1]
                                new_lines_instructions[0] = new_lines_instructions[0][1:]
                            self.lines_instructions[-1] += partial + new_lines_instructions[0]
                            new_lines_instructions = new_lines_instructions[1:]
                        self.lines_instructions += new_lines_instructions

                time.sleep(0.01)
                continue
            except OSError:
                # master fermé / process terminé
                break

            if not data:
                time.sleep(0.01)
                continue

            self.data += data

    # ------------------------------------------------------------------
    def get_text(self) -> tuple[bool, list[list[Instruction | Text]]]:
        """Retourne le contenu courant (lignes complètes + partielle)."""
        with self._lock:
            hc = self.has_change
            self.has_change = False
            return hc, list(self.lines_instructions)

    def clear(self) -> None:
        with self._lock:
            self.lines_instructions.clear()
            self.has_change = False

    def close(self) -> None:
        self._stop.set()
        for fd in (self.master_fd, self.slave_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class ConsolePTY(SectionPTY):
    """PTY pour la console gdb : lecture (stdout/stderr de gdb) ET écriture
    (envoi de commandes vers stdin de gdb)."""

    def write(self, data: str) -> None:
        """Envoie des données (ex: une commande + '\\n') au process attaché
        sur le slave de ce pty."""
        try:
            os.write(self.master_fd, data.encode("utf-8"))
        except OSError:
            pass


class PtyManager:
    """Gère l'ensemble des PTYs pour toutes les sections pwndbg."""

    def __init__(self, sections: Optional[list[tuple[str, bool, Banner, Optional[int], Optional[int]]]] = None):
        self.sections = sections or list(PWNDBG_SECTIONS)
        self.ptys: Dict[str, SectionPTY] = {section[0]: SectionPTY(*section) for section in self.sections}
        # PTY dédié à la console gdb (stdin/stdout/stderr)
        self.console = ConsolePTY("console")

    def get_text(self, section: str) ->  tuple[bool, list[list[Instruction | Text]]]:
        pty_obj = self.ptys.get(section)
        hc, text = pty_obj.get_text()
        return (hc, text) if pty_obj else (False, [])

    def clear(self, section: str) -> None:
        pty_obj = self.ptys.get(section)
        if pty_obj:
            pty_obj.clear()

    def contextoutputs(self) -> Dict[str, tuple]:
        return {name: (name, p.slave_path, p.clearing, p.banner, p.width, p.height) for name, p in self.ptys.items()}

    def close_all(self) -> None:
        for p in self.ptys.values():
            p.close()
        self.console.close()
