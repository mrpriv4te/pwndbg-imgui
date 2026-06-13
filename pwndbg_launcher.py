"""
pwndbg_launcher.py

Lance GDB + pwndbg dans un sous-processus, et configure automatiquement
`contextoutput <section> <tty> True` pour chaque section vers son PTY
dédié (cf pty_manager.py), en s'appuyant sur la doc :
https://pwndbg.re/stable/tutorials/splitting-the-context/

GDB lui-même (son invite / stdin/stdout) tourne sur un PTY séparé
("main_pty") que l'on peut éventuellement afficher dans une fenêtre
"GDB Console" de l'UI, ou laisser sur le terminal qui a lancé le script.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from typing import Dict, Optional

from pty_manager import PtyManager


GDBINIT_TEMPLATE = """\
# Auto-généré par pwndbg_launcher.py
# Redirige chaque section de contexte pwndbg vers son propre pty.

set breakpoint pending on
set disassembly-flavor intel
set print asm-demangle on

set output-radix 16
source ~/.config/gdb/AsciiPrintCommand.py

set debuginfod enabled on

source ~/vheap/vheap.py

python
import gdb
import pwndbg
from pwndbg.commands.context import contextoutput

def _pwndbg_imgui_setup():
    pwndbg.config.context_stack_lines.value = 50

    mapping = {mapping!r}
    for (name, tty_path, autoscroll, banner, width, height) in mapping.values():
        try:
            contextoutput(name, tty_path, True, banner, width, height)
        except Exception as e:
            print(f"[pwndbg-imgui] contextoutput({{name}}) failed: {{e}}")

_pwndbg_imgui_setup()
end

define hookpost-run
    context --off legend
    di connect
end
"""


class PwndbgLauncher:
    """
    Génère un fichier gdbinit qui configure `contextoutput` pour chaque
    section, puis lance `gdb -x <gdbinit> <args...>`.
    """

    def __init__(
        self,
        pty_manager: PtyManager,
        binary: Optional[str] = None,
        extra_gdb_args: Optional[list[str]] = None,
        pwndbg_init_path: Optional[str] = None,
    ):
        """
        :param pty_manager: instance de PtyManager (un pty par section)
        :param binary: chemin du binaire à debugger (optionnel)
        :param extra_gdb_args: arguments additionnels passés à gdb
        :param pwndbg_init_path: chemin vers le `gdbinit.py` de pwndbg si
               pwndbg n'est pas déjà chargé automatiquement (ex: installé
               via pipx / virtualenv et non sourcé dans ~/.gdbinit)
        """
        self.pty_manager = pty_manager
        self.binary = binary
        self.extra_gdb_args = extra_gdb_args or []
        self.pwndbg_init_path = pwndbg_init_path

        self._gdbinit_file: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------
    def _write_gdbinit(self) -> str:
        mapping = self.pty_manager.contextoutputs()

        content = ""
        # Si pwndbg n'est pas chargé via ~/.gdbinit, on le charge ici.
        if self.pwndbg_init_path:
            content += f"source {self.pwndbg_init_path}\n"

        content += GDBINIT_TEMPLATE.format(mapping=mapping)

        fd, path = tempfile.mkstemp(prefix="pwndbg_imgui_", suffix=".gdbinit")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self._gdbinit_file = path
        return path

    # ------------------------------------------------------------------
    def start(self) -> subprocess.Popen:
        """Lance gdb avec stdin/stdout/stderr connectés au slave de la
        console PTY (pty_manager.console), pour pouvoir afficher et piloter
        gdb depuis la fenêtre "GDB Console" de l'UI."""
        gdbinit_path = self._write_gdbinit()

        cmd = ["gdb", "-q", "-x", gdbinit_path]
        cmd += self.extra_gdb_args
        if self.binary:
            cmd.append(self.binary)

        console_slave_fd = self.pty_manager.console.slave_fd

        self.process = subprocess.Popen(
            cmd,
            stdin=console_slave_fd,
            stdout=console_slave_fd,
            stderr=console_slave_fd,
            start_new_session=True,  # crée une nouvelle session/groupe,
                                      # le slave devient son tty de contrôle
            close_fds=False,
        )
        return self.process

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
        if self._gdbinit_file and os.path.exists(self._gdbinit_file):
            os.unlink(self._gdbinit_file)


# ----------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    pm = PtyManager()

    print("PTYs créés :")
    for name, tty_path, autoscroll, banner, width, height in pm.contextoutputs().values():
        print(f"  {name:14s} -> {tty_path}, {autoscroll=}, {banner=}, {width=}, {height=}")
    print(f"  {'console':14s} -> {pm.console.slave_path}")
    print()
    print("Utilise run_combined.py pour lancer gdb + l'UI ensemble, "
          "ou attache-toi à la console via: cat", pm.console.slave_path,
          "(et écris dans le master pour piloter gdb).")

    launcher = PwndbgLauncher(
        pty_manager=pm,
        binary=sys.argv[1] if len(sys.argv) > 1 else None,
        pwndbg_init_path="~/pwndbg/gdbinit.py",
    )
    proc = launcher.start()
    print(f"gdb lancé (pid={proc.pid}).")
    try:
        proc.wait()
    finally:
        launcher.stop()
        pm.close_all()
