"""
run_combined.py

Lance gdb+pwndbg (configuré via contextoutput) ET l'UI ImGui dans le même
process, en partageant les mêmes PTYs.

Usage:
    python3 run_combined.py ./mon_binaire [args gdb additionnels...]
"""

from __future__ import annotations

import sys

from pty_manager import PtyManager
from pwndbg_launcher import PwndbgLauncher
from gui import main_with_manager


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else None
    extra_args = sys.argv[2:] if len(sys.argv) > 2 else None

    pm = PtyManager()

    print("PTYs créés :")
    for name, tty_path, autoscroll, banner, width, height in pm.contextoutputs().values():
        print(f"  {name:14s} -> {tty_path}, {autoscroll=}, {banner=}, {width=}, {height=}")
    print(f"  {'console':14s} -> {pm.console.slave_path}")

    launcher = PwndbgLauncher(
        pty_manager=pm,
        binary=binary,
        pwndbg_init_path="~/pwndbg/gdbinit.py",
        extra_gdb_args=extra_args,
    )

    # gdb hérite de stdin/stdout/stderr du terminal courant : son interface
    # texte reste utilisable normalement à côté de l'UI ImGui.
    proc = launcher.start()
    print(f"gdb lancé (pid={proc.pid}).")

    try:
        main_with_manager(pm)
    finally:
        launcher.stop()
        pm.close_all()
        if proc.poll() is None:
            proc.terminate()


if __name__ == "__main__":
    main()
