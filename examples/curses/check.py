"""Check `--terminal-io` with cursesdemo (see ../check.sh): run tools/guitest.py inside a
pseudo-terminal standing in for the user's, type and resize there, and read what the
program saw from $CURSES_LOG.

    python check.py OUT_DIR    # with the Python check.sh uses (imgui-bundle + numpy)
"""

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def main() -> int:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    log = os.path.join(out, "events.log")
    if os.path.exists(log):
        os.remove(log)
    pid, master = pty.fork()
    if pid == 0:  # the "terminal" the GUI is started from
        os.chdir(HERE)
        os.environ.update(PYTHONPATH=os.path.join(ROOT, "src"), CURSES_LOG=log, TERM="xterm")
        os.execv(sys.executable, [sys.executable, os.path.join(ROOT, "tools", "guitest.py"),
                                  os.path.join(HERE, "curses.steps"), "--out", out,
                                  "--", "--terminal-io", "./cursesdemo"])
    winsize(master, 24, 80)
    modes = termios.tcgetattr(master)
    # what the user does in that terminal (seconds after start); curses.steps checks the GUI side
    plan = [(6, b"\x1bOA"), (7, (30, 100)), (8, b"\x03"), (12, b"q")]  # Up in keypad mode
    t0, screen = time.monotonic(), b""
    while True:
        now = time.monotonic() - t0
        while plan and now >= plan[0][0]:
            action = plan.pop(0)[1]
            if isinstance(action, tuple):
                winsize(master, *action)
            else:
                os.write(master, action)
        if select.select([master], [], [], 0.2)[0]:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            screen += data
        if os.waitpid(pid, os.WNOHANG)[0]:  # reaped: the GUI has exited
            break
    events = open(log).read() if os.path.exists(log) else ""
    checks = {
        "the program got the terminal (24x80)": "start rows=24 cols=80" in events,
        "and its TERM (xterm, not gdb's xterm-256color)": "term=xterm\n" in events,
        "a key typed there reached it": "key KEY_UP" in events,
        "a resize reached it (30x100)": "resize rows=30 cols=100" in events,
        "it ran to its normal end": "end " in events,
        "the terminal's modes were restored": termios.tcgetattr(master) == modes,
        "the GUI side passed (curses.steps)": b"guitest: step" not in screen,
    }
    for what, ok in checks.items():
        print(("ok    " if ok else "FAIL  ") + what)
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
