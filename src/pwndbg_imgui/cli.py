"""Command line entry point: `pwndbg-imgui [GUI options] [gdb arguments...]`."""

from __future__ import annotations

import os
import sys

from . import APP_NAME
from .settings import config_dir
from .theme import THEMES


class LaunchConfig:
    def __init__(self) -> None:
        self.gdb = os.environ.get("PWNDBG_IMGUI_GDB", "gdb")
        self.init = "auto"
        self.gdb_args: list[str] = []
        self.binary: str | None = None
        self.theme: str | None = None
        self.font: str | None = None
        self.font_size: float | None = None
        self.no_io = False
        self.reset_layout = False
        self.no_viewports = False
        self.maximize = False


def usage() -> str:
    return f"""\
usage: {APP_NAME} [GUI options] [gdb arguments...]

A Dear ImGui front-end for pwndbg. Everything that is not a GUI option is passed
to gdb as-is, so it works like `pwndbg`:

  %(prog)s ./binary                     debug a binary
  %(prog)s --args ./binary arg1 arg2    with program arguments
  %(prog)s -p 1234                      attach to a process
  %(prog)s ./binary core                inspect a core dump
  %(prog)s -ex 'target remote :1234' ./binary

GUI options:
  --gdb PATH          gdb executable (default: $PWNDBG_IMGUI_GDB or `gdb`)
  --pwndbg PATH       pwndbg's gdbinit.py, if your gdbinit does not load pwndbg
  --init-cmd CMD      gdb command that loads pwndbg (e.g. init-pwndbg)
  --no-pwndbg         do not try to load pwndbg
  --theme NAME        color theme ({", ".join(THEMES)})
  --font PATH         monospace .ttf/.otf font for code panes
  --font-size N       font size
  --no-io             do not give the program its own terminal pane
  --no-viewports      keep every window inside the main window
  --maximize          start with the main window maximized
  --reset-layout      start with the default window layout
  --list-themes       list themes and exit
  -h, --help          show this help

By default pwndbg is loaded from your gdbinit, else with a user-defined
`init-pwndbg` command, else from $PWNDBG_PATH or ~/.local/share/pwndbg.
Settings and layout live in {config_dir()}.
""".replace("%(prog)s", APP_NAME)


def parse_args(argv: list[str]) -> LaunchConfig:
    cfg = LaunchConfig()
    with_value = {"--gdb", "--pwndbg", "--init-cmd", "--theme", "--font", "--font-size"}
    i = 0
    rest: list[str] = []
    while i < len(argv):
        a = argv[i]
        if a == "--args":
            rest += argv[i:]
            break
        key, eq, inline = a.partition("=")
        if key in with_value:
            if eq:
                val = inline
            elif i + 1 < len(argv):
                i += 1
                val = argv[i]
            else:
                sys.exit(f"{APP_NAME}: {key} needs a value")
            if key == "--gdb":
                cfg.gdb = val
            elif key == "--pwndbg":
                p = os.path.expanduser(val)
                if os.path.isdir(p):
                    p = os.path.join(p, "gdbinit.py")
                cfg.init = "source:" + p
            elif key == "--init-cmd":
                cfg.init = "cmd:" + val
            elif key == "--theme":
                match = [t for t in THEMES if t.lower() == val.lower()]
                if not match:
                    sys.exit(f"{APP_NAME}: unknown theme {val!r}; try --list-themes")
                cfg.theme = match[0]
            elif key == "--font":
                cfg.font = os.path.expanduser(val)
            elif key == "--font-size":
                cfg.font_size = float(val)
        elif a in ("-h", "--help"):
            print(usage())
            sys.exit(0)
        elif a == "--list-themes":
            print("\n".join(THEMES))
            sys.exit(0)
        elif a == "--no-pwndbg":
            cfg.init = "none"
        elif a == "--no-io":
            cfg.no_io = True
        elif a == "--maximize":
            cfg.maximize = True
        elif a == "--no-viewports":
            cfg.no_viewports = True
        elif a == "--reset-layout":
            cfg.reset_layout = True
        else:
            rest.append(a)
        i += 1
    cfg.gdb_args = rest
    cfg.binary = guess_binary(rest)
    return cfg


def guess_binary(args: list[str]) -> str | None:
    """Find the program gdb will load, to key per-binary settings."""
    takes_value = {"-ex", "-iex", "-x", "-ix", "-p", "-pid", "--pid", "-cd", "-d", "-directory", "-s", "-symbols",
                   "-e", "-exec", "-se", "-c", "-core", "-b", "-l", "-D", "--data-directory", "-init-eval-command",
                   "-eval-command", "-command", "-init-command", "--tty", "-tty", "-i", "-interpreter"}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--args":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-"):
            if a in takes_value:
                i += 1
            i += 1
            continue
        return a
    return None


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        from .ui.app import App  # imgui_bundle is only needed past this point
    except ImportError as e:
        print(f"{APP_NAME}: cannot load the GUI ({e}); install with: pipx install pwndbg-imgui", file=sys.stderr)
        return 1
    App(cfg).run()
    return 0
