"""Command line entry point: `pwndbg-imgui [GUI options] [gdb arguments...]`."""

from __future__ import annotations

import os
import shutil
import sys

from . import APP_NAME, __version__
from .settings import config_dir
from .theme import THEMES


def default_debugger() -> str:
    """Pick the debugger binary to launch.

    The modern pwndbg installs (install script, uv tool, Homebrew, Nix, distro
    packages) provide a `pwndbg` launcher: a gdb-compatible binary with pwndbg
    already loaded — the same thing pwntools uses via `context.gdb_binary`.
    Prefer it so pwndbg-imgui works out of the box; fall back to plain `gdb`
    (the agent then loads pwndbg from your gdbinit / init-pwndbg / known paths).
    """
    env = os.environ.get("PWNDBG_IMGUI_GDB")
    if env:
        return env
    return shutil.which("pwndbg") or "gdb"


class LaunchConfig:
    def __init__(self) -> None:
        self.gdb = default_debugger()
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
        self.attach_fd: int | None = None  # attached mode: socket from the agent
        self.gdb_pid: int | None = None


GDBINIT_SNIPPET = """\
define init-pwndbg-imgui
python
import importlib.util as _u, subprocess as _sp
try:
    _p = _sp.run(["pwndbg-imgui", "--agent-path"], capture_output=True, text=True, check=True).stdout.strip()
    _s = _u.spec_from_file_location("pwndbg_imgui_agent", _p)
    _m = _u.module_from_spec(_s)
    _s.loader.exec_module(_m)
    _m.attach()
except Exception as _e:
    print(f"[pwndbg-imgui] cannot start the GUI: {_e}")
end
end
document init-pwndbg-imgui
Load pwndbg (if needed) and open the pwndbg-imgui GUI attached to this gdb session.
end
"""


def exploit_template() -> str:
    """The pwntools exploit template shipped as package data."""
    import importlib.resources as ir

    return (ir.files("pwndbg_imgui") / "templates" / "exploit.tmpl").read_text()


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
  --gdb PATH          debugger binary (default: $PWNDBG_IMGUI_GDB, else the
                      `pwndbg` launcher if on PATH, else `gdb`)
  --pwndbg PATH       pwndbg's gdbinit.py, if your gdb does not load pwndbg
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
  --gdbinit           print an `init-pwndbg-imgui` gdb command to add to your gdbinit:
                        pwndbg-imgui --gdbinit >> ~/.config/gdb/gdbinit
                      then, in any gdb session (e.g. pwntools' gdb.debug/attach
                      gdbscript), `init-pwndbg-imgui` opens the GUI attached to it
  --agent-path        print the path of the gdb-side agent and exit
  --exploit [PATH]    write a pwntools exploit template (./exploit.py, or PATH)
                      with the pwndbg-imgui `-d ui` integration; prints to stdout
                      when piped (pwndbg-imgui --exploit > exploit.py)
  --version           print the pwndbg-imgui version and exit
  -h, --help          show this help

By default pwndbg is loaded from your gdbinit, else with a user-defined
`init-pwndbg` command, else from $PWNDBG_PATH or ~/.local/share/pwndbg.
Settings and layout live in {config_dir()}.
""".replace("%(prog)s", APP_NAME)


def parse_args(argv: list[str]) -> LaunchConfig:
    cfg = LaunchConfig()
    with_value = {"--gdb", "--pwndbg", "--init-cmd", "--theme", "--font", "--font-size", "--attach", "--gdb-pid"}
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
            elif key == "--attach":
                cfg.attach_fd = int(val)
                cfg.no_io = True  # the program's I/O belongs to whoever started it
            elif key == "--gdb-pid":
                cfg.gdb_pid = int(val)
        elif a in ("-h", "--help"):
            print(usage())
            sys.exit(0)
        elif a == "--version":
            print(f"{APP_NAME} {__version__}")
            sys.exit(0)
        elif a == "--list-themes":
            print("\n".join(THEMES))
            sys.exit(0)
        elif a == "--no-pwndbg":
            cfg.init = "none"
        elif a == "--no-io":
            cfg.no_io = True
        elif a == "--agent-path":
            from . import agent

            print(os.path.realpath(agent.__file__))
            sys.exit(0)
        elif a == "--gdbinit":
            print(GDBINIT_SNIPPET, end="")
            sys.exit(0)
        elif a == "--exploit":
            # write ./exploit.py when run on a terminal, else print (for piping)
            text = exploit_template()
            target = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("-") else None
            if target is None and not sys.stdout.isatty():
                sys.stdout.write(text)
                sys.exit(0)
            path = target or "exploit.py"
            if os.path.exists(path):
                sys.exit(f"{APP_NAME}: {path} already exists (refusing to overwrite); "
                         f"redirect instead: {APP_NAME} --exploit > other.py")
            with open(path, "w") as f:
                f.write(text)
            os.chmod(path, 0o755)
            print(f"wrote {path}")
            sys.exit(0)
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
    try:
        return App(cfg).run()
    except KeyboardInterrupt:  # forced (second Ctrl-C); cleanup already ran
        return 130
