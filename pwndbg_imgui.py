#!/usr/bin/env python3
"""
pwndbg-imgui -- a dockable Dear ImGui front-end for pwndbg.

Use it exactly like you would use `pwndbg` / `gdb`:

    pwndbg_imgui.py ./binary
    pwndbg_imgui.py --args ./binary arg1 arg2
    pwndbg_imgui.py -p <pid>
    pwndbg_imgui.py ./binary core
    pwndbg_imgui.py -ex 'target remote :1234' ./binary

Any argument that is not one of the GUI options below is passed to gdb untouched.

This single file plays two roles:

  * GUI / launcher (regular Python, needs `pip install imgui-bundle`): it creates
    a PTY for the gdb console and one for the debugged program, spawns gdb and
    draws everything.
  * Agent (sourced inside gdb with `-x`, standard library only): it loads pwndbg
    if needed, redirects every pwndbg context section to the GUI and answers
    structured requests (memory, vmmap, breakpoints, completion, ...) over a
    socketpair inherited from the GUI.
"""

from __future__ import annotations

import functools
import json
import os
import re
import socket
import struct
import sys
import threading
import time

APP_NAME = "pwndbg-imgui"
APP_VERSION = "1.0.0"

ENV_FD = "PWNDBG_IMGUI_FD"
ENV_TTY = "PWNDBG_IMGUI_TTY"
ENV_INIT = "PWNDBG_IMGUI_INIT"

# Every pwndbg context section the GUI knows how to display.
SECTIONS = (
    "regs",
    "disasm",
    "code",
    "stack",
    "backtrace",
    "args",
    "expressions",
    "threads",
    "heap_tracker",
    "last_signal",
)

# Context sections whose length can be driven by a pwndbg config parameter.
SECTION_LINES_PARAM = {
    "code": "context-code-lines",
    "backtrace": "context-backtrace-lines",
}

CLEAR_SEQ = "\x1b[H\x1b[2J"

PWNDBG_CANDIDATE_PATHS = (
    "~/.local/share/pwndbg/gdbinit.py",
    "~/pwndbg/gdbinit.py",
    "~/tools/pwndbg/gdbinit.py",
    "/usr/share/pwndbg/gdbinit.py",
    "/opt/pwndbg/gdbinit.py",
)


# ════════════════════════════════════════════════════════════════════════════
#  Agent: runs inside gdb's embedded Python (standard library only)
# ════════════════════════════════════════════════════════════════════════════
class Agent:
    def __init__(self) -> None:
        import gdb

        self.gdb = gdb
        fd = int(os.environ.pop(ENV_FD))
        os.set_inheritable(fd, False)  # never leak the socket to the inferior
        self.sock = socket.socket(fileno=fd)
        self.wlock = threading.Lock()
        self.writers: dict[str, object] = {}
        self.geom: dict[str, tuple] = {}
        self.enabled: list[str] = []
        self.ctx = None  # pwndbg.commands.context once pwndbg is loaded
        self.pwndbg = None
        self.mask = (1 << 64) - 1

    # -- transport ----------------------------------------------------------
    def send(self, obj: dict) -> None:
        data = (json.dumps(obj, separators=(",", ":"), default=str) + "\n").encode()
        with self.wlock:
            try:
                self.sock.sendall(data)
            except OSError:
                pass

    def reader_loop(self) -> None:
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(1 << 16)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    req = json.loads(line)
                except ValueError:
                    continue
                self.gdb.post_event(functools.partial(self.handle, req))

    def handle(self, req: dict) -> None:
        rid = req.get("id")
        op = req.get("op", "")
        fn = getattr(self, "op_" + op, None)
        try:
            if fn is None:
                raise ValueError(f"unknown op {op!r}")
            res = fn(**req.get("args", {}))
            out = {"id": rid, "ok": True, "res": res}
        except Exception as e:  # report every failure to the GUI
            out = {"id": rid, "ok": False, "err": str(e).strip() or type(e).__name__}
        if rid is not None:
            self.send(out)

    # -- setup --------------------------------------------------------------
    def quiet(self, cmd: str) -> str:
        try:
            return self.gdb.execute(cmd, to_string=True) or ""
        except self.gdb.error:
            return ""

    def pwndbg_loaded(self) -> bool:
        return "pwndbg" in sys.modules and "pwndbg.commands" in sys.modules

    def load_pwndbg(self, spec: str) -> None:
        if self.pwndbg_loaded() or spec == "none":
            return
        gdb = self.gdb
        candidates: list[tuple[str, str]] = []
        if spec.startswith("source:"):
            candidates.append(("source", spec[len("source:"):]))
        elif spec.startswith("cmd:"):
            candidates.append(("cmd", spec[len("cmd:"):]))
        else:
            if re.search(r"^init-pwndbg\b", self.quiet("help user-defined"), re.M):
                candidates.append(("cmd", "init-pwndbg"))
            env_path = os.environ.get("PWNDBG_PATH")
            if env_path:
                candidates.append(("source", os.path.join(env_path, "gdbinit.py")))
            for path in PWNDBG_CANDIDATE_PATHS:
                path = os.path.expanduser(path)
                if os.path.exists(path):
                    candidates.append(("source", path))

        # gdb only sets __file__ for the outermost sourced script; pwndbg's
        # gdbinit.py relies on it, so hide ours while sourcing it.
        # Likewise, runpy points sys.argv[0] at this file, which breaks
        # pwndbg's argparse `prog` handling: make it look like plain gdb.
        import __main__

        saved = __main__.__dict__.pop("__file__", None)
        saved_argv0 = sys.argv[0] if sys.argv else None
        if sys.argv:
            sys.argv[0] = ""
        try:
            for kind, value in candidates:
                try:
                    gdb.execute(value if kind == "cmd" else f"source {value}")
                except gdb.error as e:
                    print(f"[{APP_NAME}] loading pwndbg with {value!r} failed: {e}")
                if self.pwndbg_loaded():
                    break
        finally:
            if saved is not None:
                __main__.__file__ = saved
            if saved_argv0 is not None:
                sys.argv[0] = saved_argv0

    def make_writer(self, name: str):
        def write(data: str) -> None:
            if data == CLEAR_SEQ:
                return
            if data.startswith(CLEAR_SEQ):
                data = data[len(CLEAR_SEQ):]
            if data.startswith("\n"):
                data = data[1:]
            self.send({"ev": "section", "name": name, "text": data})

        return write

    def start(self) -> None:
        gdb = self.gdb
        tty = os.environ.pop(ENV_TTY, "")
        spec = os.environ.pop(ENV_INIT, "auto")
        for var in (ENV_FD, ENV_TTY, ENV_INIT):
            self.quiet(f"unset environment {var}")

        self.load_pwndbg(spec)
        for cmd in (
            "set editing off",
            "set pagination off",
            "set confirm off",
            "set height 0",
            "set width 0",
        ):
            self.quiet(cmd)
        if tty:
            self.quiet(f"set inferior-tty {tty}")

        if self.pwndbg_loaded():
            import pwndbg
            import pwndbg.commands.context as ctx

            self.pwndbg = pwndbg
            self.ctx = ctx
            for name in SECTIONS + ("legend",):
                self.writers[name] = self.make_writer(name)
                ctx.contextoutput(name, self.writers[name], True, "none", None, None)
            # Nothing is computed until the GUI says which sections are shown.
            ctx.config_context_sections.value = "regs disasm code stack backtrace"
            # The prompt lives in its own pane: no need to reserve terminal lines.
            self.quiet("set context-reserve-lines never")

        ev = gdb.events
        ev.stop.connect(self.on_stop)
        ev.cont.connect(lambda e: self.send({"ev": "cont"}))
        ev.exited.connect(self.on_exited)
        ev.new_objfile.connect(lambda e: self.send({"ev": "objfile"}))
        ev.breakpoint_created.connect(lambda b: self.send_breakpoints())
        ev.breakpoint_modified.connect(lambda b: self.send_breakpoints())
        ev.breakpoint_deleted.connect(lambda b: self.send_breakpoints())
        ev.memory_changed.connect(lambda e: self.send({"ev": "memory"}))
        ev.register_changed.connect(lambda e: self.send({"ev": "memory"}))
        ev.before_prompt.connect(self.on_prompt)

        threading.Thread(target=self.reader_loop, name="imgui-agent", daemon=True).start()
        self.send({"ev": "hello", "info": self.op_info()})
        self.send_breakpoints()

    # -- events -------------------------------------------------------------
    def on_stop(self, event) -> None:
        gdb = self.gdb
        msg: dict = {"ev": "stop", "reason": "stop"}
        if isinstance(event, gdb.BreakpointEvent):
            msg["reason"] = "breakpoint"
            msg["bps"] = [b.number for b in event.breakpoints]
        elif isinstance(event, gdb.SignalEvent):
            msg["reason"] = "signal"
            msg["signal"] = event.stop_signal
        self.send(msg)

    def on_exited(self, event) -> None:
        code = getattr(event, "exit_code", None)
        self.send({"ev": "exited", "code": code})

    def on_prompt(self) -> None:
        self.send({"ev": "state", "state": self.op_state()})

    def send_breakpoints(self) -> None:
        try:
            self.send({"ev": "bps", "bps": self.op_breakpoints()})
        except Exception:
            pass

    # -- helpers ------------------------------------------------------------
    def thread_stopped(self) -> bool:
        thr = self.gdb.selected_thread()
        return thr is not None and not thr.is_running()

    def require_stopped(self) -> None:
        if not self.thread_stopped():
            raise RuntimeError("the program is not stopped")

    def refresh_context(self) -> None:
        if self.ctx is not None and self.thread_stopped() and self.enabled:
            self.quiet("context")

    def page_of(self, addr: int):
        try:
            import pwndbg.aglib.vmmap as vmmap

            return vmmap.find(addr)
        except Exception:
            return None

    @staticmethod
    def page_kind(page) -> str:
        if page.is_stack:
            return "stack"
        if page.is_heap:
            return "heap"
        if page.execute and page.write:
            return "wx"
        if page.execute:
            return "code"
        if page.write:
            return "data"
        if page.read:
            return "rodata"
        return "guard"

    def page_dict(self, page) -> list:
        return [page.start, page.end, page.permstr, page.offset, page.objfile, self.page_kind(page)]

    # -- ops ----------------------------------------------------------------
    def op_ping(self) -> str:
        return "pong"

    def op_info(self) -> dict:
        gdb = self.gdb
        info = {
            "gdb": gdb.VERSION,
            "pwndbg": None,
            "file": gdb.current_progspace().filename,
            "sections": list(SECTIONS),
        }
        if self.pwndbg is not None:
            info["pwndbg"] = getattr(self.pwndbg, "__version__", "loaded")
        return info

    def op_state(self) -> dict:
        gdb = self.gdb
        st: dict = {"alive": False, "running": False, "pid": 0}
        try:
            st["file"] = gdb.current_progspace().filename
            inf = gdb.selected_inferior()
            st["pid"] = inf.pid
            thr = gdb.selected_thread()
            if thr is not None and thr.is_valid():
                st["alive"] = True
                st["tid"] = thr.num
                st["running"] = thr.is_running()
                if not st["running"]:
                    frame = gdb.selected_frame()
                    st["pc"] = frame.pc()
                    st["func"] = frame.name()
                    st["level"] = frame.level()
                    st["arch"] = frame.architecture().name()
                    sal = frame.find_sal()
                    if sal.symtab is not None:
                        st["src"] = sal.symtab.fullname()
                        st["line"] = sal.line
                    try:
                        import pwndbg.aglib.symbol

                        st["sym"] = pwndbg.aglib.symbol.resolve_addr(st["pc"])
                    except Exception:
                        st["sym"] = st["func"]
        except gdb.error:
            pass
        return st

    def op_exec(self, cmd: str, refresh: bool = False) -> str:
        out = self.gdb.execute(cmd, to_string=True) or ""
        if refresh:
            self.refresh_context()
            # No prompt is displayed for our requests: publish the new state
            # ourselves (selected frame, registers, memory may have changed).
            self.send({"ev": "memory"})
            self.send({"ev": "state", "state": self.op_state()})
        return out

    def op_complete(self, text: str) -> list:
        out = self.gdb.execute("complete " + text, to_string=True) or ""
        return [line for line in out.splitlines() if line.strip()]

    def op_layout(self, enabled: list, geom: dict) -> None:
        ctx = self.ctx
        if ctx is None:
            return
        changed = set(enabled) - set(self.enabled)
        for name, (w, h) in geom.items():
            if name not in self.writers:
                continue
            if self.geom.get(name) != (w, h):
                changed.add(name)
            self.geom[name] = (w, h)
            ctx.contextoutput(name, self.writers[name], True, "none", w or None, h or None)
            param = SECTION_LINES_PARAM.get(name)
            if param and h:
                self.quiet(f"set {param} {max(1, h - 1)}")
        self.enabled = [s for s in SECTIONS if s in enabled]
        ctx.config_context_sections.value = " ".join(self.enabled)
        changed &= set(self.enabled)
        if changed and self.thread_stopped():
            self.quiet("context " + " ".join(sorted(changed)))

    def op_context(self) -> None:
        self.refresh_context()

    def op_read(self, addr: int, size: int) -> dict:
        self.require_stopped()
        inf = self.gdb.selected_inferior()
        addr &= self.mask
        try:
            return {"hex": bytes(inf.read_memory(addr, size)).hex(), "bad": []}
        except self.gdb.MemoryError:
            pass
        out = bytearray(size)
        bad = []
        off = 0
        while off < size:
            n = min(size - off, 0x1000 - ((addr + off) & 0xFFF))
            try:
                out[off:off + n] = bytes(inf.read_memory(addr + off, n))
            except self.gdb.MemoryError:
                if bad and bad[-1][1] == off:
                    bad[-1][1] = off + n
                else:
                    bad.append([off, off + n])
            off += n
        return {"hex": out.hex(), "bad": bad}

    def op_write(self, addr: int, hex: str) -> None:
        self.require_stopped()
        self.gdb.selected_inferior().write_memory(addr & self.mask, bytes.fromhex(hex))
        self.refresh_context()

    def op_eval(self, expr: str) -> int:
        gdb = self.gdb
        val = gdb.parse_and_eval(expr)
        code = val.type.strip_typedefs().code
        if code in (gdb.TYPE_CODE_FUNC, gdb.TYPE_CODE_ARRAY) and val.address is not None:
            val = val.address
        try:
            return int(val) & self.mask
        except gdb.error:
            return int(val.cast(gdb.lookup_type("long"))) & self.mask

    def op_vmmap(self) -> list:
        self.require_stopped()
        import pwndbg.aglib.vmmap as vmmap

        return [self.page_dict(p) for p in vmmap.get()]

    def op_addrinfo(self, addrs: list) -> dict:
        self.require_stopped()
        import pwndbg.aglib.symbol
        import pwndbg.chain

        out = {}
        for a in addrs[:64]:
            info: dict = {}
            page = self.page_of(a)
            if page is not None:
                info["page"] = self.page_dict(page)
                try:
                    info["chain"] = pwndbg.chain.format(a)
                except Exception:
                    pass
            try:
                info["sym"] = pwndbg.aglib.symbol.resolve_addr(a)
            except Exception:
                pass
            out[str(a)] = info
        return out

    def op_breakpoints(self) -> list:
        gdb = self.gdb
        kinds = {}
        for const, name in (("BP_BREAKPOINT", "break"), ("BP_HARDWARE_BREAKPOINT", "hbreak"),
                            ("BP_WATCHPOINT", "watch"), ("BP_HARDWARE_WATCHPOINT", "watch"),
                            ("BP_READ_WATCHPOINT", "rwatch"), ("BP_ACCESS_WATCHPOINT", "awatch"),
                            ("BP_CATCHPOINT", "catch")):
            if hasattr(gdb, const):
                kinds[getattr(gdb, const)] = name
        out = []
        for b in gdb.breakpoints():
            if not b.is_valid() or b.number < 0:
                continue
            locs = []
            for loc in getattr(b, "locations", []) or []:
                try:
                    src = loc.source
                    locs.append(
                        {
                            "addr": loc.address,
                            "enabled": loc.enabled,
                            "file": src[0] if src else None,
                            "full": loc.fullname,
                            "line": src[1] if src else None,
                        }
                    )
                except Exception:
                    pass
            out.append(
                {
                    "num": b.number,
                    "type": kinds.get(b.type, str(b.type)),
                    "enabled": b.enabled,
                    "temp": b.temporary,
                    "location": b.location,
                    "expr": b.expression,
                    "cond": b.condition,
                    "hits": b.hit_count,
                    "ignore": b.ignore_count,
                    "pending": b.pending,
                    "locs": locs,
                }
            )
        return out

    def find_bps(self, addr=None, file=None, line=None) -> list:
        res = []
        for b in self.gdb.breakpoints():
            if b.type != self.gdb.BP_BREAKPOINT:
                continue
            for loc in getattr(b, "locations", []) or []:
                if addr is not None and loc.address == addr:
                    res.append(b)
                    break
                src = loc.source
                if file and src and src[1] == line and os.path.basename(src[0]) == os.path.basename(file):
                    res.append(b)
                    break
        return res

    def op_bp_toggle(self, addr: int | None = None, file: str | None = None, line: int | None = None) -> str:
        bps = self.find_bps(addr, file, line)
        if bps:
            for b in bps:
                b.delete()
            return "deleted"
        spec = f"*{addr:#x}" if addr is not None else f"{file}:{line}"
        self.gdb.Breakpoint(spec)
        return "created"

    def op_bp_delete(self, num: int) -> None:
        for b in self.gdb.breakpoints():
            if b.number == num:
                b.delete()

    def op_bp_update(self, num: int, enabled: bool | None = None, cond: str | None = None) -> None:
        for b in self.gdb.breakpoints():
            if b.number == num:
                if enabled is not None:
                    b.enabled = enabled
                if cond is not None:
                    b.condition = cond or None

    def op_commands(self) -> list:
        if self.pwndbg is None:
            return []
        import pwndbg.commands

        out = []
        for c in pwndbg.commands.commands:
            try:
                help_text = c.parser.format_help()
            except Exception:
                help_text = getattr(c, "description", "") or ""
            out.append(
                {
                    "name": c.command_name,
                    "aliases": list(c.aliases),
                    "cat": c.category.value,
                    "desc": (c.parser.description or "").strip().split("\n")[0],
                    "help": help_text,
                }
            )
        return out

    def op_config(self) -> list:
        if self.pwndbg is None:
            return []
        import pwndbg.lib.config as cfg

        kinds = {
            cfg.PARAM_BOOLEAN: "bool",
            cfg.PARAM_AUTO_BOOLEAN: "auto",
            cfg.PARAM_ENUM: "enum",
            cfg.PARAM_STRING: "str",
            cfg.PARAM_OPTIONAL_FILENAME: "str",
        }
        out = []
        for p in self.pwndbg.config.params.values():
            kind = kinds.get(p.param_class, "int")
            value = p.value
            if kind == "auto":
                value = "auto" if value is None else ("on" if value else "off")
            out.append(
                {
                    "name": p.name,
                    "kind": kind,
                    "value": value if isinstance(value, (bool, int, str)) else str(value),
                    "default": p.pretty_default(),
                    "doc": p.set_show_doc,
                    "help": p.help_docstring,
                    "enum": list(p.enum_sequence or []),
                    "scope": p.scope.name,
                }
            )
        out.sort(key=lambda d: (d["scope"], d["name"]))
        return out

    def op_quit(self) -> None:
        try:
            if self.gdb.selected_inferior().pid:
                self.gdb.execute("kill", to_string=True)
        finally:
            self.gdb.execute("quit")


def _agent_main() -> None:
    agent = Agent()
    agent.start()


# ════════════════════════════════════════════════════════════════════════════
#  GUI side: settings, themes, terminal emulation, RPC
# ════════════════════════════════════════════════════════════════════════════
def config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


class Settings:
    DEFAULTS = {
        "theme": "Pwn Night",
        "ui_size": 15.0,
        "code_size": 15.0,
        "font": "",
        "fps_idle": 20.0,
        "viewports": True,
        "remember_bps": True,
        "autofit": True,
        "io_raw": True,
        "io_echo": True,
        "io_newline": True,
        "console_history": [],
        "binaries": {},
        "views": [],
        "visible": {},
    }

    def __init__(self) -> None:
        self.path = os.path.join(config_dir(), "settings.json")
        self.data = json.loads(json.dumps(self.DEFAULTS))
        try:
            with open(self.path) as f:
                self.data.update(json.load(f))
        except (OSError, ValueError):
            pass

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value) -> None:
        self.data[key] = value

    def binary(self, path: str | None) -> dict:
        key = os.path.abspath(path) if path else "<none>"
        return self.data["binaries"].setdefault(key, {})

    def save(self) -> None:
        self.data["console_history"] = self.data["console_history"][-500:]
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self.data, f, indent=1)
            os.replace(tmp, self.path)
        except OSError:
            pass


# ── Colors ──────────────────────────────────────────────────────────────────
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
            if style_flags:
                saved = self.flags
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


# ── RPC client (GUI side) ───────────────────────────────────────────────────
class Rpc:
    def __init__(self, sock: socket.socket) -> None:
        import queue

        self.sock = sock
        self.inbox: "queue.Queue[dict]" = queue.Queue()
        self.callbacks: dict[int, tuple] = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.connected = True
        threading.Thread(target=self._reader, name="rpc-reader", daemon=True).start()

    def _reader(self) -> None:
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(1 << 20)
            except OSError:
                chunk = b""
            if not chunk:
                self.connected = False
                self.inbox.put({"ev": "disconnected"})
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    self.inbox.put(json.loads(line))
                except ValueError:
                    pass

    def request(self, op: str, cb=None, err=None, **args) -> None:
        with self.lock:
            rid = self.next_id
            self.next_id += 1
            self.callbacks[rid] = (cb, err)
        data = (json.dumps({"id": rid, "op": op, "args": args}) + "\n").encode()
        try:
            self.sock.sendall(data)
        except OSError:
            self.callbacks.pop(rid, None)

    def resolve(self, msg: dict) -> None:
        cb, err = self.callbacks.pop(msg["id"], (None, None))
        if msg.get("ok"):
            if cb:
                cb(msg.get("res"))
        elif err:
            err(msg.get("err", "error"))


# ── PTYs ────────────────────────────────────────────────────────────────────
class Pty:
    """A pseudo-terminal whose output is decoded into a Term by a reader thread."""

    def __init__(self, term: Term, raw: bool = False, keep_bytes: int = 0) -> None:
        import pty
        import tty

        self.term = term
        self.master, self.slave = pty.openpty()
        self.path = os.ttyname(self.slave)
        if raw:
            tty.setraw(self.slave)
        self.raw = raw
        self.keep_bytes = keep_bytes
        self.raw_bytes = bytearray()
        self.bytes_version = 0
        self.size = (0, 0)
        import codecs

        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="surrogateescape")
        threading.Thread(target=self._reader, name=f"pty-{self.path}", daemon=True).start()

    def _reader(self) -> None:
        import select

        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.5)
                if not ready:
                    continue
                data = os.read(self.master, 1 << 16)
            except OSError:
                return
            if not data:
                return
            if self.keep_bytes:
                with self.term.lock:
                    self.raw_bytes += data
                    if len(self.raw_bytes) > self.keep_bytes:
                        del self.raw_bytes[: len(self.raw_bytes) - self.keep_bytes]
                    self.bytes_version += 1
            self.term.feed(self.decoder.decode(data))

    def write(self, data: bytes) -> None:
        while data:
            try:
                n = os.write(self.master, data)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                return
            data = data[n:]

    def set_raw(self, raw: bool) -> None:
        import termios
        import tty

        if raw:
            tty.setraw(self.slave)
        else:
            attrs = termios.tcgetattr(self.slave)
            attrs[0] |= termios.ICRNL
            attrs[1] |= termios.OPOST | termios.ONLCR
            attrs[3] |= termios.ICANON | termios.ISIG | termios.IEXTEN
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.raw = raw

    def resize(self, rows: int, cols: int) -> None:
        import fcntl
        import termios

        if (rows, cols) == self.size or rows <= 0 or cols <= 0:
            return
        self.size = (rows, cols)
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass


# ── cyclic / de Bruijn (same algorithm as pwntools) ─────────────────────────
def de_bruijn(alphabet: bytes, n: int):
    k = len(alphabet)
    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


def cyclic(length: int, n: int = 4) -> bytes:
    out = bytearray()
    for b in de_bruijn(b"abcdefghijklmnopqrstuvwxyz", n):
        if len(out) >= length:
            break
        out.append(b)
    return bytes(out)


def cyclic_find(needle: bytes, n: int = 4) -> int:
    needle = needle[:n]
    if len(needle) < n:
        return -1
    pattern = cyclic(min(26**n, 1 << 20) + n, n)
    return pattern.find(needle)


def parse_bytes_input(text: str, mode: str) -> bytes:
    """Interpret Program I/O input according to the selected mode."""
    if mode == "hex":
        clean = re.sub(r"(0x|\\x|[\s,:])", "", text)
        return bytes.fromhex(clean)
    if mode == "python":
        import ast

        value = ast.literal_eval(text)
        if isinstance(value, str):
            return value.encode("latin-1")
        return bytes(value)
    return text.encode("utf-8", errors="surrogateescape")


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


# ════════════════════════════════════════════════════════════════════════════
#  GUI widgets
# ════════════════════════════════════════════════════════════════════════════
imgui = hello_imgui = ImVec2 = ImVec4 = fa = None  # bound by gui_main()

ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")
WORD_RE = re.compile(r"[\w$#.@]+")
PC_MARK = "►"  # ►


def v4(c, a: float = 1.0):
    return ImVec4(c[0], c[1], c[2], a)


def ctrl_pressed(key) -> bool:
    io = imgui.get_io()
    return io.key_ctrl and not io.key_alt and imgui.is_key_pressed(key, False)


def combo_width(longest: str) -> float:
    return imgui.calc_text_size(longest).x + imgui.get_frame_height() + imgui.get_style().frame_padding.x * 2


def vsep() -> None:
    """A thin vertical separator between toolbar items."""
    imgui.same_line()
    p = imgui.get_cursor_screen_pos()
    h = imgui.get_frame_height()
    imgui.get_window_draw_list().add_line(
        ImVec2(p.x + 3, p.y + h * 0.18), ImVec2(p.x + 3, p.y + h * 0.82), imgui.get_color_u32(imgui.Col_.separator), 1.0)
    imgui.dummy(ImVec2(7, h))
    imgui.same_line()


def help_marker(text: str) -> None:
    imgui.same_line()
    imgui.text_disabled("(?)")
    if imgui.begin_item_tooltip():
        imgui.push_text_wrap_pos(imgui.get_font_size() * 35)
        imgui.text_unformatted(text)
        imgui.pop_text_wrap_pos()
        imgui.end_tooltip()


class TextView:
    """Scrollable, selectable, searchable view over a Term, with clickable
    addresses, breakpoint gutter and context menu."""

    def __init__(self, app, term: Term, vid: str, follow: str = "top", gutter=None, gutter_click=None,
                 menu=None, on_dblclick=None, empty_hint: str = "") -> None:
        self.app = app
        self.term = term
        self.vid = vid
        self.follow = follow  # top | bottom | pc | none
        self.gutter = gutter
        self.gutter_click = gutter_click
        self.menu = menu
        self.on_dblclick = on_dblclick
        self.empty_hint = empty_hint
        self.seen_version = -1
        self.seen_trim = 0
        self.anchor = None  # (line, col)
        self.cursor = None
        self.dragging = False
        self.search_open = False
        self.search_text = ""
        self.search_focus = False
        self.matches: list[tuple[int, int, int]] = []
        self.match_idx = -1
        self.match_key = None
        self.at_bottom = True
        self.pending_scroll: float | None = None
        self.hover = None  # (addr, since)
        self.ctx: dict = {}
        self.rows = 0
        self.cols = 0
        self.wrap_cols = 0

    # -- selection helpers ----------------------------------------------
    def selection(self):
        if self.anchor is None or self.cursor is None or self.anchor == self.cursor:
            return None
        a, b = sorted((self.anchor, self.cursor))
        return a, b

    def selected_text(self) -> str:
        sel = self.selection()
        if not sel:
            return ""
        (l0, c0), (l1, c1) = sel
        with self.term.lock:
            lines = self.term.lines
            out = []
            for i in range(l0, min(l1, len(lines) - 1) + 1):
                t = lines[i].text
                s = c0 if i == l0 else 0
                e = c1 if i == l1 else len(t)
                out.append(t[s:e].rstrip())
            return "\n".join(out)

    def select_all(self) -> None:
        with self.term.lock:
            n = len(self.term.lines)
            self.anchor = (0, 0)
            self.cursor = (n - 1, len(self.term.lines[-1].chars))

    def copy(self, text: str | None = None) -> None:
        text = self.selected_text() if text is None else text
        if text:
            imgui.set_clipboard_text(text)
            self.app.toast("Copied to clipboard", kind="info", ttl=1.2)

    def open_search(self) -> None:
        self.search_open = True
        self.search_focus = True
        sel = self.selected_text()
        if sel and "\n" not in sel:
            self.search_text = sel

    # -- search ---------------------------------------------------------
    def _update_matches(self) -> None:
        key = (self.search_text, self.term.version)
        if key == self.match_key:
            return
        self.match_key = key
        self.matches = []
        needle = self.search_text.lower()
        if not needle:
            return
        with self.term.lock:
            for i, line in enumerate(self.term.lines):
                t = line.text.lower()
                start = t.find(needle)
                while start != -1 and len(self.matches) < 10000:
                    self.matches.append((i, start, len(needle)))
                    start = t.find(needle, start + len(needle))
        if self.match_idx >= len(self.matches):
            self.match_idx = len(self.matches) - 1

    def _goto_match(self, delta: int) -> None:
        if not self.matches:
            return
        self.match_idx = (self.match_idx + delta) % len(self.matches)
        self.pending_scroll = self.matches[self.match_idx][0]

    def _search_bar(self) -> None:
        imgui.set_next_item_width(min(320.0, imgui.get_content_region_avail().x * 0.6))
        if self.search_focus:
            imgui.set_keyboard_focus_here()
            self.search_focus = False
        changed, self.search_text = imgui.input_text_with_hint(
            f"##find{self.vid}", "Find (Enter / Shift+Enter)", self.search_text,
            imgui.InputTextFlags_.enter_returns_true,
        )
        self._update_matches()
        if changed:
            self._goto_match(-1 if imgui.get_io().key_shift else 1)
        elif imgui.is_item_edited() and self.matches:
            self.match_idx = -1
            self._goto_match(1)
        imgui.same_line()
        total = len(self.matches)
        imgui.text_disabled(f"{self.match_idx + 1 if total else 0}/{total}")
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_ARROW_UP + f"##fu{self.vid}"):
            self._goto_match(-1)
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_ARROW_DOWN + f"##fd{self.vid}"):
            self._goto_match(1)
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_XMARK + f"##fx{self.vid}") or (
            imgui.is_key_pressed(imgui.Key.escape) and imgui.is_window_focused(imgui.FocusedFlags_.root_and_child_windows)
        ):
            self.search_open = False
            self.matches = []
            self.match_key = None

    # -- main render ----------------------------------------------------
    def render(self, height: float = 0.0) -> None:
        app = self.app
        th = app.theme
        io = imgui.get_io()
        if self.search_open:
            self._search_bar()
        avail = imgui.get_content_region_avail()
        h = height if height > 0 else avail.y + height
        imgui.push_style_color(imgui.Col_.child_bg, v4(th.term_bg))
        imgui.push_style_var(imgui.StyleVar_.window_padding, ImVec2(6, 4))
        imgui.push_font(app.mono, app.code_size)
        app.measure()
        imgui.begin_child(
            f"##tv{self.vid}", ImVec2(avail.x, max(h, 20.0)),
            imgui.ChildFlags_.always_use_window_padding,
            imgui.WindowFlags_.horizontal_scrollbar | imgui.WindowFlags_.no_nav,
        )
        try:
            self._render_body(app, th, io)
        finally:
            imgui.end_child()
            imgui.pop_font()
            imgui.pop_style_var()
            imgui.pop_style_color()

    def _render_body(self, app, th, io) -> None:
        term = self.term
        char_w = app.char_w
        line_h = app.line_h
        style = imgui.get_style()
        pad = ImVec2(6, 4)
        gw = char_w * 2.2 if self.gutter else 0.0
        win_pos = imgui.get_window_pos()
        win_w = imgui.get_window_width()
        win_h = imgui.get_window_height()
        self.rows = max(1, int((win_h - pad.y * 2) // line_h))
        self.cols = max(10, int((win_w - pad.x * 2 - gw - style.scrollbar_size) // char_w))
        focused = imgui.is_window_focused()
        hovered = imgui.is_window_hovered()

        with term.lock:
            lines = term.lines
            n = len(lines)
            if n == 1 and not lines[0].chars and self.empty_hint:
                imgui.set_cursor_pos(ImVec2(pad.x, pad.y))
                imgui.push_style_color(imgui.Col_.text, v4(th.dim))
                imgui.text_wrapped(self.empty_hint)
                imgui.pop_style_color()
                return
            total_w = gw + (term.width + 2) * char_w
            total_h = n * line_h
            imgui.set_cursor_pos(ImVec2(pad.x, pad.y))
            imgui.dummy(ImVec2(total_w, total_h))
            scroll_x = imgui.get_scroll_x()
            scroll_y = imgui.get_scroll_y()
            ox = win_pos.x + pad.x - scroll_x
            oy = win_pos.y + pad.y - scroll_y
            tx = ox + gw  # text origin

            # react to new content
            if term.trimmed != self.seen_trim:
                self.seen_trim = term.trimmed
                self.anchor = self.cursor = None
            if term.version != self.seen_version:
                self.seen_version = term.version
                self._follow(lines, line_h, win_h)
            if self.pending_scroll is not None:
                imgui.set_scroll_y(max(0.0, self.pending_scroll * line_h - win_h / 2))
                self.pending_scroll = None
            self.at_bottom = scroll_y >= imgui.get_scroll_max_y() - line_h

            first = max(0, int(scroll_y // line_h) - 1)
            last = min(n, int((scroll_y + win_h) // line_h) + 1)
            dl = imgui.get_window_draw_list()
            clip_r = win_pos.x + win_w

            mouse = imgui.get_mouse_pos()
            m_line = int((mouse.y - oy) // line_h)
            m_colf = (mouse.x - tx) / char_w
            in_gutter = self.gutter is not None and mouse.x < win_pos.x + pad.x + gw - scroll_x + 2
            hover_tok = None
            if hovered and 0 <= m_line < n and not in_gutter and m_colf >= 0:
                text = lines[m_line].text
                col = int(m_colf)
                for m in ADDR_RE.finditer(text):
                    if m.start() <= col < m.end():
                        hover_tok = (m_line, m.start(), m.end(), int(m.group(), 16))
                        break

            # current line highlight (pwndbg marks it with ►)
            if self.follow == "pc":
                for i in range(first, last):
                    if PC_MARK in lines[i].text[:6]:
                        y = oy + i * line_h
                        dl.add_rect_filled(ImVec2(win_pos.x, y), ImVec2(clip_r, y + line_h), u32(th.accent, 0.10))
                        dl.add_rect_filled(ImVec2(win_pos.x, y), ImVec2(win_pos.x + 2, y + line_h), u32(th.accent, 0.9))

            # search matches
            if self.search_open and self.search_text:
                self._update_matches()
                for k, (li, c, ln) in enumerate(self.matches):
                    if first <= li < last:
                        y = oy + li * line_h
                        col = u32(th.yellow, 0.55 if k == self.match_idx else 0.22)
                        dl.add_rect_filled(ImVec2(tx + c * char_w, y), ImVec2(tx + (c + ln) * char_w, y + line_h), col)

            # selection
            sel = self.selection()
            if sel:
                (l0, c0), (l1, c1) = sel
                scol = u32(th.accent2, 0.30)
                for i in range(max(first, l0), min(last, l1 + 1)):
                    s = c0 if i == l0 else 0
                    e = c1 if i == l1 else len(lines[i].chars) + 1
                    y = oy + i * line_h
                    dl.add_rect_filled(ImVec2(tx + s * char_w, y), ImVec2(tx + e * char_w, y + line_h), scol)

            # text (context sections are faded while the program runs: they are stale)
            fade = 0.45 if self.vid in SECTION_META and app.is_running() else 1.0
            font_size = app.code_size
            bold_font = app.mono_bold
            styles = _STYLES
            for i in range(first, last):
                y = oy + i * line_h
                for col, text, sid in lines[i].spans:
                    x = tx + col * char_w
                    if x > clip_r:
                        break
                    fg, bg, flags = styles[sid]
                    if flags & INVERSE:
                        fg, bg = (bg if bg != -1 else -2), (fg if fg != -1 else -3)
                    if bg != -1:
                        if bg == -3:
                            bgc = u32(th.fg)
                        else:
                            bgc = th.color(bg, 0.85 * fade)
                        dl.add_rect_filled(ImVec2(x, y), ImVec2(x + len(text) * char_w, y + line_h), bgc)
                    if text.isspace():
                        continue
                    if flags & CTRL:
                        color = u32(th.accent2, 0.85 * fade)
                    elif flags & ECHO:
                        color = u32(th.dim, fade)
                    elif fg == -2:
                        color = u32(th.term_bg)
                    else:
                        color = th.color(fg, (0.55 if flags & DIM else 1.0) * fade)
                    if flags & BOLD and bold_font is not None:
                        dl.add_text(bold_font, font_size, ImVec2(x, y), color, text)
                    else:
                        dl.add_text(ImVec2(x, y), color, text)
                    if flags & UNDER:
                        dl.add_line(ImVec2(x, y + line_h - 1), ImVec2(x + len(text) * char_w, y + line_h - 1), color)

            # breakpoint gutter
            if self.gutter is not None:
                gx = win_pos.x + pad.x - scroll_x + gw * 0.45
                r = min(line_h, char_w * 2) * 0.28
                for i in range(first, last):
                    mark = self.gutter(i, lines[i].text)
                    if mark is None:
                        continue
                    cy = oy + i * line_h + line_h * 0.5
                    if mark == 1:
                        dl.add_circle_filled(ImVec2(gx, cy), r, u32(th.red))
                    elif mark == 2:
                        dl.add_circle(ImVec2(gx, cy), r, u32(th.red, 0.8), 0, 1.5)
                    elif hovered and in_gutter and i == m_line:
                        dl.add_circle_filled(ImVec2(gx, cy), r, u32(th.red, 0.35))

            # hovered address: underline + tooltip
            if hover_tok is not None:
                li, s, e, addr = hover_tok
                y = oy + li * line_h + line_h - 1
                dl.add_line(ImVec2(tx + s * char_w, y), ImVec2(tx + e * char_w, y), u32(th.accent, 0.9), 1.0)
                if self.hover is None or self.hover[0] != addr:
                    self.hover = (addr, time.monotonic())
                elif time.monotonic() - self.hover[1] > 0.30 and not self.dragging and not imgui.is_any_mouse_down():
                    imgui.pop_font()
                    app.addr_tooltip(addr)
                    imgui.push_font(app.mono, app.code_size)
            else:
                self.hover = None

            # mouse interaction
            def cell(round_col: bool = True):
                li = min(max(0, m_line), n - 1)
                c = m_colf + (0.5 if round_col else 0.0)
                return li, max(0, min(int(c), len(lines[li].chars)))

            if hovered and imgui.is_mouse_clicked(0):
                if in_gutter and self.gutter_click is not None and 0 <= m_line < n:
                    if self.gutter(m_line, lines[m_line].text) is not None:
                        self.gutter_click(m_line, lines[m_line].text)
                elif io.key_ctrl and hover_tok is not None:
                    app.open_memory(hover_tok[3])
                else:
                    clicks = imgui.get_mouse_clicked_count(0)
                    li, c = cell()
                    if clicks == 2 and 0 <= m_line < n:
                        text = lines[li].text
                        for m in WORD_RE.finditer(text):
                            if m.start() <= int(m_colf) < m.end():
                                self.anchor, self.cursor = (li, m.start()), (li, m.end())
                                break
                        if self.on_dblclick is not None:
                            self.on_dblclick(li, text)
                    elif clicks >= 3:
                        self.anchor, self.cursor = (li, 0), (li, len(lines[li].chars))
                    elif io.key_shift and self.anchor is not None:
                        self.cursor = (li, c)
                    else:
                        self.anchor = self.cursor = (li, c)
                        self.dragging = True
            if self.dragging:
                if imgui.is_mouse_down(0):
                    self.cursor = cell()
                    if mouse.y < win_pos.y + pad.y:
                        imgui.set_scroll_y(max(0.0, scroll_y - line_h))
                    elif mouse.y > win_pos.y + win_h - pad.y:
                        imgui.set_scroll_y(scroll_y + line_h)
                else:
                    self.dragging = False

            if hovered and imgui.is_mouse_clicked(1):
                li = m_line if 0 <= m_line < n else None
                self.ctx = {
                    "line": li,
                    "text": lines[li].text if li is not None else "",
                    "addr": hover_tok[3] if hover_tok else None,
                }
                imgui.open_popup(f"tvctx{self.vid}")

        # keyboard
        if focused or imgui.is_window_focused(imgui.FocusedFlags_.child_windows):
            if ctrl_pressed(imgui.Key.c):
                self.copy()
            elif ctrl_pressed(imgui.Key.a):
                self.select_all()
            elif ctrl_pressed(imgui.Key.f):
                self.open_search()
            elif imgui.is_key_pressed(imgui.Key.f3):
                self._goto_match(-1 if io.key_shift else 1)
            elif imgui.is_key_pressed(imgui.Key.escape):
                self.anchor = self.cursor = None
            elif imgui.is_key_pressed(imgui.Key.home) and io.key_ctrl:
                imgui.set_scroll_y(0)
            elif imgui.is_key_pressed(imgui.Key.end) and io.key_ctrl:
                imgui.set_scroll_y(imgui.get_scroll_max_y())

        imgui.pop_font()
        if imgui.begin_popup(f"tvctx{self.vid}"):
            self._context_menu()
            imgui.end_popup()
        imgui.push_font(app.mono, app.code_size)

    def _follow(self, lines, line_h: float, win_h: float) -> None:
        if self.follow == "top":
            imgui.set_scroll_y(0)
        elif self.follow == "bottom":
            if self.at_bottom:
                imgui.set_scroll_y(len(lines) * line_h + 100)
        elif self.follow == "pc":
            for i, line in enumerate(lines):
                if PC_MARK in line.text[:6]:
                    imgui.set_scroll_y(max(0.0, i * line_h - win_h * 0.35))
                    return
            imgui.set_scroll_y(0)

    def _context_menu(self) -> None:
        app = self.app
        ctx = self.ctx
        addr = ctx.get("addr")
        if addr is not None:
            imgui.text_colored(v4(app.theme.accent), f"{addr:#x}")
            app.address_menu_items(addr)
            imgui.separator()
        if self.menu is not None:
            if self.menu(ctx):
                imgui.separator()
        if imgui.menu_item_simple(fa.ICON_FA_COPY + "  Copy", "Ctrl+C", False, self.selection() is not None):
            self.copy()
        if imgui.menu_item_simple("     Copy line", "", False, ctx.get("line") is not None):
            self.copy(strip_ansi(ctx.get("text", "")).rstrip())
        if imgui.menu_item_simple("     Copy all"):
            self.copy(self.term.plain())
        if imgui.menu_item_simple("     Select all", "Ctrl+A"):
            self.select_all()
        if imgui.menu_item_simple(fa.ICON_FA_MAGNIFYING_GLASS + "  Find…", "Ctrl+F"):
            self.open_search()


def ansi_inline(app, text: str, wrap: bool = False) -> None:
    """Draw a short ANSI-colored string with regular widgets (for tooltips)."""
    term = app.inline_cache.get(text)
    if term is None:
        term = Term(max_lines=200)
        term.feed(text)
        if len(app.inline_cache) > 512:
            app.inline_cache.clear()
        app.inline_cache[text] = term
    th = app.theme
    for line in term.lines:
        first = True
        for _, chunk, sid in line.spans:
            fg, _bg, flags = _STYLES[sid]
            if not first:
                imgui.same_line(0, 0)
            first = False
            imgui.push_style_color(imgui.Col_.text, th.color(fg, 0.55 if flags & DIM else 1.0))
            imgui.text_unformatted(chunk)
            imgui.pop_style_color()
        if first:
            imgui.text_unformatted("")


# ════════════════════════════════════════════════════════════════════════════
#  Views
# ════════════════════════════════════════════════════════════════════════════
DISASM_ADDR_RE = re.compile(r"^[\sb+*►]{0,8}(0x[0-9a-fA-F]+)\b")
CODE_LINE_RE = re.compile(r"^[\s►]{0,8}(\d+)\b")
FRAME_RE = re.compile(r"^[\s►]*(\d+)\s+0x")
THREAD_RE = re.compile(r"^[\s►]*(\d+)\s")
WATCH_RE = re.compile(r"^\s*(\d+):")
REG_WORD_RE = re.compile(r"^[A-Z][A-Z0-9]{1,6}$")


class CmdView:
    """A dockable window showing the colored output of any gdb/pwndbg command."""

    _uid = 0

    def __init__(self, app, cmd: str, auto: bool = True, title: str | None = None) -> None:
        CmdView._uid += 1
        self.uid = CmdView._uid
        self.app = app
        self.cmd = cmd
        self.auto = auto
        self.term = Term(max_lines=50000)
        self.view = TextView(app, self.term, f"cv{self.uid}", follow="none",
                             empty_hint="Press Enter or Run to execute the command.")
        self.label = f"{fa.ICON_FA_TERMINAL} {title or cmd}##cv{self.uid}"
        self.status = ""
        self.busy = False
        self.ran_gen = -1
        self.last_seen = 0.0
        self.stale = False
        self.restored = False

    def refresh(self) -> None:
        """Re-run now if the view is on screen, otherwise when it next is."""
        if time.monotonic() - self.last_seen < 0.5:
            self.run()
        else:
            self.stale = True

    def run(self) -> None:
        app = self.app
        if not app.rpc or not self.cmd.strip():
            return
        self.busy = True
        self.stale = False
        t0 = time.monotonic()
        self.ran_gen = app.dirty_gen

        def done(out):
            self.busy = False
            self.term.set_text(out or "(no output)\n")
            self.status = f"{(time.monotonic() - t0) * 1000:.0f} ms"

        def fail(err):
            self.busy = False
            self.term.set_text(f"\x1b[31m{err}\x1b[0m\n")
            self.status = "error"

        app.rpc.request("exec", done, fail, cmd=self.cmd)

    def gui(self) -> None:
        app = self.app
        imgui.set_next_item_width(-imgui.get_frame_height() * 6.5)
        entered, self.cmd = imgui.input_text(f"##cmd{self.uid}", self.cmd, imgui.InputTextFlags_.enter_returns_true)
        if entered:
            self.run()
        imgui.same_line()
        if imgui.button(fa.ICON_FA_PLAY + f"##run{self.uid}"):
            self.run()
        imgui.set_item_tooltip("Run now")
        imgui.same_line()
        _, self.auto = imgui.checkbox(f"Auto##a{self.uid}", self.auto)
        imgui.set_item_tooltip("Re-run automatically every time the program stops")
        imgui.same_line()
        imgui.text_disabled("…" if self.busy else self.status)
        self.view.render()
        self.last_seen = time.monotonic()
        if (self.ran_gen == -1 or (self.stale and app.is_stopped())) and app.connected() and not self.busy:
            self.run()


class MemoryView:
    """Hex / qword memory viewer with region coloring, change highlighting,
    in-place editing and a data inspector."""

    def __init__(self, app) -> None:
        self.app = app
        self.expr = "$sp"
        self.follow = ""
        self.base: int | None = None
        self.bpr = 16
        self.mode = "bytes"  # bytes | qwords
        self.data = b""
        self.bad: list = []
        self.data_base = None
        self.prev: tuple[int, bytes] | None = None
        self.sel: int | None = None
        self.nibble: int | None = None
        self.rows = 16
        self.req_key = None
        self.error = ""
        self.focus_input = False
        self.fetched_gen = -1
        self.history: list[int] = []

    # -- data ----------------------------------------------------------
    def goto(self, addr: int, push: bool = True) -> None:
        if push and self.sel is not None:
            self.history.append(self.sel)
            self.history = self.history[-64:]
        self.sel = addr
        self.base = (addr & ~(self.bpr - 1)) - self.bpr * min(4, self.rows // 4)
        self.base = max(0, self.base)
        self.nibble = None
        self.fetch()

    def goto_expr(self, expr: str) -> None:
        expr = expr.strip()
        if not expr or not self.app.rpc:
            return
        self.app.rpc.request("eval", lambda v: self.goto(v), self.set_error, expr=expr)

    def set_error(self, err: str) -> None:
        self.error = err

    def fetch(self) -> None:
        app = self.app
        if self.base is None or not app.rpc or not app.is_stopped():
            return
        size = (self.rows + 2) * self.bpr
        key = (self.base, size, app.dirty_gen)
        if key == self.req_key:
            return
        self.req_key = key

        def done(res, base=self.base, k=key):
            if self.req_key != k:
                return
            self.data = bytes.fromhex(res["hex"])
            self.bad = res["bad"]
            self.data_base = base
            self.error = ""

        app.rpc.request("read", done, self.set_error, addr=self.base, size=size)

    def on_stop(self) -> None:
        if self.data_base is not None:
            self.prev = (self.data_base, self.data)
        self.req_key = None
        if self.follow:
            self.app.rpc.request("eval", lambda v: self.goto(v, push=False), self.set_error, expr=self.follow)
        elif self.base is None:
            self.goto_expr(self.expr)
        else:
            self.fetch()

    def byte_at(self, addr: int):
        if self.data_base is None:
            return None
        off = addr - self.data_base
        if not 0 <= off < len(self.data):
            return None
        for s, e in self.bad:
            if s <= off < e:
                return None
        return self.data[off]

    def changed(self, addr: int) -> bool:
        if not self.prev:
            return False
        pb, pd = self.prev
        off = addr - pb
        if not 0 <= off < len(pd):
            return False
        cur = self.byte_at(addr)
        return cur is not None and cur != pd[off]

    def read_int(self, addr: int, size: int):
        bs = [self.byte_at(addr + i) for i in range(size)]
        if any(b is None for b in bs):
            return None
        return int.from_bytes(bytes(bs), "little")

    def write_byte(self, addr: int, value: int) -> None:
        if self.data_base is not None:
            off = addr - self.data_base
            if 0 <= off < len(self.data):
                self.data = self.data[:off] + bytes([value]) + self.data[off + 1:]
        self.app.rpc.request("write", None, self.app.error_toast, addr=addr, hex=f"{value:02x}")

    # -- gui -----------------------------------------------------------
    def gui(self) -> None:
        app = self.app
        th = app.theme
        if self.base is None and app.is_stopped() and self.fetched_gen == -1:
            self.fetched_gen = 0
            self.goto_expr(self.expr)

        # toolbar
        if imgui.button(fa.ICON_FA_ARROW_LEFT + "##mback") and self.history:
            self.goto(self.history.pop(), push=False)
        imgui.set_item_tooltip("Back")
        imgui.same_line()
        imgui.set_next_item_width(max(120.0, imgui.get_content_region_avail().x * 0.35))
        if self.focus_input:
            imgui.set_keyboard_focus_here()
            self.focus_input = False
        entered, self.expr = imgui.input_text_with_hint(
            "##memexpr", "address / expression ($sp, main, 0x4011a0, $rdi+8)", self.expr,
            imgui.InputTextFlags_.enter_returns_true,
        )
        if entered:
            self.goto_expr(self.expr)
        imgui.same_line()
        if imgui.button("Go##mgo"):
            self.goto_expr(self.expr)
        imgui.same_line()
        imgui.set_next_item_width(combo_width("follow $rsi"))
        if imgui.begin_combo("##follow", f"follow {self.follow}" if self.follow else "no follow"):
            for f in ("", "$sp", "$pc", "$bp", "$rdi", "$rsi", "$rax"):
                if imgui.selectable(f or "no follow", self.follow == f)[0]:
                    self.follow = f
                    if f:
                        self.goto_expr(f)
            imgui.end_combo()
        imgui.set_item_tooltip("Re-evaluate this expression every time the program stops")
        imgui.same_line()
        imgui.set_next_item_width(combo_width("qwords"))
        if imgui.begin_combo("##mmode", self.mode):
            for m in ("bytes", "qwords"):
                if imgui.selectable(m, self.mode == m)[0]:
                    self.mode = m
            imgui.end_combo()
        imgui.same_line()
        imgui.set_next_item_width(combo_width("32 / row"))
        if imgui.begin_combo("##mbpr", f"{self.bpr} / row"):
            for b in (8, 16, 32):
                if imgui.selectable(f"{b} / row", self.bpr == b)[0]:
                    self.bpr = b
                    if self.sel is not None:
                        self.goto(self.sel, push=False)
            imgui.end_combo()

        if self.base is not None:
            page = app.page_for(self.sel if self.sel is not None else self.base)
            imgui.same_line()
            if page:
                imgui.text_colored(v4(th.kind_color(page[5])), f"{page[2]} {os.path.basename(page[4]) or page[5]}")
                imgui.set_item_tooltip(f"{page[0]:#x}-{page[1]:#x}  {page[4]}")
        if self.error:
            imgui.text_colored(v4(th.red), self.error)

        inspector_h = imgui.get_text_line_height_with_spacing() * 2 + 8
        avail = imgui.get_content_region_avail()
        imgui.push_style_color(imgui.Col_.child_bg, v4(th.term_bg))
        imgui.push_font(app.mono, app.code_size)
        app.measure()
        imgui.begin_child("##hex", ImVec2(avail.x, max(40.0, avail.y - inspector_h)),
                          imgui.ChildFlags_.always_use_window_padding,
                          imgui.WindowFlags_.no_scrollbar | imgui.WindowFlags_.no_nav_inputs)
        try:
            self._grid(app, th)
        finally:
            imgui.end_child()
            imgui.pop_font()
            imgui.pop_style_color()
        self._inspector(app, th)

    def _grid(self, app, th) -> None:
        cw = app.char_w
        lh = app.line_h
        pos = imgui.get_cursor_screen_pos()
        win_h = imgui.get_content_region_avail().y
        rows = max(1, int(win_h // lh))
        if rows != self.rows:
            self.rows = rows
            self.fetch()
        if self.base is None:
            imgui.text_disabled("Start the program, then enter an address or expression.")
            return
        hovered = imgui.is_window_hovered()
        io = imgui.get_io()
        if hovered and io.mouse_wheel:
            self.base = max(0, self.base - int(io.mouse_wheel * 3) * self.bpr)
            self.fetch()
        dl = imgui.get_window_draw_list()
        bpr = self.bpr
        digits = max(6, len(f"{self.base + rows * bpr:x}"))
        hex_x = pos.x + (digits + 2) * cw
        if self.mode == "bytes":
            cell = 3
            ascii_x = hex_x + (bpr * cell + bpr // 8) * cw + cw
        else:
            cell = 0
            ascii_x = hex_x + (bpr // 8) * 20 * cw + cw
        mouse = imgui.get_mouse_pos()
        hover_addr = None
        hover_qword = None
        dim = u32(th.dim)
        fg = u32(th.fg)
        for r in range(rows):
            addr = self.base + r * bpr
            y = pos.y + r * lh
            page = app.page_for(addr)
            acol = u32(th.kind_color(page[5])) if page else dim
            dl.add_text(ImVec2(pos.x, y), acol, f"{addr:0{digits}x}")
            if self.mode == "bytes":
                for i in range(bpr):
                    a = addr + i
                    x = hex_x + (i * cell + i // 8) * cw
                    b = self.byte_at(a)
                    if a == self.sel:
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + 2 * cw + 2, y + lh), u32(th.accent, 0.45), 3)
                    elif self.changed(a):
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + 2 * cw + 2, y + lh), u32(th.red, 0.28), 3)
                    if b is None:
                        dl.add_text(ImVec2(x, y), dim, "??")
                    else:
                        if a == self.sel and self.nibble is not None:
                            txt = f"{self.nibble:x}_"
                        else:
                            txt = f"{b:02x}"
                        c = dim if b == 0 else (fg if 0x20 <= b < 0x7F else (u32(th.yellow) if b == 0xFF else u32(th.cyan)))
                        dl.add_text(ImVec2(x, y), c, txt)
                    if x - cw * 0.5 <= mouse.x < x + cw * 2.5 and y <= mouse.y < y + lh:
                        hover_addr = a
            else:
                for q in range(bpr // 8):
                    a = addr + q * 8
                    x = hex_x + q * 20 * cw
                    v = self.read_int(a, 8)
                    sel = self.sel is not None and a <= self.sel < a + 8
                    if sel:
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + 18 * cw + 2, y + lh), u32(th.accent, 0.35), 3)
                    elif any(self.changed(a + k) for k in range(8)):
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + 18 * cw + 2, y + lh), u32(th.red, 0.28), 3)
                    if v is None:
                        dl.add_text(ImVec2(x, y), dim, "0x" + "?" * 16)
                    else:
                        vp = app.page_for(v)
                        c = u32(th.kind_color(vp[5])) if vp else (dim if v == 0 else fg)
                        dl.add_text(ImVec2(x, y), c, f"{v:#018x}")
                    if x <= mouse.x < x + 18 * cw and y <= mouse.y < y + lh:
                        hover_addr = a
                        hover_qword = v
            # ascii column
            chars = []
            for i in range(bpr):
                b = self.byte_at(addr + i)
                chars.append("·" if b is None or not 0x20 <= b < 0x7F else chr(b))
            dl.add_text(ImVec2(ascii_x, y), dim, "".join(chars))
            for i in range(bpr):
                if addr + i == self.sel:
                    dl.add_rect_filled(ImVec2(ascii_x + i * cw, y), ImVec2(ascii_x + (i + 1) * cw, y + lh), u32(th.accent, 0.35))
            if ascii_x <= mouse.x < ascii_x + bpr * cw and y <= mouse.y < y + lh:
                hover_addr = addr + int((mouse.x - ascii_x) // cw)

        imgui.dummy(ImVec2(ascii_x - pos.x + bpr * cw, rows * lh))

        if hovered and hover_addr is not None:
            if imgui.is_mouse_clicked(0):
                self.sel = hover_addr
                self.nibble = None
                if imgui.get_mouse_clicked_count(0) == 2 and hover_qword is not None and app.page_for(hover_qword):
                    self.goto(hover_qword)
            if imgui.is_mouse_clicked(1):
                self.sel = hover_addr
                imgui.open_popup("##memctx")
            if hover_qword is not None and app.page_for(hover_qword):
                app.addr_tooltip(hover_qword)

        if imgui.is_window_focused() and self.sel is not None:
            self._keys(io)
        imgui.pop_font()
        if imgui.begin_popup("##memctx"):
            a = self.sel
            imgui.text_colored(v4(th.accent), f"{a:#x}")
            q = self.read_int(a & ~7 if self.mode == "qwords" else a, 8)
            if q is not None and app.page_for(q) and imgui.menu_item_simple(f"Follow pointer {q:#x}"):
                self.goto(q)
            app.address_menu_items(a)
            imgui.separator()
            row = a & ~(self.bpr - 1)
            row_bytes = [self.byte_at(row + i) for i in range(self.bpr)]
            if imgui.menu_item_simple("Copy row as hex") and None not in row_bytes:
                imgui.set_clipboard_text(bytes(row_bytes).hex())
            if imgui.menu_item_simple("Copy row as Python bytes") and None not in row_bytes:
                imgui.set_clipboard_text(repr(bytes(row_bytes)))
            imgui.end_popup()
        imgui.push_font(app.mono, app.code_size)

    def _keys(self, io) -> None:
        step = 8 if self.mode == "qwords" else 1
        moves = {
            imgui.Key.left_arrow: -step, imgui.Key.right_arrow: step,
            imgui.Key.up_arrow: -self.bpr, imgui.Key.down_arrow: self.bpr,
            imgui.Key.page_up: -self.bpr * self.rows, imgui.Key.page_down: self.bpr * self.rows,
        }
        for key, delta in moves.items():
            if imgui.is_key_pressed(key):
                self.sel = max(0, self.sel + delta)
                self.nibble = None
                top, bottom = self.base, self.base + self.rows * self.bpr
                if not top <= self.sel < bottom:
                    self.base = max(0, self.base + (delta if abs(delta) >= self.bpr else (self.bpr if delta > 0 else -self.bpr)))
                    self.fetch()
        if io.key_ctrl or self.mode != "bytes":
            return
        for k in range(16):
            key = getattr(imgui.Key, f"_{k}") if k < 10 else getattr(imgui.Key, "abcdef"[k - 10])
            if imgui.is_key_pressed(key, False):
                if self.nibble is None:
                    self.nibble = k
                else:
                    self.write_byte(self.sel, (self.nibble << 4) | k)
                    self.nibble = None
                    self.sel += 1
        if imgui.is_key_pressed(imgui.Key.escape):
            self.nibble = None

    def _inspector(self, app, th) -> None:
        a = self.sel
        if a is None:
            imgui.text_disabled("Click a byte to inspect it · type hex digits to edit · wheel to scroll")
            return
        vals = []
        for size, name in ((1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")):
            v = self.read_int(a, size)
            vals.append(f"{name} {v:#x}" if v is not None else f"{name} ?")
        v8 = self.read_int(a, 8)
        if v8 is not None:
            vals.append(f"i64 {v8 - (1 << 64) if v8 >> 63 else v8}")
            vals.append(f"f64 {struct.unpack('<d', v8.to_bytes(8, 'little'))[0]:.6g}")
        imgui.push_font(app.mono, app.code_size)
        imgui.text_colored(v4(th.accent), f"{a:#x}")
        imgui.same_line()
        imgui.text_unformatted("  ".join(vals))
        if v8 is not None and app.page_for(v8):
            info = app.addr_cache.get(v8)
            if info is None:
                app.request_addrinfo(v8)
            elif info.get("chain"):
                imgui.text_disabled("→")
                imgui.same_line()
                ansi_inline(app, info["chain"])
        imgui.pop_font()


# ════════════════════════════════════════════════════════════════════════════
#  Application
# ════════════════════════════════════════════════════════════════════════════
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


SECTION_META = {
    # name: (label, icon attr, follow, visible by default, dock space)
    "regs": ("Registers", "MICROCHIP", "top", True, "Right"),
    "disasm": ("Disassembly", "CODE", "pc", True, "MainDockSpace"),
    "code": ("Source", "FILE_CODE", "pc", True, "MainDockSpace"),
    "stack": ("Stack", "LAYER_GROUP", "top", True, "RightMid"),
    "backtrace": ("Backtrace", "SHOE_PRINTS", "top", True, "RightBottom"),
    "args": ("Arguments", "LIST_OL", "top", False, "RightMid"),
    "expressions": ("Watch", "EYE", "top", True, "RightMid"),
    "threads": ("Threads", "BARS_STAGGERED", "top", True, "RightBottom"),
    "heap_tracker": ("Heap Tracker", "CUBES", "top", False, "RightBottom"),
    "last_signal": ("Last Signal", "BOLT", "top", False, "RightBottom"),
}
AUTOFIT_HEIGHT = {"disasm", "stack", "threads", "code", "backtrace"}

TOOL_PRESETS = [
    ("Heap", [("heap", "heap"), ("bins", "bins"), ("vis_heap_chunks", "vis-heap-chunks"),
              ("arena", "arena"), ("arenas", "arenas"), ("tcachebins", "tcachebins"),
              ("fastbins", "fastbins"), ("unsortedbin", "unsortedbin"), ("smallbins", "smallbins"),
              ("largebins", "largebins"), ("top_chunk", "top-chunk"), ("mp", "mp")]),
    ("Memory", [("telescope $sp 48", "telescope"), ("hexdump $sp 256", "hexdump"),
                ("probeleak $sp 0x200", "probeleak"), ("leakfind $sp", "leakfind"),
                ("stack 40", "stack"), ("retaddr", "retaddr"), ("canary", "canary")]),
    ("Binary", [("checksec", "checksec"), ("elfsections", "elfsections"), ("got", "got"),
                ("plt", "plt"), ("piebase", "piebase"), ("libcinfo", "libcinfo"),
                ("linkmap", "linkmap"), ("aslr", "aslr")]),
    ("Process", [("procinfo", "procinfo"), ("auxv", "auxv"), ("envp", "envp"), ("argv", "argv"),
                 ("tls", "tls"), ("errno", "errno"), ("info sharedlibrary", None),
                 ("info signals", None)]),
    ("Code", [("nearpc 40", "nearpc"), ("emulate 30", "emulate"), ("info functions", None),
              ("rop --grep 'pop rdi'", "rop")]),
]


class App:
    def __init__(self, cfg: LaunchConfig) -> None:
        self.cfg = cfg
        self.settings = Settings()
        st = self.settings
        if cfg.theme:
            st["theme"] = cfg.theme
        if cfg.font:
            st["font"] = cfg.font
        if cfg.font_size:
            st["code_size"] = st["ui_size"] = cfg.font_size
        self.theme = THEMES.get(st["theme"], THEMES["Pwn Night"])
        self.ui_size = float(st["ui_size"])
        self.code_size = float(st["code_size"])
        self.char_w = 8.0
        self.line_h = 18.0
        self.mono = None
        self.mono_bold = None
        self.ui_font = None
        self.fonts = find_mono_fonts()

        self.console_term = Term(max_lines=20000)
        self.console = Pty(self.console_term)
        self.io_term = Term(max_lines=20000, show_ctrl=True)
        self.io = None if cfg.no_io else Pty(self.io_term, raw=st["io_raw"], keep_bytes=1 << 20)
        self.io_hex_term = Term(max_lines=100000)
        self.io_hex_version = -1

        self.proc = None
        self.rpc: Rpc | None = None
        self.info: dict = {}
        self.state: dict = {}
        self.bps: list = []
        self.bp_addrs: dict[int, bool] = {}
        self.bp_lines: dict[tuple[str, int], bool] = {}
        self.vmmap: list = []
        self.vmmap_starts: list[int] = []
        self.legend = ""
        self.checksec: list[tuple[str, str]] = []
        self.dirty_gen = 0
        self.refreshed_gen = -1
        self.addr_cache: dict[int, dict] = {}
        self.addr_pending: set[int] = set()
        self.inline_cache: dict[str, Term] = {}
        self.commands: list | None = None
        self.config: list | None = None
        self.config_edit: dict[str, object] = {}
        self.toasts: list[dict] = []
        self.layout_sent = None
        self.layout_pending = (None, 0.0)
        self.exiting = False

        self.sections: dict[str, dict] = {}
        for name in SECTIONS:
            label, icon, follow, _vis, _dock = SECTION_META[name]
            term = Term(max_lines=5000)
            view = TextView(self, term, name, follow=follow, empty_hint=self._section_hint(name))
            self.sections[name] = {"term": term, "view": view, "label": f"{getattr(fa, 'ICON_FA_' + icon)} {label}"}
        self._setup_section_hooks()
        self.console_view = TextView(self, self.console_term, "console", follow="bottom")
        self.io_view = TextView(self, self.io_term, "io", follow="bottom",
                                empty_hint="The debugged program's stdin/stdout live here once it runs.")
        self.io_hex_view = TextView(self, self.io_hex_term, "iohex", follow="bottom")
        self.memory = MemoryView(self)
        self.cmd_views: list[CmdView] = []
        self.views_to_add: list[CmdView] = []

        # console
        self.console_input = ""
        self.history: list[str] = list(st["console_history"])
        self.history_pos = -1
        self.console_replace: str | None = None
        self.completions: list[str] = []
        self.focus_console = True
        # program io
        self.io_input = ""
        self.io_mode = "text"
        self.io_view_mode = "terminal"
        # misc tool state
        self.goto_input = ""
        self.bp_input = ""
        self.watch_input = ""
        self.vmmap_filter = ""
        self.cmd_filter = ""
        self.cmd_selected = None
        self.cfg_filter = ""
        self.cyclic_len = 200
        self.cyclic_n = 8
        self.cyclic_value = ""
        self.cyclic_result = ""
        self.palette_open = False
        self.palette_query = ""
        self.palette_sel = 0
        self.modal: dict | None = None
        self.args_input = self.settings.binary(cfg.binary).get("args", "")
        self.show_style_editor = False
        self.show_metrics = False

    # ── helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _section_hint(name: str) -> str:
        if name == "expressions":
            return "No watch expressions. Add one above (e.g. $rsp+8, *(long*)$rdi, or a command like `x/8gx $sp`)."
        if name == "code":
            return "No source available for the current location."
        return "Waiting for the program to stop…"

    def connected(self) -> bool:
        return self.rpc is not None and self.rpc.connected

    def is_alive(self) -> bool:
        return bool(self.state.get("alive"))

    def is_stopped(self) -> bool:
        return self.is_alive() and not self.state.get("running")

    def is_running(self) -> bool:
        return self.is_alive() and bool(self.state.get("running"))

    def toast(self, text: str, kind: str = "info", ttl: float = 3.5) -> None:
        self.toasts.append({"text": text, "kind": kind, "t0": time.monotonic(), "ttl": ttl})
        self.toasts = self.toasts[-6:]

    def error_toast(self, err: str) -> None:
        self.toast(err, "error", 5.0)

    def send_console(self, cmd: str) -> None:
        self.console.write((cmd + "\n").encode())

    def exec(self, cmd: str, refresh: bool = True, cb=None, quiet: bool = False) -> None:
        if not self.rpc:
            return

        def done(out):
            if out and out.strip() and not quiet:
                with self.console_term.lock:
                    if self.console_term.col:
                        self.console_term.feed("\n")
                    self.console_term.feed(out if out.endswith("\n") else out + "\n")
            if cb:
                cb(out)

        self.rpc.request("exec", done, self.error_toast, cmd=cmd, refresh=refresh)

    def interrupt(self) -> None:
        import signal

        if self.proc and self.proc.poll() is None:
            os.kill(self.proc.pid, signal.SIGINT)

    def page_for(self, addr: int | None):
        if addr is None or not self.vmmap:
            return None
        import bisect

        i = bisect.bisect_right(self.vmmap_starts, addr) - 1
        if i >= 0 and addr < self.vmmap[i][1]:
            return self.vmmap[i]
        return None

    def request_addrinfo(self, addr: int) -> None:
        if addr in self.addr_pending or addr in self.addr_cache or not self.is_stopped():
            return
        self.addr_pending.add(addr)

        def done(res, gen=self.dirty_gen):
            self.addr_pending.discard(addr)
            if gen == self.dirty_gen:
                for k, v in res.items():
                    self.addr_cache[int(k)] = v

        self.rpc.request("addrinfo", done, lambda e: self.addr_pending.discard(addr), addrs=[addr])

    def addr_tooltip(self, addr: int) -> None:
        th = self.theme
        info = self.addr_cache.get(addr)
        if info is None:
            self.request_addrinfo(addr)
        if not imgui.begin_tooltip():
            return
        imgui.push_font(self.mono, self.code_size)
        imgui.text_colored(v4(th.accent), f"{addr:#x}")
        if info is not None and info.get("sym"):
            imgui.same_line()
            imgui.text_unformatted(f"<{info['sym']}>")
        page = (info or {}).get("page") or self.page_for(addr)
        if page:
            imgui.text_colored(v4(th.kind_color(page[5])), f"{page[5]:<6} {page[2]}")
            imgui.same_line()
            imgui.text_disabled(f"{page[4] or ''}  +{addr - page[0]:#x}")
        elif info is not None:
            imgui.text_disabled("unmapped")
        if info is None:
            imgui.text_disabled("…")
        elif info.get("chain"):
            ansi_inline(self, info["chain"])
        imgui.pop_font()
        imgui.text_disabled("Ctrl+click: view memory · right-click: more")
        imgui.end_tooltip()

    def address_menu_items(self, addr: int) -> None:
        if imgui.menu_item_simple(fa.ICON_FA_MEMORY + "  View memory", "Ctrl+click"):
            self.open_memory(addr)
        if imgui.menu_item_simple(fa.ICON_FA_LAYER_GROUP + "  Telescope"):
            self.open_cmd_view(f"telescope {addr:#x} 32")
        if imgui.menu_item_simple(fa.ICON_FA_CODE + "  Disassemble"):
            self.open_cmd_view(f"nearpc {addr:#x} 30")
        if imgui.menu_item_simple(fa.ICON_FA_CIRCLE_INFO + "  xinfo"):
            self.open_cmd_view(f"xinfo {addr:#x}")
        if imgui.menu_item_simple(fa.ICON_FA_MAGNIFYING_GLASS + "  Find pointers to it"):
            self.open_cmd_view(f"search --pointer {addr:#x}", auto=False)
        if imgui.menu_item_simple(fa.ICON_FA_CIRCLE_DOT + "  Toggle breakpoint"):
            self.rpc.request("bp_toggle", None, self.error_toast, addr=addr)
        if imgui.menu_item_simple(fa.ICON_FA_EYE + "  Watch (telescope) in Watch"):
            self.exec(f'contextwatch execute "telescope {addr:#x} 4"')
        if imgui.menu_item_simple(fa.ICON_FA_BUG + "  Hardware watchpoint (write)"):
            self.exec(f"watch *(long *){addr:#x}", refresh=False)
        if imgui.menu_item_simple(fa.ICON_FA_COPY + "  Copy address"):
            imgui.set_clipboard_text(f"{addr:#x}")

    def open_memory(self, addr: int) -> None:
        self.memory.goto(addr)
        self.memory.expr = f"{addr:#x}"
        self.focus_window(f"{fa.ICON_FA_MEMORY} Memory")

    def focus_window(self, label: str) -> None:
        dw = hello_imgui.get_runner_params().docking_params.dockable_window_of_name(label)
        if dw is not None:
            dw.is_visible = True
            dw.focus_window_at_next_frame = True

    def open_cmd_view(self, cmd: str, auto: bool = True, title: str | None = None, restored: bool = False) -> None:
        for v in self.cmd_views:
            if v.cmd == cmd:
                self.focus_window(v.label)
                v.run()
                return
        view = CmdView(self, cmd, auto=auto, title=title)
        view.restored = restored
        self.cmd_views.append(view)
        self.views_to_add.append(view)

    def pwndbg_has(self, name: str | None) -> bool:
        if name is None or self.commands is None:
            return True
        return any(c["name"] == name or name in c["aliases"] for c in self.commands)

    # ── section-specific behavior ───────────────────────────────────────
    def _setup_section_hooks(self) -> None:
        dis = self.sections["disasm"]["view"]
        dis.gutter = self._disasm_gutter
        dis.gutter_click = lambda i, t: self._toggle_disasm_bp(t)
        dis.menu = self._disasm_menu
        code = self.sections["code"]["view"]
        code.gutter = self._code_gutter
        code.gutter_click = lambda i, t: self._toggle_code_bp(t)
        code.menu = self._code_menu
        bt = self.sections["backtrace"]["view"]
        bt.on_dblclick = lambda i, t: self._select_frame(t)
        bt.menu = self._backtrace_menu
        thr = self.sections["threads"]["view"]
        thr.on_dblclick = lambda i, t: self._select_thread(t)
        self.sections["regs"]["view"].menu = self._regs_menu
        self.sections["expressions"]["view"].menu = self._watch_menu

    def _disasm_addr(self, text: str):
        m = DISASM_ADDR_RE.match(text)
        return int(m.group(1), 16) if m else None

    def _disasm_gutter(self, i: int, text: str):
        a = self._disasm_addr(text)
        if a is None:
            return None
        en = self.bp_addrs.get(a)
        return 0 if en is None else (1 if en else 2)

    def _toggle_disasm_bp(self, text: str) -> None:
        a = self._disasm_addr(text)
        if a is not None:
            self.rpc.request("bp_toggle", None, self.error_toast, addr=a)

    def _disasm_menu(self, ctx) -> bool:
        a = self._disasm_addr(ctx.get("text", ""))
        if a is None:
            return False
        imgui.text_disabled(f"instruction {a:#x}")
        if imgui.menu_item_simple(fa.ICON_FA_CIRCLE_DOT + "  Toggle breakpoint"):
            self.rpc.request("bp_toggle", None, self.error_toast, addr=a)
        running = not self.is_stopped()
        if imgui.menu_item_simple(fa.ICON_FA_FORWARD + "  Run to here", "", False, not running):
            self.send_console(f"advance *{a:#x}")
        if imgui.menu_item_simple(fa.ICON_FA_LOCATION_ARROW + "  Set PC here", "", False, not running):
            self.exec(f"set $pc = {a:#x}")
        if imgui.menu_item_simple(fa.ICON_FA_MEMORY + "  View bytes"):
            self.open_memory(a)
        return True

    def _code_line(self, text: str):
        m = CODE_LINE_RE.match(text)
        return int(m.group(1)) if m else None

    def _code_gutter(self, i: int, text: str):
        n = self._code_line(text)
        src = self.state.get("src")
        if n is None or not src:
            return None
        en = self.bp_lines.get((os.path.basename(src), n))
        return 0 if en is None else (1 if en else 2)

    def _toggle_code_bp(self, text: str) -> None:
        n = self._code_line(text)
        src = self.state.get("src")
        if n is not None and src:
            self.rpc.request("bp_toggle", None, self.error_toast, file=src, line=n)

    def _code_menu(self, ctx) -> bool:
        n = self._code_line(ctx.get("text", ""))
        src = self.state.get("src")
        if n is None or not src:
            return False
        imgui.text_disabled(f"{os.path.basename(src)}:{n}")
        if imgui.menu_item_simple(fa.ICON_FA_CIRCLE_DOT + "  Toggle breakpoint"):
            self.rpc.request("bp_toggle", None, self.error_toast, file=src, line=n)
        if imgui.menu_item_simple(fa.ICON_FA_FORWARD + "  Run to here", "", False, self.is_stopped()):
            self.send_console(f"advance {src}:{n}")
        return True

    def _select_frame(self, text: str) -> None:
        m = FRAME_RE.match(text)
        if m and self.is_stopped():
            self.exec(f"frame {m.group(1)}", quiet=True)

    def _select_thread(self, text: str) -> None:
        m = THREAD_RE.match(text)
        if m and self.is_stopped():
            self.exec(f"thread {m.group(1)}", quiet=True)

    def _backtrace_menu(self, ctx) -> bool:
        m = FRAME_RE.match(ctx.get("text", ""))
        if not m:
            return False
        if imgui.menu_item_simple(f"{fa.ICON_FA_SHOE_PRINTS}  Select frame #{m.group(1)}", "double-click"):
            self._select_frame(ctx["text"])
        if imgui.menu_item_simple(f"{fa.ICON_FA_ARROW_UP_FROM_BRACKET}  Finish up to frame #{m.group(1)}", "", False,
                                  self.is_stopped() and m.group(1) != "0"):
            self.exec(f"frame {int(m.group(1)) - 1}", refresh=False, quiet=True, cb=lambda _o: self.send_console("finish"))
        return True

    def _regs_menu(self, ctx) -> bool:
        text = strip_ansi(ctx.get("text", ""))
        words = re.findall(r"[A-Za-z][A-Za-z0-9]*", text)
        reg = next((w for w in words if REG_WORD_RE.match(w)), None)
        if not reg:
            return False
        if imgui.menu_item_simple(f"{fa.ICON_FA_PEN}  Set ${reg.lower()}…", "", False, self.is_stopped()):
            self.modal = {"kind": "setreg", "reg": reg.lower(), "value": "", "focus": True}
        return True

    def _watch_menu(self, ctx) -> bool:
        m = WATCH_RE.match(strip_ansi(ctx.get("text", "")))
        if not m:
            return False
        if imgui.menu_item_simple(f"{fa.ICON_FA_TRASH}  Remove watch #{m.group(1)}"):
            self.exec(f"contextunwatch {m.group(1)}")
        return True

    # ── event handling ──────────────────────────────────────────────────
    def process_inbox(self) -> None:
        if not self.rpc:
            return
        for _ in range(500):
            try:
                msg = self.rpc.inbox.get_nowait()
            except Exception:
                break
            if "id" in msg:
                self.rpc.resolve(msg)
                continue
            ev = msg.get("ev")
            handler = getattr(self, "on_" + str(ev), None)
            if handler is not None:
                try:
                    handler(msg)
                except Exception as e:  # never let one bad message kill the UI
                    self.toast(f"internal error in {ev}: {e}", "error")

    def on_hello(self, msg) -> None:
        self.info = msg.get("info", {})
        if not self.info.get("pwndbg"):
            self.toast("pwndbg was not loaded: context panes are disabled. Use --pwndbg PATH.", "warn", 12)
        self.rpc.request("state", lambda st: self.state.update(st))
        self.rpc.request("commands", self._set_commands)
        self.refresh_checksec()
        self.restore_breakpoints()
        self.layout_sent = None

    def _set_commands(self, cmds) -> None:
        self.commands = cmds

    def on_section(self, msg) -> None:
        name = msg.get("name")
        if name == "legend":
            self.legend = msg.get("text", "").strip()
            return
        sec = self.sections.get(name)
        if sec is not None:
            sec["term"].set_text(msg.get("text", ""))

    def on_state(self, msg) -> None:
        was_alive = self.is_alive()
        self.state = msg.get("state", {})
        if self.is_alive() and not was_alive:
            self.refresh_checksec()
        if self.is_stopped() and self.refreshed_gen != self.dirty_gen:
            self.refreshed_gen = self.dirty_gen
            self.addr_cache.clear()
            self.rpc.request("vmmap", self._set_vmmap)
            self.memory.on_stop()
            for v in self.cmd_views:
                if v.auto and v.ran_gen != -1:
                    v.refresh()

    def on_stop(self, msg) -> None:
        self.dirty_gen += 1
        self.state["running"] = False
        reason = msg.get("reason")
        if reason == "breakpoint":
            nums = ", ".join(str(n) for n in msg.get("bps", []))
            self.toast(f"{fa.ICON_FA_CIRCLE_DOT}  Breakpoint {nums} hit", "info", 2.5)
        elif reason == "signal":
            sig = msg.get("signal", "")
            if sig == "SIGINT":
                self.toast(f"{fa.ICON_FA_PAUSE}  Interrupted", "info", 2.0)
            elif sig != "SIGTRAP":
                self.toast(f"{fa.ICON_FA_BOLT}  Program received {sig}", "error", 8.0)

    def on_cont(self, msg) -> None:
        self.state["alive"] = True
        self.state["running"] = True

    def on_exited(self, msg) -> None:
        code = msg.get("code")
        self.state = {"alive": False}
        self.dirty_gen += 1
        if code is None:
            self.toast(f"{fa.ICON_FA_FLAG_CHECKERED}  Program exited", "warn", 5.0)
        else:
            self.toast(f"{fa.ICON_FA_FLAG_CHECKERED}  Program exited with code {code}",
                       "ok" if code == 0 else "warn", 5.0)

    def on_objfile(self, msg) -> None:
        if self.is_stopped():
            self.rpc.request("vmmap", self._set_vmmap)

    def on_memory(self, msg) -> None:
        self.dirty_gen += 1

    def on_bps(self, msg) -> None:
        self.bps = msg.get("bps", [])
        self.bp_addrs = {}
        self.bp_lines = {}
        for b in self.bps:
            for loc in b.get("locs", []):
                en = b["enabled"] and loc.get("enabled", True)
                if loc.get("addr") is not None:
                    self.bp_addrs[loc["addr"]] = en or self.bp_addrs.get(loc["addr"], False)
                if loc.get("file") and loc.get("line"):
                    self.bp_lines[(os.path.basename(loc["file"]), loc["line"])] = en

    def on_disconnected(self, msg) -> None:
        if not self.exiting:
            hello_imgui.get_runner_params().app_shall_exit = True

    def _set_vmmap(self, pages) -> None:
        self.vmmap = sorted(pages, key=lambda p: p[0])
        self.vmmap_starts = [p[0] for p in self.vmmap]

    def refresh_checksec(self) -> None:
        def done(out):
            items = []
            for line in strip_ansi(out).splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    k, v = k.strip(), v.strip()
                    if k in ("RELRO", "Stack", "NX", "PIE", "SHSTK", "IBT", "Stripped", "FORTIFY"):
                        items.append((k, v))
            self.checksec = items

        if self.rpc:
            self.rpc.request("exec", done, None, cmd="checksec")

    # ── breakpoints persistence ─────────────────────────────────────────
    def restore_breakpoints(self) -> None:
        if not self.settings["remember_bps"] or self.bps:
            return
        saved = self.settings.binary(self.cfg.binary).get("bps", [])
        if not saved:
            return
        for bp in saved:
            def created(out, bp=bp):
                m = re.search(r"(?:point|Watchpoint) (\d+)", out or "")
                if not m:
                    return
                num = int(m.group(1))
                if bp.get("cond") or not bp.get("enabled", True):
                    self.rpc.request("bp_update", None, None, num=num,
                                     enabled=bp.get("enabled", True), cond=bp.get("cond") or "")

            self.rpc.request("exec", created, None, cmd=f"{bp['kind']} {bp['where']}")
        self.toast(f"{fa.ICON_FA_CIRCLE_DOT}  Restored {len(saved)} breakpoint(s)", "info", 4.0)

    def save_breakpoints(self) -> None:
        if not self.settings["remember_bps"]:
            return
        out = []
        for b in self.bps:
            where = b.get("location") or b.get("expr")
            kind = b.get("type")
            if not where or kind not in ("break", "hbreak", "watch", "rwatch", "awatch") or b.get("temp"):
                continue
            out.append({"kind": kind, "where": where, "enabled": b["enabled"], "cond": b.get("cond")})
        self.settings.binary(self.cfg.binary)["bps"] = out

    # ── layout sync with pwndbg ─────────────────────────────────────────
    def sync_layout(self) -> None:
        if not self.connected() or not self.info.get("pwndbg"):
            return
        dp = hello_imgui.get_runner_params().docking_params
        enabled = []
        geom = {}
        for name, sec in self.sections.items():
            dw = dp.dockable_window_of_name(sec["label"])
            if dw is None or not dw.is_visible:
                continue
            enabled.append(name)
            view = sec["view"]
            w = view.cols if view.cols > 10 else 0
            h = view.rows if (self.settings["autofit"] and name in AUTOFIT_HEIGHT and view.rows > 2) else 0
            geom[name] = [w, h]
        key = json.dumps([enabled, geom])
        if key == self.layout_sent:
            return
        now = time.monotonic()
        if self.layout_pending[0] != key:
            self.layout_pending = (key, now)
            return
        if now - self.layout_pending[1] < 0.2:
            return
        self.layout_sent = key
        self.rpc.request("layout", None, self.error_toast, enabled=enabled, geom=geom)

    # ── hello_imgui callbacks ───────────────────────────────────────────
    def load_fonts(self) -> None:
        import imgui_bundle

        assets = os.path.join(os.path.dirname(imgui_bundle.__file__), "assets")
        hello_imgui.set_assets_folder(assets)
        fonts_dir = os.path.join(assets, "fonts")
        fa_path = os.path.join(fonts_dir, "Font_Awesome_6_Free-Solid-900.otf")

        def load(path: str, merge_icons: bool):
            font = hello_imgui.load_font(path, 16.0, hello_imgui.FontLoadingParams(inside_assets=False))
            if merge_icons and os.path.exists(fa_path):
                params = hello_imgui.FontLoadingParams(merge_to_last_font=True, inside_assets=False)
                params.font_config.glyph_offset = ImVec2(0, 1)
                hello_imgui.load_font(fa_path, 14.0, params)
            return font

        ui_path = os.path.join(fonts_dir, "Roboto", "Roboto-Regular.ttf")
        if not os.path.exists(ui_path):
            ui_path = os.path.join(fonts_dir, "DroidSans.ttf")
        self.ui_font = load(ui_path, True)

        mono_path = self.settings["font"]
        if not mono_path or not os.path.exists(mono_path):
            mono_path = self.fonts[0][1] if self.fonts else os.path.join(fonts_dir, "Inconsolata-Medium.ttf")
        self.mono_path = mono_path
        self.mono = load(mono_path, True)
        bold = find_bold_variant(mono_path)
        self.mono_bold = load(bold, False) if bold else None

    def setup_style(self) -> None:
        self.apply_theme(self.theme)

    def apply_theme(self, th: Theme) -> None:
        self.theme = th
        th._cache.clear()
        self.inline_cache.clear()
        self.settings["theme"] = th.name
        style = imgui.get_style()
        if th.dark:
            imgui.style_colors_dark(style)
        else:
            imgui.style_colors_light(style)
        C = imgui.Col_
        bg, panel, border, fg, dim, acc = th.bg, th.panel, th.border, th.fg, th.dim, th.accent
        frame = mix(panel, fg, 0.06)
        colors = {
            C.text: v4(fg), C.text_disabled: v4(dim),
            C.window_bg: v4(panel), C.child_bg: v4(panel, 0.0), C.popup_bg: v4(mix(panel, fg, 0.03), 0.98),
            C.border: v4(border), C.border_shadow: v4(bg, 0.0),
            C.frame_bg: v4(frame), C.frame_bg_hovered: v4(mix(frame, acc, 0.18)), C.frame_bg_active: v4(mix(frame, acc, 0.30)),
            C.title_bg: v4(bg), C.title_bg_active: v4(bg), C.title_bg_collapsed: v4(bg),
            C.menu_bar_bg: v4(bg),
            C.scrollbar_bg: v4(panel, 0.0), C.scrollbar_grab: v4(mix(panel, fg, 0.18)),
            C.scrollbar_grab_hovered: v4(mix(panel, fg, 0.28)), C.scrollbar_grab_active: v4(acc, 0.8),
            C.check_mark: v4(acc), C.slider_grab: v4(acc, 0.85), C.slider_grab_active: v4(acc),
            C.button: v4(mix(frame, fg, 0.04)), C.button_hovered: v4(mix(frame, acc, 0.30)), C.button_active: v4(mix(frame, acc, 0.50)),
            C.header: v4(mix(panel, acc, 0.22)), C.header_hovered: v4(mix(panel, acc, 0.32)), C.header_active: v4(mix(panel, acc, 0.45)),
            C.separator: v4(border), C.separator_hovered: v4(acc, 0.7), C.separator_active: v4(acc),
            C.resize_grip: v4(acc, 0.15), C.resize_grip_hovered: v4(acc, 0.5), C.resize_grip_active: v4(acc, 0.8),
            C.tab: v4(bg), C.tab_hovered: v4(mix(panel, acc, 0.30)), C.tab_selected: v4(panel),
            C.tab_selected_overline: v4(acc), C.tab_dimmed: v4(bg), C.tab_dimmed_selected: v4(panel),
            C.tab_dimmed_selected_overline: v4(acc, 0.35),
            C.docking_preview: v4(acc, 0.45), C.docking_empty_bg: v4(bg),
            C.table_header_bg: v4(mix(panel, fg, 0.05)), C.table_border_strong: v4(border), C.table_border_light: v4(mix(panel, border, 0.6)),
            C.table_row_bg: v4(panel, 0.0), C.table_row_bg_alt: v4(fg, 0.025),
            C.text_selected_bg: v4(th.accent2, 0.35), C.drag_drop_target: v4(acc), C.nav_cursor: v4(acc),
            C.modal_window_dim_bg: v4(bg, 0.6), C.plot_lines: v4(acc), C.plot_histogram: v4(acc),
            C.text_link: v4(th.accent2), C.input_text_cursor: v4(acc),
        }
        for idx, col in colors.items():
            style.set_color_(idx, col)
        style.window_rounding = 6.0
        style.child_rounding = 4.0
        style.frame_rounding = 4.0
        style.popup_rounding = 6.0
        style.grab_rounding = 4.0
        style.scrollbar_rounding = 6.0
        style.tab_rounding = 4.0
        style.window_border_size = 1.0
        style.frame_border_size = 0.0
        style.popup_border_size = 1.0
        style.tab_border_size = 0.0
        style.window_padding = ImVec2(8, 6)
        style.frame_padding = ImVec2(7, 4)
        style.item_spacing = ImVec2(7, 5)
        style.item_inner_spacing = ImVec2(5, 4)
        style.scrollbar_size = 12.0
        style.grab_min_size = 10.0
        style.window_title_align = ImVec2(0.0, 0.5)
        style.separator_text_border_size = 1.0
        style.docking_separator_size = 3.0
        style.tab_bar_overline_size = 2.0
        style.window_menu_button_position = imgui.Dir.none

    def pre_new_frame(self) -> None:
        self.process_inbox()
        if self.proc is not None and self.proc.poll() is not None and not self.exiting:
            hello_imgui.get_runner_params().app_shall_exit = True
        rp = hello_imgui.get_runner_params()
        for v in self.views_to_add:
            dw = hello_imgui.DockableWindow(v.label, "MainDockSpace", v.gui)
            dw.focus_window_at_next_frame = not v.restored
            dw.remember_is_visible = False
            dw.include_in_view_menu = False
            hello_imgui.add_dockable_window(dw, force_dockspace=not v.restored)
        self.views_to_add = []
        for v in list(self.cmd_views):
            dw = rp.docking_params.dockable_window_of_name(v.label)
            if dw is not None and not dw.is_visible:
                hello_imgui.remove_dockable_window(v.label)
                self.cmd_views.remove(v)
        style = imgui.get_style()
        if abs(style.font_size_base - self.ui_size) > 0.01:
            style.font_size_base = self.ui_size
            style._next_frame_font_size_base = self.ui_size
        self.sync_layout()

    def post_init(self) -> None:
        for v in self.settings["views"]:
            if isinstance(v, dict) and v.get("cmd"):
                self.open_cmd_view(v["cmd"], auto=v.get("auto", True), restored=True)

    def before_exit(self) -> None:
        self.exiting = True
        self.save_breakpoints()
        st = self.settings
        st["views"] = [{"cmd": v.cmd, "auto": v.auto} for v in self.cmd_views]
        st["console_history"] = self.history
        st["ui_size"] = self.ui_size
        st["code_size"] = self.code_size
        st.binary(self.cfg.binary)["args"] = self.args_input
        st.save()


    def measure(self) -> None:
        """Must be called with the mono font pushed."""
        self.char_w = imgui.calc_text_size("M").x
        self.line_h = float(int(imgui.get_font_size() * 1.28))

    # ── actions ─────────────────────────────────────────────────────────
    def actions(self) -> list[tuple]:
        """(label, icon, shortcut, enabled, callback) for toolbar/menu/palette."""
        alive, stopped, running = self.is_alive(), self.is_stopped(), self.is_running()
        sc = self.send_console
        return [
            ("Run", "PLAY", "Ctrl+F5", not running, lambda: sc("run")),
            ("Start (break at main)", "FLAG_CHECKERED", "", not running, lambda: sc("start")),
            ("Start at entry point", "ARROW_RIGHT_TO_BRACKET", "", not running, lambda: sc("entry")),
            ("Run with arguments…", "KEYBOARD", "", not running, self.open_args_modal),
            ("Continue", "FORWARD", "F5", stopped, lambda: sc("continue")),
            ("Pause", "PAUSE", "F6", running, self.interrupt),
            ("Step into (si)", "ARROW_TURN_DOWN", "F7", stopped, lambda: sc("si")),
            ("Step over (ni)", "ARROW_RIGHT_FROM_BRACKET", "F8", stopped, lambda: sc("ni")),
            ("Step source line (step)", "ARROW_TURN_DOWN", "Shift+F7", stopped, lambda: sc("step")),
            ("Next source line (next)", "ARROW_RIGHT_FROM_BRACKET", "Shift+F8", stopped, lambda: sc("next")),
            ("Step out (finish)", "ARROW_UP_FROM_BRACKET", "Ctrl+F7", stopped, lambda: sc("finish")),
            ("Kill", "SKULL", "Shift+F5", alive and not running, lambda: sc("kill")),
        ]

    def stepping_extras(self) -> list[tuple[str, str]]:
        return [
            ("nextcall", "Continue to the next call"),
            ("nextjmp", "Continue to the next jump"),
            ("nextret", "Continue to the next return-like instruction"),
            ("nextsyscall", "Continue to the next syscall (skip calls)"),
            ("stepret", "Step until a return-like instruction"),
            ("stepsyscall", "Step until the next syscall"),
            ("nextproginstr", "Continue until back in the main binary"),
            ("xuntil", "Continue until an address/expression"),
        ]

    def open_args_modal(self) -> None:
        self.modal = {"kind": "args", "value": self.args_input, "focus": True}

    def run_action(self, label: str) -> None:
        for a in self.actions():
            if a[0] == label and a[3]:
                a[4]()

    def handle_shortcuts(self) -> None:
        io = imgui.get_io()
        K = imgui.Key
        pressed = lambda k: imgui.is_key_pressed(k, False)  # noqa: E731
        if pressed(K.f5):
            if io.key_ctrl or (not self.is_alive() and not io.key_shift):
                self.run_action("Run")
            elif io.key_shift:
                self.run_action("Kill")
            else:
                self.run_action("Continue")
        elif pressed(K.f6):
            self.run_action("Pause")
        elif pressed(K.f7):
            self.run_action("Step out (finish)" if io.key_ctrl else ("Step source line (step)" if io.key_shift else "Step into (si)"))
        elif pressed(K.f8):
            self.run_action("Next source line (next)" if io.key_shift else "Step over (ni)")
        if io.key_ctrl and not io.key_alt:
            if pressed(K.p):
                self.palette_open = True
            elif pressed(K.g):
                self.focus_window(f"{fa.ICON_FA_MEMORY} Memory")
                self.memory.focus_input = True
            elif pressed(K.equal) or pressed(K.keypad_add):
                self.set_code_size(self.code_size + 1)
            elif pressed(K.minus) or pressed(K.keypad_subtract):
                self.set_code_size(self.code_size - 1)
            elif pressed(K._0):
                self.set_code_size(float(Settings.DEFAULTS["code_size"]))
            elif pressed(K.grave_accent):
                self.focus_window(f"{fa.ICON_FA_TERMINAL} Console")
                self.focus_console = True
        if io.key_ctrl and io.mouse_wheel and imgui.is_window_hovered(imgui.HoveredFlags_.any_window):
            self.set_code_size(self.code_size + (1 if io.mouse_wheel > 0 else -1))
            io.mouse_wheel = 0.0

    def set_code_size(self, size: float) -> None:
        self.code_size = max(8.0, min(40.0, size))

    # ── menus ───────────────────────────────────────────────────────────
    def show_menus(self) -> None:
        dp = hello_imgui.get_runner_params().docking_params
        if imgui.begin_menu("Debug"):
            for label, icon, shortcut, enabled, cb in self.actions():
                if imgui.menu_item_simple(f"{getattr(fa, 'ICON_FA_' + icon)}  {label}", shortcut, False, enabled):
                    cb()
            imgui.separator()
            if imgui.begin_menu(f"{fa.ICON_FA_ANGLES_RIGHT}  pwndbg stepping", self.is_stopped()):
                for cmd, desc in self.stepping_extras():
                    if imgui.menu_item_simple(cmd, "", False, self.pwndbg_has(cmd)):
                        if cmd == "xuntil":
                            self.modal = {"kind": "console", "title": "xuntil", "prefix": "xuntil ", "value": "", "focus": True}
                        else:
                            self.send_console(cmd)
                    imgui.set_item_tooltip(desc)
                imgui.end_menu()
            if imgui.menu_item_simple(f"{fa.ICON_FA_CHEVRON_LEFT}  Previous context", "", False, self.pwndbg_has("contextprev")):
                self.exec("contextprev", refresh=False, quiet=True)
            if imgui.menu_item_simple(f"{fa.ICON_FA_CHEVRON_RIGHT}  Next context", "", False, self.pwndbg_has("contextnext")):
                self.exec("contextnext", refresh=False, quiet=True)
            if imgui.menu_item_simple(f"{fa.ICON_FA_ARROWS_ROTATE}  Refresh context"):
                self.rpc.request("context")
            imgui.separator()
            if imgui.menu_item_simple(f"{fa.ICON_FA_XMARK}  Quit", "Alt+F4"):
                hello_imgui.get_runner_params().app_shall_exit = True
            imgui.end_menu()

        if imgui.begin_menu("View"):
            imgui.separator_text("Context")
            for name, sec in self.sections.items():
                self._window_toggle(dp, sec["label"])
            imgui.separator_text("Tools")
            for label in self.tool_labels():
                self._window_toggle(dp, label)
            imgui.separator()
            if imgui.menu_item_simple(f"{fa.ICON_FA_TABLE_CELLS}  Reset layout"):
                dp.layout_reset = True
                for dw in dp.dockable_windows:
                    dw.is_visible = self.default_visible.get(dw.label, dw.is_visible)
                self.layout_sent = None
            imgui.end_menu()

        if imgui.begin_menu("pwndbg"):
            for group, items in TOOL_PRESETS:
                if imgui.begin_menu(group):
                    for cmd, name in items:
                        if imgui.menu_item_simple(cmd, "", False, self.pwndbg_has(name)):
                            self.open_cmd_view(cmd)
                    imgui.end_menu()
            imgui.separator()
            if imgui.menu_item_simple(f"{fa.ICON_FA_TERMINAL}  New command view…"):
                self.modal = {"kind": "newview", "value": "", "focus": True}
            if imgui.menu_item_simple(f"{fa.ICON_FA_BOOK}  Command browser"):
                self.focus_window(f"{fa.ICON_FA_BOOK} Commands")
            if imgui.menu_item_simple(f"{fa.ICON_FA_SLIDERS}  pwndbg config"):
                self.focus_window(f"{fa.ICON_FA_SLIDERS} pwndbg Config")
            if imgui.menu_item_simple(f"{fa.ICON_FA_WAND_MAGIC_SPARKLES}  Command palette", "Ctrl+P"):
                self.palette_open = True
            imgui.end_menu()

        if imgui.begin_menu("Settings"):
            if imgui.begin_menu(f"{fa.ICON_FA_PALETTE}  Theme"):
                for th in THEMES.values():
                    self._theme_swatch(th)
                    imgui.same_line()
                    if imgui.menu_item_simple(th.name, "", th is self.theme):
                        self.apply_theme(th)
                imgui.end_menu()
            imgui.set_next_item_width(imgui.get_font_size() * 8)
            changed, v = imgui.slider_float("UI size", self.ui_size, 10.0, 26.0, "%.0f")
            if changed:
                self.ui_size = round(v)
            imgui.set_next_item_width(imgui.get_font_size() * 8)
            changed, v = imgui.slider_float("Code size", self.code_size, 8.0, 32.0, "%.0f")
            if changed:
                self.set_code_size(round(v))
            imgui.separator()
            if imgui.menu_item_simple(f"{fa.ICON_FA_GEAR}  Preferences…"):
                self.focus_window(f"{fa.ICON_FA_GEAR} Preferences")
            _, self.show_style_editor = imgui.menu_item("ImGui style editor", "", self.show_style_editor)
            _, self.show_metrics = imgui.menu_item("ImGui metrics", "", self.show_metrics)
            imgui.end_menu()

        if imgui.begin_menu("Help"):
            if imgui.menu_item_simple(f"{fa.ICON_FA_KEYBOARD}  Keyboard shortcuts"):
                self.modal = {"kind": "help"}
            imgui.separator()
            imgui.text_disabled(f"{APP_NAME} {APP_VERSION}")
            imgui.text_disabled(f"pwndbg {self.info.get('pwndbg') or 'not loaded'}")
            imgui.text_disabled(f"gdb {self.info.get('gdb', '?')}")
            imgui.end_menu()

    def _window_toggle(self, dp, label: str) -> None:
        dw = dp.dockable_window_of_name(label)
        if dw is None:
            return
        clicked, _ = imgui.menu_item(label, "", dw.is_visible)
        if clicked:
            dw.is_visible = not dw.is_visible
            if dw.is_visible:
                dw.focus_window_at_next_frame = True

    def _theme_swatch(self, th: Theme) -> None:
        dl = imgui.get_window_draw_list()
        p = imgui.get_cursor_screen_pos()
        s = imgui.get_text_line_height()
        cols = [th.panel, th.accent, th.red, th.green, th.yellow, th.blue]
        for i, c in enumerate(cols):
            dl.add_rect_filled(ImVec2(p.x + i * s * 0.55, p.y + 2), ImVec2(p.x + (i + 1) * s * 0.55, p.y + s - 1), u32(c), 1.5)
        imgui.dummy(ImVec2(len(cols) * s * 0.55, s))

    # ── toolbar & status bar ────────────────────────────────────────────
    def toolbar(self) -> None:
        th = self.theme
        imgui.push_style_var(imgui.StyleVar_.frame_padding, ImVec2(8, 5))
        imgui.push_style_var(imgui.StyleVar_.item_spacing, ImVec2(4, 4))
        imgui.push_style_color(imgui.Col_.button, v4(th.panel, 0.0))
        tool = [
            ("Run", th.green), ("Start (break at main)", th.green), ("Continue", th.green),
            ("Pause", th.yellow), None, ("Step into (si)", th.cyan), ("Step over (ni)", th.cyan),
            ("Step out (finish)", th.cyan), None, ("Kill", th.red),
        ]
        actions = {a[0]: a for a in self.actions()}
        imgui.set_cursor_pos_y(imgui.get_cursor_pos_y() + 1)
        for item in tool:
            if item is None:
                vsep()
                continue
            label, color = item
            _, icon, shortcut, enabled, cb = actions[label]
            imgui.begin_disabled(not enabled)
            imgui.push_style_color(imgui.Col_.text, v4(color))
            if imgui.button(f"{getattr(fa, 'ICON_FA_' + icon)}##tb{label}"):
                cb()
            imgui.pop_style_color()
            imgui.end_disabled()
            if imgui.is_item_hovered(imgui.HoveredFlags_.allow_when_disabled | imgui.HoveredFlags_.delay_short):
                imgui.set_tooltip(f"{label}  [{shortcut}]" if shortcut else label)
            imgui.same_line()
        imgui.begin_disabled(not self.is_stopped())
        if imgui.button(f"{fa.ICON_FA_ANGLES_RIGHT} {fa.ICON_FA_CARET_DOWN}##tbmore"):
            imgui.open_popup("##stepmore")
        imgui.end_disabled()
        imgui.set_item_tooltip("pwndbg stepping commands")
        if imgui.begin_popup("##stepmore"):
            for cmd, desc in self.stepping_extras():
                if cmd != "xuntil" and imgui.menu_item_simple(cmd, "", False, self.pwndbg_has(cmd)):
                    self.send_console(cmd)
                imgui.set_item_tooltip(desc)
            imgui.end_popup()
        vsep()
        if imgui.button(f"{fa.ICON_FA_CHEVRON_LEFT}##ctxprev"):
            self.exec("contextprev", refresh=False, quiet=True)
        imgui.set_item_tooltip("Previous context (history)")
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_CHEVRON_RIGHT}##ctxnext"):
            self.exec("contextnext", refresh=False, quiet=True)
        imgui.set_item_tooltip("Next context (history)")
        imgui.pop_style_color()
        vsep()
        imgui.set_next_item_width(imgui.get_font_size() * 16)
        entered, self.goto_input = imgui.input_text_with_hint(
            "##goto", f"{fa.ICON_FA_CROSSHAIRS} go to address / symbol…", self.goto_input,
            imgui.InputTextFlags_.enter_returns_true,
        )
        if entered and self.goto_input.strip():
            if imgui.get_io().key_ctrl:
                self.open_cmd_view(f"nearpc {self.goto_input.strip()} 40")
            else:
                self.memory.expr = self.goto_input.strip()
                self.memory.goto_expr(self.memory.expr)
                self.focus_window(f"{fa.ICON_FA_MEMORY} Memory")
        imgui.set_item_tooltip("Enter: open in Memory · Ctrl+Enter: disassemble")
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_WAND_MAGIC_SPARKLES}##pal"):
            self.palette_open = True
        imgui.set_item_tooltip("Command palette  [Ctrl+P]")
        # state badge, right aligned
        text, color = self.state_text()
        w = imgui.calc_text_size(text).x + 24
        imgui.same_line(max(imgui.get_cursor_pos_x(), imgui.get_window_width() - w - 12))
        imgui.set_cursor_pos_y(imgui.get_cursor_pos_y() + 4)
        dl = imgui.get_window_draw_list()
        p = imgui.get_cursor_screen_pos()
        h = imgui.get_text_line_height()
        dl.add_rect_filled(ImVec2(p.x - 6, p.y - 3), ImVec2(p.x + w - 6, p.y + h + 3), u32(color, 0.16), h)
        dl.add_circle_filled(ImVec2(p.x + 5, p.y + h / 2), 4.0, u32(color))
        imgui.set_cursor_screen_pos(ImVec2(p.x + 14, p.y))
        imgui.text_colored(v4(color), text)
        imgui.pop_style_var(2)

    def state_text(self):
        th = self.theme
        if not self.connected():
            return "gdb not connected", th.red
        if self.is_running():
            return "Running", th.green
        if self.is_stopped():
            sym = self.state.get("sym") or self.state.get("func") or ""
            pc = self.state.get("pc")
            where = f"{sym} " if sym else ""
            return f"Stopped · {where}{pc:#x}" if pc is not None else "Stopped", th.yellow
        return "Not running", th.dim

    def status_bar(self) -> None:
        th = self.theme
        st = self.state
        parts = []
        f = st.get("file") or self.info.get("file")
        if f:
            parts.append(os.path.basename(f))
        if st.get("pid"):
            parts.append(f"pid {st['pid']}")
        if st.get("arch"):
            parts.append(st["arch"])
        if st.get("tid"):
            parts.append(f"thread {st['tid']}")
        if st.get("level"):
            parts.append(f"frame #{st['level']}")
        if st.get("src"):
            parts.append(f"{os.path.basename(st['src'])}:{st.get('line')}")
        imgui.text_disabled("  ·  ".join(parts) if parts else "no file")
        for k, v in self.checksec:
            low = v.lower()
            if k == "Stripped":
                c = th.dim
            elif any(w in low for w in ("full", "found", "enabled", "yes")) and not low.startswith("no"):
                c = th.green
            elif "partial" in low:
                c = th.yellow
            else:
                c = th.red
            imgui.same_line(0, 14)
            imgui.text_colored(v4(c), f"{k}")
            imgui.set_item_tooltip(f"{k}: {v}")
        if self.legend:
            imgui.same_line(0, 18)
            imgui.push_font(self.mono, self.ui_size * 0.9)
            ansi_inline(self, self.legend.splitlines()[0])
            imgui.pop_font()

    # ── docked windows ──────────────────────────────────────────────────
    def section_gui(self, name: str):
        def gui() -> None:
            sec = self.sections[name]
            if not self.info.get("pwndbg") and self.connected() and self.info:
                imgui.text_colored(v4(self.theme.yellow), "pwndbg is not loaded in gdb (see --pwndbg).")
            if name == "expressions":
                self._watch_bar()
            sec["view"].render()

        return gui

    def _watch_bar(self) -> None:
        imgui.set_next_item_width(-imgui.calc_text_size(" Add  Cmd ").x - 30)
        entered, self.watch_input = imgui.input_text_with_hint(
            "##watch", "expression to watch, e.g. *(long*)$rdi", self.watch_input, imgui.InputTextFlags_.enter_returns_true)
        imgui.same_line()
        add = imgui.button("Add##w") or entered
        imgui.same_line()
        add_cmd = imgui.button("Cmd##w")
        imgui.set_item_tooltip("Watch the output of a command instead (e.g. `x/4gx $sp`)")
        expr = self.watch_input.strip().replace('"', '\\"')
        if (add or add_cmd) and expr:
            self.exec(f'contextwatch {"execute" if add_cmd else "eval"} "{expr}"')
            self.watch_input = ""

    def console_gui(self) -> None:
        th = self.theme
        footer = imgui.get_frame_height_with_spacing() + 2
        self.console_view.render(-footer)
        self.console.resize(self.console_view.rows, self.console_view.cols)
        if self.completions:
            n = min(len(self.completions), 12)
            imgui.set_next_window_pos(imgui.get_cursor_screen_pos(), imgui.Cond_.always, ImVec2(0, 1))
            if imgui.begin_tooltip():
                for c in self.completions[:n]:
                    imgui.text_unformatted(c)
                if len(self.completions) > n:
                    imgui.text_disabled(f"… {len(self.completions) - n} more")
                imgui.end_tooltip()
        running = self.is_running()
        icon = fa.ICON_FA_PERSON_RUNNING if running else fa.ICON_FA_ANGLES_RIGHT
        imgui.text_colored(v4(th.green if running else th.accent), icon)
        imgui.same_line()
        imgui.set_next_item_width(-1)
        if self.focus_console or (
            imgui.is_window_focused() and not imgui.is_any_item_active() and not imgui.is_any_mouse_down()
            and self.console_view.selection() is None and not self.console_view.search_open
        ):
            imgui.set_keyboard_focus_here()
            self.focus_console = False
        flags = (imgui.InputTextFlags_.enter_returns_true | imgui.InputTextFlags_.callback_history
                 | imgui.InputTextFlags_.callback_completion | imgui.InputTextFlags_.callback_always)
        hint = "program running — F6 / Ctrl+C to interrupt" if running else "gdb / pwndbg command  (Tab: complete, ↑↓: history)"
        imgui.push_font(self.mono, self.code_size)
        entered, self.console_input = imgui.input_text_with_hint("##console_in", hint, self.console_input, flags, self._console_cb)
        imgui.pop_font()
        if imgui.is_item_active():
            io = imgui.get_io()
            if io.key_ctrl and imgui.is_key_pressed(imgui.Key.c, False) and running:
                self.interrupt()
            elif io.key_ctrl and imgui.is_key_pressed(imgui.Key.l, False):
                self.console_term.clear()
            elif io.key_ctrl and imgui.is_key_pressed(imgui.Key.d, False) and not self.console_input:
                self.send_console("")
        if imgui.is_item_edited():
            self.completions = []
        if entered:
            cmd = self.console_input
            if cmd.strip() and (not self.history or self.history[-1] != cmd):
                self.history.append(cmd)
            self.history_pos = -1
            self.completions = []
            self.send_console(cmd)
            self.console_input = ""
            self.console_view.at_bottom = True
            imgui.set_keyboard_focus_here(-1)

    def _console_cb(self, data) -> int:
        F = imgui.InputTextFlags_
        if data.event_flag == F.callback_always:
            if self.console_replace is not None:
                data.delete_chars(0, data.buf_text_len)
                data.insert_chars(0, self.console_replace)
                self.console_replace = None
            return 0
        if data.event_flag == F.callback_history:
            if not self.history:
                return 0
            if data.event_key == imgui.Key.up_arrow:
                self.history_pos = len(self.history) - 1 if self.history_pos == -1 else max(0, self.history_pos - 1)
            elif data.event_key == imgui.Key.down_arrow and self.history_pos != -1:
                self.history_pos += 1
                if self.history_pos >= len(self.history):
                    self.history_pos = -1
            text = self.history[self.history_pos] if self.history_pos != -1 else ""
            data.delete_chars(0, data.buf_text_len)
            data.insert_chars(0, text)
            return 0
        if data.event_flag == F.callback_completion and self.rpc and not self.is_running():
            text = data.buf

            def done(lines, text=text):
                if not lines:
                    self.completions = []
                    return
                prefix = os.path.commonprefix(lines)
                if len(lines) == 1:
                    self.console_replace = lines[0] + " "
                    self.completions = []
                else:
                    if len(prefix) > len(text):
                        self.console_replace = prefix
                    self.completions = lines

            self.rpc.request("complete", done, None, text=text)
        return 0

    def io_gui(self) -> None:
        th = self.theme
        st = self.settings
        if self.io is None:
            imgui.text_disabled("Program I/O is disabled (--no-io): the program shares the gdb console.")
            return
        # header
        imgui.set_next_item_width(combo_width("Python expr"))
        modes = {"text": "Text", "python": "Python expr", "hex": "Hex"}
        if imgui.begin_combo("##iomode", modes[self.io_mode]):
            for k, v in modes.items():
                if imgui.selectable(v, self.io_mode == k)[0]:
                    self.io_mode = k
            imgui.end_combo()
        imgui.set_item_tooltip("Text: sent as typed\nPython expr: b'A'*40 + p64(0x401136), cyclic(100), …\nHex: 41 41 0a")
        imgui.same_line()
        _, st["io_newline"] = imgui.checkbox("\\n", st["io_newline"])
        imgui.set_item_tooltip("Append a newline to what you send")
        imgui.same_line()
        _, st["io_echo"] = imgui.checkbox("Echo", st["io_echo"])
        imgui.set_item_tooltip("Show what you send (dimmed)")
        imgui.same_line()
        changed, st["io_raw"] = imgui.checkbox("Raw", st["io_raw"])
        if changed:
            self.io.set_raw(st["io_raw"])
        imgui.set_item_tooltip("Raw TTY: bytes pass through untouched (binary-safe).\nUncheck for a canonical TTY (line editing, ^C, ^D = EOF).")
        imgui.same_line()
        imgui.set_next_item_width(combo_width("Terminal"))
        if imgui.begin_combo("##ioview", self.io_view_mode.capitalize()):
            for k in ("terminal", "hexdump"):
                if imgui.selectable(k.capitalize(), self.io_view_mode == k)[0]:
                    self.io_view_mode = k
            imgui.end_combo()
        imgui.same_line()
        if imgui.button(fa.ICON_FA_TRASH + "##ioclear"):
            self.io_term.clear()
            with self.io_term.lock:
                self.io.raw_bytes.clear()
                self.io.bytes_version += 1
        imgui.set_item_tooltip("Clear")
        imgui.same_line()
        imgui.begin_disabled(st["io_raw"])
        if imgui.button("EOF"):
            self.io.write(b"\x04")
        imgui.end_disabled()
        if imgui.is_item_hovered(imgui.HoveredFlags_.allow_when_disabled):
            imgui.set_tooltip("Send ^D (end of file). Needs a non-raw TTY.")
        imgui.same_line()
        imgui.text_disabled(self.io.path)

        footer = imgui.get_frame_height_with_spacing() + 2
        if self.io_view_mode == "hexdump":
            if self.io.bytes_version != self.io_hex_version:
                self.io_hex_version = self.io.bytes_version
                with self.io_term.lock:
                    data = bytes(self.io.raw_bytes)
                self.io_hex_term.set_text(hexdump_ansi(data))
            self.io_hex_view.render(-footer)
        else:
            self.io_view.render(-footer)
            self.io.resize(self.io_view.rows, self.io_view.cols)

        imgui.text_colored(v4(th.accent2), fa.ICON_FA_KEYBOARD)
        imgui.same_line()
        imgui.set_next_item_width(-imgui.calc_text_size("Send").x - imgui.get_style().frame_padding.x * 2 - 8)
        imgui.push_font(self.mono, self.code_size)
        entered, self.io_input = imgui.input_text_with_hint(
            "##io_in", "input for the program (Enter to send)", self.io_input, imgui.InputTextFlags_.enter_returns_true)
        imgui.pop_font()
        imgui.same_line()
        if (imgui.button("Send##io") or entered) and (self.io_input or st["io_newline"]):
            self.send_io(self.io_input)
            imgui.set_keyboard_focus_here(-1)

    def send_io(self, text: str) -> None:
        try:
            if self.io_mode == "python":
                data = eval_payload(text)
            else:
                data = parse_bytes_input(text, self.io_mode)
        except Exception as e:
            self.toast(f"bad input: {e}", "error")
            return
        if self.settings["io_newline"]:
            data += b"\n"
        self.io.write(data)
        if self.settings["io_echo"]:
            self.io_term.feed(data.decode("utf-8", errors="surrogateescape"), ECHO)
        self.io_input = ""

    def memory_gui(self) -> None:
        self.memory.gui()

    def vmmap_gui(self) -> None:
        th = self.theme
        imgui.set_next_item_width(-imgui.calc_text_size(" Refresh ").x - 20)
        _, self.vmmap_filter = imgui.input_text_with_hint("##vmf", f"{fa.ICON_FA_FILTER} filter (name, perms, address)", self.vmmap_filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##vmr") and self.is_stopped():
            self.rpc.request("vmmap", self._set_vmmap)
        if not self.vmmap:
            imgui.text_disabled("The memory map appears once the program is stopped.")
            return
        flt = self.vmmap_filter.lower().strip()
        addr_flt = None
        if flt.startswith("0x"):
            try:
                addr_flt = int(flt, 16)
            except ValueError:
                pass
        flags = (imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.scroll_y
                 | imgui.TableFlags_.resizable | imgui.TableFlags_.sizing_fixed_fit)
        imgui.push_font(self.mono, self.code_size)
        if imgui.begin_table("##vmmap", 6, flags):
            imgui.table_setup_scroll_freeze(0, 1)
            for col in ("Start", "End", "Size", "Perm", "Offset"):
                imgui.table_setup_column(col)
            imgui.table_setup_column("File", imgui.TableColumnFlags_.width_stretch)
            imgui.table_headers_row()
            for i, p in enumerate(self.vmmap):
                start, end, perm, off, objfile, kind = p
                if addr_flt is not None:
                    if not start <= addr_flt < end:
                        continue
                elif flt and flt not in objfile.lower() and flt not in perm and flt not in kind:
                    continue
                imgui.table_next_row()
                imgui.table_next_column()
                imgui.push_style_color(imgui.Col_.text, v4(th.kind_color(kind)))
                clicked, _ = imgui.selectable(
                    f"{start:#x}##vm{i}", False,
                    imgui.SelectableFlags_.span_all_columns | imgui.SelectableFlags_.allow_double_click)
                if clicked and imgui.is_mouse_double_clicked(0):
                    self.open_memory(start)
                if imgui.begin_popup_context_item(f"##vmctx{i}"):
                    imgui.pop_font()
                    if imgui.menu_item_simple(f"{fa.ICON_FA_MEMORY}  View memory"):
                        self.open_memory(start)
                    if imgui.menu_item_simple(f"{fa.ICON_FA_LAYER_GROUP}  Telescope start"):
                        self.open_cmd_view(f"telescope {start:#x} 32")
                    if imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy start"):
                        imgui.set_clipboard_text(f"{start:#x}")
                    if imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy end"):
                        imgui.set_clipboard_text(f"{end:#x}")
                    if objfile and imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy path"):
                        imgui.set_clipboard_text(objfile)
                    imgui.push_font(self.mono, self.code_size)
                    imgui.end_popup()
                imgui.table_next_column()
                imgui.text_unformatted(f"{end:#x}")
                imgui.table_next_column()
                imgui.text_unformatted(f"{end - start:#x}")
                imgui.table_next_column()
                imgui.text_unformatted(perm)
                imgui.table_next_column()
                imgui.text_unformatted(f"{off:#x}")
                imgui.table_next_column()
                imgui.text_unformatted(os.path.basename(objfile) if objfile.startswith("/") else objfile)
                if objfile.startswith("/"):
                    imgui.set_item_tooltip(objfile)
                imgui.pop_style_color()
            imgui.end_table()
        imgui.pop_font()

    def breakpoints_gui(self) -> None:
        th = self.theme
        imgui.set_next_item_width(-imgui.calc_text_size(" Break  Temp  Watch  RWatch ").x - 40)
        entered, self.bp_input = imgui.input_text_with_hint(
            "##bpin", "main · *0x401136 · file.c:42 · $rip+8 · var", self.bp_input, imgui.InputTextFlags_.enter_returns_true)
        where = self.bp_input.strip()
        for kind, label, tip in (("break", "Break", "Software breakpoint"), ("tbreak", "Temp", "Temporary breakpoint"),
                                 ("watch", "Watch", "Write watchpoint"), ("rwatch", "RWatch", "Read watchpoint")):
            imgui.same_line()
            if (imgui.button(f"{label}##bp") or (entered and kind == "break")) and where:
                self.exec(f"{kind} {where}", refresh=False)
                self.bp_input = ""
            imgui.set_item_tooltip(tip)
        if not self.bps:
            imgui.text_disabled("No breakpoints. Click the gutter of Disassembly/Source, or add one above.")
            return
        flags = (imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.scroll_y
                 | imgui.TableFlags_.resizable | imgui.TableFlags_.sizing_fixed_fit)
        if imgui.begin_table("##bps", 7, flags):
            imgui.table_setup_scroll_freeze(0, 1)
            for col in ("", "#", "Type", "Where", "Address", "Hits"):
                imgui.table_setup_column(col)
            imgui.table_setup_column("Condition", imgui.TableColumnFlags_.width_stretch)
            imgui.table_headers_row()
            for b in self.bps:
                num = b["num"]
                imgui.table_next_row()
                imgui.table_next_column()
                changed, en = imgui.checkbox(f"##en{num}", b["enabled"])
                if changed:
                    self.rpc.request("bp_update", None, self.error_toast, num=num, enabled=en)
                imgui.same_line()
                if imgui.small_button(f"{fa.ICON_FA_TRASH}##del{num}"):
                    self.rpc.request("bp_delete", None, self.error_toast, num=num)
                imgui.table_next_column()
                imgui.text_colored(v4(th.red if b["enabled"] else th.dim), str(num))
                imgui.table_next_column()
                imgui.text_unformatted(b.get("type", "?") + (" (temp)" if b.get("temp") else ""))
                imgui.table_next_column()
                imgui.text_unformatted(b.get("location") or b.get("expr") or "")
                if b.get("pending"):
                    imgui.same_line()
                    imgui.text_disabled("(pending)")
                imgui.table_next_column()
                addrs = [loc["addr"] for loc in b.get("locs", []) if loc.get("addr") is not None]
                if addrs:
                    imgui.push_font(self.mono, self.code_size)
                    if imgui.text_link(f"{addrs[0]:#x}##bpa{num}"):
                        self.open_memory(addrs[0])
                    imgui.pop_font()
                    if len(addrs) > 1:
                        imgui.same_line()
                        imgui.text_disabled(f"+{len(addrs) - 1}")
                imgui.table_next_column()
                imgui.text_unformatted(str(b.get("hits", 0)))
                imgui.table_next_column()
                key = f"cond{num}"
                if key not in self.config_edit:
                    self.config_edit[key] = b.get("cond") or ""
                imgui.set_next_item_width(-1)
                entered, self.config_edit[key] = imgui.input_text_with_hint(
                    f"##{key}", "condition (Enter)", self.config_edit[key], imgui.InputTextFlags_.enter_returns_true)
                if entered:
                    self.rpc.request("bp_update", None, self.error_toast, num=num, cond=self.config_edit[key])
                elif not imgui.is_item_active():
                    self.config_edit[key] = b.get("cond") or ""
            imgui.end_table()

    def commands_gui(self) -> None:
        th = self.theme
        if self.commands is None:
            imgui.text_disabled("Loading pwndbg commands…")
            return
        if not self.commands:
            imgui.text_disabled("pwndbg is not loaded.")
            return
        imgui.set_next_item_width(-1)
        _, self.cmd_filter = imgui.input_text_with_hint("##cmdf", f"{fa.ICON_FA_FILTER} filter {len(self.commands)} commands", self.cmd_filter)
        flt = self.cmd_filter.lower().strip()
        avail = imgui.get_content_region_avail()
        imgui.begin_child("##cmdlist", ImVec2(avail.x * 0.38, 0), imgui.ChildFlags_.borders | imgui.ChildFlags_.resize_x)
        cats: dict[str, list] = {}
        for c in self.commands:
            if flt and flt not in c["name"] and flt not in c["desc"].lower() and not any(flt in a for a in c["aliases"]):
                continue
            cats.setdefault(c["cat"], []).append(c)
        for cat in sorted(cats):
            imgui.set_next_item_open(bool(flt), imgui.Cond_.always if flt else imgui.Cond_.once)
            if imgui.tree_node(f"{cat} ({len(cats[cat])})"):
                for c in sorted(cats[cat], key=lambda c: c["name"]):
                    if imgui.selectable(c["name"], self.cmd_selected is c)[0]:
                        self.cmd_selected = c
                    if imgui.is_item_hovered() and imgui.is_mouse_double_clicked(0):
                        self.open_cmd_view(c["name"])
                    imgui.set_item_tooltip(c["desc"])
                imgui.tree_pop()
        imgui.end_child()
        imgui.same_line()
        imgui.begin_child("##cmdhelp", ImVec2(0, 0))
        c = self.cmd_selected
        if c is None:
            imgui.text_disabled("Select a command. Double-click opens it as a live view.")
        else:
            imgui.text_colored(v4(th.accent), c["name"])
            if c["aliases"]:
                imgui.same_line()
                imgui.text_disabled("aliases: " + ", ".join(c["aliases"]))
            if imgui.button(f"{fa.ICON_FA_TERMINAL} Insert in console"):
                self.console_replace = c["name"] + " "
                self.focus_window(f"{fa.ICON_FA_TERMINAL} Console")
                self.focus_console = True
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_TABLE_CELLS} Open as view"):
                self.open_cmd_view(c["name"])
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_PLAY} Run in console"):
                self.send_console(c["name"])
            imgui.separator()
            imgui.push_font(self.mono, self.code_size * 0.92)
            imgui.text_unformatted(strip_ansi(c["help"]))
            imgui.pop_font()
        imgui.end_child()

    def config_gui(self) -> None:
        th = self.theme
        if self.config is None:
            if self.connected() and self.info.get("pwndbg"):
                self.config = []
                self.rpc.request("config", self._set_config, self.error_toast)
            imgui.text_disabled("Loading…")
            return
        imgui.set_next_item_width(-imgui.calc_text_size(" Reload ").x - 20)
        _, self.cfg_filter = imgui.input_text_with_hint("##cfgf", f"{fa.ICON_FA_FILTER} filter parameters", self.cfg_filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##cfgr"):
            self.rpc.request("config", self._set_config, self.error_toast)
        flt = self.cfg_filter.lower().strip()
        flags = (imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.scroll_y
                 | imgui.TableFlags_.resizable)
        if not imgui.begin_table("##cfg", 3, flags):
            return
        imgui.table_setup_scroll_freeze(0, 1)
        imgui.table_setup_column("Parameter", imgui.TableColumnFlags_.width_fixed, imgui.get_font_size() * 14)
        imgui.table_setup_column("Value", imgui.TableColumnFlags_.width_fixed, imgui.get_font_size() * 12)
        imgui.table_setup_column("Description", imgui.TableColumnFlags_.width_stretch)
        imgui.table_headers_row()
        scope = None
        for p in self.config:
            if flt and flt not in p["name"] and flt not in p["doc"].lower():
                continue
            if p["scope"] != scope and not flt:
                scope = p["scope"]
                imgui.table_next_row(imgui.TableRowFlags_.headers)
                imgui.table_next_column()
                imgui.text_colored(v4(th.accent), scope.upper())
            imgui.table_next_row()
            imgui.table_next_column()
            imgui.text_unformatted(p["name"])
            imgui.set_item_tooltip(p["help"])
            imgui.table_next_column()
            imgui.set_next_item_width(-1)
            imgui.push_font(self.mono, self.ui_size)
            self._config_widget(p)
            imgui.pop_font()
            imgui.table_next_column()
            imgui.text_disabled(p["doc"])
        imgui.end_table()

    def _set_config(self, cfg) -> None:
        self.config = cfg

    def _config_widget(self, p) -> None:
        name, kind, value = p["name"], p["kind"], p["value"]

        def setv(v):
            p["value"] = v
            out = "on" if v is True else ("off" if v is False else str(v))
            self.exec(f"set {name} {out}", quiet=True)

        if kind == "bool":
            changed, v = imgui.checkbox(f"##{name}", bool(value))
            if changed:
                setv(v)
        elif kind in ("enum", "auto"):
            options = p["enum"] if kind == "enum" else ["on", "off", "auto"]
            if imgui.begin_combo(f"##{name}", str(value)):
                for o in options:
                    if imgui.selectable(o, o == value)[0]:
                        setv(o)
                imgui.end_combo()
        else:
            key = "cfg:" + name
            if key not in self.config_edit:
                self.config_edit[key] = str(value)
            entered, self.config_edit[key] = imgui.input_text(f"##{name}", self.config_edit[key], imgui.InputTextFlags_.enter_returns_true)
            if entered:
                v = self.config_edit[key]
                setv(int(v, 0) if kind == "int" and re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", v) else v)
            elif not imgui.is_item_active():
                self.config_edit[key] = str(value)

    def cyclic_gui(self) -> None:
        th = self.theme
        imgui.separator_text("Generate")
        imgui.set_next_item_width(imgui.get_font_size() * 7)
        _, self.cyclic_len = imgui.input_int("length", self.cyclic_len, 16, 256)
        self.cyclic_len = max(1, min(self.cyclic_len, 100000))
        imgui.same_line()
        imgui.set_next_item_width(imgui.get_font_size() * 5)
        if imgui.begin_combo("n", str(self.cyclic_n)):
            for n in (4, 8):
                if imgui.selectable(str(n), n == self.cyclic_n)[0]:
                    self.cyclic_n = n
            imgui.end_combo()
        imgui.set_item_tooltip("Subsequence size: 4 for 32-bit, 8 for 64-bit targets")
        pattern = cyclic(self.cyclic_len, self.cyclic_n)
        if imgui.button(f"{fa.ICON_FA_COPY} Copy"):
            imgui.set_clipboard_text(pattern.decode())
            self.toast("Pattern copied", "info", 1.2)
        imgui.same_line()
        imgui.begin_disabled(self.io is None)
        if imgui.button(f"{fa.ICON_FA_KEYBOARD} Send to program"):
            self.io.write(pattern + (b"\n" if self.settings["io_newline"] else b""))
            if self.settings["io_echo"]:
                self.io_term.feed(pattern.decode() + "\n", ECHO)
        imgui.end_disabled()
        imgui.push_font(self.mono, self.code_size)
        imgui.push_text_wrap_pos(0)
        preview = pattern[:400].decode() + ("…" if len(pattern) > 400 else "")
        imgui.text_colored(v4(th.dim), preview)
        imgui.pop_text_wrap_pos()
        imgui.pop_font()
        imgui.separator_text("Find offset")
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        entered, self.cyclic_value = imgui.input_text_with_hint(
            "##cyv", "0x6161616c6161616b, 'kaaa', $rsp…", self.cyclic_value, imgui.InputTextFlags_.enter_returns_true)
        for reg in ("$pc", "$sp", "$bp"):
            imgui.same_line()
            if imgui.button(reg) and self.is_stopped():
                expr = f"*(unsigned long *){reg}" if reg != "$pc" else "$pc"
                self.rpc.request("eval", self._cyclic_lookup, lambda e: setattr(self, "cyclic_result", e), expr=expr)
            imgui.set_item_tooltip(f"Look up the value of {'$pc' if reg == '$pc' else '*' + reg}")
        if entered:
            v = self.cyclic_value.strip()
            if v.startswith(("'", '"')):
                self._cyclic_lookup(v.strip("'\"").encode())
            elif re.fullmatch(r"(0x)?[0-9a-fA-F]+", v):
                self._cyclic_lookup(int(v, 16))
            elif self.rpc:
                self.rpc.request("eval", self._cyclic_lookup, lambda e: setattr(self, "cyclic_result", e), expr=v)
        if self.cyclic_result:
            imgui.text_colored(v4(th.green if "offset" in self.cyclic_result else th.red), self.cyclic_result)

    def _cyclic_lookup(self, value) -> None:
        n = self.cyclic_n
        if isinstance(value, int):
            needle = (value & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
            shown = f"{value:#x}"
        else:
            needle = value
            shown = repr(value)
        off = cyclic_find(needle, n)
        if off < 0 and isinstance(value, int) and n == 8:
            off = cyclic_find((value & 0xFFFFFFFF).to_bytes(4, "little"), 4)
        self.cyclic_result = f"{shown} found at offset {off} ({off:#x})" if off >= 0 else f"{shown} not found in the pattern"

    def prefs_gui(self) -> None:
        st = self.settings
        imgui.separator_text("Appearance")
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        if imgui.begin_combo("Theme", self.theme.name):
            for th in THEMES.values():
                self._theme_swatch(th)
                imgui.same_line()
                if imgui.selectable(th.name, th is self.theme)[0]:
                    self.apply_theme(th)
            imgui.end_combo()
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        current = next((f for f, p in self.fonts if p == self.mono_path), os.path.basename(self.mono_path))
        if imgui.begin_combo("Code font", current):
            for fam, path in self.fonts:
                if imgui.selectable(fam, path == self.mono_path)[0]:
                    st["font"] = path
                    self.toast("Font change applies on next start", "info")
            imgui.end_combo()
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        changed, v = imgui.slider_float("UI size", self.ui_size, 10.0, 26.0, "%.0f")
        if changed:
            self.ui_size = round(v)
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        changed, v = imgui.slider_float("Code size  (Ctrl+wheel)", self.code_size, 8.0, 32.0, "%.0f")
        if changed:
            self.set_code_size(round(v))
        imgui.separator_text("Behavior")
        _, st["autofit"] = imgui.checkbox("Fit context sections to their window", st["autofit"])
        help_marker("Disassembly, stack, source, backtrace and threads show exactly as many lines as fit.")
        _, st["remember_bps"] = imgui.checkbox("Remember breakpoints per binary", st["remember_bps"])
        changed, st["viewports"] = imgui.checkbox("Allow floating OS windows (viewports)", st["viewports"])
        if changed:
            self.toast("Applies on next start", "info")
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        changed, v = imgui.slider_float("Idle FPS", float(st["fps_idle"]), 5.0, 60.0, "%.0f")
        if changed:
            st["fps_idle"] = round(v)
            hello_imgui.get_runner_params().fps_idling.fps_idle = st["fps_idle"]
        imgui.separator_text("Files")
        imgui.text_disabled(f"settings: {st.path}")

    def tool_labels(self) -> list[str]:
        return [lbl for lbl, *_ in self.tool_windows()]

    def tool_windows(self):
        return [
            (f"{fa.ICON_FA_TERMINAL} Console", self.console_gui, "Bottom", True),
            (f"{fa.ICON_FA_KEYBOARD} Program I/O", self.io_gui, "Bottom", True),
            (f"{fa.ICON_FA_MEMORY} Memory", self.memory_gui, "MainDockSpace", True),
            (f"{fa.ICON_FA_MAP} VMMap", self.vmmap_gui, "RightBottom", True),
            (f"{fa.ICON_FA_CIRCLE_DOT} Breakpoints", self.breakpoints_gui, "RightBottom", True),
            (f"{fa.ICON_FA_BOOK} Commands", self.commands_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_SLIDERS} pwndbg Config", self.config_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_HASHTAG} Pattern (cyclic)", self.cyclic_gui, "RightBottom", False),
            (f"{fa.ICON_FA_GEAR} Preferences", self.prefs_gui, "RightBottom", False),
        ]

    # ── overlays: palette, modals, toasts ───────────────────────────────
    def palette_items(self) -> list[tuple[str, str, object]]:
        items = []
        for label, icon, shortcut, enabled, cb in self.actions():
            if enabled:
                items.append((f"{getattr(fa, 'ICON_FA_' + icon)}  {label}", shortcut, cb))
        for sec in self.sections.values():
            items.append((f"Show  {sec['label']}", "window", lambda l=sec["label"]: self.focus_window(l)))
        for label in self.tool_labels():
            items.append((f"Show  {label}", "window", lambda l=label: self.focus_window(l)))
        for th in THEMES.values():
            items.append((f"{fa.ICON_FA_PALETTE}  Theme: {th.name}", "theme", lambda t=th: self.apply_theme(t)))
        for group, presets in TOOL_PRESETS:
            for cmd, name in presets:
                if self.pwndbg_has(name):
                    items.append((f"{fa.ICON_FA_TABLE_CELLS}  View: {cmd}", group, lambda c=cmd: self.open_cmd_view(c)))
        for c in self.commands or []:
            items.append((f"{fa.ICON_FA_TERMINAL}  {c['name']} — {c['desc']}", c["cat"],
                          lambda c=c: self._palette_command(c)))
        return items

    def _palette_command(self, c) -> None:
        if imgui.get_io().key_shift:
            self.open_cmd_view(c["name"])
        else:
            self.console_replace = c["name"] + " "
            self.focus_window(f"{fa.ICON_FA_TERMINAL} Console")
            self.focus_console = True

    def palette(self) -> None:
        if self.palette_open:
            imgui.open_popup("##palette")
            self.palette_open = False
            self.palette_query = ""
            self.palette_sel = 0
            self._palette_focus = True
        vp = imgui.get_main_viewport()
        w = min(720.0, vp.size.x * 0.7)
        imgui.set_next_window_pos(ImVec2(vp.pos.x + (vp.size.x - w) / 2, vp.pos.y + vp.size.y * 0.12), imgui.Cond_.always)
        imgui.set_next_window_size(ImVec2(w, 0), imgui.Cond_.always)
        if not imgui.begin_popup("##palette"):
            return
        if getattr(self, "_palette_focus", False):
            imgui.set_keyboard_focus_here()
            self._palette_focus = False
        imgui.set_next_item_width(-1)
        changed, self.palette_query = imgui.input_text_with_hint(
            "##palq", "Type a command, window, theme or pwndbg command…  (Shift+Enter: open as view)", self.palette_query)
        if changed:
            self.palette_sel = 0
        q = self.palette_query.lower().split()
        scored = []
        for label, hint, cb in self.palette_items():
            low = label.lower()
            if all(t in low for t in q):
                score = sum(low.find(t) for t in q) + len(low) * 0.01
                scored.append((score, label, hint, cb))
        scored.sort(key=lambda s: s[0])
        scored = scored[:14]
        K = imgui.Key
        if imgui.is_key_pressed(K.down_arrow):
            self.palette_sel = min(self.palette_sel + 1, len(scored) - 1)
        if imgui.is_key_pressed(K.up_arrow):
            self.palette_sel = max(self.palette_sel - 1, 0)
        run = None
        for i, (_, label, hint, cb) in enumerate(scored):
            clicked, _ = imgui.selectable(f"{label}##pal{i}", i == self.palette_sel)
            if hint:
                imgui.same_line(w - imgui.calc_text_size(hint).x - 24)
                imgui.text_disabled(hint)
            if clicked:
                run = cb
        if scored and (imgui.is_key_pressed(K.enter) or imgui.is_key_pressed(K.keypad_enter)):
            run = scored[min(self.palette_sel, len(scored) - 1)][3]
        if run is not None:
            run()
            imgui.close_current_popup()
        if imgui.is_key_pressed(K.escape):
            imgui.close_current_popup()
        imgui.end_popup()

    def modals(self) -> None:
        m = self.modal
        if m is None:
            return
        titles = {
            "args": "Run with arguments", "setreg": f"Set ${m.get('reg', '')}", "newview": "New command view",
            "console": m.get("title", ""), "help": "Keyboard shortcuts",
        }
        title = titles.get(m["kind"], "") + "##modal"
        if not imgui.is_popup_open(title):
            imgui.open_popup(title)
        vp = imgui.get_main_viewport()
        imgui.set_next_window_pos(vp.get_center(), imgui.Cond_.appearing, ImVec2(0.5, 0.5))
        opened, _ = imgui.begin_popup_modal(title, True, imgui.WindowFlags_.always_auto_resize)
        if not opened:
            self.modal = None
            return
        done = False
        if m["kind"] == "help":
            rows = [
                ("F5", "Continue (Run when not started)"), ("Ctrl+F5", "Run / restart"), ("Shift+F5", "Kill"),
                ("F6", "Pause (interrupt)"), ("F7 / F8", "Step into / over (instruction)"),
                ("Shift+F7 / Shift+F8", "Step / next (source line)"), ("Ctrl+F7", "Step out (finish)"),
                ("Ctrl+P", "Command palette"), ("Ctrl+G", "Go to address (Memory)"), ("Ctrl+`", "Focus console"),
                ("Ctrl+= / Ctrl+- / Ctrl+0", "Zoom code font"), ("Ctrl+wheel", "Zoom code font"),
                ("Ctrl+F / F3", "Find in a text pane"), ("Ctrl+C / Ctrl+A", "Copy / select all in a text pane"),
                ("Ctrl+click address", "Open address in Memory"), ("Right-click", "Context actions everywhere"),
                ("Click the gutter", "Toggle breakpoint (Disassembly, Source)"),
                ("Double-click", "Select frame (Backtrace) / thread (Threads)"),
                ("Tab / Up / Down (console)", "Complete / history; empty Enter repeats the last command"),
                ("Ctrl+L (console)", "Clear console"),
            ]
            if imgui.begin_table("##keys", 2, imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_h):
                for k, d in rows:
                    imgui.table_next_row()
                    imgui.table_next_column()
                    imgui.text_colored(v4(self.theme.accent), k)
                    imgui.table_next_column()
                    imgui.text_unformatted(d)
                imgui.end_table()
            done = imgui.button("Close") or imgui.is_key_pressed(imgui.Key.escape)
        else:
            hints = {
                "args": "arguments, e.g.  AAAA $(python3 -c 'print(1)') < input.txt",
                "setreg": "value or expression",
                "newview": "any gdb / pwndbg command, e.g. telescope $rdi 20",
                "console": "argument",
            }
            if m.get("focus"):
                imgui.set_keyboard_focus_here()
                m["focus"] = False
            imgui.set_next_item_width(imgui.get_font_size() * 28)
            entered, m["value"] = imgui.input_text_with_hint("##mv", hints[m["kind"]], m["value"], imgui.InputTextFlags_.enter_returns_true)
            ok = imgui.button("OK", ImVec2(90, 0)) or entered
            imgui.same_line()
            cancel = imgui.button("Cancel", ImVec2(90, 0)) or imgui.is_key_pressed(imgui.Key.escape)
            if ok:
                v = m["value"].strip()
                if m["kind"] == "args":
                    self.args_input = v
                    self.settings.binary(self.cfg.binary)["args"] = v
                    self.send_console(f"run {v}" if v else "run")
                elif m["kind"] == "setreg" and v:
                    self.exec(f"set ${m['reg']} = {v}")
                elif m["kind"] == "newview" and v:
                    self.open_cmd_view(v)
                elif m["kind"] == "console" and v:
                    self.send_console(m["prefix"] + v)
            done = ok or cancel
        if done:
            imgui.close_current_popup()
            self.modal = None
        imgui.end_popup()

    def draw_toasts(self) -> None:
        now = time.monotonic()
        self.toasts = [t for t in self.toasts if now - t["t0"] < t["ttl"]]
        if not self.toasts:
            return
        th = self.theme
        vp = imgui.get_main_viewport()
        y = vp.pos.y + vp.size.y - 46
        colors = {"info": th.accent2, "ok": th.green, "warn": th.yellow, "error": th.red}
        for i, t in enumerate(reversed(self.toasts)):
            age = now - t["t0"]
            alpha = min(1.0, age * 6, (t["ttl"] - age) * 2)
            imgui.set_next_window_pos(ImVec2(vp.pos.x + vp.size.x - 18, y), imgui.Cond_.always, ImVec2(1, 1))
            imgui.set_next_window_bg_alpha(0.95 * alpha)
            imgui.push_style_var(imgui.StyleVar_.alpha, max(0.0, alpha))
            imgui.push_style_var(imgui.StyleVar_.window_rounding, 8.0)
            imgui.push_style_var(imgui.StyleVar_.window_padding, ImVec2(14, 9))
            imgui.push_style_color(imgui.Col_.border, v4(colors.get(t["kind"], th.accent), 0.8))
            flags = (imgui.WindowFlags_.no_decoration | imgui.WindowFlags_.always_auto_resize | imgui.WindowFlags_.no_inputs
                     | imgui.WindowFlags_.no_nav | imgui.WindowFlags_.no_focus_on_appearing | imgui.WindowFlags_.no_docking
                     | imgui.WindowFlags_.no_saved_settings)
            imgui.begin(f"##toast{i}", None, flags)
            if t["kind"] in ("warn", "error"):
                imgui.text_colored(v4(colors[t["kind"]]), t["text"])
            else:
                imgui.text_unformatted(t["text"])
            y -= imgui.get_window_height() + 8
            imgui.end()
            imgui.pop_style_color()
            imgui.pop_style_var(3)

    def show_gui(self) -> None:
        self.handle_shortcuts()
        self.palette()
        self.modals()
        self.draw_toasts()
        if self.show_style_editor:
            _, self.show_style_editor = imgui.begin("ImGui style editor", self.show_style_editor)
            imgui.show_style_editor()
            imgui.end()
        if self.show_metrics:
            imgui.show_metrics_window()

    # ── startup / shutdown ──────────────────────────────────────────────
    def spawn_gdb(self) -> None:
        import fcntl
        import subprocess
        import termios

        parent, child = socket.socketpair()
        env = dict(os.environ)
        for var in ("TMUX", "TMUX_PANE", "LINES", "COLUMNS"):
            env.pop(var, None)
        env["TERM"] = "xterm-256color"
        env[ENV_FD] = str(child.fileno())
        env[ENV_TTY] = self.io.path if self.io else ""
        env[ENV_INIT] = self.cfg.init
        me = os.path.realpath(__file__)
        bootstrap = f"python import runpy; runpy.run_path({me!r}, run_name='__pwndbg_imgui_agent__')"
        cmd = [self.cfg.gdb, "-q", "-iex", "set editing off", "-ex", bootstrap] + self.cfg.gdb_args
        self.console.resize(40, 160)

        def preexec() -> None:
            try:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except OSError:
                pass

        slave = self.console.slave
        try:
            self.proc = subprocess.Popen(
                cmd, stdin=slave, stdout=slave, stderr=slave, env=env,
                pass_fds=(child.fileno(),), start_new_session=True, preexec_fn=preexec,
            )
        except FileNotFoundError:
            sys.exit(f"{APP_NAME}: cannot execute gdb ({self.cfg.gdb!r}); use --gdb PATH")
        child.close()
        self.rpc = Rpc(parent)

    def shutdown(self) -> None:
        import signal

        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        inferior = self.state.get("pid") or 0
        attached = any(a in ("-p", "-pid", "--pid") or a.startswith("--pid=") for a in self.cfg.gdb_args)
        # gdb only services our requests while the program is stopped
        if self.is_running():
            self.interrupt()
            time.sleep(0.3)
        if self.connected():
            self.rpc.request("quit")
        for _ in range(30):
            if proc.poll() is not None:
                return
            time.sleep(0.05)
        proc.terminate()
        try:
            proc.wait(1.5)
        except Exception:
            proc.kill()
        if inferior and not attached:
            try:
                os.kill(inferior, signal.SIGKILL)
            except OSError:
                pass

    def build_runner(self):
        rp = hello_imgui.RunnerParams()
        title = APP_NAME + (f" — {os.path.basename(self.cfg.binary)}" if self.cfg.binary else "")
        rp.app_window_params.window_title = title
        rp.app_window_params.window_geometry.size = (1680, 1000)
        rp.app_window_params.restore_previous_geometry = True
        rp.imgui_window_params.default_imgui_window_type = hello_imgui.DefaultImGuiWindowType.provide_full_screen_dock_space
        rp.imgui_window_params.enable_viewports = self.settings["viewports"] and not self.cfg.no_viewports
        rp.imgui_window_params.show_menu_bar = True
        rp.imgui_window_params.show_menu_app = False
        rp.imgui_window_params.show_menu_view = False
        rp.imgui_window_params.show_status_bar = True
        rp.imgui_window_params.show_status_fps = False
        rp.imgui_window_params.remember_status_bar_settings = False
        rp.imgui_window_params.remember_theme = False
        rp.imgui_window_params.background_color = v4(self.theme.bg)
        rp.fps_idling.enable_idling = True
        rp.fps_idling.fps_idle = float(self.settings["fps_idle"])
        rp.ini_folder_type = hello_imgui.IniFolderType.absolute_path
        rp.ini_filename = os.path.join(config_dir(), "layout.ini")
        rp.ini_clear_previous_settings = self.cfg.reset_layout

        cb = rp.callbacks
        cb.load_additional_fonts = self.load_fonts
        cb.setup_imgui_style = self.setup_style
        cb.show_menus = self.show_menus
        cb.show_status = self.status_bar
        cb.show_gui = self.show_gui
        cb.pre_new_frame = self.pre_new_frame
        cb.post_init = self.post_init
        cb.before_exit = self.before_exit
        opts = hello_imgui.EdgeToolbarOptions(size_em=2.35, window_padding_em=ImVec2(0.5, 0.25))
        cb.add_edge_toolbar(hello_imgui.EdgeToolbarType.top, self.toolbar, opts)

        D = hello_imgui.DockingSplit
        rp.docking_params.docking_splits = [
            D("MainDockSpace", "Right", imgui.Dir.right, 0.42),
            D("MainDockSpace", "Bottom", imgui.Dir.down, 0.36),
            D("Right", "RightMid", imgui.Dir.down, 0.60),
            D("RightMid", "RightBottom", imgui.Dir.down, 0.45),
        ]
        windows = []
        self.default_visible = {}
        order = ["disasm", "code"]
        for name in order + [n for n in SECTIONS if n not in order]:
            label, _icon, _follow, visible, dock = SECTION_META[name]
            lbl = self.sections[name]["label"]
            dw = hello_imgui.DockableWindow(lbl, dock, self.section_gui(name))
            dw.is_visible = visible
            self.default_visible[lbl] = visible
            windows.append(dw)
        for label, fn, dock, visible in self.tool_windows():
            dw = hello_imgui.DockableWindow(label, dock, fn)
            dw.is_visible = visible
            self.default_visible[label] = visible
            if label.endswith(" Memory"):
                windows.insert(2, dw)
            else:
                windows.append(dw)
        for dw in windows:
            if dw.label in (self.sections["disasm"]["label"], f"{fa.ICON_FA_TERMINAL} Console"):
                dw.focus_window_at_next_frame = True
        rp.docking_params.dockable_windows = windows
        rp.docking_params.main_dock_space_node_flags = imgui.DockNodeFlags_.none
        return rp

    def run(self) -> None:
        self.spawn_gdb()
        rp = self.build_runner()
        try:
            hello_imgui.run(rp)
        finally:
            self.shutdown()


def hexdump_ansi(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = []
        for i, b in enumerate(chunk):
            h = f"{b:02x}"
            if b == 0:
                h = f"\x1b[90m{h}\x1b[0m"
            elif 0x20 <= b < 0x7F:
                h = f"\x1b[32m{h}\x1b[0m"
            hexes.append(h + (" " if i != 7 else "  "))
        pad = "   " * (16 - len(chunk)) + (" " if len(chunk) <= 8 else "")
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "\x1b[90m.\x1b[0m" for b in chunk)
        lines.append(f"\x1b[33m{off:08x}\x1b[0m  {''.join(hexes)}{pad} │{asc}│")
    return "\n".join(lines) + ("\n" if lines else "")


def eval_payload(expr: str) -> bytes:
    """Evaluate a pwntools-like payload expression for Program I/O."""

    def p(bits):
        return lambda v: (v & ((1 << bits) - 1)).to_bytes(bits // 8, "little")

    def flat(*items):
        out = b""
        for it in items:
            if isinstance(it, (list, tuple)):
                out += flat(*it)
            elif isinstance(it, int):
                out += p(64)(it)
            elif isinstance(it, str):
                out += it.encode("latin-1")
            else:
                out += bytes(it)
        return out

    env = {
        "__builtins__": {"bytes": bytes, "bytearray": bytearray, "int": int, "len": len, "range": range,
                         "chr": chr, "ord": ord, "hex": hex, "str": str, "list": list, "sum": sum},
        "p8": p(8), "p16": p(16), "p32": p(32), "p64": p(64), "flat": flat,
        "u32": lambda b: int.from_bytes(b[:4].ljust(4, b"\0"), "little"),
        "u64": lambda b: int.from_bytes(b[:8].ljust(8, b"\0"), "little"),
        "cyclic": lambda n, k=4: cyclic(n, k),
    }
    value = eval(expr, env)  # the user's own payload expression
    if isinstance(value, str):
        return value.encode("latin-1")
    if isinstance(value, int):
        return p(64)(value)
    if isinstance(value, (list, tuple)):
        return flat(*value)
    return bytes(value)


# ════════════════════════════════════════════════════════════════════════════
#  Command line
# ════════════════════════════════════════════════════════════════════════════
def usage() -> str:
    return f"""\
usage: {os.path.basename(sys.argv[0])} [GUI options] [gdb arguments...]

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
  --reset-layout      start with the default window layout
  --list-themes       list themes and exit
  -h, --help          show this help

By default pwndbg is loaded from your gdbinit, else with a user-defined
`init-pwndbg` command, else from $PWNDBG_PATH or ~/.local/share/pwndbg.
Settings and layout live in {config_dir()}.
""".replace("%(prog)s", os.path.basename(sys.argv[0]))


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


def gui_main(argv: list[str]) -> int:
    global imgui, hello_imgui, ImVec2, ImVec4, fa
    cfg = parse_args(argv)
    try:
        from imgui_bundle import ImVec2 as _V2, ImVec4 as _V4, hello_imgui as _hi, icons_fontawesome_6 as _fa, imgui as _im
    except ImportError:
        print(f"{APP_NAME}: the GUI needs imgui-bundle:  pip install imgui-bundle", file=sys.stderr)
        return 1
    imgui, hello_imgui, ImVec2, ImVec4, fa = _im, _hi, _V2, _V4, _fa
    app = App(cfg)
    app.run()
    return 0


if __name__ == "__pwndbg_imgui_agent__":
    _agent_main()
elif __name__ == "__main__":
    sys.exit(gui_main(sys.argv[1:]))
