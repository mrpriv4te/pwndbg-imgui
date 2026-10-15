"""gdb-side agent: runs inside gdb's embedded Python (standard library only).

It is loaded by gdb from its file path (not imported from the pipx environment, whose
packages must not leak into pwndbg's), loads pwndbg if needed, redirects every context
section to the GUI and answers JSON requests over a socketpair inherited from the GUI.
"""

# pyright: reportMissingImports=false, reportMissingModuleSource=false
# (gdb and pwndbg only exist inside gdb's own Python)

from __future__ import annotations

import functools
import json
import os
import socket
import sys
import threading
from typing import Any

APP_NAME = "pwndbg-imgui"

REPO_URL = "https://github.com/mrpriv4te/pwndbg-imgui"

ENV_FD = "PWNDBG_IMGUI_FD"


ENV_TTY = "PWNDBG_IMGUI_TTY"


ENV_INIT = "PWNDBG_IMGUI_INIT"


ENV_DEBUG = "PWNDBG_IMGUI_DEBUG"


def debug_log_path() -> str:
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(cache, f"{APP_NAME}-debug.log")


def debug_enabled() -> bool:
    return bool(os.environ.get(ENV_DEBUG))


def debug(where: str) -> None:
    """Log the exception being handled, with $PWNDBG_IMGUI_DEBUG set (`--debug`).

    Many errors are deliberately swallowed (a symbol that doesn't resolve, a
    section that can't render); this makes them visible when something breaks.
    Shared by both sides: the GUI imports this module, gdb loads it by path."""
    if not os.environ.get(ENV_DEBUG):
        return
    import time
    import traceback

    side = "gui" if __name__ == "pwndbg_imgui.agent" else "agent"
    exc = traceback.format_exc() if sys.exc_info()[0] is not None else ""
    try:
        path = debug_log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{side} {os.getpid()}] {where}\n{exc}")
    except OSError:
        pass


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


SECTION_LINES_PARAM = {
    "code": "context-code-lines",
    "backtrace": "context-backtrace-lines",
}


CLEAR_SEQ = "\x1b[H\x1b[2J"


# Where a source/classic pwndbg install keeps gdbinit.py. The modern installs
# (install script, uv, Homebrew, Nix, distro packages) ship a `pwndbg` launcher
# that the GUI prefers, so these are only the raw-`gdb` fallback.
PWNDBG_CANDIDATE_PATHS = (
    "~/.local/share/pwndbg/gdbinit.py",
    "~/pwndbg/gdbinit.py",
    "~/tools/pwndbg/gdbinit.py",
    "/usr/share/pwndbg/gdbinit.py",
    "/usr/local/share/pwndbg/gdbinit.py",
    "/opt/pwndbg/gdbinit.py",
)
PWNDBG_CANDIDATE_GLOBS = (
    "~/.local/share/uv/tools/pwndbg/share/pwndbg/gdbinit.py",
    "~/.local/lib/pwndbg-gdb/*/share/pwndbg/gdbinit.py",
    "/usr/local/lib/pwndbg-gdb/*/share/pwndbg/gdbinit.py",
)


class Agent:
    """Bridge between gdb/pwndbg and the GUI.

    `attached` is False when the GUI launched gdb (the GUI owns gdb's terminal) and
    True when the GUI was started from an existing gdb session (`init-pwndbg-imgui`):
    the user's terminal is left alone and the GUI console goes through `op_console`.
    """

    def __init__(self, sock: socket.socket, attached: bool = False) -> None:
        import gdb

        self.gdb = gdb
        self.sock = sock
        self.attached = attached
        self.closed = False
        self.handlers: list[tuple[Any, Any]] = []  # (gdb event registry, callback)
        self.saved_sections: str | None = None
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
        self.gdb.post_event(self.detach)  # the GUI is gone

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
            debug(f"op {op}({req.get('args')})")
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
            # exact name only: gdb would happily run `init-pwndbg` as an abbreviation
            # of another command (like `init-pwndbg-imgui`, which would recurse)
            user_cmds = {line.split(" -- ")[0].strip() for line in self.quiet("help user-defined").splitlines()}
            if "init-pwndbg" in user_cmds:
                candidates.append(("cmd", "init-pwndbg"))
            env_path = os.environ.get("PWNDBG_PATH")
            if env_path:
                candidates.append(("source", os.path.join(env_path, "gdbinit.py")))
            for path in PWNDBG_CANDIDATE_PATHS:
                path = os.path.expanduser(path)
                if os.path.exists(path):
                    candidates.append(("source", path))
            # Modern installs (install script, uv tool) put gdbinit.py under a
            # versioned/opaque prefix; glob for it as a last resort.
            import glob

            for pattern in PWNDBG_CANDIDATE_GLOBS:
                for path in sorted(glob.glob(os.path.expanduser(pattern))):
                    candidates.append(("source", path))

        # gdb only sets __file__ for the outermost sourced script; pwndbg's
        # gdbinit.py relies on it, so hide any outer one while sourcing it.
        # pwndbg's argparse `prog` handling also expects gdb's empty sys.argv[0].
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
            if not data.strip() and name in self.FALLBACKS and self.thread_stopped():
                try:
                    data = getattr(self, self.FALLBACKS[name])()
                except Exception as e:
                    debug(f"section fallback {name}")
                    data = f"\x1b[90m({e})\x1b[0m"
            self.send({"ev": "section", "name": name, "text": data})

        return write

    # pwndbg prints nothing for these sections in common situations
    # (a single thread, $pc not on a call, heap tracking disabled).
    FALLBACKS = {"threads": "fallback_threads", "args": "fallback_args", "heap_tracker": "fallback_heap_tracker"}

    def fallback_threads(self) -> str:
        gdb = self.gdb
        current = gdb.selected_thread()
        lines = []
        for t in sorted(gdb.selected_inferior().threads(), key=lambda t: t.num):
            if not t.is_valid():
                continue
            marker = "\x1b[32m\u25ba\x1b[0m" if t == current else " "
            if t.is_running():
                status = "\x1b[92mrunning\x1b[0m"
            elif t.is_exited():
                status = "\x1b[90mexited\x1b[0m"
            else:
                status = "\x1b[33mstopped\x1b[0m"
            where = ""
            if t == current and t.is_stopped():
                frame = gdb.selected_frame()
                sym = self.op_state().get("sym") or frame.name() or ""
                where = f" \x1b[31m{frame.pc():#x}\x1b[0m" + (f" <{sym}>" if sym else "")
            name = t.name or ""
            lines.append(f" {marker} {t.num:<3} \x1b[36m{name!r}\x1b[0m tid {t.ptid[1]} {status}{where}")
        return "\n".join(lines)

    def fallback_args(self) -> str:
        out = ""
        try:
            frame = self.gdb.selected_frame()
            if frame.function() is not None:
                out = self.quiet("info args").rstrip()
        except self.gdb.error:
            pass
        hint = "\x1b[90mpwndbg lists call arguments when $pc is on a call instruction.\x1b[0m"
        return f"{out}\n\n{hint}" if out else hint

    def fallback_heap_tracker(self) -> str:
        return ("\x1b[90mHeap tracking is disabled.\n"
                "Enable it with `track-heap enable` (button above) to detect use-after-free,\n"
                "double free and other misuse of the glibc allocator.\x1b[0m")

    def start(self) -> None:
        gdb = self.gdb
        if self.attached:
            # gdb belongs to the user's terminal: only what the GUI cannot work without.
            # In tmux, a user `init-pwndbg` may split panes for the context (splitmind):
            # pointless with the GUI, so hide tmux while pwndbg loads.
            tmux = {k: os.environ.pop(k) for k in ("TMUX_PANE",) if k in os.environ}
            try:
                self.load_pwndbg("auto")
            finally:
                os.environ.update(tmux)
            self.quiet("set pagination off")
        else:
            tty = os.environ.pop(ENV_TTY, "")
            spec = os.environ.pop(ENV_INIT, "auto")
            for var in (ENV_FD, ENV_TTY, ENV_INIT):
                self.quiet(f"unset environment {var}")
            self.load_pwndbg(spec)
            for cmd in ("set editing off", "set pagination off", "set confirm off", "set height 0", "set width 0"):
                self.quiet(cmd)
            if tty:
                self.quiet(f"set inferior-tty {tty}")

        if self.pwndbg_loaded():
            import pwndbg
            import pwndbg.commands.context as ctx

            self.pwndbg = pwndbg
            self.ctx = ctx
            self.saved_sections = ctx.config_context_sections.value
            for name in SECTIONS + ("legend",):
                self.writers[name] = self.make_writer(name)
                ctx.contextoutput(name, self.writers[name], True, "none", None, None)
            # Nothing is computed until the GUI says which sections are shown.
            ctx.config_context_sections.value = "regs disasm code stack backtrace"
            # The prompt lives in its own pane: no need to reserve terminal lines.
            self.quiet("set context-reserve-lines never")

        ev = gdb.events
        self.listen(ev.stop, self.on_stop)
        self.listen(ev.cont, lambda e: self.send({"ev": "cont"}))
        self.listen(ev.exited, self.on_exited)
        self.listen(ev.new_objfile, lambda e: self.send({"ev": "objfile"}))
        self.listen(ev.breakpoint_created, lambda b: self.send_breakpoints())
        self.listen(ev.breakpoint_modified, lambda b: self.send_breakpoints())
        # fired *before* gdb drops the breakpoint: leave it out explicitly
        self.listen(ev.breakpoint_deleted, lambda b: self.send_breakpoints(exclude=b.number))
        self.listen(ev.memory_changed, lambda e: self.send({"ev": "memory"}))
        self.listen(ev.register_changed, lambda e: self.send({"ev": "memory"}))
        self.listen(ev.before_prompt, self.on_prompt)

        threading.Thread(target=self.reader_loop, name="imgui-agent", daemon=True).start()
        self.send_breakpoints()  # before hello: the GUI only restores saved ones into an empty session
        self.send({"ev": "hello", "info": self.op_info()})
        if self.attached:
            self.send({"ev": "state", "state": self.op_state()})
            self.refresh_context()

    def listen(self, registry, callback) -> None:
        registry.connect(callback)
        self.handlers.append((registry, callback))

    def detach(self) -> None:
        """Undo everything start() did, so the gdb session goes on as before."""
        if self.closed:
            return
        self.closed = True
        for registry, callback in self.handlers:
            try:
                registry.disconnect(callback)
            except Exception:
                debug("disconnect event handler")
        self.handlers.clear()
        if self.ctx is not None:
            for name in self.writers:
                self.ctx.resetcontextoutput(name)
            if self.saved_sections is not None:
                self.ctx.config_context_sections.value = self.saved_sections
        try:
            self.sock.close()
        except OSError:
            pass
        if self.attached:
            print(f"[{APP_NAME}] GUI closed: the context is displayed in this terminal again.")

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
        if self.attached:
            # Commands run from the GUI console resume the program asynchronously,
            # and no prompt follows their stop (neither our state update nor
            # pwndbg's context): publish both once gdb has finished stopping.
            self.gdb.post_event(self.publish_stop)

    def publish_stop(self) -> None:
        if self.closed or not self.thread_stopped():
            return
        self.refresh_context()
        self.send({"ev": "state", "state": self.op_state()})

    def on_exited(self, event) -> None:
        code = getattr(event, "exit_code", None)
        self.send({"ev": "exited", "code": code})

    def on_prompt(self) -> None:
        self.send({"ev": "state", "state": self.op_state()})

    def send_breakpoints(self, exclude: int | None = None) -> None:
        try:
            bps = [b for b in self.op_breakpoints() if b["num"] != exclude]
            self.send({"ev": "bps", "bps": bps})
        except Exception:
            debug("send_breakpoints")

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
            debug(f"vmmap.find({addr:#x})")
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

    def remote_target(self) -> str | None:
        """The gdbserver address (e.g. "localhost:1234") when the inferior runs through a
        remote target, so its stdin/stdout don't go through gdb's inferior-tty (e.g.
        pwntools gdb.debug); None for a local target."""
        try:
            conn = self.gdb.selected_inferior().connection
            if conn is not None and conn.type in ("remote", "extended-remote"):
                return conn.details or conn.type
        except Exception:
            debug("remote_target")
        return None

    def progspace_file(self) -> str | None:
        prog = self.gdb.current_progspace()  # None when gdb has no program space yet
        return prog.filename if prog is not None else None

    def target_layout(self) -> tuple[int, str]:
        """(pointer size in bytes, "little" | "big") of the current target. Also keeps the
        address mask in sync (32-bit targets: ARM, MIPS32, i386...)."""
        size, endian = 8, "little"
        try:
            size = self.gdb.lookup_type("void").pointer().sizeof
        except Exception:
            debug("target_layout: pointer size")
        if "big endian" in self.quiet("show endian"):
            endian = "big"
        self.mask = (1 << (8 * size)) - 1
        return size, endian

    def target_is_remote(self) -> bool:
        return self.remote_target() is not None

    def op_info(self) -> dict:
        gdb = self.gdb
        info = {
            "gdb": gdb.VERSION,
            "pwndbg": None,
            "file": self.progspace_file(),
            "sections": list(SECTIONS),
            "remote": self.target_is_remote(),
            "remote_addr": self.remote_target(),
        }
        if self.pwndbg is not None:
            info["pwndbg"] = getattr(self.pwndbg, "__version__", "loaded")
        return info

    def op_state(self) -> dict:
        gdb = self.gdb
        remote = self.remote_target()
        st: dict = {"alive": False, "running": False, "pid": 0, "remote": remote is not None, "remote_addr": remote}
        try:
            st["file"] = self.progspace_file()
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
                    st["ptrsize"], st["endian"] = self.target_layout()
                    sal = frame.find_sal()
                    if sal.symtab is not None:
                        st["src"] = sal.symtab.fullname()
                        st["line"] = sal.line
                    try:
                        import pwndbg.aglib.symbol

                        st["sym"] = pwndbg.aglib.symbol.resolve_addr(st["pc"])
                    except Exception:
                        debug("state: resolve pc symbol")
                        st["sym"] = st["func"]
                    if self.pwndbg is not None:
                        try:  # registers changed since the previous stop (pwndbg marks them with *)
                            regs = self.pwndbg.aglib.regs
                            st["changed_regs"] = [r.lower() for r in regs.changed]
                            st["reg_names"] = sorted(r.lower() for r in regs.all)  # to find cells
                        except Exception:
                            debug("state: changed registers")
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

    def op_console(self, cmd: str) -> str:
        """Run a command typed in the GUI console (attached mode: gdb's own
        terminal belongs to the user). Execution commands block until the
        program stops, exactly like at the gdb prompt."""
        gdb = self.gdb
        confirm = gdb.parameter("confirm")
        self.quiet("set confirm off")  # a y/n query would wait on the user's terminal
        try:
            out = gdb.execute(cmd, from_tty=True, to_string=True) or ""
        except KeyboardInterrupt:
            out = "Quit\n"
        except gdb.error as e:
            out = f"\x1b[31m{e}\x1b[0m\n"
        finally:
            if confirm:
                self.quiet("set confirm on")
        # no prompt is displayed for these commands: publish what a prompt would
        self.refresh_context()
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

    def symbol_at(self, addr: int) -> str | None:
        """"main+28"-style name for an address (pwndbg's resolver), or None."""
        if self.pwndbg is None:
            return None
        try:
            import pwndbg.aglib.symbol

            return pwndbg.aglib.symbol.resolve_addr(addr) or None
        except Exception:
            debug(f"symbol_at({addr:#x})")
            return None

    def frame_info(self, frame) -> dict:
        """Where a frame is: pc, function, symbol+offset, and source file:line or module."""
        gdb = self.gdb
        pc = frame.pc()
        info: dict = {"pc": pc, "func": frame.name(), "sym": self.symbol_at(pc)}
        sal = frame.find_sal()
        if sal.symtab is not None:
            info["file"], info["line"] = sal.symtab.filename, sal.line
        else:
            lib = gdb.solib_name(pc)  # None: the main program (or no symbols at all)
            info["module"] = os.path.basename(lib or self.progspace_file() or "")
        return info

    def op_frames(self, limit: int = 256) -> dict:
        """The selected thread's call stack, innermost frame first."""
        self.require_stopped()
        gdb = self.gdb
        selected = gdb.selected_frame()
        frames = []
        frame = gdb.newest_frame()
        while frame is not None and len(frames) < limit:
            frames.append({"level": frame.level(), "selected": frame == selected, **self.frame_info(frame)})
            try:
                frame = frame.older()
            except gdb.error:  # unwinding failed further up: show what we have
                frame = None
        return {"frames": frames, "truncated": frame is not None}

    def op_threads(self) -> dict:
        """The inferior's threads, with where each stopped one is. Switches to each thread
        to read its innermost frame, then restores the selected thread and frame."""
        gdb = self.gdb
        current = gdb.selected_thread()
        level = None
        if current is not None and not current.is_running():
            level = gdb.selected_frame().level()
        threads = []
        try:
            for t in sorted(gdb.selected_inferior().threads(), key=lambda t: t.num):
                state = "exited" if t.is_exited() else ("running" if t.is_running() else "stopped")
                entry = {"num": t.num, "name": t.name or "", "tid": t.ptid[1] or t.ptid[2] or t.ptid[0],
                         "state": state, "selected": t == current}
                if state == "stopped":
                    try:
                        t.switch()
                        entry.update(self.frame_info(gdb.newest_frame()))
                    except gdb.error:
                        debug(f"threads: frame of thread {t.num}")
                threads.append(entry)
        finally:
            if current is not None and current.is_valid():
                current.switch()
                if level:
                    frame = gdb.newest_frame()
                    for _ in range(level):
                        frame = frame.older() or frame
                    frame.select()
        return {"threads": threads}

    def op_heap(self, limit: int = 4000) -> dict:
        """The current thread's glibc heap, from pwndbg's own model: every chunk of the
        arena's heaps (address, size, flags, which bin holds it if free) and the non-empty
        bins. Returns {"error": ...} when there is nothing to show yet."""
        self.require_stopped()
        if self.pwndbg is None:
            return {"error": "pwndbg is not loaded."}
        import pwndbg.aglib.heap.glibc as glibc

        try:
            import pwndbg.libc

            libc = pwndbg.libc.which().value  # "glibc" | "musl" | "unknown"
        except Exception:  # an older pwndbg: assume glibc, as its heap commands did
            debug("heap: libc type")
            libc = "glibc"
        if libc != "glibc":
            return {"error": f"The heap view shows glibc's allocator; this program's libc is {libc}."}
        alloc = glibc.get_allocator()
        if not alloc.is_initialized():
            return {"error": "The heap is not initialized yet (the program hasn't called malloc)."}
        arena = alloc.thread_arena
        if arena is None:
            return {"error": "No arena for the current thread."}
        all_bins = [alloc.tcachebins(None) if alloc.has_tcache() else None,
                    alloc.fastbins(arena.address), alloc.unsortedbin(arena.address),
                    alloc.smallbins(arena.address), alloc.largebins(arena.address)]
        all_bins = [b for b in all_bins if b is not None]

        chunks = []
        for heap in arena.heaps:
            for chunk in heap:
                if len(chunks) >= limit:
                    break
                size = chunk.real_size or 0
                where = None
                if chunk.is_top_chunk:
                    where = "top"
                else:
                    for bins in all_bins:
                        if bins.contains_chunk(size, chunk.address):
                            where = bins.bin_type.value
                            break
                chunks.append({"addr": chunk.address, "size": size, "prev_inuse": bool(chunk.prev_inuse),
                               "mmapped": bool(chunk.is_mmapped), "bin": where})
                if chunk.is_top_chunk:
                    break

        bins_out = []
        for bins in all_bins:
            for key, b in bins.bins.items():
                chain = [a for a in b.fd_chain if a]
                if chain or b.count:
                    bins_out.append({"type": bins.bin_type.value, "key": key if isinstance(key, str) else int(key),
                                     "count": b.count, "chain": chain[:16], "corrupted": bool(b.is_corrupted)})
        return {"arena": arena.address, "main": bool(arena.is_main_arena), "chunks": chunks,
                "truncated": len(chunks) >= limit, "bins": bins_out}

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
                    debug(f"addrinfo: chain {a:#x}")
            try:
                info["sym"] = pwndbg.aglib.symbol.resolve_addr(a)
            except Exception:
                debug(f"addrinfo: symbol {a:#x}")
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
                    debug("breakpoints: location")
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
                debug(f"commands: help for {getattr(c, 'command_name', c)}")
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

    def op_watches(self) -> list:
        """pwndbg's context watches (contextwatch), as [expression, "eval" | "execute"]."""
        if self.ctx is None:
            return []
        return [[expr, cmd] for expr, cmd in self.ctx.expressions]

    def op_add_watches(self, watches: list) -> None:
        """Add context watches (saved for this binary), skipping ones already there."""
        if self.ctx is None:
            return
        have = {(expr, cmd) for expr, cmd in self.ctx.expressions}
        for expr, cmd in watches:
            if cmd in ("eval", "execute") and (expr, cmd) not in have:
                self.ctx.expressions.append((expr, cmd))
                have.add((expr, cmd))
        self.refresh_context()

    def op_params(self, names: list) -> dict:
        """Current values of a few pwndbg parameters, by their gdb name (show-flags...)."""
        if self.pwndbg is None:
            return {}
        wanted = set(names)
        return {p.name: p.value for p in self.pwndbg.config.params.values()
                if p.name in wanted and isinstance(p.value, (bool, int, str))}

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
        def as_set_arg(kind: str, v) -> str:  # a value as `set <name> <arg>` takes it
            if kind == "auto" and v is None:
                return "auto"
            if isinstance(v, bool):
                return "on" if v else "off"
            return str(v)

        out = []
        for p in self.pwndbg.config.params.values():
            kind = kinds.get(p.param_class, "int")
            value = p.value
            modified = p.value != p.default
            if kind == "auto":
                value = "auto" if value is None else ("on" if value else "off")
            out.append(
                {
                    "name": p.name,
                    "kind": kind,
                    "value": value if isinstance(value, (bool, int, str)) else str(value),
                    "default": p.pretty_default(),
                    "modified": modified,
                    "reset": as_set_arg(kind, p.default),  # the default, ready for `set`
                    "doc": p.set_show_doc,
                    "help": p.help_docstring,
                    "enum": list(p.enum_sequence or []),
                    "scope": p.scope.name,
                }
            )
        out.sort(key=lambda d: (d["scope"], d["name"]))
        return out

    def op_decomp_status(self) -> dict:
        try:
            import pwndbg.dintegration as di
        except Exception:
            debug("decomp_status: import pwndbg.dintegration")
            return {"available": False, "connected": False}
        m = di.manager
        cfg = self.pwndbg.config if self.pwndbg is not None else None
        return {
            "available": True,
            "connected": m.is_connected(),
            "name": m.decompiler_name() if m.is_connected() else None,
            "host": str(getattr(cfg, "decompiler_host", "")) if cfg is not None else "",
            "port": str(getattr(cfg, "decompiler_port", "")) if cfg is not None else "",
        }

    def op_decompile(self, addr: int | None = None) -> dict:
        """Whole-function decompilation (highlighted, ► on the current line)."""
        self.require_stopped()
        import pwndbg.dintegration as di

        m = di.manager
        if not m.is_connected():
            return {"connected": False, "lines": None}
        if addr is None:
            addr = self.gdb.selected_frame().pc()
        lines = m.decompile_pretty(addr, 1 << 20)  # "all lines" (-1 is not honored)
        sym = None
        try:
            import pwndbg.aglib.symbol

            sym = pwndbg.aglib.symbol.resolve_addr(addr)
        except Exception:
            debug("decompile: resolve symbol")
        return {"connected": True, "name": m.decompiler_name(), "addr": addr, "sym": sym, "lines": lines}

    def op_quit(self) -> None:
        try:
            if self.gdb.selected_inferior().pid:
                self.gdb.execute("kill", to_string=True)
        finally:
            self.gdb.execute("quit")


def main() -> None:
    """Entry point when the GUI launched gdb: the socket fd comes from the environment."""
    fd = int(os.environ.pop(ENV_FD))
    os.set_inheritable(fd, False)  # never leak the socket to the inferior
    Agent(socket.socket(fileno=fd)).start()


_active: list[Agent] = []
_starting: list[bool] = []


def attach(gui_args: str = "") -> None:
    """Start the GUI from inside a running gdb session (the `init-pwndbg-imgui` command).

    `gui_args` (or $PWNDBG_IMGUI_ARGS) are extra GUI options, e.g. "--maximize".
    $PWNDBG_IMGUI_CMD overrides the GUI command (default: `pwndbg-imgui`).
    """
    if _starting:
        return  # re-entered while starting (e.g. through a command abbreviation)
    if _active and not _active[0].closed:
        print(f"[{APP_NAME}] the GUI is already running.")
        return
    _starting.append(True)
    try:
        _attach(gui_args)
    finally:
        _starting.clear()


def _attach(gui_args: str) -> None:
    import shlex
    import subprocess

    parent, child = socket.socketpair()
    cmd = shlex.split(os.environ.get("PWNDBG_IMGUI_CMD", "pwndbg-imgui"))
    cmd += ["--attach", str(child.fileno()), "--gdb-pid", str(os.getpid())]
    cmd += shlex.split(gui_args or os.environ.get("PWNDBG_IMGUI_ARGS", ""))
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    os.makedirs(cache, exist_ok=True)
    log_path = os.path.join(cache, f"{APP_NAME}.log")
    try:
        with open(log_path, "ab") as log:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             pass_fds=(child.fileno(),), start_new_session=True)
    except OSError as e:
        parent.close()
        print(f"[{APP_NAME}] cannot start `{cmd[0]}` ({e}). Is pwndbg-imgui installed and on PATH? "
              f"See {REPO_URL}")
        return
    finally:
        child.close()
    agent = Agent(parent, attached=True)
    _active[:] = [agent]
    agent.start()
    print(f"[{APP_NAME}] GUI started (log: {log_path}). Closing it gives the context back to this terminal.")
