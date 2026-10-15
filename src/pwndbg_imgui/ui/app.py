"""The application: state, gdb process, event handling and the hello_imgui runner."""

from __future__ import annotations

import functools
import json
import os
import re
import socket
import sys
import time

from imgui_bundle import ImVec2, hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from .. import APP_NAME
from .. import agent
from ..agent import ENV_FD, ENV_INIT, ENV_TTY, SECTIONS, debug
from ..fonts import find_mono_fonts
from ..settings import Settings, config_dir
from ..term import Term, strip_ansi
from ..theme import THEMES
from ..transport import Pty, Rpc
from .appearance import AppearanceMixin
from .chrome import ChromeMixin
from .native import NativeWindow
from .panels import PanelsMixin
from .panes import BacktracePane, BreakpointsPane, HeapPane, ThreadsPane, VmmapPane
from .sections import SectionsMixin
from .views import CmdView, DecompView, MemoryView
from .widgets import TextView, ansi_inline, v4


from .catalog import AUTOFIT_HEIGHT, SECTION_META


class App(SectionsMixin, AppearanceMixin, PanelsMixin, ChromeMixin):
    def __init__(self, cfg) -> None:
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
        self._slider_edit: dict[str, float] = {}  # deferred-commit scratch (UI-size slider)
        self._restore_layout_ini: str | None = None  # pending "restore my layout"
        self.char_w = 8.0
        self.line_h = 18.0
        self.text_dy = 2.0
        self.mono = None
        self.mono_bold = None
        self.ui_font = None
        self.fonts = find_mono_fonts()

        self.console_term = Term(max_lines=20000)
        # attached mode (`init-pwndbg-imgui`): gdb runs in the user's terminal, we don't own it
        self.attached = cfg.attach_fd is not None
        self.console = None if self.attached else Pty(self.console_term)
        self.last_console_cmd = ""
        self.io_term = Term(max_lines=20000, show_ctrl=True)
        self.io = None if cfg.no_io else Pty(self.io_term, raw=st["io_raw"], keep_bytes=1 << 20)
        self.io_hex_term = Term(max_lines=100000)
        self.io_hex_version = -1

        self.proc = None
        self.rpc: Rpc | None = None
        self.info: dict = {}
        self.state: dict = {}
        self.bps: list = []
        self.bps_dirty = False  # has the session loaded/created breakpoints? (guards saving an empty list)
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
        self.exit_signal = 0  # SIGINT/SIGTERM received: close at the next frame
        self.last_persist = time.monotonic()
        self.section_extra: dict[str, int] = {"stack": 0}
        self.load_more_t = 0.0
        self.gdb_idle = False  # True while gdb sits at its prompt
        self.native: NativeWindow | None = None  # set when the themed title bar is active
        self.titlebar_drag = None

        self.sections: dict[str, dict] = {}
        for name in SECTIONS:
            label, icon, follow, _vis, _dock = SECTION_META[name]
            term = Term(max_lines=5000)
            view = TextView(self, term, name, follow=follow, empty_hint=functools.partial(self._section_hint, name))
            self.sections[name] = {"term": term, "view": view, "label": f"{getattr(fa, 'ICON_FA_' + icon)} {label}"}
        self._setup_section_hooks()
        self.console_view = TextView(self, self.console_term, "console", follow="bottom")
        self.io_view = TextView(self, self.io_term, "io", follow="bottom",
                                empty_hint="The debugged program's stdin/stdout live here once it runs.")
        self.io_hex_view = TextView(self, self.io_hex_term, "iohex", follow="bottom")
        self.memory = MemoryView(self)
        self.decomp = DecompView(self)
        self.vmmap_pane = VmmapPane(self)
        self.breakpoints_pane = BreakpointsPane(self)
        self.heap_pane = HeapPane(self)
        self.backtrace_pane = BacktracePane(self)
        self.threads_pane = ThreadsPane(self)
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
        self.io_history: list[dict] = [h for h in st["io_history"] if isinstance(h, dict)]
        self.io_history_pos = -1
        self.io_view_mode = "terminal"
        # misc tool state
        self.watch_input = ""
        self.cmd_filter = ""
        self.cmd_selected = None
        self.cfg_filter = ""
        self.cyclic_len = 200
        self.cyclic_n: int | None = None  # None: the target's pointer size (see cyclic_size)
        self.cyclic_value = ""
        self.cyclic_result = ""
        self.palette_open = False
        self.palette_query = ""
        self.palette_sel = 0
        self.modal: dict | None = None
        self.args_input = self.settings.binary(cfg.binary).get("args", "")
        self.show_style_editor = False
        self.show_metrics = False

    def _section_hint(self, name: str) -> str:
        if name == "expressions":
            return "No watch expressions. Add one above (e.g. $sp+8, *(long*)$sp, or a command like `x/8gx $sp`)."
        if not self.is_stopped():
            return "Waiting for the program to stop…"
        if name == "code":
            return "No source available for the current location."
        return "Nothing to show here."

    def connected(self) -> bool:
        return self.rpc is not None and self.rpc.connected

    def is_alive(self) -> bool:
        return bool(self.state.get("alive"))

    def is_stopped(self) -> bool:
        return self.is_alive() and not self.state.get("running")

    @property
    def ptrsize(self) -> int:
        """Pointer size of the target, in bytes (8 until the agent reports it)."""
        return int(self.state.get("ptrsize") or 8)

    @property
    def endian(self) -> str:
        return "big" if self.state.get("endian") == "big" else "little"

    def is_running(self) -> bool:
        return self.is_alive() and bool(self.state.get("running"))

    def io_is_external(self) -> bool:
        """The program's I/O does not flow through our PTY (remote/gdbserver target)."""
        return bool(self.state.get("remote") or self.info.get("remote"))

    def ui_size_slider(self, label: str) -> None:
        """A UI-size slider that only applies on release.

        Changing the UI font live would resize the slider itself under the
        cursor and make the whole UI shake while dragging, so we preview the
        handle with a scratch value and commit to self.ui_size on release.
        """
        pending = self._slider_edit.get(label)
        shown = pending if pending is not None else self.ui_size
        changed, v = imgui.slider_float(label, shown, 10.0, 26.0, "%.0f")
        if changed:
            self._slider_edit[label] = round(v)
        if imgui.is_item_deactivated_after_edit():
            self.ui_size = self._slider_edit.pop(label, self.ui_size)
        elif pending is not None and not imgui.is_item_active():
            self._slider_edit.pop(label, None)  # released without a committed edit

    def toast(self, text: str, kind: str = "info", ttl: float = 3.5, actions: list | None = None,
              key: str | None = None) -> None:
        if key is not None and any(t.get("key") == key for t in self.toasts):
            return  # don't stack the same prompt twice
        self.toasts.append({"text": text, "kind": kind, "t0": time.monotonic(), "ttl": ttl,
                            "actions": actions, "key": key})
        self.toasts = self.toasts[-6:]

    def error_toast(self, err: str) -> None:
        self.toast(err, "error", 5.0)

    def send_console(self, cmd: str) -> None:
        self.gdb_idle = False
        if self.console is not None:
            self.console.write((cmd + "\n").encode())
            return
        # attached mode: run it through the agent and show it like a terminal would
        cmd = cmd or self.last_console_cmd  # empty line repeats, as in gdb
        self.last_console_cmd = cmd
        with self.console_term.lock:
            if self.console_term.col:
                self.console_term.feed("\n")
            self.console_term.feed(f"\x1b[1;31mpwndbg>\x1b[0m {cmd}\n")
        if not cmd or not self.rpc:
            self.gdb_idle = True
            return

        def done(out):
            self.gdb_idle = True
            if out:
                self.console_term.feed(out if out.endswith("\n") else out + "\n")

        def fail(err):
            self.gdb_idle = True
            self.console_term.feed(f"\x1b[31m{err}\x1b[0m\n")

        self.rpc.request("console", done, fail, cmd=cmd)

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

        if self.attached:
            if self.cfg.gdb_pid:
                os.kill(self.cfg.gdb_pid, signal.SIGINT)
        elif self.proc and self.proc.poll() is None:
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
                    debug(f"event {ev}")
                    self.toast(f"internal error in {ev}: {e}", "error")

    def on_hello(self, msg) -> None:
        self.info = msg.get("info", {})
        if self.cfg.binary is None and self.info.get("file"):
            self.cfg.binary = self.info["file"]  # attached mode: learn it from gdb
        if not self.info.get("pwndbg"):
            self.toast("pwndbg was not loaded: context panes are disabled. Use --pwndbg PATH.", "warn", 12)
        self.rpc.request("state", lambda st: self.state.update(st))
        self.rpc.request("commands", self._set_commands)
        self.refresh_checksec()
        self.restore_breakpoints()
        if self.info.get("pwndbg"):
            self.apply_pwndbg_config()
        self.layout_sent = None

    def _set_commands(self, cmds) -> None:
        self.commands = cmds

    # pwndbg config persistence ----------------------------------------------
    # These are driven by the GUI (layout, context routing), so persisting the
    # user's value would fight that logic. Everything else is remembered.
    PERSIST_EVERY = 60.0  # seconds between automatic settings saves

    PWNDBG_CONFIG_DENY = {"context-sections", "context-output", "context-reserve-lines"}

    def persist_pwndbg_param(self, name: str, value: str) -> None:
        if not self.settings["persist_pwndbg_config"] or name in self.PWNDBG_CONFIG_DENY:
            return
        self.settings["pwndbg_config"][name] = value

    def apply_pwndbg_config(self) -> None:
        """Re-apply the pwndbg parameters the user changed in earlier sessions."""
        if not self.settings["persist_pwndbg_config"]:
            return
        for name, value in self.settings["pwndbg_config"].items():
            if name not in self.PWNDBG_CONFIG_DENY:
                self.exec(f"set {name} {value}", refresh=False, quiet=True)

    def on_section(self, msg) -> None:
        name = msg.get("name")
        if name == "legend":
            self.legend = msg.get("text", "").strip()
            return
        sec = self.sections.get(name)
        if sec is not None:
            sec["term"].set_text(msg.get("text", ""))

    def on_state(self, msg) -> None:
        self.gdb_idle = True  # sent right before gdb shows its prompt
        was_alive = self.is_alive()
        self.state = msg.get("state", {})
        if self.is_alive() and not was_alive:
            self.refresh_checksec()
        if self.is_stopped() and self.refreshed_gen != self.dirty_gen:
            self.refreshed_gen = self.dirty_gen
            self.addr_cache.clear()
            self.rpc.request("vmmap", self._set_vmmap)
            self.memory.on_stop()
            if self.decomp.follow_pc:
                self.decomp.refresh()
            for v in self.cmd_views:
                if v.auto and v.ran_gen != -1:
                    v.refresh()

    def on_stop(self, msg) -> None:
        self.dirty_gen += 1
        for name in self.section_extra:
            view = self.sections[name]["view"]
            if not view.locked:  # a locked view keeps the extra lines it loaded
                self.section_extra[name] = 0
                view.keep_scroll_once = False
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
        if self.bps:
            self.bps_dirty = True  # real breakpoints exist this session; safe to persist them
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

    def restore_breakpoints(self) -> None:
        """Offer to re-create the breakpoints saved for this binary (the user
        chooses from a toast; nothing is restored without asking)."""
        if not self.settings["remember_bps"] or self.bps:
            return
        saved = self.settings.binary(self.cfg.binary).get("bps", [])
        if not saved:
            return
        n = len(saved)
        self.toast(
            f"{fa.ICON_FA_CIRCLE_DOT}  Restore {n} saved breakpoint(s)?",
            "info", ttl=12.0, key="restore_bps",
            actions=[("Restore", lambda: self._do_restore_breakpoints(saved)), ("Dismiss", None)],
        )

    def _do_restore_breakpoints(self, saved: list) -> None:
        if self.bps:  # the user added some in the meantime; don't duplicate silently
            return
        self.bps_dirty = True  # a deliberate load: persist whatever the session ends with
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
        self.toast(f"{fa.ICON_FA_CIRCLE_DOT}  Restored {len(saved)} breakpoint(s)", "info", 3.0)

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
        # Don't wipe the saved list when the user dismissed the restore prompt
        # (or quit before deciding): keep remembering them for next time.
        if not out and not self.bps_dirty:
            return
        self.settings.binary(self.cfg.binary)["bps"] = out

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
            if self.section_extra.get(name):
                h = max(h, view.rows) + self.section_extra[name]
            geom[name] = [w, h]
        key = json.dumps([enabled, geom])
        if key == self.layout_sent:
            return
        now = time.monotonic()
        if self.layout_pending[0] != key:
            self.layout_pending = (key, now)
            return
        if now - self.layout_pending[1] < 0.2 and not any(self.section_extra.values()):
            return
        self.layout_sent = key
        self.rpc.request("layout", None, self.error_toast, enabled=enabled, geom=geom)

    # ── user-saved layout (View menu) ───────────────────────────────────
    def has_user_layout(self) -> bool:
        data = self.settings["user_layout"]
        return bool(data and data.get("ini"))

    def save_user_layout(self) -> None:
        dp = hello_imgui.get_runner_params().docking_params
        self.settings["user_layout"] = {
            "ini": imgui.save_ini_settings_to_memory(),
            "visible": {dw.label: dw.is_visible for dw in dp.dockable_windows},
        }
        self.settings.save()
        self.toast(f"{fa.ICON_FA_FLOPPY_DISK}  Current layout saved as your default", "ok", 2.5)

    def restore_user_layout(self) -> None:
        data = self.settings["user_layout"]
        if not data or not data.get("ini"):
            self.toast("No saved layout yet — use “Save current layout” first", "warn", 3.0)
            return
        dp = hello_imgui.get_runner_params().docking_params
        for dw in dp.dockable_windows:
            if dw.label in data.get("visible", {}):
                dw.is_visible = data["visible"][dw.label]
        self._restore_layout_ini = data["ini"]  # applied at the start of the next frame
        self.layout_sent = None
        self.toast(f"{fa.ICON_FA_ROTATE_LEFT}  Your layout restored", "info", 2.5)

    def pre_new_frame(self) -> None:
        self.process_inbox()
        if self.proc is not None and self.proc.poll() is not None and not self.exiting:
            hello_imgui.get_runner_params().app_shall_exit = True
        if self.exit_signal:
            hello_imgui.get_runner_params().app_shall_exit = True
        if time.monotonic() - self.last_persist > self.PERSIST_EVERY and not self.exiting:
            self.persist()
        if self._restore_layout_ini is not None:
            imgui.load_ini_settings_from_memory(self._restore_layout_ini)
            self._restore_layout_ini = None
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
        native = None
        try:
            native = NativeWindow()
        except (OSError, AttributeError):
            pass
        if self.cfg.maximize and native is not None and not native.maximized():
            native.toggle_maximize()  # the restored previous size can override the initial state
        if hello_imgui.get_runner_params().app_window_params.borderless:
            try:
                self.native = native or NativeWindow()
                if not self.native.can_move:
                    self.toast("This Wayland session can't move a borderless window: "
                               "disable the themed title bar in Preferences.", "warn", 10)
            except (OSError, AttributeError) as e:
                self.toast(f"Themed title bar unavailable: {e}", "warn", 6)
        for v in self.settings["views"]:
            if isinstance(v, dict) and v.get("cmd"):
                self.open_cmd_view(v["cmd"], auto=v.get("auto", True), restored=True)

    def before_exit(self) -> None:
        self.exiting = True
        self.persist()

    def persist(self) -> None:
        """Hand the session's state to the settings and write them. Also runs every
        PERSIST_EVERY seconds, so a crash or a forced quit loses little."""
        self.last_persist = time.monotonic()
        self.save_breakpoints()
        st = self.settings
        st["views"] = [{"cmd": v.cmd, "auto": v.auto} for v in self.cmd_views]
        st["console_history"] = self.history
        st["io_history"] = self.io_history
        st["ui_size"] = self.ui_size
        st["code_size"] = self.code_size
        st.binary(self.cfg.binary)["args"] = self.args_input
        st.save()

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
        # gdb runs its own Python (with pwndbg's environment): load the stdlib-only
        # agent from its file instead of exposing this package's environment to it.
        agent_path = os.path.realpath(agent.__file__)
        bootstrap = (
            "python import importlib.util as _u; "
            f"_s = _u.spec_from_file_location('pwndbg_imgui_agent', {agent_path!r}); "
            "_m = _u.module_from_spec(_s); _s.loader.exec_module(_m); _m.main()"
        )
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

        if self.attached:
            # leave gdb running: closing the socket makes the agent give the
            # context back to the user's terminal
            if self.rpc:
                try:
                    self.rpc.sock.close()
                except OSError:
                    pass
            return

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
        if self.cfg.maximize:
            rp.app_window_params.window_geometry.window_size_state = hello_imgui.WindowSizeState.maximized
        if self.settings["custom_titlebar"]:
            # we draw the title bar ourselves (see titlebar()); keep hello_imgui's resize handling
            rp.app_window_params.borderless = True
            rp.app_window_params.borderless_movable = False
            rp.app_window_params.borderless_closable = False
            rp.app_window_params.borderless_resizable = True
            rp.app_window_params.borderless_highlight_color = v4(self.theme.accent, 0.35)
        rp.imgui_window_params.default_imgui_window_type = hello_imgui.DefaultImGuiWindowType.provide_full_screen_dock_space
        rp.imgui_window_params.enable_viewports = self.settings["viewports"] and not self.cfg.no_viewports
        rp.imgui_window_params.show_menu_bar = True
        rp.imgui_window_params.show_menu_app = False
        rp.imgui_window_params.show_menu_view = False
        # the status bar is an edge toolbar like the top one (hello_imgui's own status bar
        # has its own rounded/outlined style)
        rp.imgui_window_params.show_status_bar = False
        rp.imgui_window_params.show_status_fps = False
        rp.imgui_window_params.remember_status_bar_settings = False
        rp.imgui_window_params.remember_theme = False
        rp.imgui_window_params.background_color = v4(self.theme.bg)
        rp.fps_idling.enable_idling = True
        rp.fps_idling.fps_idle = float(self.settings["fps_idle"])
        rp.ini_folder_type = hello_imgui.IniFolderType.absolute_path
        rp.ini_filename = os.path.join(config_dir(), "layout.ini")
        rp.ini_clear_previous_settings = self.cfg.reset_layout
        sanitize_window_geometry(rp.ini_filename)

        cb = rp.callbacks
        cb.load_additional_fonts = self.load_fonts
        cb.setup_imgui_style = self.setup_style
        cb.show_menus = self.show_menus
        cb.show_gui = self.show_gui
        cb.pre_new_frame = self.pre_new_frame
        cb.post_init = self.post_init
        cb.before_exit = self.before_exit
        opts = hello_imgui.EdgeToolbarOptions(size_em=2.35, window_padding_em=ImVec2(0.5, 0.25))
        cb.add_edge_toolbar(hello_imgui.EdgeToolbarType.top, self.toolbar, opts)
        status = hello_imgui.EdgeToolbarOptions(size_em=1.6, window_padding_em=ImVec2(0.6, 0.2))
        cb.add_edge_toolbar(hello_imgui.EdgeToolbarType.bottom, self.status_bar, status)

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
            if label.endswith((" Memory", DecompView.LABEL)):
                windows.insert(2, dw)
            else:
                windows.append(dw)
        for dw in windows:
            if dw.label in (self.sections["disasm"]["label"], f"{fa.ICON_FA_TERMINAL} Console"):
                dw.focus_window_at_next_frame = True
        rp.docking_params.dockable_windows = windows
        rp.docking_params.main_dock_space_node_flags = imgui.DockNodeFlags_.none
        return rp

    def on_exit_signal(self, signum, _frame) -> None:
        """Ctrl-C / SIGTERM in the launching terminal: close like the window's close
        button (settings saved, gdb stopped). A second Ctrl-C forces it."""
        import signal

        if self.exit_signal:
            signal.signal(signal.SIGINT, signal.SIG_DFL)  # a third one kills outright
            raise KeyboardInterrupt
        self.exit_signal = signum
        hint = " (Ctrl-C again to force)" if signum == signal.SIGINT else ""
        print(f"\n{APP_NAME}: closing...{hint}", file=sys.stderr)

    def run(self) -> int:
        """Run until the window closes; returns the process exit status."""
        import signal

        previous = {s: signal.signal(s, self.on_exit_signal) for s in (signal.SIGINT, signal.SIGTERM)}
        rp = None
        try:
            if self.attached:
                self.rpc = Rpc(socket.socket(fileno=self.cfg.attach_fd))
            else:
                self.spawn_gdb()
            rp = self.build_runner()
            hello_imgui.run(rp)
        finally:
            self.shutdown()
            if rp is not None:
                sanitize_window_geometry(rp.ini_filename)  # e.g. closed while minimized
            for s, handler in previous.items():
                signal.signal(s, handler)
        return 128 + self.exit_signal if self.exit_signal else 0


def sanitize_window_geometry(ini_path: str) -> None:
    """Drop a saved main-window geometry that would make the window unusable.

    hello_imgui saves the window size on exit; when the app was minimized it
    records 1x1, and every later launch would open an invisible window."""
    try:
        with open(ini_path) as f:
            lines = f.read().split("\n")
    except OSError:
        return
    section = ""
    bad = False
    for line in lines:
        if line.startswith("["):
            section = line
        elif section == "[AppWindow]" and line.startswith(("WindowSize=", "WindowPosition=")):
            try:
                x, y = (int(float(v)) for v in line.split("=", 1)[1].split(","))
            except ValueError:
                bad = True
                continue
            if line.startswith("WindowSize=") and (x < 400 or y < 300):
                bad = True
            if line.startswith("WindowPosition=") and (x < -10000 or y < -10000):
                bad = True
    if not bad:
        return
    out, section = [], ""
    for line in lines:
        if line.startswith("["):
            section = line
        if section == "[AppWindow]" and line.startswith(("WindowSize=", "WindowPosition=")):
            continue
        out.append(line)
    try:
        with open(ini_path, "w") as f:
            f.write("\n".join(out))
    except OSError:
        pass
