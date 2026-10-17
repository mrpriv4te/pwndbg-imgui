"""Composite views: command output, decompiler, memory."""

from __future__ import annotations

import os
import re
import struct
import time

from imgui_bundle import ImVec2, imgui
from imgui_bundle import icons_fontawesome_6 as fa

from ..term import Term, strip_ansi
from ..theme import u32
from .catalog import arg_regs
from .widgets import TextView, ansi_inline, combo_width, v4

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


class DecompView:
    """Whole-function decompilation from pwndbg's decompiler integration
    (decomp2dbg: Ghidra, IDA, Binary Ninja, angr)."""

    LABEL = "Decompiler"

    def __init__(self, app) -> None:
        self.app = app
        self.term = Term(max_lines=20000)
        self.view = TextView(app, self.term, "decomp", follow="pc", empty_hint=self.hint)
        self.view.lockable = True
        self.status: dict = {}
        self.error = ""
        self.follow_pc = True
        self.target = ""  # expression decompiled when not following $pc
        self.title = ""
        self.last_seen = 0.0
        self.stale = True
        self.busy = False
        self.auto_tried = False

    def hint(self) -> str:
        if self.error:
            return self.error
        if not self.status.get("available", True):
            return "This pwndbg has no decompiler integration."
        if not self.status.get("connected"):
            return ("Not connected to a decompiler.\n\nOpen the binary in Ghidra / IDA / Binary Ninja / angr with the "
                    "decomp2dbg plugin started (Ghidra: Ctrl+Shift+D), then press Connect.\n"
                    "Install the plugin with `di install ghidra` (or ida, binja, angr).")
        if not self.app.is_stopped():
            return "Waiting for the program to stop…"
        return "No decompilation for this address."

    def refresh_status(self, then=None) -> None:
        def done(st):
            self.status = st
            if then:
                then()

        if self.app.rpc:
            self.app.rpc.request("decomp_status", done, None)

    def refresh(self) -> None:
        """Re-decompile now if visible, otherwise when it next is."""
        if time.monotonic() - self.last_seen < 0.5:
            self.fetch()
        else:
            self.stale = True

    def fetch(self) -> None:
        app = self.app
        self.stale = False
        if not app.rpc or not app.is_stopped() or self.busy:
            return
        if not self.status.get("connected"):
            self.refresh_status(lambda: self.status.get("connected") and self.fetch())
            return
        self.busy = True

        def done(res):
            self.busy = False
            self.error = ""
            if not res.get("connected"):
                self.status["connected"] = False
                self.term.clear()
                return
            lines = res.get("lines")
            if lines is None:
                self.term.clear()
                self.error = f"The decompiler returned nothing for {res['addr']:#x}."
                return
            self.title = res.get("sym") or f"{res['addr']:#x}"
            self.term.set_text("\n".join(lines))
            if not self.follow_pc:
                self.view.pending_scroll = 0

        def fail(err):
            self.busy = False
            self.term.clear()
            self.error = f"Decompilation failed: {err}"
            self.refresh_status()

        if self.follow_pc or not self.target.strip():
            app.rpc.request("decompile", done, fail)
        else:
            app.rpc.request("eval", lambda a: app.rpc.request("decompile", done, fail, addr=a),
                            lambda e: fail(e), expr=self.target.strip())

    def connect(self) -> None:
        self.error = ""
        self.app.exec("decompiler-integration connect", refresh=False,
                      cb=lambda _o: self.refresh_status(self.fetch))

    def gui(self) -> None:
        app = self.app
        th = app.theme
        self.last_seen = time.monotonic()
        st = self.status
        connected = bool(st.get("connected"))
        if not st and app.connected() and app.info.get("pwndbg"):
            self.status = {"pending": True}
            self.refresh_status()
        # one automatic connection attempt per session, once the program stops
        if (not connected and st.get("available") and not self.auto_tried and app.is_stopped()
                and app.settings["decomp_autoconnect"]):
            self.auto_tried = True
            self.connect()

        color = th.green if connected else th.dim
        imgui.align_text_to_frame_padding()  # line the status dot/text up with the buttons
        imgui.text_colored(v4(color), fa.ICON_FA_CIRCLE)
        imgui.same_line()
        if connected:
            imgui.text_unformatted(f"{st.get('name')}")
        else:
            imgui.text_disabled(f"not connected ({st.get('host', '?')}:{st.get('port', '?')})")
        imgui.same_line()
        imgui.begin_disabled(not app.is_alive())
        if not connected:
            if imgui.button(f"{fa.ICON_FA_PLUG} Connect"):
                self.connect()
        else:
            if imgui.button(f"{fa.ICON_FA_LINK_SLASH}##dd"):
                app.exec("decompiler-integration disconnect", refresh=False,
                         cb=lambda _o: self.refresh_status(self.term.clear))
            imgui.set_item_tooltip("Disconnect")
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##ds"):
                app.exec("decompiler-integration sync", cb=lambda _o: self.fetch())
            imgui.set_item_tooltip("Sync symbols and variables from the decompiler")
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_CROSSHAIRS}##dj"):
                app.exec("decompiler-integration jump", refresh=False, quiet=True)
            imgui.set_item_tooltip("Move the decompiler's cursor to $pc")
        imgui.end_disabled()
        imgui.same_line()
        changed, self.follow_pc = imgui.checkbox("Follow PC", self.follow_pc)
        if changed and self.follow_pc:
            self.fetch()
        imgui.same_line()
        imgui.set_next_item_width(max(80.0, imgui.get_content_region_avail().x - imgui.calc_text_size("Go").x - 24))
        entered, self.target = imgui.input_text_with_hint(
            "##dtarget", "function / address to decompile (main, 0x401156)", self.target,
            imgui.InputTextFlags_.enter_returns_true)
        imgui.same_line()
        if (imgui.button("Go##dgo") or entered) and self.target.strip():
            self.follow_pc = False
            self.fetch()
        if self.title and self.term.lines and self.term.lines[0].chars:
            imgui.text_disabled(f"{fa.ICON_FA_CODE}  {self.title}" + ("" if self.follow_pc else "   (not following $pc)"))
        self.view.render()
        if self.stale and app.is_stopped():
            self.fetch()


class DisasmTarget:
    """The Disassembly window when it isn't following $pc: the whole function holding a
    chosen address (`nearpc -f`), or, where no function boundaries are known, `nearpc`
    from that address, extended as you scroll past the end like the stack."""

    STEP = 64  # instructions per chunk
    MAX = 4096

    def __init__(self, app) -> None:
        self.app = app
        self.term = Term(max_lines=50000)
        self.view = TextView(app, self.term, "disasmt", follow="pc", empty_hint=self.hint)
        self.view.on_scroll_end = self.more
        self.follow_pc = True
        self.target = ""  # what the user typed
        self.addr: int | None = None  # where it resolved
        self.func = True  # whole function; False: linear from the address
        self.count = self.STEP  # instructions asked for (linear)
        self.end = False  # nearpc returned fewer: undecodable bytes follow
        self.title = ""
        self.error = ""
        self.busy = False
        self.ran_gen = -1
        self.more_t = 0.0

    def hint(self) -> str:
        return self.error or "Type a function or an address, then Go."

    def ready(self) -> bool:
        app = self.app
        return bool(app.rpc) and app.connected() and not app.state.get("running")

    def go(self) -> None:
        """Resolve the typed target once, so `$pc+0x20` stays put across stops."""
        target = self.target.strip()
        if not target or not self.ready():
            return
        self.follow_pc = False
        self.busy = True

        def done(addr: int) -> None:
            self.busy = False
            self.addr, self.func, self.count, self.end = addr, True, self.STEP, False
            self.title = f"{addr:#x}" if target.lower() == f"{addr:#x}" else f"{target}  {addr:#x}"
            self.view.pending_scroll = 0
            self.fetch()

        def fail(err):
            self.busy = False
            self.addr, self.title = None, ""  # forget the previous target: a stop mustn't bring it back
            self.term.clear()
            self.error = f"Cannot evaluate {target!r}: {err}"

        self.app.rpc.request("eval", done, fail, expr=target)

    def fetch(self, keep_scroll: bool = False) -> None:
        if self.addr is None or self.busy or not self.ready():
            return
        app = self.app
        self.busy = True
        self.ran_gen = app.dirty_gen

        def done(out, func=self.func):
            self.busy = False
            self.error = ""
            text = strip_ansi(out or "")
            shown = sum(1 for ln in text.split("\n") if DISASM_ADDR_RE.match(ln))
            if func and not shown:  # "function boundaries of … could not be found"
                self.func = False
                self.fetch(keep_scroll)
                return
            if not shown and text.strip():
                self.term.clear()
                self.error = text.strip()
                return
            self.view.keep_scroll_once = keep_scroll
            self.term.set_text(out or "")
            self.end = not func and shown < self.count
            name = re.search(r"<([^>+]+)", text) if func else None  # the function's name, from its first line
            if name and not self.title.startswith(name.group(1)):
                self.title = f"{name.group(1)}  ·  {self.title}"

        def fail(err, func=self.func):
            self.busy = False
            if func:  # an older pwndbg without `nearpc -f`
                self.func = False
                self.fetch(keep_scroll)
                return
            self.term.clear()
            self.error = f"Disassembly failed: {err}"

        # -n: no branch arrows; -r 0: start at the address itself
        n = "" if app.settings["disasm_branches"] else "-n "
        cmd = f"nearpc {n}-f {self.addr:#x}" if self.func else f"nearpc {n}-r 0 {self.addr:#x} {self.count}"
        app.rpc.request("exec", done, fail, cmd=cmd)

    def more(self) -> None:
        """Scrolled past the end: show the next chunk."""
        now = time.monotonic()
        if self.addr is None or self.func or self.end or self.count >= self.MAX or self.busy or now - self.more_t < 0.4:
            return
        self.more_t = now
        self.count = min(self.MAX, self.count + self.STEP)
        self.fetch(keep_scroll=True)

    def bar(self) -> None:
        """Follow PC + target box, above the Disassembly window."""
        changed, self.follow_pc = imgui.checkbox("Follow PC##dis", self.follow_pc)
        if changed and not self.follow_pc and self.addr is None:
            self.go()
        imgui.same_line()
        st = self.app.settings
        imgui.begin_disabled(self.follow_pc)
        changed, st["disasm_branches"] = imgui.checkbox("Branches##disbr", st["disasm_branches"])
        imgui.end_disabled()
        imgui.set_item_tooltip("Draw branch arrows (nearpc without -n). Only for a chosen function or address:\n"
                               "the Follow PC view follows pwndbg's own settings.")
        if changed:
            self.fetch(keep_scroll=True)
        imgui.same_line()
        imgui.set_next_item_width(max(80.0, imgui.get_content_region_avail().x - imgui.calc_text_size("Go").x - 24))
        entered, self.target = imgui.input_text_with_hint(
            "##distarget", "function / address to disassemble (main, 0x401156)", self.target,
            imgui.InputTextFlags_.enter_returns_true)
        imgui.same_line()
        imgui.begin_disabled(not self.target.strip())
        if imgui.button("Go##disgo") or (entered and self.target.strip()):
            self.go()
        imgui.end_disabled()
        if not self.follow_pc and self.title and not self.error:
            end = ("" if self.func else "   · linear, no function boundaries") + (
                ": stops where the next bytes don't decode" if self.end else "")
            imgui.text_disabled(f"{fa.ICON_FA_CODE}  {self.title}   (not following $pc){end}")

    def gui(self) -> None:
        """The chosen disassembly; re-run after each stop so the ► and breakpoints stay current."""
        if self.ran_gen != self.app.dirty_gen and self.app.is_stopped():
            self.fetch(keep_scroll=True)
        self.view.render()


class MemoryView:
    """Hex / pointer-sized word memory viewer with region coloring, change highlighting,
    in-place editing and a data inspector."""

    def __init__(self, app) -> None:
        self.app = app
        self.expr = "$sp"
        self.follow = ""
        self.base: int | None = None
        self.bpr = 16
        self.mode = "bytes"  # bytes | words (pointer-sized: qwords on 64-bit, dwords on 32-bit)
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

    def read_bytes(self, addr: int, size: int) -> bytes | None:
        """`size` loaded bytes at `addr`, or None if any of them is unknown / unreadable."""
        out = bytearray()
        for i in range(size):
            b = self.byte_at(addr + i)
            if b is None:
                return None
            out.append(b)
        return bytes(out)

    def read_int(self, addr: int, size: int):
        bs = self.read_bytes(addr, size)
        return None if bs is None else int.from_bytes(bs, self.app.endian)

    def mode_label(self, mode: str) -> str:
        return mode if mode == "bytes" else ("qwords" if self.app.ptrsize == 8 else "dwords")

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
        imgui.set_next_item_width(combo_width("follow $x30"))
        if imgui.begin_combo("##follow", f"follow {self.follow}" if self.follow else "no follow"):
            for f in ("", "$sp", "$pc", "$fp", *arg_regs(app.state.get("arch"))):
                if imgui.selectable(f or "no follow", self.follow == f)[0]:
                    self.follow = f
                    if f:
                        self.goto_expr(f)
            imgui.end_combo()
        imgui.set_item_tooltip("Re-evaluate this expression every time the program stops")
        imgui.same_line()
        imgui.set_next_item_width(combo_width("qwords"))
        if imgui.begin_combo("##mmode", self.mode_label(self.mode)):
            for m in ("bytes", "words"):
                if imgui.selectable(self.mode_label(m), self.mode == m)[0]:
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
        dy = app.text_dy  # center the glyphs in their row (see AppearanceMixin.measure)
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
        ws = app.ptrsize  # word mode: one pointer-sized value per cell
        word_w = 2 + 2 * ws  # "0x" + hex digits
        word_cell = word_w + 2
        if self.mode == "bytes":
            cell = 3
            ascii_x = hex_x + (bpr * cell + bpr // 8) * cw + cw
        else:
            cell = 0
            ascii_x = hex_x + (bpr // ws) * word_cell * cw + cw
        mouse = imgui.get_mouse_pos()
        hover_addr = None
        hover_word = None
        dim = u32(th.dim)
        fg = u32(th.fg)
        for r in range(rows):
            addr = self.base + r * bpr
            y = pos.y + r * lh
            page = app.page_for(addr)
            acol = u32(th.kind_color(page[5])) if page else dim
            dl.add_text(ImVec2(pos.x, y + dy), acol, f"{addr:0{digits}x}")
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
                        dl.add_text(ImVec2(x, y + dy), dim, "??")
                    else:
                        if a == self.sel and self.nibble is not None:
                            txt = f"{self.nibble:x}_"
                        else:
                            txt = f"{b:02x}"
                        c = dim if b == 0 else (fg if 0x20 <= b < 0x7F else (u32(th.yellow) if b == 0xFF else u32(th.cyan)))
                        dl.add_text(ImVec2(x, y + dy), c, txt)
                    if x - cw * 0.5 <= mouse.x < x + cw * 2.5 and y <= mouse.y < y + lh:
                        hover_addr = a
            else:
                for q in range(bpr // ws):
                    a = addr + q * ws
                    x = hex_x + q * word_cell * cw
                    v = self.read_int(a, ws)
                    sel = self.sel is not None and a <= self.sel < a + ws
                    if sel:
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + word_w * cw + 2, y + lh), u32(th.accent, 0.35), 3)
                    elif any(self.changed(a + k) for k in range(ws)):
                        dl.add_rect_filled(ImVec2(x - 2, y), ImVec2(x + word_w * cw + 2, y + lh), u32(th.red, 0.28), 3)
                    if v is None:
                        dl.add_text(ImVec2(x, y + dy), dim, "0x" + "?" * (2 * ws))
                    else:
                        vp = app.page_for(v)
                        c = u32(th.kind_color(vp[5])) if vp else (dim if v == 0 else fg)
                        dl.add_text(ImVec2(x, y + dy), c, f"{v:#0{word_w}x}")
                    if x <= mouse.x < x + word_w * cw and y <= mouse.y < y + lh:
                        hover_addr = a
                        hover_word = v
            # ascii column
            chars = []
            for i in range(bpr):
                b = self.byte_at(addr + i)
                chars.append("·" if b is None or not 0x20 <= b < 0x7F else chr(b))
            dl.add_text(ImVec2(ascii_x, y + dy), dim, "".join(chars))
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
                if imgui.get_mouse_clicked_count(0) == 2 and hover_word is not None and app.page_for(hover_word):
                    self.goto(hover_word)
            if imgui.is_mouse_clicked(1):
                self.sel = hover_addr
                imgui.open_popup("##memctx")
            if hover_word is not None and app.page_for(hover_word):
                app.addr_tooltip(hover_word)

        if imgui.is_window_focused() and self.sel is not None:
            self._keys(io)
        imgui.pop_font()
        if imgui.begin_popup("##memctx"):
            if self.sel is not None:  # set by the right-click that opened it
                self._context_menu(app, th, self.sel)
            imgui.end_popup()
        imgui.push_font(app.mono, app.code_size)

    def _context_menu(self, app, th, a: int) -> None:
        imgui.text_colored(v4(th.accent), f"{a:#x}")
        ws = self.app.ptrsize
        q = self.read_int(a & ~(ws - 1) if self.mode == "words" else a, ws)
        if q is not None and app.page_for(q) and imgui.menu_item_simple(f"Follow pointer {q:#x}"):
            self.goto(q)
        imgui.push_id("addr")
        app.address_menu_items(a)
        imgui.pop_id()
        imgui.separator()
        row_bytes = self.read_bytes(a & ~(self.bpr - 1), self.bpr)
        if imgui.menu_item_simple("Copy row as hex") and row_bytes is not None:
            imgui.set_clipboard_text(row_bytes.hex())
        if imgui.menu_item_simple("Copy row as Python bytes") and row_bytes is not None:
            imgui.set_clipboard_text(repr(row_bytes))

    def _keys(self, io) -> None:
        if self.sel is None or self.base is None:
            return
        step = self.app.ptrsize if self.mode == "words" else 1
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
            vals.append(f"f64 {struct.unpack('>d' if app.endian == 'big' else '<d', v8.to_bytes(8, app.endian))[0]:.6g}")
        imgui.push_font(app.mono, app.code_size)
        imgui.text_colored(v4(th.accent), f"{a:#x}")
        imgui.same_line()
        imgui.text_unformatted("  ".join(vals))
        ptr = self.read_int(a, app.ptrsize)
        if ptr is not None and app.page_for(ptr):
            info = app.addr_cache.get(ptr)
            if info is None:
                app.request_addrinfo(ptr)
            elif info.get("chain"):
                imgui.text_disabled("→")
                imgui.same_line()
                ansi_inline(app, info["chain"])
        imgui.pop_font()
