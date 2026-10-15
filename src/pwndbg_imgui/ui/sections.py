"""Behavior specific to each pwndbg context pane (gutters, context menus)."""

from __future__ import annotations

import os
import re
import time

from imgui_bundle import imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..registers import register_cells
from ..term import strip_ansi
from ..theme import u32
from .views import CODE_LINE_RE, DISASM_ADDR_RE, FRAME_RE, REG_WORD_RE, THREAD_RE, WATCH_RE


class SectionsMixin:
    """Behavior specific to each pwndbg context pane (gutters, context menus)."""

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
        self.sections["regs"]["view"].row_tint = self._regs_tint
        self.sections["stack"]["view"].on_scroll_end = lambda: self.load_more("stack")
        for name in ("regs", "stack", "backtrace", "args", "expressions", "threads", "heap_tracker", "last_signal"):
            self.sections[name]["view"].lockable = True
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
        if ctx.get("addr") != a and imgui.menu_item_simple(fa.ICON_FA_CIRCLE_DOT + "  Toggle breakpoint"):
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

    def _regs_tint(self, text: str):
        """Tint the registers that changed since the previous stop: the whole row with one
        register per line, only that register's cell with show-compact-regs columns."""
        changed = self.state.get("changed_regs")
        if not changed:
            return None
        cells = register_cells(text, self.state.get("reg_names") or changed)
        tint = u32(self.theme.red, 0.14)
        if len(cells) == 1:
            return [(0, None, tint)] if cells[0][2] in changed else None
        return [(s, e, tint) for s, e, name in cells if name in changed]

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

    def load_more(self, name: str) -> None:
        """Scrolling past the end of the stack asks pwndbg for more lines."""
        now = time.monotonic()
        if not self.is_stopped() or now - self.load_more_t < 0.4:
            return
        self.load_more_t = now
        view = self.sections[name]["view"]
        self.section_extra[name] += max(8, view.rows)
        view.keep_scroll_once = True
        self.layout_pending = (None, 0.0)
