"""Menus, toolbar, title bar, status bar, palette, dialogs and toasts."""

from __future__ import annotations

import os
import time

from imgui_bundle import ImVec2, hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from .. import APP_NAME, __version__
from ..settings import Settings
from ..theme import THEMES, Theme, mix, u32
from .catalog import TOOL_PRESETS
from .widgets import ansi_inline, v4, vsep


class ChromeMixin:
    """Menus, toolbar, title bar, status bar, palette, dialogs and toasts."""

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

    def show_menus(self) -> None:
        dp = hello_imgui.get_runner_params().docking_params
        if self.native is not None:
            # menu bars lay items out horizontally on their own (same_line() misbehaves there)
            imgui.text_colored(v4(self.theme.accent), f"{fa.ICON_FA_BUG} pwndbg")
            imgui.dummy(ImVec2(4, 0))
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
            self.ui_size_slider("UI size")
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
            imgui.text_disabled(f"{APP_NAME} {__version__}")
            imgui.text_disabled(f"pwndbg {self.info.get('pwndbg') or 'not loaded'}")
            imgui.text_disabled(f"gdb {self.info.get('gdb', '?')}")
            imgui.end_menu()
        if self.native is not None:
            self.titlebar()

    def titlebar(self) -> None:
        """Rest of the themed title bar: centered title, window buttons, dragging."""
        nw = self.native
        th = self.theme
        bar_h = imgui.get_window_height()
        win_w = imgui.get_window_width()
        btn_w = round(bar_h * 1.45)
        controls_w = btn_w * 3

        title = APP_NAME + (f"  —  {os.path.basename(self.cfg.binary)}" if self.cfg.binary else "")
        tw = imgui.calc_text_size(title).x
        cx = (win_w - tw) / 2
        if cx > imgui.get_cursor_pos_x() + 24 and cx + tw < win_w - controls_w - 24:
            imgui.set_cursor_pos_x(cx)
            imgui.text_colored(v4(th.fg if nw.focused() else th.dim, 0.85), title)

        # window buttons, full bar height, flush right (explicit positions: menu bar layout)
        imgui.push_style_var(imgui.StyleVar_.frame_rounding, 0.0)
        imgui.push_style_var(imgui.StyleVar_.item_spacing, ImVec2(0, 0))
        imgui.push_style_color(imgui.Col_.button, v4(th.bg, 0.0))
        imgui.push_style_color(imgui.Col_.button_hovered, v4(mix(th.bg, th.fg, 0.12)))
        imgui.push_style_color(imgui.Col_.button_active, v4(mix(th.bg, th.fg, 0.20)))
        size = ImVec2(btn_w, bar_h)
        imgui.set_cursor_pos(ImVec2(win_w - controls_w, 0))
        if imgui.button(f"{fa.ICON_FA_WINDOW_MINIMIZE}##wmin", size):
            nw.iconify()
        imgui.set_item_tooltip("Minimize")
        imgui.set_cursor_pos(ImVec2(win_w - controls_w + btn_w, 0))
        icon = fa.ICON_FA_WINDOW_RESTORE if nw.maximized() else fa.ICON_FA_WINDOW_MAXIMIZE
        if imgui.button(f"{icon}##wmax", size):
            nw.toggle_maximize()
        imgui.set_item_tooltip("Restore" if nw.maximized() else "Maximize")
        imgui.set_cursor_pos(ImVec2(win_w - btn_w, 0))
        imgui.push_style_color(imgui.Col_.button_hovered, v4(th.red, 0.85))
        imgui.push_style_color(imgui.Col_.button_active, v4(th.red))
        if imgui.button(f"{fa.ICON_FA_XMARK}##wclose", size):
            hello_imgui.get_runner_params().app_shall_exit = True
        imgui.set_item_tooltip("Close")
        imgui.pop_style_color(5)
        imgui.pop_style_var(2)

        # drag the empty parts of the bar to move the window, double-click to maximize
        empty = (imgui.is_window_hovered() and not imgui.is_any_item_hovered()
                 and not imgui.is_any_item_active() and not imgui.is_popup_open("", imgui.PopupFlags_.any_popup_id))
        if empty and imgui.is_mouse_double_clicked(0):
            nw.toggle_maximize()
            self.titlebar_drag = None
        elif empty and imgui.is_mouse_clicked(0) and nw.can_move:
            self.titlebar_drag = (nw.cursor(), nw.pos(), False)
        if self.titlebar_drag is not None:
            if imgui.is_mouse_down(0):
                (sx, sy), (wx, wy), moved = self.titlebar_drag
                x, y = nw.cursor()
                if moved or abs(x - sx) + abs(y - sy) > 4:
                    if not moved and nw.maximized():
                        nw.toggle_maximize()  # dragging a maximized window un-maximizes it
                    self.titlebar_drag = ((sx, sy), (wx, wy), True)
                    nw.set_pos(wx + x - sx, wy + y - sy)
            else:
                self.titlebar_drag = None

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
        pad = 12.0
        w = pad + 8 + 8 + imgui.calc_text_size(text).x + pad  # pad | dot | gap | text | pad
        imgui.same_line(max(imgui.get_cursor_pos_x(), imgui.get_window_width() - w - 12))
        dl = imgui.get_window_draw_list()
        x = imgui.get_cursor_screen_pos().x
        h = imgui.get_text_line_height()
        cy = imgui.get_window_pos().y + imgui.get_window_height() / 2  # center of the toolbar
        pill_h = h + 8
        dl.add_rect_filled(ImVec2(x, cy - pill_h / 2), ImVec2(x + w, cy + pill_h / 2), u32(color, 0.16), pill_h / 2)
        dl.add_circle_filled(ImVec2(x + pad + 4, cy), 4.0, u32(color))
        dl.add_text(ImVec2(x + pad + 16, cy - h / 2), u32(color), text)
        imgui.dummy(ImVec2(w, 1))
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
        dismissed = []
        for i, t in enumerate(reversed(self.toasts)):
            actions = t.get("actions")
            age = now - t["t0"]
            # actionable toasts stay opaque until acted on, then fade out
            alpha = min(1.0, age * 6) if actions else min(1.0, age * 6, (t["ttl"] - age) * 2)
            imgui.set_next_window_pos(ImVec2(vp.pos.x + vp.size.x - 18, y), imgui.Cond_.always, ImVec2(1, 1))
            imgui.set_next_window_bg_alpha(0.95 * alpha)
            imgui.push_style_var(imgui.StyleVar_.alpha, max(0.0, alpha))
            imgui.push_style_var(imgui.StyleVar_.window_rounding, 8.0)
            imgui.push_style_var(imgui.StyleVar_.window_padding, ImVec2(14, 9))
            imgui.push_style_color(imgui.Col_.border, v4(colors.get(t["kind"], th.accent), 0.8))
            flags = (imgui.WindowFlags_.no_decoration | imgui.WindowFlags_.always_auto_resize
                     | imgui.WindowFlags_.no_nav | imgui.WindowFlags_.no_focus_on_appearing | imgui.WindowFlags_.no_docking
                     | imgui.WindowFlags_.no_saved_settings)
            if not actions:
                flags |= imgui.WindowFlags_.no_inputs
            imgui.begin(f"##toast{i}", None, flags)
            if t["kind"] in ("warn", "error"):
                imgui.text_colored(v4(colors[t["kind"]]), t["text"])
            else:
                imgui.text_unformatted(t["text"])
            if actions:
                for j, (label, cb) in enumerate(actions):
                    if j:
                        imgui.same_line()
                    if imgui.small_button(f"{label}##toast{i}_{j}"):
                        if cb is not None:
                            cb()
                        dismissed.append(t)
            y -= imgui.get_window_height() + 8
            imgui.end()
            imgui.pop_style_color()
            imgui.pop_style_var(3)
        for t in dismissed:
            if t in self.toasts:
                self.toasts.remove(t)

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
