"""The dockable tool windows."""

from __future__ import annotations

import os
import re

from imgui_bundle import ImVec2, hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..payload import cyclic, cyclic_find
from ..term import ECHO, strip_ansi
from ..theme import THEMES
from .console_panes import ConsolePane, ProgramIOPane
from .panes import BreakpointsPane, HeapPane, VmmapPane
from .views import DecompView
from .widgets import TableCard, buttons_width, help_marker, v4


class PanelsMixin:
    """The dockable tool windows."""

    def section_gui(self, name: str):
        def gui() -> None:
            sec = self.sections[name]
            if not self.info.get("pwndbg") and self.connected() and self.info:
                imgui.text_colored(v4(self.theme.yellow), "pwndbg is not loaded in gdb (see --pwndbg).")
            table = {"backtrace": self.backtrace_pane, "threads": self.threads_pane}.get(name)
            if table is not None:
                table.refresh_if_stale()  # once per stop, also while showing the fallback
                if not table.unavailable():  # else: pwndbg's own text, below
                    table.gui()
                    return
            if name == "regs":
                self.registers_bar.gui()
            if name == "expressions":
                self._watch_bar()
            elif name == "heap_tracker":
                imgui.begin_disabled(not self.is_stopped())
                if imgui.button("Enable##ht"):
                    self.exec("track-heap enable")
                imgui.same_line()
                if imgui.button("Disable##ht"):
                    self.exec("track-heap disable")
                imgui.same_line()
                if imgui.button("Toggle stop on error##ht"):
                    self.exec("track-heap toggle-break")
                imgui.end_disabled()
                imgui.push_text_wrap_pos(0)
                imgui.text_colored(
                    v4(self.theme.yellow),
                    f"{fa.ICON_FA_TRIANGLE_EXCLAMATION}  While tracking is enabled, don't call allocator functions from "
                    "gdb (call malloc(16), call free(p), …): the tracker cannot follow calls made by gdb, the program "
                    "stops inside the function and later allocations may go untracked. Disable tracking first.")
                imgui.pop_text_wrap_pos()
            sec["view"].render()

        return gui

    def _watch_bar(self) -> None:
        imgui.set_next_item_width(-buttons_width("Add", "Cmd"))
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

    def memory_gui(self) -> None:
        self.memory.gui()

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
                self.console_pane.prefill(c["name"] + " ")
                self.focus_window(ConsolePane.LABEL)
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
        st = self.settings
        n_saved = len(st["pwndbg_config"])
        imgui.set_next_item_width(-buttons_width(fa.ICON_FA_ARROWS_ROTATE))
        _, self.cfg_filter = imgui.input_text_with_hint("##cfgf", f"{fa.ICON_FA_FILTER} filter parameters", self.cfg_filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##cfgr"):
            self.reload_config()
        imgui.set_item_tooltip("Reload values from gdb")
        n_modified = sum(1 for p in self.config if self.config_modified(p))
        _, self.cfg_modified_only = imgui.checkbox(f"Modified only ({n_modified})##cfgmod", self.cfg_modified_only)
        imgui.set_item_tooltip("Show only the parameters that differ from pwndbg's default")
        imgui.same_line(0, 18)
        _, st["persist_pwndbg_config"] = imgui.checkbox("Remember my changes across runs", st["persist_pwndbg_config"])
        help_marker("pwndbg does not persist its config itself. When enabled, parameters you change here "
                    "are saved and re-applied automatically on the next run "
                    "(context routing and layout parameters are left to the GUI).")
        if n_saved:
            imgui.same_line()
            imgui.text_disabled(f"· {n_saved} saved")
            imgui.same_line()
            if imgui.small_button("Forget##cfgforget"):
                st["pwndbg_config"].clear()
                self.toast("Saved pwndbg config cleared (current session unchanged)", "info", 3.0)
        flt = self.cfg_filter.lower().strip()
        if self.cfg_card is None:
            fixed = imgui.TableColumnFlags_.width_fixed
            self.cfg_card = TableCard(self, "##cfg", [
                ("Parameter", fixed, lambda: imgui.get_font_size() * 14),
                ("Value", fixed, lambda: imgui.get_font_size() * 12),
                ("Description", imgui.TableColumnFlags_.width_stretch),
            ], imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.pad_outer_x
               | imgui.TableFlags_.scroll_x | imgui.TableFlags_.scroll_y | imgui.TableFlags_.resizable, framed=True)
        card = self.cfg_card
        if not card.begin():
            card.end()
            return
        scope = None
        for p in self.config:
            if flt and flt not in p["name"] and flt not in p["doc"].lower():
                continue
            modified = self.config_modified(p)
            if self.cfg_modified_only and not modified:
                continue
            if p["scope"] != scope and not flt and not self.cfg_modified_only:
                scope = p["scope"]
                imgui.table_next_row(imgui.TableRowFlags_.headers)
                imgui.table_next_column()
                imgui.text_colored(v4(th.accent), scope.upper())
            imgui.table_next_row()
            imgui.table_next_column()
            card.cell(p["name"])
            if modified:  # differs from pwndbg's default
                imgui.text_colored(v4(th.accent), f"● {p['name']}")
                imgui.set_item_tooltip(f"Changed (default: {p['default']})\n\n{p['help']}")
            elif p["name"] in self.PWNDBG_CONFIG_DENY:
                imgui.text_disabled(f"  {p['name']}")
                imgui.set_item_tooltip(f"Managed by pwndbg-imgui (it routes the context panes)\n\n{p['help']}")
            else:
                imgui.text_unformatted(f"  {p['name']}")
                imgui.set_item_tooltip(p["help"])
            imgui.table_next_column()
            card.cell(str(p["value"]))
            reset_w = buttons_width(fa.ICON_FA_ROTATE_LEFT) if modified else 0.0
            imgui.set_next_item_width(-reset_w if modified else -1)
            imgui.push_font(self.mono, self.ui_size)
            self._config_widget(p)
            imgui.pop_font()
            if modified:
                imgui.same_line()
                if imgui.small_button(f"{fa.ICON_FA_ROTATE_LEFT}##rst{p['name']}"):
                    self.reset_config_param(p)
                imgui.set_item_tooltip(f"Reset to the default: {p['default']}")
            imgui.table_next_column()
            card.cell(p["doc"])
            imgui.text_disabled(p["doc"])
        card.end()

    def _set_config(self, cfg) -> None:
        self.config = cfg

    def config_modified(self, p) -> bool:
        """Differs from pwndbg's default, and is the user's to change (not one the GUI sets)."""
        return bool(p.get("modified")) and p["name"] not in self.PWNDBG_CONFIG_DENY

    def reload_config(self) -> None:
        """Fetch values again (after a change: the modified markers come from gdb)."""
        if self.rpc:
            self.rpc.request("config", self._set_config, self.error_toast)
            self.registers_bar.fetch()  # its controls show some of the same parameters

    def reset_config_param(self, p) -> None:
        self.exec(f"set {p['name']} {p['reset']}", quiet=True, cb=lambda _o: self.reload_config())
        self.forget_pwndbg_param(p["name"])
        self.config_edit.pop("cfg:" + p["name"], None)

    def _config_widget(self, p) -> None:
        name, kind, value = p["name"], p["kind"], p["value"]

        def setv(v):
            p["value"] = v
            out = "on" if v is True else ("off" if v is False else str(v))
            self.exec(f"set {name} {out}", quiet=True, cb=lambda _o: self.reload_config())
            self.persist_pwndbg_param(name, out)

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
        if imgui.begin_combo("n", f"auto ({self.cyclic_size()})" if self.cyclic_n is None else str(self.cyclic_n)):
            for n in (None, 4, 8):
                if imgui.selectable(f"auto ({self.ptrsize if self.ptrsize in (4, 8) else 8})" if n is None
                                    else str(n), n == self.cyclic_n)[0]:
                    self.cyclic_n = n
            imgui.end_combo()
        imgui.set_item_tooltip("Subsequence size: 4 for 32-bit, 8 for 64-bit targets (auto: the target's)")
        pattern = cyclic(self.cyclic_len, self.cyclic_size())
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
            "##cyv", "0x6161616c6161616b, 'kaaa', $sp…", self.cyclic_value, imgui.InputTextFlags_.enter_returns_true)
        for reg in ("$pc", "$sp", "$fp"):
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

    def cyclic_size(self) -> int:
        if self.cyclic_n is not None:
            return self.cyclic_n
        return 4 if self.ptrsize == 4 else 8

    def _cyclic_lookup(self, value) -> None:
        n = self.cyclic_size()
        if isinstance(value, int):
            # the bytes as they sit in memory: a target word (or wider if typed that way)
            width = max(self.ptrsize, (value.bit_length() + 7) // 8)
            mem = (value & ((1 << (8 * width)) - 1)).to_bytes(width, self.endian)
            shown = f"{value:#x}"
        else:
            mem = value
            shown = repr(value)
        off = cyclic_find(mem[:n], n)
        if off < 0 and n == 8:
            off = cyclic_find(mem[:4], 4)  # a pattern made with n=4
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
        self.ui_size_slider("UI size")
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        changed, v = imgui.slider_float("Code size  (Ctrl+wheel)", self.code_size, 8.0, 32.0, "%.0f")
        if changed:
            self.set_code_size(round(v))
        imgui.separator_text("Behavior")
        changed, st["custom_titlebar"] = imgui.checkbox("Themed title bar (instead of the system one)", st["custom_titlebar"])
        if changed:
            self.toast("Applies on next start", "info")
        _, st["autofit"] = imgui.checkbox("Fit context sections to their window", st["autofit"])
        help_marker("Disassembly, stack, source, backtrace and threads show exactly as many lines as fit.")
        _, st["remember_bps"] = imgui.checkbox("Remember breakpoints per binary", st["remember_bps"])
        _, st["decomp_autoconnect"] = imgui.checkbox("Connect to the decompiler automatically", st["decomp_autoconnect"])
        help_marker("When the Decompiler window is open, try `decompiler-integration connect` once the program stops.")
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
            (ConsolePane.LABEL, self.console_pane.gui, "Bottom", True),
            (ProgramIOPane.LABEL, self.io_pane.gui, "Bottom", True),
            (f"{fa.ICON_FA_MEMORY} Memory", self.memory_gui, "MainDockSpace", True),
            (f"{fa.ICON_FA_DRAGON} {DecompView.LABEL}", self.decomp.gui, "MainDockSpace", True),
            (VmmapPane.LABEL, self.vmmap_pane.gui, "RightBottom", True),
            (BreakpointsPane.LABEL, self.breakpoints_pane.gui, "RightBottom", True),
            (HeapPane.LABEL, self.heap_pane.gui, "Right", True),
            (f"{fa.ICON_FA_BOOK} Commands", self.commands_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_SLIDERS} pwndbg Config", self.config_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_HASHTAG} Pattern (cyclic)", self.cyclic_gui, "RightBottom", True),
            (f"{fa.ICON_FA_GEAR} Preferences", self.prefs_gui, "RightBottom", False),
        ]
