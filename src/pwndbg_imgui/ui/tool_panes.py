"""Tool panes: the pwndbg command browser, the pwndbg Config editor and the cyclic pattern
tool. Each owns its state and draws itself (shared data, like the command list, stays on App)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from imgui_bundle import ImVec2, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..payload import cyclic, cyclic_find
from ..term import ECHO, strip_ansi
from .console_panes import ConsolePane
from .widgets import TableCard, buttons_width, help_marker, v4

if TYPE_CHECKING:
    from .app import App


class CommandsPane:
    """Browse pwndbg's commands by category, with their help; insert, run or open one as a view."""

    LABEL = f"{fa.ICON_FA_BOOK} Commands"

    def __init__(self, app: App) -> None:
        self.app = app
        self.filter = ""
        self.selected: dict | None = None

    def gui(self) -> None:
        app = self.app
        th = app.theme
        if app.commands is None:
            imgui.text_disabled("Loading pwndbg commands…")
            return
        if not app.commands:
            imgui.text_disabled("pwndbg is not loaded.")
            return
        imgui.set_next_item_width(-1)
        _, self.filter = imgui.input_text_with_hint("##cmdf", f"{fa.ICON_FA_FILTER} filter {len(app.commands)} commands", self.filter)
        flt = self.filter.lower().strip()
        avail = imgui.get_content_region_avail()
        imgui.begin_child("##cmdlist", ImVec2(avail.x * 0.38, 0), imgui.ChildFlags_.borders | imgui.ChildFlags_.resize_x)
        cats: dict[str, list] = {}
        for c in app.commands:
            if flt and flt not in c["name"] and flt not in c["desc"].lower() and not any(flt in a for a in c["aliases"]):
                continue
            cats.setdefault(c["cat"], []).append(c)
        for cat in sorted(cats):
            imgui.set_next_item_open(bool(flt), imgui.Cond_.always if flt else imgui.Cond_.once)
            if imgui.tree_node(f"{cat} ({len(cats[cat])})"):
                for c in sorted(cats[cat], key=lambda c: c["name"]):
                    if imgui.selectable(c["name"], self.selected is c)[0]:
                        self.selected = c
                    if imgui.is_item_hovered() and imgui.is_mouse_double_clicked(0):
                        app.open_cmd_view(c["name"])
                    imgui.set_item_tooltip(c["desc"])
                imgui.tree_pop()
        imgui.end_child()
        imgui.same_line()
        imgui.begin_child("##cmdhelp", ImVec2(0, 0))
        c = self.selected
        if c is None:
            imgui.text_disabled("Select a command. Double-click opens it as a live view.")
        else:
            imgui.text_colored(v4(th.accent), c["name"])
            if c["aliases"]:
                imgui.same_line()
                imgui.text_disabled("aliases: " + ", ".join(c["aliases"]))
            if imgui.button(f"{fa.ICON_FA_TERMINAL} Insert in console"):
                app.console_pane.prefill(c["name"] + " ")
                app.focus_window(ConsolePane.LABEL)
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_TABLE_CELLS} Open as view"):
                app.open_cmd_view(c["name"])
            imgui.same_line()
            if imgui.button(f"{fa.ICON_FA_PLAY} Run in console"):
                app.send_console(c["name"])
            imgui.separator()
            imgui.push_font(app.mono, app.code_size * 0.92)
            imgui.text_unformatted(strip_ansi(c["help"]))
            imgui.pop_font()
        imgui.end_child()


class ConfigPane:
    """pwndbg's parameters: edit them, see which differ from the default, reset one, and keep
    the changes across runs (App.persist_pwndbg_param)."""

    LABEL = f"{fa.ICON_FA_SLIDERS} pwndbg Config"

    def __init__(self, app: App) -> None:
        self.app = app
        self.params: list | None = None  # from the agent's `config` op
        self.edit: dict[str, str] = {}  # text being typed, per parameter
        self.filter = ""
        self.modified_only = False
        self.card: TableCard | None = None  # created at first draw (column widths need the font)

    def gui(self) -> None:
        app = self.app
        th = app.theme
        if self.params is None:
            if app.connected() and app.info.get("pwndbg") and app.rpc:
                self.params = []
                app.rpc.request("config", self.set_params, app.error_toast)
            imgui.text_disabled("Loading…")
            return
        st = app.settings
        n_saved = len(st["pwndbg_config"])
        imgui.set_next_item_width(-buttons_width(fa.ICON_FA_ARROWS_ROTATE))
        _, self.filter = imgui.input_text_with_hint("##cfgf", f"{fa.ICON_FA_FILTER} filter parameters", self.filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##cfgr"):
            self.reload()
        imgui.set_item_tooltip("Reload values from gdb")
        n_modified = sum(1 for p in self.params if self.modified(p))
        _, self.modified_only = imgui.checkbox(f"Modified only ({n_modified})##cfgmod", self.modified_only)
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
                app.toast("Saved pwndbg config cleared (current session unchanged)", "info", 3.0)
        flt = self.filter.lower().strip()
        if self.card is None:
            fixed = imgui.TableColumnFlags_.width_fixed
            self.card = TableCard(app, "##cfg", [
                ("Parameter", fixed, lambda: imgui.get_font_size() * 14),
                ("Value", fixed, lambda: imgui.get_font_size() * 12),
                ("Description", imgui.TableColumnFlags_.width_stretch),
            ], imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.pad_outer_x
               | imgui.TableFlags_.scroll_x | imgui.TableFlags_.scroll_y | imgui.TableFlags_.resizable, framed=True)
        card = self.card
        if not card.begin():
            card.end()
            return
        scope = None
        for p in self.params:
            if flt and flt not in p["name"] and flt not in p["doc"].lower():
                continue
            modified = self.modified(p)
            if self.modified_only and not modified:
                continue
            if p["scope"] != scope and not flt and not self.modified_only:
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
            elif p["name"] in app.PWNDBG_CONFIG_DENY:
                imgui.text_disabled(f"  {p['name']}")
                imgui.set_item_tooltip(f"Managed by pwndbg-imgui (it routes the context panes)\n\n{p['help']}")
            else:
                imgui.text_unformatted(f"  {p['name']}")
                imgui.set_item_tooltip(p["help"])
            imgui.table_next_column()
            card.cell(str(p["value"]))
            reset_w = buttons_width(fa.ICON_FA_ROTATE_LEFT) if modified else 0.0
            imgui.set_next_item_width(-reset_w if modified else -1)
            imgui.push_font(app.mono, app.ui_size)
            self._widget(p)
            imgui.pop_font()
            if modified:
                imgui.same_line()
                if imgui.small_button(f"{fa.ICON_FA_ROTATE_LEFT}##rst{p['name']}"):
                    self.reset(p)
                imgui.set_item_tooltip(f"Reset to the default: {p['default']}")
            imgui.table_next_column()
            card.cell(p["doc"])
            imgui.text_disabled(p["doc"])
        card.end()

    def set_params(self, cfg) -> None:
        self.params = cfg

    def modified(self, p) -> bool:
        app = self.app
        """Differs from pwndbg's default, and is the user's to change (not one the GUI sets)."""
        return bool(p.get("modified")) and p["name"] not in app.PWNDBG_CONFIG_DENY

    def reload(self) -> None:
        """Fetch values again (after a change: the modified markers come from gdb)."""
        app = self.app
        if app.rpc:
            app.rpc.request("config", self.set_params, app.error_toast)
            app.registers_bar.fetch()  # its controls show some of the same parameters

    def reset(self, p) -> None:
        app = self.app
        app.exec(f"set {p['name']} {p['reset']}", quiet=True, cb=lambda _o: self.reload())
        app.forget_pwndbg_param(p["name"])
        self.edit.pop("cfg:" + p["name"], None)

    def _widget(self, p) -> None:
        app = self.app
        name, kind, value = p["name"], p["kind"], p["value"]

        def setv(v):
            p["value"] = v
            out = "on" if v is True else ("off" if v is False else str(v))
            app.exec(f"set {name} {out}", quiet=True, cb=lambda _o: self.reload())
            app.persist_pwndbg_param(name, out)

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
            if key not in self.edit:
                self.edit[key] = str(value)
            entered, self.edit[key] = imgui.input_text(f"##{name}", self.edit[key], imgui.InputTextFlags_.enter_returns_true)
            if entered:
                v = self.edit[key]
                setv(int(v, 0) if kind == "int" and re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", v) else v)
            elif not imgui.is_item_active():
                self.edit[key] = str(value)


class CyclicPane:
    """De Bruijn patterns (pwntools-compatible): generate / copy / send one, find an offset."""

    LABEL = f"{fa.ICON_FA_HASHTAG} Pattern (cyclic)"

    def __init__(self, app: App) -> None:
        self.app = app
        self.length = 200
        self.n: int | None = None  # None: the target's pointer size (see size())
        self.value = ""
        self.result = ""

    def gui(self) -> None:
        app = self.app
        th = app.theme
        imgui.separator_text("Generate")
        imgui.set_next_item_width(imgui.get_font_size() * 7)
        _, self.length = imgui.input_int("length", self.length, 16, 256)
        self.length = max(1, min(self.length, 100000))
        imgui.same_line()
        imgui.set_next_item_width(imgui.get_font_size() * 5)
        if imgui.begin_combo("n", f"auto ({self.size()})" if self.n is None else str(self.n)):
            for n in (None, 4, 8):
                if imgui.selectable(f"auto ({app.ptrsize if app.ptrsize in (4, 8) else 8})" if n is None
                                    else str(n), n == self.n)[0]:
                    self.n = n
            imgui.end_combo()
        imgui.set_item_tooltip("Subsequence size: 4 for 32-bit, 8 for 64-bit targets (auto: the target's)")
        pattern = cyclic(self.length, self.size())
        if imgui.button(f"{fa.ICON_FA_COPY} Copy"):
            imgui.set_clipboard_text(pattern.decode())
            app.toast("Pattern copied", "info", 1.2)
        imgui.same_line()
        io = app.io
        imgui.begin_disabled(io is None)
        if imgui.button(f"{fa.ICON_FA_KEYBOARD} Send to program"):
            if io is not None:
                io.write(pattern + (b"\n" if app.settings["io_newline"] else b""))
            if app.settings["io_echo"]:
                app.io_term.feed(pattern.decode() + "\n", ECHO)
        imgui.end_disabled()
        imgui.push_font(app.mono, app.code_size)
        imgui.push_text_wrap_pos(0)
        preview = pattern[:400].decode() + ("…" if len(pattern) > 400 else "")
        imgui.text_colored(v4(th.dim), preview)
        imgui.pop_text_wrap_pos()
        imgui.pop_font()
        imgui.separator_text("Find offset")
        imgui.set_next_item_width(imgui.get_font_size() * 14)
        entered, self.value = imgui.input_text_with_hint(
            "##cyv", "0x6161616c6161616b, 'kaaa', $sp…", self.value, imgui.InputTextFlags_.enter_returns_true)
        for reg in ("$pc", "$sp", "$fp"):
            imgui.same_line()
            if imgui.button(reg) and app.is_stopped() and app.rpc:
                expr = f"*(unsigned long *){reg}" if reg != "$pc" else "$pc"
                app.rpc.request("eval", self.lookup, lambda e: setattr(self, "result", e), expr=expr)
            imgui.set_item_tooltip(f"Look up the value of {'$pc' if reg == '$pc' else '*' + reg}")
        if entered:
            v = self.value.strip()
            if v.startswith(("'", '"')):
                self.lookup(v.strip("'\"").encode())
            elif re.fullmatch(r"(0x)?[0-9a-fA-F]+", v):
                self.lookup(int(v, 16))
            elif app.rpc:
                app.rpc.request("eval", self.lookup, lambda e: setattr(self, "result", e), expr=v)
        if self.result:
            imgui.text_colored(v4(th.green if "offset" in self.result else th.red), self.result)

    def size(self) -> int:
        app = self.app
        if self.n is not None:
            return self.n
        return 4 if app.ptrsize == 4 else 8

    def lookup(self, value) -> None:
        app = self.app
        n = self.size()
        if isinstance(value, int):
            # the bytes as they sit in memory: a target word (or wider if typed that way)
            width = max(app.ptrsize, (value.bit_length() + 7) // 8)
            mem = (value & ((1 << (8 * width)) - 1)).to_bytes(width, app.endian)
            shown = f"{value:#x}"
        else:
            mem = value
            shown = repr(value)
        off = cyclic_find(mem[:n], n)
        if off < 0 and n == 8:
            off = cyclic_find(mem[:4], 4)  # a pattern made with n=4
        self.result = f"{shown} found at offset {off} ({off:#x})" if off >= 0 else f"{shown} not found in the pattern"
