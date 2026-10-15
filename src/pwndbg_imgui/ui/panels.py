"""The dockable tool windows."""

from __future__ import annotations

import os
import re

from imgui_bundle import ImVec2, hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..agent import debug, debug_enabled
from ..payload import cyclic, cyclic_find, eval_payload, hexdump_ansi, parse_bytes_input
from ..term import ECHO, strip_ansi
from ..theme import THEMES
from .panes import BreakpointsPane, HeapPane, VmmapPane
from .views import DecompView
from .widgets import TableCard, buttons_width, combo_width, help_marker, v4


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

    def console_gui(self) -> None:
        th = self.theme
        footer = imgui.get_frame_height_with_spacing() + 2
        self.console_view.render(-footer)
        if self.console is not None:
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
        imgui.align_text_to_frame_padding()  # center the icon on the input box's line
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
        if running:
            hint = "program running — commands are queued until it stops (F6 / Ctrl+C interrupts)"
        elif not self.gdb_idle and self.connected():
            hint = "gdb is busy — commands are queued"
        else:
            hint = "gdb / pwndbg command  (Tab: complete, ↑↓: history)"
        imgui.push_font(self.mono, self.code_size)
        entered, self.console_input = imgui.input_text_with_hint("##console_in", hint, self.console_input, flags, self._console_cb)
        imgui.pop_font()
        if (not entered and self.console_input.strip() and debug_enabled()
                and (imgui.is_key_pressed(imgui.Key.enter, False) or imgui.is_key_pressed(imgui.Key.keypad_enter, False))):
            debug(f"console: Enter pressed but the command was not submitted ({self._focus_report()})")
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
            debug(f"console: submit {cmd!r} (attached={self.attached} running={running} "
                  f"gdb_idle={self.gdb_idle} connected={self.connected()})")
            if cmd.strip() and (not self.history or self.history[-1] != cmd):
                self.history.append(cmd)
            self.history_pos = -1
            self.completions = []
            if running:
                self.toast(f"{fa.ICON_FA_PERSON_RUNNING}  Program running: '{cmd}' runs when it stops (F6 to interrupt)", "warn", 4.0)
            elif not self.gdb_idle and self.connected():
                self.toast(f"{fa.ICON_FA_HOURGLASS_HALF}  gdb is busy: '{cmd}' is queued", "warn", 3.0)
            self.send_console(cmd)
            self.console_input = ""
            self.console_view.at_bottom = True
            imgui.set_keyboard_focus_here(-1)

    def _focus_report(self) -> str:
        """Who has the keyboard right now, for --debug logs of input problems."""
        io = imgui.get_io()
        try:
            ctx = imgui.get_current_context()
            focused = ctx.nav_window.name if ctx.nav_window else None
            active = ctx.active_id_window.name if ctx.active_id_window else None
            active_id = ctx.active_id
        except Exception:
            focused = active = active_id = "?"
        return (f"focused window={focused!r}, active item={active_id} in {active!r}, "
                f"input active={imgui.is_item_active()}, want_text_input={io.want_text_input}, "
                f"ctrl={io.key_ctrl} alt={io.key_alt} shift={io.key_shift} super={io.key_super}, "
                f"app focus lost={io.app_focus_lost}")

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
        if self.io is None or self.io_is_external():
            imgui.push_text_wrap_pos(0)
            if self.attached:
                imgui.text_disabled("This GUI is attached to an existing gdb session (init-pwndbg-imgui): the program's "
                                    "input/output belong to whoever started it (e.g. your pwntools script).")
            elif self.io is not None:  # io_is_external(): a remote target
                where = self.state.get("remote_addr") or self.info.get("remote_addr") or "gdbserver"
                imgui.text_colored(v4(th.accent), f"{fa.ICON_FA_CIRCLE_INFO}  Remote target ({where})")
                imgui.text_disabled("The program runs under gdbserver, so its input/output don't go through gdb "
                                    "and can't be shown here. Talk to it where it was started:")
                imgui.bullet_text("pwntools (gdb.debug, exploit.py -d ui): from the script, "
                                  "e.g. io.sendline(...) / io.interactive()")
                imgui.bullet_text("gdbserver started by hand: in the terminal where gdbserver runs")
            else:
                imgui.text_disabled("Program I/O is disabled (--no-io): the program shares the gdb console.")
            imgui.pop_text_wrap_pos()
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
        imgui.set_next_item_width(-buttons_width("Send"))
        imgui.push_font(self.mono, self.code_size)
        entered, self.io_input = imgui.input_text_with_hint(
            "##io_in", "input for the program (Enter to send, Up/Down: history)", self.io_input,
            imgui.InputTextFlags_.enter_returns_true | imgui.InputTextFlags_.callback_history, self._io_history_cb)
        imgui.pop_font()
        imgui.same_line()
        if (imgui.button("Send##io") or entered) and (self.io_input or st["io_newline"]):
            self.send_io(self.io_input)
            imgui.set_keyboard_focus_here(-1)

    def _io_history_cb(self, data) -> int:
        hist = self.io_history
        if not hist:
            return 0
        if data.event_key == imgui.Key.up_arrow:
            self.io_history_pos = len(hist) - 1 if self.io_history_pos == -1 else max(0, self.io_history_pos - 1)
        elif data.event_key == imgui.Key.down_arrow and self.io_history_pos != -1:
            self.io_history_pos += 1
            if self.io_history_pos >= len(hist):
                self.io_history_pos = -1
        entry = hist[self.io_history_pos] if self.io_history_pos != -1 else {"text": ""}
        if entry.get("mode") in ("text", "python", "hex"):
            self.io_mode = entry["mode"]  # a payload comes back with the mode it was sent in
        data.delete_chars(0, data.buf_text_len)
        data.insert_chars(0, entry["text"])
        return 0

    def send_io(self, text: str) -> None:
        try:
            if self.io_mode == "python":
                data = eval_payload(text, word=self.ptrsize, endian=self.endian)
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
        entry = {"mode": self.io_mode, "text": text}
        if text and (not self.io_history or self.io_history[-1] != entry):
            self.io_history.append(entry)
        self.io_history_pos = -1
        self.io_input = ""

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
        st = self.settings
        n_saved = len(st["pwndbg_config"])
        imgui.set_next_item_width(-buttons_width(fa.ICON_FA_ARROWS_ROTATE))
        _, self.cfg_filter = imgui.input_text_with_hint("##cfgf", f"{fa.ICON_FA_FILTER} filter parameters", self.cfg_filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##cfgr"):
            self.rpc.request("config", self._set_config, self.error_toast)
        imgui.set_item_tooltip("Reload values from gdb")
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
               | imgui.TableFlags_.scroll_y | imgui.TableFlags_.resizable, framed=True)
        card = self.cfg_card
        if not card.begin():
            card.end()
            return
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
            card.cell(p["name"])
            imgui.text_unformatted(p["name"])
            imgui.set_item_tooltip(p["help"])
            imgui.table_next_column()
            card.cell(str(p["value"]))
            imgui.set_next_item_width(-1)
            imgui.push_font(self.mono, self.ui_size)
            self._config_widget(p)
            imgui.pop_font()
            imgui.table_next_column()
            card.cell(p["doc"])
            imgui.text_disabled(p["doc"])
        card.end()

    def _set_config(self, cfg) -> None:
        self.config = cfg

    def _config_widget(self, p) -> None:
        name, kind, value = p["name"], p["kind"], p["value"]

        def setv(v):
            p["value"] = v
            out = "on" if v is True else ("off" if v is False else str(v))
            self.exec(f"set {name} {out}", quiet=True)
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
            (f"{fa.ICON_FA_TERMINAL} Console", self.console_gui, "Bottom", True),
            (f"{fa.ICON_FA_KEYBOARD} Program I/O", self.io_gui, "Bottom", True),
            (f"{fa.ICON_FA_MEMORY} Memory", self.memory_gui, "MainDockSpace", True),
            (f"{fa.ICON_FA_DRAGON} {DecompView.LABEL}", self.decomp.gui, "MainDockSpace", True),
            (VmmapPane.LABEL, self.vmmap_pane.gui, "RightBottom", True),
            (BreakpointsPane.LABEL, self.breakpoints_pane.gui, "RightBottom", True),
            (HeapPane.LABEL, self.heap_pane.gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_BOOK} Commands", self.commands_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_SLIDERS} pwndbg Config", self.config_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_HASHTAG} Pattern (cyclic)", self.cyclic_gui, "RightBottom", False),
            (f"{fa.ICON_FA_GEAR} Preferences", self.prefs_gui, "RightBottom", False),
        ]
