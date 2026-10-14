"""The dockable tool windows."""

from __future__ import annotations

import os
import re

from imgui_bundle import ImVec2, hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..payload import cyclic, cyclic_find, eval_payload, hexdump_ansi, parse_bytes_input
from ..term import ECHO, strip_ansi
from ..theme import THEMES
from .views import DecompView
from .widgets import buttons_width, combo_width, help_marker, v4


class PanelsMixin:
    """The dockable tool windows."""

    def section_gui(self, name: str):
        def gui() -> None:
            sec = self.sections[name]
            if not self.info.get("pwndbg") and self.connected() and self.info:
                imgui.text_colored(v4(self.theme.yellow), "pwndbg is not loaded in gdb (see --pwndbg).")
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
            if running:
                self.toast(f"{fa.ICON_FA_PERSON_RUNNING}  Program running: '{cmd}' runs when it stops (F6 to interrupt)", "warn", 4.0)
            elif not self.gdb_idle and self.connected():
                self.toast(f"{fa.ICON_FA_HOURGLASS_HALF}  gdb is busy: '{cmd}' is queued", "warn", 3.0)
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
        if self.io is None or self.io_is_external():
            imgui.push_text_wrap_pos(0)
            if self.attached:
                imgui.text_disabled("This GUI is attached to an existing gdb session (init-pwndbg-imgui): the program's "
                                    "input/output belong to whoever started it (e.g. your pwntools script).")
            elif self.io is not None and self.state.get("remote"):
                imgui.text_disabled("The target is remote (gdbserver): the program's input/output go through the "
                                    "remote side, not this window. This is the case with pwntools' gdb.debug — "
                                    "interact with the program in the script that launched it.")
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
        entry = {"mode": self.io_mode, "text": text}
        if text and (not self.io_history or self.io_history[-1] != entry):
            self.io_history.append(entry)
        self.io_history_pos = -1
        self.io_input = ""

    def memory_gui(self) -> None:
        self.memory.gui()

    def vmmap_gui(self) -> None:
        th = self.theme
        imgui.set_next_item_width(-buttons_width(fa.ICON_FA_ARROWS_ROTATE))
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
        buttons = (("break", "Break", "Software breakpoint"), ("tbreak", "Temp", "Temporary breakpoint"),
                   ("watch", "Watch", "Write watchpoint"), ("rwatch", "RWatch", "Read watchpoint"))
        buttons_w = buttons_width(*(b[1] for b in buttons))
        # keep the buttons on the input's line when it leaves the input usable room, else wrap them
        inline = imgui.get_content_region_avail().x - buttons_w >= imgui.get_font_size() * 10
        imgui.set_next_item_width(-buttons_w if inline else -1)
        entered, self.bp_input = imgui.input_text_with_hint(
            "##bpin", "main · *0x401136 · file.c:42 · $rip+8 · var", self.bp_input, imgui.InputTextFlags_.enter_returns_true)
        where = self.bp_input.strip()
        for i, (kind, label, tip) in enumerate(buttons):
            if inline or i:
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
            (f"{fa.ICON_FA_MAP} VMMap", self.vmmap_gui, "RightBottom", True),
            (f"{fa.ICON_FA_CIRCLE_DOT} Breakpoints", self.breakpoints_gui, "RightBottom", True),
            (f"{fa.ICON_FA_BOOK} Commands", self.commands_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_SLIDERS} pwndbg Config", self.config_gui, "MainDockSpace", False),
            (f"{fa.ICON_FA_HASHTAG} Pattern (cyclic)", self.cyclic_gui, "RightBottom", False),
            (f"{fa.ICON_FA_GEAR} Preferences", self.prefs_gui, "RightBottom", False),
        ]
