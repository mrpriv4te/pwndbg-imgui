"""The Console and Program I/O panes: input boxes, history, completion.

The terminals themselves (gdb's PTY, the program's PTY and their Term / TextView) stay on
App, which other code feeds and reads; a pane owns its input state and draws itself."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from imgui_bundle import ImVec2, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..agent import debug, debug_enabled
from ..payload import eval_payload, hexdump_ansi, parse_bytes_input
from ..term import ECHO
from .widgets import buttons_width, combo_width, v4

if TYPE_CHECKING:
    from .app import App


class ConsolePane:
    """The gdb console's input line: history (Up/Down), completion (Tab, through gdb; with
    several matches, Up/Down/Tab pick one and Enter inserts it), Ctrl+C / Ctrl+L / Ctrl+D,
    and a debug trace of what Enter did (--debug)."""

    SHOWN = 12  # completion matches listed at once

    LABEL = f"{fa.ICON_FA_TERMINAL} Console"

    def __init__(self, app: App, history: list[str]) -> None:
        self.app = app
        self.input = ""
        self.history = history
        self.history_pos = -1
        self.replace: str | None = None  # text to put in the input box at the next frame
        self.completions: list[str] = []
        self.comp_sel = -1  # highlighted match, -1: none yet
        self.keep_completions = False  # our own edit of the input (the common prefix): keep the list
        self.focus_next = True

    def prefill(self, text: str) -> None:
        """Put text in the input box (e.g. a command name from the palette) and focus it."""
        self.replace = text
        self.focus_next = True

    def gui(self) -> None:
        app = self.app
        th = app.theme
        footer = imgui.get_frame_height_with_spacing() + 2
        app.console_view.render(-footer)
        if app.console is not None:
            app.console.resize(app.console_view.rows, app.console_view.cols)
        if self.completions:
            self._completion_list()
        running = app.is_running()
        icon = fa.ICON_FA_PERSON_RUNNING if running else fa.ICON_FA_ANGLES_RIGHT
        imgui.align_text_to_frame_padding()  # center the icon on the input box's line
        imgui.text_colored(v4(th.green if running else th.accent), icon)
        imgui.same_line()
        imgui.set_next_item_width(-1)
        if self.focus_next or (
            imgui.is_window_focused() and not imgui.is_any_item_active() and not imgui.is_any_mouse_down()
            and app.console_view.selection() is None and not app.console_view.search_open
        ):
            imgui.set_keyboard_focus_here()
            self.focus_next = False
        flags = (imgui.InputTextFlags_.enter_returns_true | imgui.InputTextFlags_.callback_history
                 | imgui.InputTextFlags_.callback_completion | imgui.InputTextFlags_.callback_always)
        if running:
            hint = "program running — commands are queued until it stops (F6 / Ctrl+C interrupts)"
        elif not app.gdb_idle and app.connected():
            hint = "gdb is busy — commands are queued"
        else:
            hint = "gdb / pwndbg command  (Tab: complete, ↑↓: history)"
        # Esc closes the match list; ImGui's input would also revert the text to what it was
        # when focused (often empty), so keep what was typed
        closing = bool(self.completions) and imgui.is_key_pressed(imgui.Key.escape, False)
        if self.completions and imgui.get_io().key_shift and imgui.is_key_pressed(imgui.Key.tab):
            self.move_selection(-1)  # ImGui only calls the completion callback for a plain Tab
        typed = self.input
        imgui.push_font(app.mono, app.ui_size)  # an input box: sized like the UI, not the code panes
        entered, self.input = imgui.input_text_with_hint("##console_in", hint, self.input, flags, self._callback)
        imgui.pop_font()
        if closing:
            self.completions = []
            if self.input != typed:
                self.input = self.replace = typed
            self.focus_next = True
        if (not entered and self.input.strip() and debug_enabled()
                and (imgui.is_key_pressed(imgui.Key.enter, False) or imgui.is_key_pressed(imgui.Key.keypad_enter, False))):
            debug(f"console: Enter pressed but the command was not submitted ({self._focus_report()})")
        if imgui.is_item_active():
            io = imgui.get_io()
            if io.key_ctrl and imgui.is_key_pressed(imgui.Key.c, False) and running:
                app.interrupt()
            elif io.key_ctrl and imgui.is_key_pressed(imgui.Key.l, False):
                app.console_term.clear()
            elif io.key_ctrl and imgui.is_key_pressed(imgui.Key.d, False) and not self.input:
                app.send_console("")
        if imgui.is_item_edited():
            if self.keep_completions:
                self.keep_completions = False
            else:
                self.completions = []
        if entered and self.completions and self.comp_sel >= 0:  # Enter picks the highlighted match
            self.replace = self.completions[self.comp_sel] + " "
            self.completions = []
            imgui.set_keyboard_focus_here(-1)
        elif entered:
            cmd = self.input
            debug(f"console: submit {cmd!r} (attached={app.attached} running={running} "
                  f"gdb_idle={app.gdb_idle} connected={app.connected()})")
            if cmd.strip() and (not self.history or self.history[-1] != cmd):
                self.history.append(cmd)
            self.history_pos = -1
            self.completions = []
            if running:
                app.toast(f"{fa.ICON_FA_PERSON_RUNNING}  Program running: '{cmd}' runs when it stops (F6 to interrupt)", "warn", 4.0)
            elif not app.gdb_idle and app.connected():
                app.toast(f"{fa.ICON_FA_HOURGLASS_HALF}  gdb is busy: '{cmd}' is queued", "warn", 3.0)
            app.send_console(cmd)
            self.input = ""
            app.console_view.at_bottom = True
            imgui.set_keyboard_focus_here(-1)

    def _completion_list(self) -> None:
        """The matches above the input box, scrolled so the highlighted one shows."""
        comps, sel = self.completions, self.comp_sel
        first = 0 if len(comps) <= self.SHOWN else max(0, min(sel - self.SHOWN // 2, len(comps) - self.SHOWN))
        imgui.set_next_window_pos(imgui.get_cursor_screen_pos(), imgui.Cond_.always, ImVec2(0, 1))
        if not imgui.begin_tooltip():
            return
        if first:
            imgui.text_disabled(f"… {first} more")
        for i in range(first, min(len(comps), first + self.SHOWN)):
            imgui.selectable(f"{comps[i]}##comp{i}", i == sel)
        if len(comps) > first + self.SHOWN:
            imgui.text_disabled(f"… {len(comps) - first - self.SHOWN} more")
        imgui.separator()
        imgui.text_disabled("↑↓ / Tab: choose   Enter: insert   Esc: close")
        imgui.end_tooltip()

    def move_selection(self, step: int) -> None:
        n = len(self.completions)
        if n:
            if self.comp_sel < 0:  # first move: Down / Tab to the first match, Up to the last
                self.comp_sel = 0 if step > 0 else n - 1
            else:
                self.comp_sel = (self.comp_sel + step) % n

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

    def _callback(self, data) -> int:
        app = self.app
        F = imgui.InputTextFlags_
        if data.event_flag == F.callback_always:
            if self.replace is not None:
                data.delete_chars(0, data.buf_text_len)
                data.insert_chars(0, self.replace)
                self.replace = None
            return 0
        if data.event_flag == F.callback_history and self.completions:  # walk the matches, not the history
            self.move_selection(-1 if data.event_key == imgui.Key.up_arrow else 1)
            return 0
        if data.event_flag == F.callback_completion and self.completions:
            self.move_selection(1)
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
        if data.event_flag == F.callback_completion and app.rpc and not app.is_running():
            text = data.buf

            def done(lines, text=text):
                if not lines:
                    self.completions = []
                    return
                prefix = os.path.commonprefix(lines)
                if len(lines) == 1:
                    self.replace = lines[0] + " "
                    self.completions = []
                else:
                    if len(prefix) > len(text):
                        self.replace = prefix
                        self.keep_completions = True
                    self.completions = lines
                    self.comp_sel = -1

            app.rpc.request("complete", done, None, text=text)
        return 0


class ProgramIOPane:
    """The program's terminal: send text / Python payload expressions / hex, history,
    raw or canonical TTY, a hexdump view of the output."""

    LABEL = f"{fa.ICON_FA_KEYBOARD} Program I/O"

    def __init__(self, app: App, history: list[dict]) -> None:
        self.app = app
        self.input = ""
        self.mode = "text"  # text | python | hex
        self.history = history  # [{"mode", "text"}]
        self.history_pos = -1
        self.view_mode = "terminal"  # terminal | hexdump
        self.hex_version = -1

    def gui(self) -> None:
        app = self.app
        th = app.theme
        st = app.settings
        if app.io is None or app.io_is_external():
            imgui.push_text_wrap_pos(0)
            if app.attached:
                imgui.text_disabled("This GUI is attached to an existing gdb session (init-pwndbg-imgui): the program's "
                                    "input/output belong to whoever started it (e.g. your pwntools script).")
            elif app.io is not None:  # io_is_external(): a remote target
                where = app.state.get("remote_addr") or app.info.get("remote_addr") or "gdbserver"
                imgui.text_colored(v4(th.accent), f"{fa.ICON_FA_CIRCLE_INFO}  Remote target ({where})")
                imgui.text_disabled("The program runs under gdbserver, so its input/output don't go through gdb "
                                    "and can't be shown here. Talk to it where it was started:")
                imgui.bullet_text("pwntools (gdb.debug, exploit.py -d ui): from the script, "
                                  "e.g. io.sendline(...) / io.interactive()")
                imgui.bullet_text("gdbserver started by hand: in the terminal where gdbserver runs")
            elif app.cfg.terminal_io:
                imgui.text_colored(v4(th.accent), f"{fa.ICON_FA_CIRCLE_INFO}  Program I/O in your terminal (--terminal-io)")
                imgui.text_disabled(f"The program reads and writes the terminal pwndbg-imgui was started from "
                                    f"({app.cfg.terminal_io}): type there, e.g. for ncurses programs. Ctrl-C there "
                                    "interrupts the running program.")
            else:
                imgui.text_disabled("Program I/O is disabled (--no-io): the program shares the gdb console.")
            imgui.pop_text_wrap_pos()
            return
        # header
        imgui.set_next_item_width(combo_width("Python expr"))
        modes = {"text": "Text", "python": "Python expr", "hex": "Hex"}
        if imgui.begin_combo("##iomode", modes[self.mode]):
            for k, v in modes.items():
                if imgui.selectable(v, self.mode == k)[0]:
                    self.mode = k
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
            app.io.set_raw(st["io_raw"])
        imgui.set_item_tooltip("Raw TTY: bytes pass through untouched (binary-safe).\nUncheck for a canonical TTY (line editing, ^C, ^D = EOF).")
        imgui.same_line()
        imgui.set_next_item_width(combo_width("Terminal"))
        if imgui.begin_combo("##ioview", self.view_mode.capitalize()):
            for k in ("terminal", "hexdump"):
                if imgui.selectable(k.capitalize(), self.view_mode == k)[0]:
                    self.view_mode = k
            imgui.end_combo()
        imgui.same_line()
        if imgui.button(fa.ICON_FA_TRASH + "##ioclear"):
            app.io_term.clear()
            with app.io_term.lock:
                app.io.raw_bytes.clear()
                app.io.bytes_version += 1
        imgui.set_item_tooltip("Clear")
        imgui.same_line()
        imgui.begin_disabled(st["io_raw"])
        if imgui.button("EOF"):
            app.io.write(b"\x04")
        imgui.end_disabled()
        if imgui.is_item_hovered(imgui.HoveredFlags_.allow_when_disabled):
            imgui.set_tooltip("Send ^D (end of file). Needs a non-raw TTY.")
        imgui.same_line()
        imgui.text_disabled(app.io.path)

        footer = imgui.get_frame_height_with_spacing() + 2
        if self.view_mode == "hexdump":
            if app.io.bytes_version != self.hex_version:
                self.hex_version = app.io.bytes_version
                with app.io_term.lock:
                    data = bytes(app.io.raw_bytes)
                app.io_hex_term.set_text(hexdump_ansi(data))
            app.io_hex_view.render(-footer)
        else:
            app.io_view.render(-footer)
            app.io.resize(app.io_view.rows, app.io_view.cols)

        imgui.align_text_to_frame_padding()  # center the icon on the input box's line
        imgui.text_colored(v4(th.accent2), fa.ICON_FA_KEYBOARD)
        imgui.same_line()
        imgui.set_next_item_width(-buttons_width("Send"))
        imgui.push_font(app.mono, app.ui_size)  # an input box: sized like the UI, not the code panes
        entered, self.input = imgui.input_text_with_hint(
            "##io_in", "input for the program (Enter to send, Up/Down: history)", self.input,
            imgui.InputTextFlags_.enter_returns_true | imgui.InputTextFlags_.callback_history, self._history_cb)
        imgui.pop_font()
        imgui.same_line()
        if (imgui.button("Send##io") or entered) and (self.input or st["io_newline"]):
            self.send(self.input)
            imgui.set_keyboard_focus_here(-1)

    def _history_cb(self, data) -> int:
        hist = self.history
        if not hist:
            return 0
        if data.event_key == imgui.Key.up_arrow:
            self.history_pos = len(hist) - 1 if self.history_pos == -1 else max(0, self.history_pos - 1)
        elif data.event_key == imgui.Key.down_arrow and self.history_pos != -1:
            self.history_pos += 1
            if self.history_pos >= len(hist):
                self.history_pos = -1
        entry = hist[self.history_pos] if self.history_pos != -1 else {"text": ""}
        if entry.get("mode") in ("text", "python", "hex"):
            self.mode = entry["mode"]  # a payload comes back with the mode it was sent in
        data.delete_chars(0, data.buf_text_len)
        data.insert_chars(0, entry["text"])
        return 0

    def send(self, text: str) -> None:
        app = self.app
        if app.io is None:  # --no-io / attached: no terminal of ours for the program
            return
        try:
            if self.mode == "python":
                data = eval_payload(text, word=app.ptrsize, endian=app.endian)
            else:
                data = parse_bytes_input(text, self.mode)
        except Exception as e:
            app.toast(f"bad input: {e}", "error")
            return
        if app.settings["io_newline"]:
            data += b"\n"
        app.io.write(data)
        if app.settings["io_echo"]:
            app.io_term.feed(data.decode("utf-8", errors="surrogateescape"), ECHO)
        entry = {"mode": self.mode, "text": text}
        if text and (not self.history or self.history[-1] != entry):
            self.history.append(entry)
        self.history_pos = -1
        self.input = ""
