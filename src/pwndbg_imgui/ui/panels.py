"""The dockable tool windows."""

from __future__ import annotations

import os

from imgui_bundle import hello_imgui, imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..theme import THEMES
from .console_panes import ConsolePane, ProgramIOPane
from .tool_panes import CommandsPane, ConfigPane, CyclicPane
from .panes import BreakpointsPane, HeapPane, VmmapPane
from .views import DecompView
from .widgets import buttons_width, help_marker, v4


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
            elif name == "disasm":
                self.disasm_target.bar()
                if not self.disasm_target.follow_pc:
                    self.disasm_target.gui()
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

    def memory_gui(self) -> None:
        self.memory.gui()

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
            (CommandsPane.LABEL, self.commands_pane.gui, "MainDockSpace", False),
            (ConfigPane.LABEL, self.config_pane.gui, "MainDockSpace", False),
            (CyclicPane.LABEL, self.cyclic_pane.gui, "RightBottom", True),
            (f"{fa.ICON_FA_GEAR} Preferences", self.prefs_gui, "RightBottom", False),
        ]
