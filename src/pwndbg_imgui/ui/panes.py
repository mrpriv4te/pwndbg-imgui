"""Tool panes as standalone classes: each owns its UI state and draws itself.

The data they show (memory map, breakpoints) lives on App, which other panes use too;
a pane only keeps what belongs to its own widgets (filters, inputs being edited).
New panes go here rather than into the mixins, so they can be type-checked."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from imgui_bundle import imgui
from imgui_bundle import icons_fontawesome_6 as fa
from .widgets import buttons_width, v4

if TYPE_CHECKING:
    from .app import App

TABLE_FLAGS = (imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.pad_outer_x
               | imgui.TableFlags_.scroll_y | imgui.TableFlags_.resizable | imgui.TableFlags_.sizing_fixed_fit)


class VmmapPane:
    """The memory map: filterable by name, permissions or a contained address."""

    LABEL = f"{fa.ICON_FA_MAP} VMMap"

    def __init__(self, app: App) -> None:
        self.app = app
        self.filter = ""

    def matches(self, page) -> bool:
        start, end, perm, _off, objfile, kind = page
        flt = self.filter.lower().strip()
        if flt.startswith("0x"):
            try:
                addr = int(flt, 16)
            except ValueError:
                pass
            else:
                return start <= addr < end
        return not flt or flt in objfile.lower() or flt in perm or flt in kind

    def gui(self) -> None:
        app = self.app
        th = app.theme
        imgui.set_next_item_width(-buttons_width(fa.ICON_FA_ARROWS_ROTATE))
        _, self.filter = imgui.input_text_with_hint("##vmf", f"{fa.ICON_FA_FILTER} filter (name, perms, address)",
                                                    self.filter)
        imgui.same_line()
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##vmr") and app.is_stopped() and app.rpc:
            app.rpc.request("vmmap", app._set_vmmap)
        if not app.vmmap:
            imgui.text_disabled("The memory map appears once the program is stopped.")
            return
        imgui.push_font(app.mono, app.code_size)
        if imgui.begin_table("##vmmap", 6, TABLE_FLAGS):
            imgui.table_setup_scroll_freeze(0, 1)
            for col in ("Start", "End", "Size", "Perm", "Offset"):
                imgui.table_setup_column(col)
            imgui.table_setup_column("File", imgui.TableColumnFlags_.width_stretch)
            imgui.table_headers_row()
            for i, p in enumerate(app.vmmap):
                if not self.matches(p):
                    continue
                start, end, perm, off, objfile, kind = p
                imgui.table_next_row()
                imgui.table_next_column()
                imgui.push_style_color(imgui.Col_.text, v4(th.kind_color(kind)))
                clicked, _ = imgui.selectable(
                    f"{start:#x}##vm{i}", False,
                    imgui.SelectableFlags_.span_all_columns | imgui.SelectableFlags_.allow_double_click)
                if clicked and imgui.is_mouse_double_clicked(0):
                    app.open_memory(start)
                if imgui.begin_popup_context_item(f"##vmctx{i}"):
                    imgui.pop_font()
                    self._menu(start, end, objfile)
                    imgui.push_font(app.mono, app.code_size)
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

    def _menu(self, start: int, end: int, objfile: str) -> None:
        app = self.app
        if imgui.menu_item_simple(f"{fa.ICON_FA_MEMORY}  View memory"):
            app.open_memory(start)
        if imgui.menu_item_simple(f"{fa.ICON_FA_LAYER_GROUP}  Telescope start"):
            app.open_cmd_view(f"telescope {start:#x} 32")
        if imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy start"):
            imgui.set_clipboard_text(f"{start:#x}")
        if imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy end"):
            imgui.set_clipboard_text(f"{end:#x}")
        if objfile and imgui.menu_item_simple(f"{fa.ICON_FA_COPY}  Copy path"):
            imgui.set_clipboard_text(objfile)


class BreakpointsPane:
    """Breakpoints and watchpoints: add, enable/disable, delete, edit conditions."""

    LABEL = f"{fa.ICON_FA_CIRCLE_DOT} Breakpoints"
    KINDS = (("break", "Break", "Software breakpoint"), ("tbreak", "Temp", "Temporary breakpoint"),
             ("watch", "Watch", "Write watchpoint"), ("rwatch", "RWatch", "Read watchpoint"))

    def __init__(self, app: App) -> None:
        self.app = app
        self.input = ""
        self.cond_edit: dict[int, str] = {}  # breakpoint number -> condition being typed

    def gui(self) -> None:
        self._add_bar()
        if not self.app.bps:
            imgui.text_disabled("No breakpoints. Click the gutter of Disassembly/Source, or add one above.")
            return
        if imgui.begin_table("##bps", 7, TABLE_FLAGS):
            imgui.table_setup_scroll_freeze(0, 1)
            for col in ("", "#", "Type", "Where", "Address", "Hits"):
                imgui.table_setup_column(col)
            imgui.table_setup_column("Condition", imgui.TableColumnFlags_.width_stretch)
            imgui.table_headers_row()
            for b in self.app.bps:
                self._row(b)
            imgui.end_table()

    def _add_bar(self) -> None:
        buttons_w = buttons_width(*(k[1] for k in self.KINDS))
        # keep the buttons on the input's line when it leaves the input usable room, else wrap them
        inline = imgui.get_content_region_avail().x - buttons_w >= imgui.get_font_size() * 10
        imgui.set_next_item_width(-buttons_w if inline else -1)
        entered, self.input = imgui.input_text_with_hint(
            "##bpin", "main · *0x401136 · file.c:42 · $rip+8 · var", self.input, imgui.InputTextFlags_.enter_returns_true)
        where = self.input.strip()
        for i, (kind, label, tip) in enumerate(self.KINDS):
            if inline or i:
                imgui.same_line()
            if (imgui.button(f"{label}##bp") or (entered and kind == "break")) and where:
                self.app.exec(f"{kind} {where}", refresh=False)
                self.input = ""
            imgui.set_item_tooltip(tip)

    def _row(self, b: dict) -> None:
        app = self.app
        th = app.theme
        num = b["num"]
        imgui.table_next_row()
        imgui.table_next_column()
        changed, en = imgui.checkbox(f"##en{num}", b["enabled"])
        if changed:
            self._update(num, enabled=en)
        imgui.same_line()
        if imgui.small_button(f"{fa.ICON_FA_TRASH}##del{num}") and app.rpc:
            app.rpc.request("bp_delete", None, app.error_toast, num=num)
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
            imgui.push_font(app.mono, app.code_size)
            if imgui.text_link(f"{addrs[0]:#x}##bpa{num}"):
                app.open_memory(addrs[0])
            imgui.pop_font()
            if len(addrs) > 1:
                imgui.same_line()
                imgui.text_disabled(f"+{len(addrs) - 1}")
        imgui.table_next_column()
        imgui.text_unformatted(str(b.get("hits", 0)))
        imgui.table_next_column()
        cond = b.get("cond") or ""
        imgui.set_next_item_width(-1)
        entered, self.cond_edit[num] = imgui.input_text_with_hint(
            f"##cond{num}", "condition (Enter)", self.cond_edit.get(num, cond), imgui.InputTextFlags_.enter_returns_true)
        if entered:
            self._update(num, cond=self.cond_edit[num])
        elif not imgui.is_item_active():
            self.cond_edit[num] = cond  # follow changes made elsewhere (e.g. `condition 1 ...` in the console)

    def _update(self, num: int, **changes) -> None:
        if self.app.rpc:
            self.app.rpc.request("bp_update", None, self.app.error_toast, num=num, **changes)
