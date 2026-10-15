"""Tool panes as standalone classes: each owns its UI state and draws itself.

The data they show (memory map, breakpoints) lives on App, which other panes use too;
a pane only keeps what belongs to its own widgets (filters, inputs being edited).
New panes go here rather than into the mixins, so they can be type-checked."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from imgui_bundle import imgui
from imgui_bundle import icons_fontawesome_6 as fa
from .widgets import begin_table_card, buttons_width, end_table_card, v4

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
        began = begin_table_card(app, "##vmmap", 6, TABLE_FLAGS)
        if began:
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
        end_table_card(began)
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
        began = begin_table_card(self.app, "##bps", 7, TABLE_FLAGS)
        if began:
            imgui.table_setup_scroll_freeze(0, 1)
            for col in ("", "#", "Type", "Where", "Address", "Hits"):
                imgui.table_setup_column(col)
            imgui.table_setup_column("Condition", imgui.TableColumnFlags_.width_stretch)
            imgui.table_headers_row()
            for b in self.app.bps:
                self._row(b)
        end_table_card(began)

    def _add_bar(self) -> None:
        buttons_w = buttons_width(*(k[1] for k in self.KINDS))
        # keep the buttons on the input's line when it leaves the input usable room, else wrap them
        inline = imgui.get_content_region_avail().x - buttons_w >= imgui.get_font_size() * 10
        imgui.set_next_item_width(-buttons_w if inline else -1)
        entered, self.input = imgui.input_text_with_hint(
            "##bpin", "main · *0x401136 · file.c:42 · $pc+8 · var", self.input, imgui.InputTextFlags_.enter_returns_true)
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


class HeapPane:
    """The glibc heap of the current thread's arena: chunks and non-empty bins (agent op
    `heap`, built on pwndbg's heap model). Refreshed at each stop while visible."""

    LABEL = f"{fa.ICON_FA_CUBES_STACKED} Heap"
    STATE_NAMES = {"tcachebins": "tcache", "fastbins": "fastbin", "unsortedbin": "unsorted",
                   "smallbins": "smallbin", "largebins": "largebin", "top": "top"}

    def __init__(self, app: App) -> None:
        self.app = app
        self.data: dict | None = None
        self.error = ""
        self.fetched_gen = -1  # App.dirty_gen of the data shown
        self.pending = False
        self.selected: int | None = None

    def refresh(self) -> None:
        app = self.app
        if not app.rpc or not app.is_stopped() or self.pending:
            return
        self.pending = True
        self.fetched_gen = app.dirty_gen

        def done(res) -> None:
            self.pending = False
            self.error = res.get("error", "")
            self.data = None if self.error else res

        def fail(err: str) -> None:
            self.pending = False
            self.error = err
            self.data = None

        app.rpc.request("heap", done, fail)

    def state_color(self, state: str | None):
        th = self.app.theme
        if state is None:
            return th.fg
        if state == "top":
            return th.dim
        return {"tcachebins": th.cyan, "fastbins": th.blue, "unsortedbin": th.magenta}.get(state, th.yellow)

    def gui(self) -> None:
        app = self.app
        if app.is_stopped() and self.fetched_gen != app.dirty_gen:
            self.refresh()  # only while visible: hidden panes aren't drawn
        if imgui.button(f"{fa.ICON_FA_ARROWS_ROTATE}##heapr"):
            self.fetched_gen = -1
            self.refresh()
        imgui.same_line()
        if not app.is_stopped():
            imgui.text_disabled("The heap appears once the program is stopped.")
            return
        if self.error:
            imgui.text_disabled(self.error)
            return
        if self.data is None:
            imgui.text_disabled("Loading…")
            return
        d = self.data
        chunks = d["chunks"]
        free = sum(1 for c in chunks if c["bin"] not in (None, "top"))
        imgui.text_disabled(f"{'main_arena' if d['main'] else 'arena'} {d['arena']:#x} · {len(chunks)} chunks"
                            f" · {free} free" + (" · truncated" if d["truncated"] else ""))
        avail = imgui.get_content_region_avail()
        bins_h = min(avail.y * 0.4, imgui.get_text_line_height_with_spacing() * (len(d["bins"]) + 1.5) + 16)
        imgui.push_font(app.mono, app.code_size)
        self._chunks(chunks, max(60.0, avail.y - bins_h - imgui.get_style().item_spacing.y))
        self._bins(d["bins"], {c["addr"] for c in chunks})
        imgui.pop_font()

    def _chunks(self, chunks: list, height: float) -> None:
        app = self.app
        began = begin_table_card(app, "##heapchunks", 4, TABLE_FLAGS, height)
        if not began:
            end_table_card(began)
            return
        imgui.table_setup_scroll_freeze(0, 1)
        for col in ("Chunk", "Size", "Flags"):
            imgui.table_setup_column(col)
        imgui.table_setup_column("State", imgui.TableColumnFlags_.width_stretch)
        imgui.table_headers_row()
        for c in chunks:
            addr, state = c["addr"], c["bin"]
            imgui.table_next_row()
            imgui.table_next_column()
            imgui.push_style_color(imgui.Col_.text, v4(self.state_color(state)))
            clicked, _ = imgui.selectable(f"{addr:#x}##hc{addr}", self.selected == addr,
                                          imgui.SelectableFlags_.span_all_columns
                                          | imgui.SelectableFlags_.allow_double_click)
            if clicked:
                self.selected = addr
                if imgui.is_mouse_double_clicked(0):
                    app.open_memory(addr)
            imgui.set_item_tooltip("Double-click: open in Memory")
            imgui.table_next_column()
            imgui.text_unformatted(f"{c['size']:#x}")
            imgui.table_next_column()
            imgui.text_unformatted(("P" if c["prev_inuse"] else "-") + ("M" if c["mmapped"] else "-"))
            imgui.table_next_column()
            imgui.text_unformatted(self.STATE_NAMES.get(state, "") if state else "in use")
            imgui.pop_style_color()
        end_table_card(began)

    def _bins(self, bins: list, chunk_addrs: set) -> None:
        app = self.app
        if not bins:
            imgui.text_disabled("All bins are empty.")
            return
        began = begin_table_card(app, "##heapbins", 3, TABLE_FLAGS, fit=True)
        if not began:
            end_table_card(began)
            return
        for col in ("Bin", "Count"):
            imgui.table_setup_column(col)
        imgui.table_setup_column("Chain (fd)", imgui.TableColumnFlags_.width_stretch)
        imgui.table_headers_row()
        for i, b in enumerate(bins):
            imgui.table_next_row()
            imgui.table_next_column()
            key = b["key"] if isinstance(b["key"], str) else f"{b['key']:#x}"
            imgui.text_colored(v4(self.state_color(b["type"])), f"{self.STATE_NAMES[b['type']]} {key}")
            if b["corrupted"]:
                imgui.same_line()
                imgui.text_colored(v4(app.theme.red), "corrupted")
            imgui.table_next_column()
            imgui.text_unformatted("" if b["count"] is None else str(b["count"]))
            imgui.table_next_column()
            for j, a in enumerate(b["chain"]):
                if j:
                    imgui.same_line(0, 4)
                    imgui.text_disabled("→")
                    imgui.same_line(0, 4)
                # tcache entries point at the chunk's user data (chunk + 2 words)
                chunk = a if a in chunk_addrs else a - 2 * app.ptrsize
                if chunk in chunk_addrs:
                    if imgui.text_link(f"{a:#x}##hb{i}_{j}"):
                        self.selected = chunk
                        app.open_memory(a)
                else:
                    imgui.text_disabled(f"{a:#x}")  # e.g. the bin's head inside the arena
        end_table_card(began)
