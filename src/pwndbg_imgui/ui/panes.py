"""Tool panes as standalone classes: each owns its UI state and draws itself.

The data they show (memory map, breakpoints) lives on App, which other panes use too;
a pane only keeps what belongs to its own widgets (filters, inputs being edited).
New panes go here rather than into the mixins, so they can be type-checked."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from imgui_bundle import imgui
from imgui_bundle import icons_fontawesome_6 as fa
from ..term import Term
from .widgets import TableCard, TextView, buttons_width, v4

if TYPE_CHECKING:
    from .app import App

STRETCH = imgui.TableColumnFlags_.width_stretch
TABLE_FLAGS = (imgui.TableFlags_.row_bg | imgui.TableFlags_.borders_inner_v | imgui.TableFlags_.pad_outer_x
               | imgui.TableFlags_.scroll_x | imgui.TableFlags_.scroll_y | imgui.TableFlags_.resizable
               | imgui.TableFlags_.sizing_fixed_fit)


class VmmapPane:
    """The memory map: filterable by name, permissions or a contained address."""

    LABEL = f"{fa.ICON_FA_MAP} VMMap"

    def __init__(self, app: App) -> None:
        self.app = app
        self.filter = ""
        self.card = TableCard(app, "##vmmap", ["Start", "End", "Size", "Perm", "Offset", ("File", STRETCH)],
                              TABLE_FLAGS)

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
        pages = [(i, p) for i, p in enumerate(app.vmmap) if self.matches(p)]
        card = self.card
        if card.begin(rows=len(pages)):
            for i, p in pages:
                start, end, perm, off, objfile, kind = p
                imgui.table_next_row()
                imgui.table_next_column()
                row = imgui.table_get_row_index()
                card.cell(f"{start:#x}")
                imgui.push_style_color(imgui.Col_.text, v4(th.kind_color(kind)))
                clicked, _ = imgui.selectable(
                    f"{start:#x}##vm{i}", False,
                    imgui.SelectableFlags_.span_all_columns | imgui.SelectableFlags_.allow_double_click)
                if clicked and imgui.is_mouse_double_clicked(0):
                    app.open_memory(start)
                if imgui.begin_popup_context_item(f"##vmctx{i}"):
                    imgui.pop_font()
                    self._menu(start, objfile)
                    card.copy_menu(row)
                    imgui.push_font(app.mono, app.code_size)
                    imgui.end_popup()
                for text in (f"{end:#x}", f"{end - start:#x}", perm, f"{off:#x}"):
                    imgui.table_next_column()
                    card.cell(text)
                    imgui.text_unformatted(text)
                imgui.table_next_column()
                card.cell(objfile)
                imgui.text_unformatted(os.path.basename(objfile) if objfile.startswith("/") else objfile)
                if objfile.startswith("/"):
                    imgui.set_item_tooltip(objfile)
                imgui.pop_style_color()
        card.end()
        imgui.pop_font()

    def _menu(self, start: int, objfile: str) -> None:
        app = self.app
        if imgui.menu_item_simple(f"{fa.ICON_FA_MEMORY}  View memory"):
            app.open_memory(start)
        if imgui.menu_item_simple(f"{fa.ICON_FA_LAYER_GROUP}  Telescope start"):
            app.open_cmd_view(f"telescope {start:#x} 32")
        imgui.separator()


class BreakpointsPane:
    """Breakpoints and watchpoints: add, enable/disable, delete, edit conditions."""

    LABEL = f"{fa.ICON_FA_CIRCLE_DOT} Breakpoints"
    KINDS = (("break", "Break", "Software breakpoint"), ("tbreak", "Temp", "Temporary breakpoint"),
             ("watch", "Watch", "Write watchpoint"), ("rwatch", "RWatch", "Read watchpoint"))

    def __init__(self, app: App) -> None:
        self.app = app
        self.input = ""
        self.cond_edit: dict[int, str] = {}  # breakpoint number -> condition being typed
        self.card = TableCard(app, "##bps", ["", "#", "Type", "Where", "Address", "Hits", ("Condition", STRETCH)],
                              TABLE_FLAGS, framed=True)

    def gui(self) -> None:
        self._add_bar()
        if not self.app.bps:
            imgui.text_disabled("No breakpoints. Click the gutter of Disassembly/Source, or add one above.")
            return
        if self.card.begin(rows=len(self.app.bps)):
            for b in self.app.bps:
                self._row(b)
        self.card.end()

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
        card = self.card
        addrs = [loc["addr"] for loc in b.get("locs", []) if loc.get("addr") is not None]
        imgui.table_next_row()
        imgui.table_next_column()
        card.cell("enabled" if b["enabled"] else "disabled")
        changed, en = imgui.checkbox(f"##en{num}", b["enabled"])
        if changed:
            self._update(num, enabled=en)
        imgui.same_line()
        if imgui.small_button(f"{fa.ICON_FA_TRASH}##del{num}") and app.rpc:
            app.rpc.request("bp_delete", None, app.error_toast, num=num)
        imgui.table_next_column()
        card.cell(str(num))
        imgui.text_colored(v4(th.red if b["enabled"] else th.dim), str(num))
        imgui.table_next_column()
        kind = b.get("type", "?") + (" (temp)" if b.get("temp") else "")
        card.cell(kind)
        imgui.text_unformatted(kind)
        imgui.table_next_column()
        where = b.get("location") or b.get("expr") or ""
        card.cell(where)
        imgui.text_unformatted(where)
        if b.get("pending"):
            imgui.same_line()
            imgui.text_disabled("(pending)")
        imgui.table_next_column()
        card.cell(" ".join(f"{a:#x}" for a in addrs))
        if addrs:
            imgui.push_font(app.mono, app.code_size)
            if imgui.text_link(f"{addrs[0]:#x}##bpa{num}"):
                app.open_memory(addrs[0])
            imgui.pop_font()
            if len(addrs) > 1:
                imgui.same_line()
                imgui.text_disabled(f"+{len(addrs) - 1}")
        imgui.table_next_column()
        card.cell(str(b.get("hits", 0)))
        imgui.text_unformatted(str(b.get("hits", 0)))
        imgui.table_next_column()
        cond = b.get("cond") or ""
        card.cell(cond)
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
        # the Memory tab: pwndbg's vis-heap-chunks, from the selected chunk if any
        self.vis_term = Term(max_lines=50000)
        self.vis_view = TextView(app, self.vis_term, "visheap", follow="none",
                                 empty_hint="Run the program to a point where the heap exists.")
        self.vis_count = 10  # chunks to draw; 0: all of them
        self.vis_from_selected = True
        self.vis_no_skip = False
        self.vis_no_truncate = False
        self.vis_key = None  # (dirty_gen, command) of the output shown
        self.vis_pending = False
        self.show_memory_tab = False  # select the Memory tab at the next frame
        self.chunks_card = TableCard(app, "##heapchunks", ["Chunk", "Size", "Flags", ("State", STRETCH)], TABLE_FLAGS)
        self.bins_card = TableCard(app, "##heapbins", ["Bin", "Count", ("Chain (fd)", STRETCH)], TABLE_FLAGS)

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
        if not imgui.begin_tab_bar("##heaptabs"):
            return
        if imgui.begin_tab_item(f"{fa.ICON_FA_TABLE_LIST} Chunks##heapt")[0]:
            self._chunks_tab(d, chunks)
            imgui.end_tab_item()
        memory_flags = imgui.TabItemFlags_.set_selected if self.show_memory_tab else 0
        self.show_memory_tab = False
        if imgui.begin_tab_item(f"{fa.ICON_FA_MEMORY} Memory (vis-heap-chunks)##heapm", None, memory_flags)[0]:
            self._memory_tab()
            imgui.end_tab_item()
        imgui.end_tab_bar()

    def _chunks_tab(self, d: dict, chunks: list) -> None:
        app = self.app
        imgui.push_font(app.mono, app.code_size)
        avail = imgui.get_content_region_avail().y
        style = imgui.get_style()
        row = imgui.get_text_line_height() + 2 * style.cell_padding.y
        bins_h = min(avail * 0.4, row * (len(d["bins"]) + 1) + 2) if d["bins"] else row
        self._chunks(chunks, max(60.0, avail - bins_h - style.item_spacing.y))
        self._bins(d["bins"], {c["addr"] for c in chunks})
        imgui.pop_font()

    def vis_command(self) -> str:
        parts = ["vis-heap-chunks"]
        if self.vis_count:
            parts.append(str(self.vis_count))
            if self.vis_from_selected and self.selected is not None:
                parts.append(f"{self.selected:#x}")
        else:
            parts.append("--all-chunks")
        if self.vis_no_skip:
            parts.append("--no-skip")
        if self.vis_no_truncate:
            parts.append("--no-truncate")
        return " ".join(parts)

    def _memory_tab(self) -> None:
        app = self.app
        imgui.align_text_to_frame_padding()
        imgui.text_disabled("Chunks")
        imgui.same_line()
        imgui.set_next_item_width(imgui.get_font_size() * 6)
        _, self.vis_count = imgui.input_int("##viscount", self.vis_count, 5)
        self.vis_count = max(0, min(self.vis_count, 10000))
        imgui.set_item_tooltip("How many chunks to draw (0: all of them)")
        imgui.same_line()
        imgui.begin_disabled(self.vis_count == 0)
        sel = f"{self.selected:#x}" if self.selected is not None else "the selected chunk"
        _, self.vis_from_selected = imgui.checkbox(f"From {sel}##visfrom", self.vis_from_selected)
        imgui.set_item_tooltip("Start at the chunk selected in the Chunks tab (else the heap's first one)")
        imgui.end_disabled()
        imgui.same_line()
        _, self.vis_no_skip = imgui.checkbox("No skip##visskip", self.vis_no_skip)
        imgui.set_item_tooltip("Show repeated rows instead of collapsing them (--no-skip)")
        imgui.same_line()
        _, self.vis_no_truncate = imgui.checkbox("Whole chunks##vistrunc", self.vis_no_truncate)
        imgui.set_item_tooltip("Don't truncate large chunks (--no-truncate)")
        cmd = self.vis_command()
        key = (app.dirty_gen, cmd)
        if app.is_stopped() and key != self.vis_key and not self.vis_pending and app.rpc:
            self.vis_pending = True
            self.vis_key = key

            def done(out) -> None:
                self.vis_pending = False
                self.vis_term.set_text(out or "(no output)\n")

            def fail(err) -> None:
                self.vis_pending = False
                self.vis_term.set_text(f"\x1b[31m{err}\x1b[0m\n")

            app.rpc.request("exec", done, fail, cmd=cmd)
        self.vis_view.render()

    def _chunks(self, chunks: list, max_height: float) -> None:
        app = self.app
        card = self.chunks_card
        if not card.begin(rows=len(chunks), max_height=max_height):
            card.end()
            return
        for c in chunks:
            addr, state = c["addr"], c["bin"]
            flags = ("P" if c["prev_inuse"] else "-") + ("M" if c["mmapped"] else "-")
            state_name = self.STATE_NAMES.get(state, "") if state else "in use"
            imgui.table_next_row()
            imgui.table_next_column()
            row = imgui.table_get_row_index()
            card.cell(f"{addr:#x}")
            imgui.push_style_color(imgui.Col_.text, v4(self.state_color(state)))
            clicked, _ = imgui.selectable(f"{addr:#x}##hc{addr}", self.selected == addr,
                                          imgui.SelectableFlags_.span_all_columns
                                          | imgui.SelectableFlags_.allow_double_click)
            if clicked:
                self.selected = addr
                if imgui.is_mouse_double_clicked(0):
                    app.open_memory(addr)
            imgui.set_item_tooltip("Double-click: open in Memory · right-click: more")
            if imgui.begin_popup_context_item(f"##hcctx{addr}"):
                imgui.pop_font()
                if imgui.menu_item_simple(f"{fa.ICON_FA_MEMORY}  Open in Memory"):
                    app.open_memory(addr)
                if imgui.menu_item_simple(f"{fa.ICON_FA_CUBES_STACKED}  Visualize from here (vis-heap-chunks)"):
                    self.selected = addr
                    self.vis_from_selected = True
                    self.show_memory_tab = True
                imgui.separator()
                card.copy_menu(row)
                imgui.push_font(app.mono, app.code_size)
                imgui.end_popup()
            for text in (f"{c['size']:#x}", flags, state_name):
                imgui.table_next_column()
                card.cell(text)
                imgui.text_unformatted(text)
            imgui.pop_style_color()
        card.end()

    def _bins(self, bins: list, chunk_addrs: set) -> None:
        app = self.app
        if not bins:
            imgui.text_disabled("All bins are empty.")
            return
        card = self.bins_card
        if not card.begin(rows=len(bins)):
            card.end()
            return
        for i, b in enumerate(bins):
            imgui.table_next_row()
            imgui.table_next_column()
            key = b["key"] if isinstance(b["key"], str) else f"{b['key']:#x}"
            card.cell(f"{self.STATE_NAMES[b['type']]} {key}" + (" corrupted" if b["corrupted"] else ""))
            imgui.text_colored(v4(self.state_color(b["type"])), f"{self.STATE_NAMES[b['type']]} {key}")
            if b["corrupted"]:
                imgui.same_line()
                imgui.text_colored(v4(app.theme.red), "corrupted")
            imgui.table_next_column()
            count = "" if b["count"] is None else str(b["count"])
            card.cell(count)
            imgui.text_unformatted(count)
            imgui.table_next_column()
            card.cell(" -> ".join(f"{a:#x}" for a in b["chain"]))
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
        card.end()


class StopRefreshed:
    """Data fetched from the agent once per stop, and only while the pane is drawn."""

    OP = ""  # agent op returning the data

    def __init__(self, app: App) -> None:
        self.app = app
        self.data: dict | None = None
        self.error = ""
        self.fetched_gen = -1  # App.dirty_gen of the data shown
        self.pending = False

    def unavailable(self) -> bool:
        """The data can't be shown (pwndbg missing, old gdb...): show pwndbg's text instead."""
        return bool(self.error) and self.app.is_stopped()

    def invalidate(self) -> None:
        """Refetch at the next draw (e.g. after selecting another frame or thread)."""
        self.fetched_gen = -1

    def refresh_if_stale(self) -> None:
        app = self.app
        if not app.rpc or not app.is_stopped() or self.pending or self.fetched_gen == app.dirty_gen:
            return
        self.pending = True
        self.fetched_gen = app.dirty_gen

        def done(res) -> None:
            self.pending = False
            self.error, self.data = res.get("error", ""), res

        def fail(err: str) -> None:
            self.pending = False
            self.error, self.data = err, None

        app.rpc.request(self.OP, done, fail)

    @staticmethod
    def location_text(entry: dict) -> str:
        name = entry.get("sym") or entry.get("func") or "??"
        where = f"{entry['file']}:{entry['line']}" if entry.get("file") else entry.get("module") or ""
        return f"{name} {where}".strip()

    def location_cell(self, entry: dict) -> None:
        """function / symbol, then source file:line or module, dimmed."""
        th = self.app.theme
        imgui.text_colored(v4(th.fg), entry.get("sym") or entry.get("func") or "??")
        where = (f"{os.path.basename(entry['file'])}:{entry['line']}" if entry.get("file")
                 else entry.get("module") or "")
        if where:
            imgui.same_line()
            imgui.text_disabled(where)
            if entry.get("file"):
                imgui.set_item_tooltip(f"{entry['file']}:{entry['line']}")

    def address_cell(self, addr: int) -> None:
        app = self.app
        page = app.page_for(addr)
        color = app.theme.kind_color(page[5]) if page else app.theme.fg
        imgui.text_colored(v4(color), f"{addr:#x}")
        if imgui.is_item_hovered() and imgui.get_io().key_ctrl and imgui.is_mouse_clicked(0):
            app.open_memory(addr)


class BacktracePane(StopRefreshed):
    """The selected thread's call stack as a table (agent op `frames`). Click a frame to
    select it; right-click for more."""

    OP = "frames"

    def __init__(self, app: App) -> None:
        super().__init__(app)
        self.card = TableCard(app, "##frames", ["#", "Address", ("Function / location", STRETCH)], TABLE_FLAGS)

    def gui(self) -> None:
        app = self.app
        self.refresh_if_stale()
        if not app.is_stopped():
            imgui.text_disabled("The call stack appears once the program is stopped.")
            return
        if self.error or self.data is None:
            imgui.text_disabled(self.error or "Loading…")
            return
        frames = self.data["frames"]
        imgui.push_font(app.mono, app.code_size)
        card = self.card
        if card.begin(rows=len(frames) + bool(self.data.get("truncated"))):
            for f in frames:
                level = f["level"]
                imgui.table_next_row()
                imgui.table_next_column()
                row = imgui.table_get_row_index()
                card.cell(str(level))
                clicked, _ = imgui.selectable(f"{'►' if f['selected'] else ' '} {level}##fr{level}", f["selected"],
                                              imgui.SelectableFlags_.span_all_columns
                                              | imgui.SelectableFlags_.allow_overlap)
                if clicked and not f["selected"]:
                    self.select(level)
                if imgui.begin_popup_context_item(f"##frctx{level}"):
                    imgui.pop_font()
                    self._menu(f)
                    card.copy_menu(row)
                    imgui.push_font(app.mono, app.code_size)
                    imgui.end_popup()
                imgui.table_next_column()
                card.cell(f"{f['pc']:#x}")
                self.address_cell(f["pc"])
                imgui.table_next_column()
                card.cell(self.location_text(f))
                self.location_cell(f)
            if self.data.get("truncated"):
                imgui.table_next_row()
                imgui.table_next_column()
                imgui.text_disabled("…")
        card.end()
        imgui.pop_font()

    def select(self, level: int) -> None:
        app = self.app
        if app.is_stopped():
            app.exec(f"frame {level}", quiet=True, cb=lambda _out: self.invalidate())

    def _menu(self, f: dict) -> None:
        app = self.app
        level, pc = f["level"], f["pc"]
        if imgui.menu_item_simple(f"{fa.ICON_FA_SHOE_PRINTS}  Select frame #{level}", "click", False, not f["selected"]):
            self.select(level)
        if imgui.menu_item_simple(f"{fa.ICON_FA_ARROW_UP_FROM_BRACKET}  Finish up to frame #{level}", "", False,
                                  app.is_stopped() and level > 0):
            app.exec(f"frame {level - 1}", refresh=False, quiet=True, cb=lambda _o: app.send_console("finish"))
        imgui.separator()
        if imgui.menu_item_simple(f"{fa.ICON_FA_CODE}  Disassemble at {pc:#x}"):
            app.open_cmd_view(f"nearpc {pc:#x} 40")
        if imgui.menu_item_simple(f"{fa.ICON_FA_MEMORY}  Memory at {pc:#x}"):
            app.open_memory(pc)
        imgui.separator()


class ThreadsPane(StopRefreshed):
    """The inferior's threads as a table (agent op `threads`). Click one to switch to it."""

    OP = "threads"
    STATE_ICONS = {"stopped": fa.ICON_FA_PAUSE, "running": fa.ICON_FA_PLAY, "exited": fa.ICON_FA_XMARK}

    def __init__(self, app: App) -> None:
        super().__init__(app)
        self.card = TableCard(app, "##threads", ["#", "Name", "TID", "State", ("Location", STRETCH)], TABLE_FLAGS)

    def gui(self) -> None:
        app = self.app
        self.refresh_if_stale()
        if not app.is_stopped():
            imgui.text_disabled("Threads appear once the program is stopped.")
            return
        if self.error or self.data is None:
            imgui.text_disabled(self.error or "Loading…")
            return
        th = app.theme
        threads = self.data["threads"]
        imgui.push_font(app.mono, app.code_size)
        card = self.card
        if card.begin(rows=len(threads)):
            for t in threads:
                num = t["num"]
                imgui.table_next_row()
                imgui.table_next_column()
                row = imgui.table_get_row_index()
                card.cell(str(num))
                clicked, _ = imgui.selectable(f"{'►' if t['selected'] else ' '} {num}##th{num}", t["selected"],
                                              imgui.SelectableFlags_.span_all_columns
                                              | imgui.SelectableFlags_.allow_overlap)
                if clicked and not t["selected"] and t["state"] == "stopped":
                    self.select(num)
                if imgui.begin_popup_context_item(f"##thctx{num}"):
                    imgui.pop_font()
                    if imgui.menu_item_simple(f"{fa.ICON_FA_ARROW_RIGHT}  Switch to thread {num}", "click", False,
                                              not t["selected"] and t["state"] == "stopped"):
                        self.select(num)
                    imgui.separator()
                    card.copy_menu(row)
                    imgui.push_font(app.mono, app.code_size)
                    imgui.end_popup()
                imgui.table_next_column()
                card.cell(t["name"] or "")
                imgui.text_unformatted(t["name"] or "")
                imgui.table_next_column()
                card.cell(str(t["tid"]))
                imgui.text_disabled(str(t["tid"]))
                imgui.table_next_column()
                card.cell(t["state"])
                color = {"stopped": th.yellow, "running": th.green}.get(t["state"], th.dim)
                imgui.text_colored(v4(color), f"{self.STATE_ICONS.get(t['state'], '')} {t['state']}")
                imgui.table_next_column()
                card.cell(f"{t['pc']:#x} {self.location_text(t)}" if "pc" in t else "")
                if "pc" in t:
                    self.address_cell(t["pc"])
                    imgui.same_line()
                    self.location_cell(t)
        card.end()
        imgui.pop_font()

    def select(self, num: int) -> None:
        app = self.app
        if app.is_stopped():
            def switched(_out) -> None:
                self.invalidate()
                app.backtrace_pane.invalidate()  # another thread, another call stack

            app.exec(f"thread {num}", quiet=True, cb=switched)


class RegistersBar:
    """Controls above the Registers pane for pwndbg's register-display parameters: compact
    mode, its column count, the flags and return-address registers. Changes are applied with
    `set`, redraw the context and are remembered like the Config pane's."""

    PARAMS = ("show-compact-regs", "show-compact-regs-columns", "show-flags", "show-retaddr-reg")
    MODES = (("off", "one register per line"), ("on", "columns, grouped like the plain view"),
             ("very", "columns, packed as tightly as possible"), ("hardcut", "columns, long values cut"))

    def __init__(self, app: App) -> None:
        self.app = app
        self.values: dict | None = None  # parameter -> value, None until fetched
        self.pending = False
        self.fetched_gen = -1

    def fetch(self) -> None:
        app = self.app
        if not app.rpc or self.pending:
            return
        self.pending = True
        self.fetched_gen = app.dirty_gen

        def done(values) -> None:
            self.pending = False
            self.values = values or {}

        def fail(_err) -> None:
            self.pending = False
            self.values = {}

        app.rpc.request("params", done, fail, names=list(self.PARAMS))

    def set(self, name: str, value) -> None:
        app = self.app
        arg = "on" if value is True else "off" if value is False else str(value)
        if self.values is not None:
            self.values[name] = value
        app.persist_pwndbg_param(name, arg)

        def applied(_out) -> None:
            self.fetch()
            if app.config_pane.params is not None:  # keep the Config pane's markers in step
                app.config_pane.reload()

        app.exec(f"set {name} {arg}", quiet=True, cb=applied)  # refreshes the context

    def gui(self) -> None:
        app = self.app
        if self.values is None or (app.is_stopped() and self.fetched_gen != app.dirty_gen):
            self.fetch()  # at first, then once per stop (they may change from the console)
        if not self.values or not app.info.get("pwndbg"):
            return
        v = self.values
        mode = str(v.get("show-compact-regs", "off"))
        imgui.align_text_to_frame_padding()
        imgui.text_disabled("Compact")
        imgui.same_line()
        imgui.set_next_item_width(imgui.calc_text_size("hardcut").x + imgui.get_frame_height() + 12)
        if imgui.begin_combo("##regcompact", mode):
            for name, desc in self.MODES:
                if imgui.selectable(name, name == mode)[0] and name != mode:
                    self.set("show-compact-regs", name)
                imgui.set_item_tooltip(desc)
            imgui.end_combo()
        imgui.set_item_tooltip("pwndbg's show-compact-regs: registers in columns")
        imgui.same_line()
        imgui.begin_disabled(mode == "off")
        imgui.text_disabled("Columns")
        imgui.same_line()
        imgui.set_next_item_width(imgui.get_font_size() * 5.5)
        cols = int(v.get("show-compact-regs-columns", 2))
        changed, cols_new = imgui.input_int("##regcols", cols, 1)
        if changed and 0 <= cols_new <= 8 and cols_new != cols:
            self.set("show-compact-regs-columns", cols_new)
        imgui.set_item_tooltip("show-compact-regs-columns (0: as many as fit)")
        imgui.end_disabled()
        imgui.same_line(0, 14)
        changed, flags = imgui.checkbox("Flags##regflags", bool(v.get("show-flags")))
        if changed:
            self.set("show-flags", flags)
        imgui.set_item_tooltip("show-flags: show the flags register (EFLAGS, CPSR...)")
        imgui.same_line()
        changed, retaddr = imgui.checkbox("Return address##regret", bool(v.get("show-retaddr-reg")))
        if changed:
            self.set("show-retaddr-reg", retaddr)
        imgui.set_item_tooltip("show-retaddr-reg: show the return address register (LR, RA...)")
