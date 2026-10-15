"""Reusable widgets: the terminal text view and small layout helpers."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from imgui_bundle import ImVec2, ImVec4, imgui
from imgui_bundle import icons_fontawesome_6 as fa

from ..term import _STYLES, BOLD, CTRL, DIM, ECHO, INVERSE, UNDER, Term, strip_ansi
from ..theme import mix, u32
from .catalog import SECTION_META

ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")


WORD_RE = re.compile(r"[\w$#.@]+")


PC_MARK = "►"  # ►


def v4(c, a: float = 1.0):
    return ImVec4(c[0], c[1], c[2], a)


def ctrl_pressed(key) -> bool:
    io = imgui.get_io()
    return io.key_ctrl and not io.key_alt and imgui.is_key_pressed(key, False)


def buttons_width(*labels: str) -> float:
    """Room taken by buttons placed after an item with same_line()."""
    st = imgui.get_style()
    return sum(imgui.calc_text_size(lbl.split("##")[0]).x + st.frame_padding.x * 2 + st.item_spacing.x for lbl in labels)


class TableCard:
    """A table in a rounded "card" that stands out from the pane.

    - rounded: ImGui tables can't round their corners, so after the table is drawn its four
      corners are masked with the pane's color, which rounds the header's top corners and the
      last row's bottom corners (and any highlight there);
    - sized to its rows when they fit (the last row sits at the bottom of the card), else it
      fills the space left and scrolls, with a gap between the rows and the scrollbar;
    - copyable: cells record their text (cell()); right-click a row for a Copy menu (one
      cell, the row, all rows as TSV), Ctrl+C copies the hovered row. Tables whose rows have
      their own context menu add the same items with copy_menu(row).

        self.card = TableCard(app, "##id", ["Name", ("Value", stretch)], flags)  # once
        card = self.card
        if card.begin(rows=len(items)):  # every frame
            for item in items:
                imgui.table_next_row(); imgui.table_next_column()
                card.cell(name); imgui.text_unformatted(name) ...
        card.end()
    """

    RADIUS = 6.0

    def __init__(self, app, str_id: str, columns: list, flags: int, framed: bool = False,
                 freeze: bool = True, bg=None) -> None:
        self.app = app
        self.id = str_id
        # (name, column flags, initial width or a callable giving it); a bare name is (name, 0, 0)
        self.columns: list[tuple[str, int, object]] = []
        for c in columns:
            c = (c,) if isinstance(c, str) else tuple(c)
            self.columns.append((str(c[0]), int(c[1]) if len(c) > 1 else 0, c[2] if len(c) > 2 else 0.0))
        self.flags = flags
        self.framed = framed  # rows hold widgets (checkbox, input): frame-high rows
        self.freeze = freeze
        self.bg = bg  # color behind the card, for the rounded corners: None = the pane's; or a callable
        self.bg_now = None
        self.began = False
        self.cells: dict[int, list[str]] = {}  # this frame: table row index -> cell texts
        self.prev_cells: dict[int, list[str]] = {}  # last frame's, complete (for row menus)
        self.menu_row = 0
        self.row_tops: list[tuple[int, float]] = []
        self.dl = None
        self.rect = None

    # -- drawing -----------------------------------------------------------------
    def begin(self, rows: int | None = None, max_height: float | None = None) -> bool:
        """rows: how many rows will follow, to size the card to them (None: fill the space
        left, or max_height)."""
        app = self.app
        th = app.theme
        style = imgui.get_style()
        self.bg_now = th.panel if self.bg is None else (self.bg() if callable(self.bg) else self.bg)
        room = imgui.get_content_region_avail().y if max_height is None else max_height
        height = 0.0 if max_height is None else max_height
        if rows is not None:  # fit the rows when they fit, else fill and scroll
            line = imgui.get_frame_height() if self.framed else imgui.get_text_line_height()
            header_h = imgui.get_text_line_height() + 2 * style.cell_padding.y
            need = header_h + rows * (line + 2 * style.cell_padding.y) + 2
            if need < room:
                height = need
        imgui.push_style_var(imgui.StyleVar_.child_rounding, self.RADIUS)
        imgui.push_style_var(imgui.StyleVar_.window_padding, ImVec2(0, 0))
        imgui.push_style_color(imgui.Col_.child_bg, v4(mix(th.panel, th.fg, 0.05)))
        imgui.begin_child(f"{self.id}_card", ImVec2(0, height), imgui.ChildFlags_.none,
                          imgui.WindowFlags_.no_scrollbar | imgui.WindowFlags_.no_scroll_with_mouse)
        imgui.pop_style_color()
        imgui.pop_style_var(2)
        pos, size = imgui.get_window_pos(), imgui.get_window_size()
        self.rect = (pos, ImVec2(pos.x + size.x, pos.y + size.y))
        self.dl = imgui.get_window_draw_list()
        # a gap between the rows and the scrollbar's grab (the track itself is transparent):
        # more padding, and a wider bar by as much, so the grab is as wide as everywhere else
        # (read the style before pushing: scrollbar_padding changes with the first push)
        gap, size, pad = 3.0, style.scrollbar_size, style.scrollbar_padding
        imgui.push_style_var(imgui.StyleVar_.scrollbar_padding, gap)
        imgui.push_style_var(imgui.StyleVar_.scrollbar_size, size + 2 * (gap - pad))
        self.began = imgui.begin_table(self.id, len(self.columns), self.flags, ImVec2(0, 0), self._inner_width())
        imgui.pop_style_var(2)
        if not self.began:
            return False
        if self.freeze and self.flags & imgui.TableFlags_.scroll_y:
            imgui.table_setup_scroll_freeze(0, 1)
        for name, cflags, width in self.columns:
            imgui.table_setup_column(name, cflags, float(width() if callable(width) else width))  # type: ignore[arg-type]
        imgui.table_headers_row()
        self.prev_cells, self.cells = self.cells, {}
        self.row_tops = []
        return True

    def _inner_width(self) -> float:
        """With horizontal scrolling, a stretch column only fills the visible width and its
        long text gets clipped: make the table as wide as the widest texts recorded last
        frame (or the card, if wider), so it scrolls instead and the last column still fills."""
        if not self.flags & imgui.TableFlags_.scroll_x or not (self.prev_cells or self.cells):
            return 0.0
        pad = imgui.get_style().cell_padding.x * 2 + 1
        rows = list((self.prev_cells or self.cells).values())
        total = 0.0
        for i, (name, cflags, width) in enumerate(self.columns):
            if cflags & imgui.TableColumnFlags_.width_fixed and width:  # an explicit width
                total += float(width() if callable(width) else width) + pad  # type: ignore[arg-type]
                continue
            texts = [name] + [r[i] for r in rows if i < len(r)]
            total += max(imgui.calc_text_size(t).x for t in texts) + pad
        return max(imgui.get_content_region_avail().x, total)

    def cell(self, text: str) -> None:
        """Record the current cell's text (call once per cell, in order)."""
        row, col = imgui.table_get_row_index(), imgui.table_get_column_index()
        cells = self.cells.setdefault(row, [])
        if col == 0:
            self.row_tops.append((row, imgui.get_cursor_screen_pos().y))
        cells.extend([""] * (col + 1 - len(cells)))
        cells[col] = text

    def end(self) -> None:
        if self.began:
            self.dl = imgui.get_window_draw_list()  # the table's own (scrolling) window
            self._copy_handling()
            imgui.end_table()
        self._round_corners()
        imgui.end_child()

    def _round_corners(self) -> None:
        if self.rect is None or self.dl is None:
            return
        import math

        (p0, p1), r, dl = self.rect, self.RADIUS, self.dl
        th = self.app.theme
        bg = u32(self.bg_now)
        dl.push_clip_rect(p0, p1, False)
        for corner, center, a0, a1 in (
            (ImVec2(p0.x, p0.y), ImVec2(p0.x + r, p0.y + r), 1.5 * math.pi, math.pi),
            (ImVec2(p1.x, p0.y), ImVec2(p1.x - r, p0.y + r), 1.5 * math.pi, 2.0 * math.pi),
            (ImVec2(p1.x, p1.y), ImVec2(p1.x - r, p1.y - r), 0.0, 0.5 * math.pi),
            (ImVec2(p0.x, p1.y), ImVec2(p0.x + r, p1.y - r), 0.5 * math.pi, math.pi),
        ):
            dl.path_clear()
            dl.path_line_to(corner)
            dl.path_arc_to(center, r, a0, a1, 8)
            dl.path_fill_concave(bg)
        dl.add_rect(p0, p1, u32(mix(th.border, th.fg, 0.08)), r)
        dl.pop_clip_rect()

    # -- copying -----------------------------------------------------------------
    def _hovered_row(self) -> int | None:
        y = imgui.get_mouse_pos().y
        row = None
        for idx, top in self.row_tops:
            if top <= y:
                row = idx
        return row

    def _copy_handling(self) -> None:
        if not imgui.is_window_hovered(imgui.HoveredFlags_.child_windows):
            return
        row = self._hovered_row()
        if row is None:
            return
        io = imgui.get_io()
        if io.key_ctrl and imgui.is_key_pressed(imgui.Key.c, False) and not imgui.is_any_item_active():
            self.app.copy_text(self.row_text(row))
        if imgui.is_mouse_released(1) and not imgui.is_popup_open("", imgui.PopupFlags_.any_popup_id):
            self.menu_row = row
            imgui.open_popup(f"{self.id}_copy")
        if imgui.begin_popup(f"{self.id}_copy"):
            self.copy_menu(self.menu_row, submenu=False)
            imgui.end_popup()

    def row_cells(self, row: int) -> list[str]:
        return self.cells.get(row) or self.prev_cells.get(row) or []

    def row_text(self, row: int) -> str:
        return "\t".join(self.row_cells(row))

    def copy_menu(self, row: int, submenu: bool = True) -> None:
        """Copy items for a row: each cell, the row, all rows (TSV with the header)."""
        cells = self.row_cells(row)
        if submenu and not imgui.begin_menu(f"{fa.ICON_FA_COPY}  Copy"):
            return
        for (name, _flags, _width), text in zip(self.columns, cells, strict=False):
            if text and imgui.menu_item_simple(f"{name or 'cell'}:  {text[:60]}"):
                self.app.copy_text(text)
        imgui.separator()
        if imgui.menu_item_simple("Whole row", "Ctrl+C"):
            self.app.copy_text(self.row_text(row))
        if imgui.menu_item_simple("All rows (TSV)"):
            header = "\t".join(name for name, _flags, _width in self.columns)
            body = "\n".join(self.row_text(r) for r in sorted(self.prev_cells or self.cells))
            self.app.copy_text(header + "\n" + body)
        if submenu:
            imgui.end_menu()


def combo_width(longest: str) -> float:
    return imgui.calc_text_size(longest).x + imgui.get_frame_height() + imgui.get_style().frame_padding.x * 2


def vsep() -> None:
    """A thin vertical separator between toolbar items."""
    imgui.same_line()
    p = imgui.get_cursor_screen_pos()
    h = imgui.get_frame_height()
    imgui.get_window_draw_list().add_line(
        ImVec2(p.x + 3, p.y + h * 0.18), ImVec2(p.x + 3, p.y + h * 0.82), imgui.get_color_u32(imgui.Col_.separator), 1.0)
    imgui.dummy(ImVec2(7, h))
    imgui.same_line()


def help_marker(text: str) -> None:
    imgui.same_line()
    imgui.text_disabled("(?)")
    if imgui.begin_item_tooltip():
        imgui.push_text_wrap_pos(imgui.get_font_size() * 35)
        imgui.text_unformatted(text)
        imgui.pop_text_wrap_pos()
        imgui.end_tooltip()


class TextView:
    """Scrollable, selectable, searchable view over a Term, with clickable
    addresses, breakpoint gutter and context menu."""

    def __init__(self, app, term: Term, vid: str, follow: str = "top", gutter: Callable | None = None,
                 gutter_click: Callable | None = None, menu: Callable | None = None,
                 on_dblclick: Callable | None = None, empty_hint: str | Callable[[], str] = "") -> None:
        self.app = app
        self.term = term
        self.vid = vid
        self.follow = follow  # top | bottom | pc | none
        self.gutter = gutter
        self.gutter_click = gutter_click
        self.menu = menu
        self.on_dblclick = on_dblclick
        self.empty_hint = empty_hint
        self.seen_version = -1
        self.seen_trim = 0
        self.anchor = None  # (line, col)
        self.cursor = None
        self.dragging = False
        self.search_open = False
        self.search_text = ""
        self.search_focus = False
        self.matches: list[tuple[int, int, int]] = []
        self.match_idx = -1
        self.match_key = None
        self.at_bottom = True
        self.pending_scroll: float | None = None
        self.hover = None  # (addr, since)
        self.ctx: dict = {}
        self.rows = 0
        self.cols = 0
        self.wrap_cols = 0
        self.on_scroll_end = None  # called when the user scrolls past the bottom
        self.keep_scroll_once = False
        self.lockable = False  # show a lock toggle that freezes the scroll position
        self.locked = False
        # optional (line text) -> [(col0, col1 or None = row end, ImU32)]: spans to tint
        self.row_tint: Callable[[str], list[tuple[int, int | None, int]] | None] | None = None

    # -- selection helpers ----------------------------------------------
    def selection(self):
        if self.anchor is None or self.cursor is None or self.anchor == self.cursor:
            return None
        a, b = sorted((self.anchor, self.cursor))
        return a, b

    def selected_text(self) -> str:
        sel = self.selection()
        if not sel:
            return ""
        (l0, c0), (l1, c1) = sel
        with self.term.lock:
            lines = self.term.lines
            out = []
            for i in range(l0, min(l1, len(lines) - 1) + 1):
                t = lines[i].text
                s = c0 if i == l0 else 0
                e = c1 if i == l1 else len(t)
                out.append(t[s:e].rstrip())
            return "\n".join(out)

    def select_all(self) -> None:
        with self.term.lock:
            n = len(self.term.lines)
            self.anchor = (0, 0)
            self.cursor = (n - 1, len(self.term.lines[-1].chars))

    def copy(self, text: str | None = None) -> None:
        text = self.selected_text() if text is None else text
        if text:
            imgui.set_clipboard_text(text)
            self.app.toast("Copied to clipboard", kind="info", ttl=1.2)

    def open_search(self) -> None:
        self.search_open = True
        self.search_focus = True
        sel = self.selected_text()
        if sel and "\n" not in sel:
            self.search_text = sel

    # -- search ---------------------------------------------------------
    def _update_matches(self) -> None:
        key = (self.search_text, self.term.version)
        if key == self.match_key:
            return
        self.match_key = key
        self.matches = []
        needle = self.search_text.lower()
        if not needle:
            return
        with self.term.lock:
            for i, line in enumerate(self.term.lines):
                t = line.text.lower()
                start = t.find(needle)
                while start != -1 and len(self.matches) < 10000:
                    self.matches.append((i, start, len(needle)))
                    start = t.find(needle, start + len(needle))
        if self.match_idx >= len(self.matches):
            self.match_idx = len(self.matches) - 1

    def _goto_match(self, delta: int) -> None:
        if not self.matches:
            return
        self.match_idx = (self.match_idx + delta) % len(self.matches)
        self.pending_scroll = self.matches[self.match_idx][0]

    def _search_bar(self) -> None:
        imgui.set_next_item_width(min(320.0, imgui.get_content_region_avail().x * 0.6))
        if self.search_focus:
            imgui.set_keyboard_focus_here()
            self.search_focus = False
        changed, self.search_text = imgui.input_text_with_hint(
            f"##find{self.vid}", "Find (Enter / Shift+Enter)", self.search_text,
            imgui.InputTextFlags_.enter_returns_true,
        )
        self._update_matches()
        if changed:
            self._goto_match(-1 if imgui.get_io().key_shift else 1)
        elif imgui.is_item_edited() and self.matches:
            self.match_idx = -1
            self._goto_match(1)
        imgui.same_line()
        total = len(self.matches)
        imgui.text_disabled(f"{self.match_idx + 1 if total else 0}/{total}")
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_ARROW_UP + f"##fu{self.vid}"):
            self._goto_match(-1)
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_ARROW_DOWN + f"##fd{self.vid}"):
            self._goto_match(1)
        imgui.same_line()
        if imgui.small_button(fa.ICON_FA_XMARK + f"##fx{self.vid}") or (
            imgui.is_key_pressed(imgui.Key.escape) and imgui.is_window_focused(imgui.FocusedFlags_.root_and_child_windows)
        ):
            self.search_open = False
            self.matches = []
            self.match_key = None

    # -- main render ----------------------------------------------------
    def render(self, height: float = 0.0) -> None:
        app = self.app
        th = app.theme
        io = imgui.get_io()
        if self.search_open:
            self._search_bar()
        avail = imgui.get_content_region_avail()
        h = height if height > 0 else avail.y + height
        imgui.push_style_color(imgui.Col_.child_bg, v4(th.term_bg))
        imgui.push_style_var(imgui.StyleVar_.window_padding, ImVec2(6, 4))
        imgui.push_font(app.mono, app.code_size)
        app.measure()
        imgui.begin_child(
            f"##tv{self.vid}", ImVec2(avail.x, max(h, 20.0)),
            imgui.ChildFlags_.always_use_window_padding,
            imgui.WindowFlags_.horizontal_scrollbar | imgui.WindowFlags_.no_nav,
        )
        try:
            self._render_body(app, th, io)
        finally:
            imgui.end_child()
            imgui.pop_font()
            imgui.pop_style_var()
            imgui.pop_style_color()

    def _render_body(self, app, th, io) -> None:
        term = self.term
        char_w = app.char_w
        line_h = app.line_h
        style = imgui.get_style()
        pad = ImVec2(6, 4)
        gw = char_w * 2.2 if self.gutter else 0.0
        win_pos = imgui.get_window_pos()
        win_w = imgui.get_window_width()
        win_h = imgui.get_window_height()
        self.rows = max(1, int((win_h - pad.y * 2) // line_h))
        self.cols = max(10, int((win_w - pad.x * 2 - gw - style.scrollbar_size) // char_w))
        focused = imgui.is_window_focused()
        hovered = imgui.is_window_hovered()

        with term.lock:
            lines = term.lines
            n = len(lines)
            hint = self.empty_hint() if callable(self.empty_hint) else self.empty_hint
            if n == 1 and not lines[0].chars and hint:
                imgui.set_cursor_pos(ImVec2(pad.x, pad.y))
                imgui.push_style_color(imgui.Col_.text, v4(th.dim))
                imgui.text_wrapped(hint)
                imgui.pop_style_color()
                return
            total_w = gw + (term.width + 2) * char_w
            total_h = n * line_h
            imgui.set_cursor_pos(ImVec2(pad.x, pad.y))
            imgui.dummy(ImVec2(total_w, total_h))
            scroll_x = imgui.get_scroll_x()
            scroll_y = imgui.get_scroll_y()
            ox = win_pos.x + pad.x - scroll_x
            oy = win_pos.y + pad.y - scroll_y
            tx = ox + gw  # text origin

            # react to new content
            if term.trimmed != self.seen_trim:
                self.seen_trim = term.trimmed
                self.anchor = self.cursor = None
            if term.version != self.seen_version:
                self.seen_version = term.version
                self._follow(lines, line_h, win_h)
            if self.pending_scroll is not None:
                imgui.set_scroll_y(max(0.0, self.pending_scroll * line_h - win_h / 2))
                self.pending_scroll = None
            self.at_bottom = scroll_y >= imgui.get_scroll_max_y() - line_h
            if (self.on_scroll_end is not None and hovered and io.mouse_wheel < 0
                    and scroll_y >= imgui.get_scroll_max_y() - 1):
                self.on_scroll_end()

            first = max(0, int(scroll_y // line_h) - 1)
            last = min(n, int((scroll_y + win_h) // line_h) + 1)
            dl = imgui.get_window_draw_list()
            clip_r = win_pos.x + win_w

            mouse = imgui.get_mouse_pos()
            m_line = int((mouse.y - oy) // line_h)
            m_colf = (mouse.x - tx) / char_w
            in_gutter = self.gutter is not None and mouse.x < win_pos.x + pad.x + gw - scroll_x + 2
            hover_tok = None
            if hovered and 0 <= m_line < n and not in_gutter and m_colf >= 0:
                text = lines[m_line].text
                col = int(m_colf)
                for m in ADDR_RE.finditer(text):
                    if m.start() <= col < m.end():
                        hover_tok = (m_line, m.start(), m.end(), int(m.group(), 16))
                        break

            # current line highlight (pwndbg marks it with ►)
            if self.follow == "pc":
                for i in range(first, last):
                    if PC_MARK in lines[i].text[:6]:
                        y = oy + i * line_h
                        dl.add_rect_filled(ImVec2(win_pos.x, y), ImVec2(clip_r, y + line_h), u32(th.accent, 0.10))
                        dl.add_rect_filled(ImVec2(win_pos.x, y), ImVec2(win_pos.x + 2, y + line_h), u32(th.accent, 0.9))

            if self.row_tint is not None:
                for i in range(first, last):
                    y = oy + i * line_h
                    for c0, c1, tint in self.row_tint(lines[i].text) or ():
                        if c1 is None:  # the whole row, edge to edge (like the current line)
                            dl.add_rect_filled(ImVec2(win_pos.x, y), ImVec2(clip_r, y + line_h), tint)
                        else:  # one cell: pad it like text, with rounded corners
                            x0, x1 = tx + (c0 - 0.6) * char_w, tx + (c1 + 0.6) * char_w
                            dl.add_rect_filled(ImVec2(x0, y + 1), ImVec2(x1, y + line_h - 1), tint, 3.0)

            # search matches
            if self.search_open and self.search_text:
                self._update_matches()
                for k, (li, c, ln) in enumerate(self.matches):
                    if first <= li < last:
                        y = oy + li * line_h
                        col = u32(th.yellow, 0.55 if k == self.match_idx else 0.22)
                        dl.add_rect_filled(ImVec2(tx + c * char_w, y), ImVec2(tx + (c + ln) * char_w, y + line_h), col)

            # selection
            sel = self.selection()
            if sel:
                (l0, c0), (l1, c1) = sel
                scol = u32(th.accent2, 0.30)
                for i in range(max(first, l0), min(last, l1 + 1)):
                    s = c0 if i == l0 else 0
                    e = c1 if i == l1 else len(lines[i].chars) + 1
                    y = oy + i * line_h
                    dl.add_rect_filled(ImVec2(tx + s * char_w, y), ImVec2(tx + e * char_w, y + line_h), scol)

            # text (context sections are faded while the program runs: they are stale)
            fade = 0.45 if self.vid in SECTION_META and app.is_running() else 1.0
            font_size = app.code_size
            bold_font = app.mono_bold
            styles = _STYLES
            for i in range(first, last):
                y = oy + i * line_h
                for col, text, sid in lines[i].spans:
                    x = tx + col * char_w
                    if x > clip_r:
                        break
                    fg, bg, flags = styles[sid]
                    if flags & INVERSE:
                        fg, bg = (bg if bg != -1 else -2), (fg if fg != -1 else -3)
                    if bg != -1:
                        if bg == -3:
                            bgc = u32(th.fg)
                        else:
                            bgc = th.color(bg, 0.85 * fade)
                        dl.add_rect_filled(ImVec2(x, y), ImVec2(x + len(text) * char_w, y + line_h), bgc)
                    if text.isspace():
                        continue
                    if flags & CTRL:
                        color = u32(th.accent2, 0.85 * fade)
                    elif flags & ECHO:
                        color = u32(th.dim, fade)
                    elif fg == -2:
                        color = u32(th.term_bg)
                    else:
                        color = th.color(fg, (0.55 if flags & DIM else 1.0) * fade)
                    ty = y + app.text_dy
                    if flags & BOLD and bold_font is not None:
                        dl.add_text(bold_font, font_size, ImVec2(x, ty), color, text)
                    else:
                        dl.add_text(ImVec2(x, ty), color, text)
                    if flags & UNDER:
                        uy = y + line_h - app.text_dy - 1
                        dl.add_line(ImVec2(x, uy), ImVec2(x + len(text) * char_w, uy), color)

            # breakpoint gutter
            if self.gutter is not None:
                gx = win_pos.x + pad.x - scroll_x + gw * 0.45
                r = min(line_h, char_w * 2) * 0.28
                for i in range(first, last):
                    mark = self.gutter(i, lines[i].text)
                    if mark is None:
                        continue
                    cy = oy + i * line_h + line_h * 0.5
                    if mark == 1:
                        dl.add_circle_filled(ImVec2(gx, cy), r, u32(th.red))
                    elif mark == 2:
                        dl.add_circle(ImVec2(gx, cy), r, u32(th.red, 0.8), 0, 1.5)
                    elif hovered and in_gutter and i == m_line:
                        dl.add_circle_filled(ImVec2(gx, cy), r, u32(th.red, 0.35))

            # hovered address: underline + tooltip
            if hover_tok is not None:
                li, s, e, addr = hover_tok
                y = oy + li * line_h + line_h - 1
                dl.add_line(ImVec2(tx + s * char_w, y), ImVec2(tx + e * char_w, y), u32(th.accent, 0.9), 1.0)
                if self.hover is None or self.hover[0] != addr:
                    self.hover = (addr, time.monotonic())
                elif time.monotonic() - self.hover[1] > 0.30 and not self.dragging and not imgui.is_any_mouse_down():
                    imgui.pop_font()
                    app.addr_tooltip(addr)
                    imgui.push_font(app.mono, app.code_size)
            else:
                self.hover = None

            # scroll lock toggle, top-right corner of the visible area
            on_button = False
            if self.lockable:
                icon = fa.ICON_FA_LOCK if self.locked else fa.ICON_FA_LOCK_OPEN
                bw = imgui.calc_text_size(icon).x + style.frame_padding.x * 2
                bar = style.scrollbar_size if imgui.get_scroll_max_y() > 0 else 0.0
                imgui.set_cursor_pos(ImVec2(scroll_x + win_w - bw - bar - 6, scroll_y + 4))
                imgui.push_style_color(imgui.Col_.button, v4(th.panel, 0.85 if self.locked else 0.35))
                imgui.push_style_color(imgui.Col_.text, v4(th.accent if self.locked else th.dim))
                if imgui.small_button(f"{icon}##lock{self.vid}"):
                    self.locked = not self.locked
                imgui.pop_style_color(2)
                on_button = imgui.is_item_hovered()
                if on_button:
                    imgui.pop_font()
                    imgui.set_tooltip("Scroll position locked" if self.locked else
                                      "Lock the scroll position (don't jump on each stop)")
                    imgui.push_font(app.mono, app.code_size)
                hovered = hovered and not on_button

            # mouse interaction
            def cell(round_col: bool = True):
                li = min(max(0, m_line), n - 1)
                c = m_colf + (0.5 if round_col else 0.0)
                return li, max(0, min(int(c), len(lines[li].chars)))

            if hovered and imgui.is_mouse_clicked(0):
                if in_gutter and self.gutter and self.gutter_click and 0 <= m_line < n:
                    if self.gutter(m_line, lines[m_line].text) is not None:
                        self.gutter_click(m_line, lines[m_line].text)
                elif io.key_ctrl and hover_tok is not None:
                    app.open_memory(hover_tok[3])
                else:
                    clicks = imgui.get_mouse_clicked_count(0)
                    li, c = cell()
                    if clicks == 2 and 0 <= m_line < n:
                        text = lines[li].text
                        for m in WORD_RE.finditer(text):
                            if m.start() <= int(m_colf) < m.end():
                                self.anchor, self.cursor = (li, m.start()), (li, m.end())
                                break
                        if self.on_dblclick is not None:
                            self.on_dblclick(li, text)
                    elif clicks >= 3:
                        self.anchor, self.cursor = (li, 0), (li, len(lines[li].chars))
                    elif io.key_shift and self.anchor is not None:
                        self.cursor = (li, c)
                    else:
                        self.anchor = self.cursor = (li, c)
                        self.dragging = True
            if self.dragging:
                if imgui.is_mouse_down(0):
                    self.cursor = cell()
                    if mouse.y < win_pos.y + pad.y:
                        imgui.set_scroll_y(max(0.0, scroll_y - line_h))
                    elif mouse.y > win_pos.y + win_h - pad.y:
                        imgui.set_scroll_y(scroll_y + line_h)
                else:
                    self.dragging = False

            if hovered and imgui.is_mouse_clicked(1):
                li = m_line if 0 <= m_line < n else None
                self.ctx = {
                    "line": li,
                    "text": lines[li].text if li is not None else "",
                    "addr": hover_tok[3] if hover_tok else None,
                }
                imgui.open_popup(f"tvctx{self.vid}")

        # keyboard
        if focused or imgui.is_window_focused(imgui.FocusedFlags_.child_windows):
            if ctrl_pressed(imgui.Key.c):
                self.copy()
            elif ctrl_pressed(imgui.Key.a):
                self.select_all()
            elif ctrl_pressed(imgui.Key.f):
                self.open_search()
            elif imgui.is_key_pressed(imgui.Key.f3):
                self._goto_match(-1 if io.key_shift else 1)
            elif imgui.is_key_pressed(imgui.Key.escape):
                self.anchor = self.cursor = None
            elif imgui.is_key_pressed(imgui.Key.home) and io.key_ctrl:
                imgui.set_scroll_y(0)
            elif imgui.is_key_pressed(imgui.Key.end) and io.key_ctrl:
                imgui.set_scroll_y(imgui.get_scroll_max_y())

        imgui.pop_font()
        if imgui.begin_popup(f"tvctx{self.vid}"):
            self._context_menu()
            imgui.end_popup()
        imgui.push_font(app.mono, app.code_size)

    def _follow(self, lines, line_h: float, win_h: float) -> None:
        if self.locked:
            return
        if self.keep_scroll_once:
            self.keep_scroll_once = False
            return
        if self.follow == "top":
            imgui.set_scroll_y(0)
        elif self.follow == "bottom":
            if self.at_bottom:
                imgui.set_scroll_y(len(lines) * line_h + 100)
        elif self.follow == "pc":
            for i, line in enumerate(lines):
                if PC_MARK in line.text[:6]:
                    imgui.set_scroll_y(max(0.0, i * line_h - win_h * 0.35))
                    return
            imgui.set_scroll_y(0)

    def _context_menu(self) -> None:
        app = self.app
        ctx = self.ctx
        addr = ctx.get("addr")
        if addr is not None:
            imgui.text_colored(v4(app.theme.accent), f"{addr:#x}")
            imgui.push_id("addr")
            app.address_menu_items(addr)
            imgui.pop_id()
            imgui.separator()
        if self.menu is not None:
            imgui.push_id("view")
            if self.menu(ctx):
                imgui.separator()
            imgui.pop_id()
        if imgui.menu_item_simple(fa.ICON_FA_COPY + "  Copy", "Ctrl+C", False, self.selection() is not None):
            self.copy()
        if imgui.menu_item_simple("     Copy line", "", False, ctx.get("line") is not None):
            self.copy(strip_ansi(ctx.get("text", "")).rstrip())
        if imgui.menu_item_simple("     Copy all"):
            self.copy(self.term.plain())
        if imgui.menu_item_simple("     Select all", "Ctrl+A"):
            self.select_all()
        if imgui.menu_item_simple(fa.ICON_FA_MAGNIFYING_GLASS + "  Find…", "Ctrl+F"):
            self.open_search()


def ansi_inline(app, text: str, wrap: bool = False) -> None:
    """Draw a short ANSI-colored string with regular widgets (for tooltips)."""
    term = app.inline_cache.get(text)
    if term is None:
        term = Term(max_lines=200)
        term.feed(text)
        if len(app.inline_cache) > 512:
            app.inline_cache.clear()
        app.inline_cache[text] = term
    th = app.theme
    for line in term.lines:
        first = True
        for _, chunk, sid in line.spans:
            fg, _bg, flags = _STYLES[sid]
            if not first:
                imgui.same_line(0, 0)
            first = False
            imgui.push_style_color(imgui.Col_.text, th.color(fg, 0.55 if flags & DIM else 1.0))
            imgui.text_unformatted(chunk)
            imgui.pop_style_color()
        if first:
            imgui.text_unformatted("")
