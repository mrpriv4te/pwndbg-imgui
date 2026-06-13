"""
gui.py

Wrapper pyimgui (imgui_bundle) pour pwndbg.

Rendu coloré avec sélection de texte :
- Le texte coloré ANSI est dessiné via imgui.draw_list + add_text dans un
  child scrollable.
- Un input_text_multiline transparent (frame_bg_alpha = 0, text alpha = 0)
  est superposé exactement par-dessus, en lecture seule, pour fournir la
  sélection de texte native (Ctrl+A, clic-glisser, Ctrl+C).
- La console gdb a en plus un champ de saisie en bas avec historique.

Dépendances :
    pip install imgui-bundle
"""

from __future__ import annotations
from typing import Literal

from imgui_bundle import imgui, hello_imgui, ImVec2, ImVec4

from pty_manager import PtyManager, PWNDBG_SECTIONS

from stransi.ansi import Text
from stransi.instruction import Instruction
from stransi.color import SetColor, ColorRole
from stransi.attribute import SetAttribute, Attribute


ANSI_COLORS = {
    0: ImVec4(0.13, 0.13, 0.13, 1.0),  # black
    1: ImVec4(0.86, 0.27, 0.27, 1.0),  # red
    2: ImVec4(0.40, 0.78, 0.40, 1.0),  # green
    3: ImVec4(0.90, 0.80, 0.30, 1.0),  # yellow
    4: ImVec4(0.40, 0.55, 0.95, 1.0),  # blue
    5: ImVec4(0.80, 0.45, 0.85, 1.0),  # magenta
    6: ImVec4(0.35, 0.80, 0.85, 1.0),  # cyan
    7: ImVec4(0.85, 0.85, 0.85, 1.0),  # white
    8: ImVec4(0.45, 0.45, 0.45, 1.0),  # bright black (gray)
    9: ImVec4(1.00, 0.40, 0.40, 1.0),  # bright red
    10: ImVec4(0.55, 0.95, 0.55, 1.0),  # bright green
    11: ImVec4(1.00, 0.95, 0.45, 1.0),  # bright yellow
    12: ImVec4(0.55, 0.70, 1.00, 1.0),  # bright blue
    13: ImVec4(0.95, 0.60, 1.00, 1.0),  # bright magenta
    14: ImVec4(0.55, 0.95, 1.00, 1.0),  # bright cyan
    15: ImVec4(1.00, 1.00, 1.00, 1.0),  # bright white
}


# ------------------------------------------------------------------
# Configuration des sections
# ------------------------------------------------------------------
SECTION_LABELS = {
    "regs": "Registers",
    "disasm": "Disassembly",
    "code": "Code",
    "stack": "Stack",
    "expressions": "Expressions (Watch)",
    "backtrace": "Backtrace",
    "threads": "Threads",
    "heap_tracker": "Heap Tracker",
    "last_signal": "Last Signal",
}


# ------------------------------------------------------------------
# Rendu coloré + overlay sélectionnable
# ------------------------------------------------------------------


def _imgui_color(c: ImVec4) -> int:
    """Convertit ImVec4 (0-1 float) en couleur ImU32 pour le DrawList."""
    r = int(max(0.0, min(1.0, c.x)) * 255)
    g = int(max(0.0, min(1.0, c.y)) * 255)
    b = int(max(0.0, min(1.0, c.z)) * 255)
    a = int(max(0.0, min(1.0, c.w)) * 255)
    return (a << 24) | (b << 16) | (g << 8) | r


def render_colored_text_with_selection(
    widget_id: str,
    lines: list[list[Instruction | Text]],
    size: ImVec2,
    autoscroll: Literal["up", "down", "none"],
    column: int = 1,
) -> None:
    """
    Affiche du texte coloré (ANSI) dans une zone de taille `size` avec
    possibilité de sélectionner/copier le texte.

    Technique :
    1. Parse les séquences ANSI en spans colorés.
    2. Dessine les spans via le DrawList de la fenêtre courante (add_text).
    3. Superpose un input_text_multiline entièrement transparent contenant
       le texte plain-text, ce qui fournit la sélection et le Ctrl+C natifs.
    """
    plain_text = "\n".join("".join(inst for inst in line if isinstance(inst, Text)) for line in lines)

    # if widget_id == "stack":
    #     print(lines)

    font = imgui.get_font()
    font_size = imgui.get_font_size()
    line_height = imgui.get_text_line_height_with_spacing()

    imgui.begin_child(f"##{widget_id}_colored", size, imgui.ChildFlags_.none, imgui.WindowFlags_.none)

    scroll_y = imgui.get_scroll_y()
    scroll_x = imgui.get_scroll_x()
    content_width = max(size.x, imgui.get_content_region_avail().x)

    num_lines = len(lines)
    num_rows = (num_lines + column - 1) // column  # Ceiling division
    total_height = line_height * num_rows
    imgui.dummy(ImVec2(content_width, total_height))

    # Visible rows (not lines), then derive line range from that
    first_visible_row = max(0, int(scroll_y / line_height) - 1)
    last_visible_row = min(num_rows, int((scroll_y + size.y) / line_height) + 2)

    # Convert row range to line index range
    first_visible_line = first_visible_row * column
    last_visible_line = min(num_lines, last_visible_row * column)

    draw_list = imgui.get_window_draw_list()
    origin = imgui.get_window_pos()
    origin = ImVec2(origin.x - scroll_x, origin.y - scroll_y)

    col_width = content_width / column

    col: imgui.ImU32 = _imgui_color(ImVec4(0.85, 0.85, 0.85, 1.0))

    for line_idx in range(first_visible_line, last_visible_line):
        ints = lines[line_idx]
        if not ints:
            continue

        row = line_idx // column
        col_pos = line_idx % column

        y = origin.y + row * line_height
        x = origin.x + col_pos * col_width

        col = _imgui_color(ImVec4(0.85, 0.85, 0.85, 1.0))

        for inst in ints:
            if isinstance(inst, Text):
                draw_list.add_text(ImVec2(x, y), col, inst)
                x += imgui.calc_text_size(inst).x
            elif isinstance(inst, SetColor) and inst.role == ColorRole.FOREGROUND:
                if inst.color:
                    if inst.color.ansi256.code in ANSI_COLORS:
                        col = _imgui_color(ANSI_COLORS[inst.color.ansi256.code])
                    else:
                        r, g, b = inst.color.rgb
                        col = _imgui_color(ImVec4(r, g, b, 1.0))
                else:
                    col = _imgui_color(ImVec4(0.85, 0.85, 0.85, 1.0))
            elif isinstance(inst, SetAttribute) and inst.attribute == Attribute.NORMAL:
                col = _imgui_color(ImVec4(0.85, 0.85, 0.85, 1.0))

    match autoscroll:
        case "down":
            imgui.set_scroll_here_y(1.0)
        case "up":
            imgui.set_scroll_here_y(0.0)

    imgui.end_child()

    # --- Overlay input_text_multiline transparent pour la sélection ---
    # On le positionne exactement par-dessus le child qu'on vient de dessiner.
    # overlay_pos = imgui.get_item_rect_min()  # coin haut-gauche du child
    # imgui.set_next_window_pos(overlay_pos)

    # imgui.push_style_color(imgui.Col_.frame_bg, ImVec4(0, 0, 0, 0))
    # imgui.push_style_color(imgui.Col_.frame_bg_hovered, ImVec4(0, 0, 0, 0))
    # imgui.push_style_color(imgui.Col_.frame_bg_active, ImVec4(0, 0, 0, 0))
    # imgui.push_style_color(imgui.Col_.text, ImVec4(0, 0, 0, 0))
    # La sélection doit rester visible : on lui donne une couleur semi-transparente
    # sel_col = imgui.get_style_color_vec4(imgui.Col_.text_selected_bg)
    # sel_col.w = 0.4
    # imgui.push_style_color(imgui.Col_.text_selected_bg, sel_col)

    # imgui.input_text_multiline(
    #     f"##{widget_id}_overlay",
    #     plain_text,
    #     size,
    # )

    # # print(plain_text.encode())
    # imgui.pop_style_color(1)


# ------------------------------------------------------------------
class PwndbgGuiApp:
    def __init__(self, pty_manager: PtyManager):
        self.pty_manager = pty_manager
        self.font: imgui.ImFont | None = None

        self.section_visible: dict[str, bool] = {
            s[0]: s[0] in ("regs", "disasm", "code", "stack", "expressions", "backtrace", "threads") for s in PWNDBG_SECTIONS
        }
        self.console_visible: bool = True
        # self.autoscroll: dict[str, bool] = {s[0]: True for s in PWNDBG_SECTIONS}
        # self.autoscroll["console"] = True

        # Console input
        self._console_input = ""
        self._console_history: list[str] = []
        self._console_history_pos: int = -1

        self._dock_initialized = False

    # ------------------------------------------------------------------
    def setup_default_docking(self):
        dockspace_id = imgui.get_id("MainDockSpace")
        if self._dock_initialized:
            return
        self._dock_initialized = True

        imgui.internal.dock_builder_remove_node(dockspace_id)
        imgui.internal.dock_builder_add_node(dockspace_id, imgui.internal.DockNodeFlagsPrivate_.dock_space)
        imgui.internal.dock_builder_set_node_size(dockspace_id, imgui.get_main_viewport().size)

        sn_h1 = imgui.internal.dock_builder_split_node(dockspace_id, imgui.Dir.down, 0.775)
        sn_h2 = imgui.internal.dock_builder_split_node(sn_h1.id_at_dir, imgui.Dir.down, 0.60)
        sn_h3 = imgui.internal.dock_builder_split_node(sn_h2.id_at_dir, imgui.Dir.down, 0.50)

        sn_v1 = imgui.internal.dock_builder_split_node(sn_h2.id_at_opposite_dir, imgui.Dir.right, 0.50)
        sn_v2 = imgui.internal.dock_builder_split_node(sn_h3.id_at_dir, imgui.Dir.right, 0.25)

        imgui.internal.dock_builder_dock_window("Registers", sn_h1.id_at_opposite_dir)

        imgui.internal.dock_builder_dock_window("Disassembly", sn_v1.id_at_opposite_dir)
        imgui.internal.dock_builder_dock_window("Code", sn_v1.id_at_dir)

        imgui.internal.dock_builder_dock_window("Stack", sn_h3.id_at_opposite_dir)

        imgui.internal.dock_builder_dock_window("GDB Console", sn_v2.id_at_opposite_dir)
        imgui.internal.dock_builder_dock_window("Expressions (Watch)", sn_v2.id_at_dir)
        imgui.internal.dock_builder_dock_window("Backtrace", sn_v2.id_at_dir)
        imgui.internal.dock_builder_dock_window("Threads", sn_v2.id_at_dir)

        imgui.internal.dock_builder_finish(dockspace_id)

    # ------------------------------------------------------------------
    def load_additional_fonts(self):
        self.font = hello_imgui.load_font_ttf("fonts/JetBrainsMono-VariableFont_wght.ttf", 15.0)

    # ------------------------------------------------------------------
    def gui(self):
        viewport = imgui.get_main_viewport()
        dockspace_id = imgui.get_id("MainDockSpace")
        imgui.dock_space_over_viewport(dockspace_id, viewport, imgui.DockNodeFlags_.passthru_central_node)

        self.setup_default_docking()
        self.draw_menu_bar()

        for section in PWNDBG_SECTIONS:
            if self.section_visible.get(section[0], False):
                self.draw_section_window(section[0])

        if self.console_visible:
            self.draw_console_window()

    # ------------------------------------------------------------------
    def draw_menu_bar(self):
        if imgui.begin_main_menu_bar():
            if imgui.begin_menu("Window"):
                for section in PWNDBG_SECTIONS:
                    label = SECTION_LABELS.get(section[0], section[0])
                    changed, new_value = imgui.menu_item(label, "", self.section_visible.get(section[0], False))
                    if changed:
                        self.section_visible[section[0]] = new_value

                imgui.separator()
                changed, new_value = imgui.menu_item("GDB Console", "", self.console_visible)
                if changed:
                    self.console_visible = new_value

                imgui.separator()
                if imgui.menu_item("Show all", "", False)[0]:
                    for s in PWNDBG_SECTIONS:
                        self.section_visible[s[0]] = True
                    self.console_visible = True
                if imgui.menu_item("Hide all", "", False)[0]:
                    for s in PWNDBG_SECTIONS:
                        self.section_visible[s[0]] = False
                    self.console_visible = False
                if imgui.menu_item("Reset layout", "", False)[0]:
                    self._dock_initialized = False
                imgui.end_menu()

            # if imgui.begin_menu("View"):
            #     for section in PWNDBG_SECTIONS:
            #         label = SECTION_LABELS.get(section[0], section[0])
            #         auto = self.autoscroll.get(section[0], True)
            #         changed, new_value = imgui.menu_item(f"Auto-scroll: {label}", "", auto)
            #         if changed:
            #             self.autoscroll[section[0]] = new_value
            #     imgui.separator()
            #     changed, new_value = imgui.menu_item(
            #         "Auto-scroll: GDB Console", "", self.autoscroll.get("console", True)
            #     )
            #     if changed:
            #         self.autoscroll["console"] = new_value
            #     imgui.end_menu()

            imgui.end_main_menu_bar()

    # ------------------------------------------------------------------
    def draw_section_window(self, section: str):
        title = SECTION_LABELS.get(section, section)
        expanded, opened = imgui.begin(title, True, imgui.WindowFlags_.none)
        if expanded:
            has_change, text = self.pty_manager.get_text(section)
            avail = imgui.get_content_region_avail()
            render_colored_text_with_selection(
                section,
                text,
                avail,
                ("up" if section == "stack" else "down") if has_change else "none",
                2 if section == "regs" else 1,
            )
        imgui.end()
        if not opened:
            self.section_visible[section] = False

    # ------------------------------------------------------------------
    def draw_console_window(self):
        expanded, opened = imgui.begin("GDB Console", True, imgui.WindowFlags_.none)
        if expanded:
            console = self.pty_manager.console
            has_change, text = console.get_text()

            footer_height = imgui.get_frame_height_with_spacing()
            avail = imgui.get_content_region_avail()
            output_size = ImVec2(avail.x, avail.y - footer_height - 1)

            render_colored_text_with_selection("console", text, output_size, "down" if has_change else "none")

            # --- Champ de saisie ---
            imgui.push_item_width(-1)
            input_flags = imgui.InputTextFlags_.enter_returns_true | imgui.InputTextFlags_.callback_history

            def history_callback(data: imgui.InputTextCallbackData):
                if data.event_flag == imgui.InputTextFlags_.callback_history:
                    if not self._console_history:
                        return 0
                    if data.event_key == imgui.Key.up_arrow:
                        if self._console_history_pos == -1:
                            self._console_history_pos = len(self._console_history) - 1
                        elif self._console_history_pos > 0:
                            self._console_history_pos -= 1
                    elif data.event_key == imgui.Key.down_arrow:
                        if self._console_history_pos != -1:
                            self._console_history_pos += 1
                            if self._console_history_pos >= len(self._console_history):
                                self._console_history_pos = -1
                    new_text = (
                        self._console_history[self._console_history_pos] if self._console_history_pos != -1 else ""
                    )
                    data.delete_chars(0, data.buf_text_len)
                    data.insert_chars(0, new_text)
                return 0

            if imgui.is_window_focused() and not imgui.is_any_item_active():
                imgui.set_keyboard_focus_here()

            entered, self._console_input = imgui.input_text(
                "##console_input",
                self._console_input,
                input_flags,
                history_callback,
            )
            imgui.pop_item_width()

            if entered:
                cmd = self._console_input
                if cmd.strip():
                    self._console_history.append(cmd)
                self._console_history_pos = -1
                console.write(cmd + "\n")
                self._console_input = ""
                imgui.set_keyboard_focus_here(-1)
                imgui.set_scroll_here_y(1.0)

        imgui.end()
        if not opened:
            self.console_visible = False


# ------------------------------------------------------------------
def main_with_manager(pty_manager: PtyManager):
    app = PwndbgGuiApp(pty_manager)

    runner_params = hello_imgui.RunnerParams()
    runner_params.app_window_params.window_title = "pwndbg ImGui"
    runner_params.app_window_params.window_geometry.size = (1600, 900)
    runner_params.app_window_params.window_geometry.full_screen_mode = hello_imgui.FullScreenMode.full_monitor_work_area
    runner_params.imgui_window_params.default_imgui_window_type = hello_imgui.DefaultImGuiWindowType.no_default_window
    runner_params.imgui_window_params.enable_viewports = True
    runner_params.imgui_window_params.show_menu_bar = False
    runner_params.imgui_window_params.background_color = ImVec4(0.09, 0.09, 0.09, 1.0)
    runner_params.callbacks.show_gui = app.gui
    runner_params.callbacks.load_additional_fonts = app.load_additional_fonts

    hello_imgui.run(runner_params)


def main():
    pm = PtyManager()

    print("Sections / PTYs créés :")
    for name, tty_path, clearing, banner, width, height in pm.contextoutputs().values():
        print(f"  {name:14s} -> {tty_path}, {clearing=}, {banner=}, {width=}, {height=}")
    print(f"  console PTY   -> {pm.console.slave_path}")

    try:
        main_with_manager(pm)
    finally:
        pm.close_all()


if __name__ == "__main__":
    main()
