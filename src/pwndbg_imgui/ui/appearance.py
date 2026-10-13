"""Fonts and theme."""

from __future__ import annotations

import os

from imgui_bundle import ImVec2, hello_imgui, imgui
from ..fonts import find_bold_variant, find_fallback_fonts
from ..theme import Theme, mix
from .widgets import v4


class AppearanceMixin:
    """Fonts and theme."""

    def load_fonts(self) -> None:
        import imgui_bundle

        assets = os.path.join(os.path.dirname(imgui_bundle.__file__), "assets")
        hello_imgui.set_assets_folder(assets)
        fonts_dir = os.path.join(assets, "fonts")
        fa_path = os.path.join(fonts_dir, "Font_Awesome_6_Free-Solid-900.otf")

        fallbacks: list[str] | None = None

        def load(path: str, merge_icons: bool):
            nonlocal fallbacks
            font = hello_imgui.load_font(path, 16.0, hello_imgui.FontLoadingParams(inside_assets=False))
            if merge_icons and os.path.exists(fa_path):
                params = hello_imgui.FontLoadingParams(merge_to_last_font=True, inside_assets=False)
                params.font_config.glyph_offset = ImVec2(0, 1)
                hello_imgui.load_font(fa_path, 14.0, params)
            # glyphs missing from `path` (►, ◂, ─, ⚠, …) come from these, in order
            if fallbacks is None:
                fallbacks = find_fallback_fonts()
            for fb in fallbacks:
                if os.path.realpath(fb) != os.path.realpath(path):
                    params = hello_imgui.FontLoadingParams(merge_to_last_font=True, inside_assets=False)
                    hello_imgui.load_font(fb, 16.0, params)
            return font

        ui_path = os.path.join(fonts_dir, "Roboto", "Roboto-Regular.ttf")
        if not os.path.exists(ui_path):
            ui_path = os.path.join(fonts_dir, "DroidSans.ttf")
        self.ui_font = load(ui_path, True)

        mono_path = self.settings["font"]
        if not mono_path or not os.path.exists(mono_path):
            mono_path = self.fonts[0][1] if self.fonts else os.path.join(fonts_dir, "Inconsolata-Medium.ttf")
        self.mono_path = mono_path
        self.mono = load(mono_path, True)
        bold = find_bold_variant(mono_path)
        self.mono_bold = load(bold, False) if bold else None

    def setup_style(self) -> None:
        self.apply_theme(self.theme)

    def apply_theme(self, th: Theme) -> None:
        self.theme = th
        th._cache.clear()
        self.inline_cache.clear()
        self.settings["theme"] = th.name
        style = imgui.get_style()
        if th.dark:
            imgui.style_colors_dark(style)
        else:
            imgui.style_colors_light(style)
        C = imgui.Col_
        bg, panel, border, fg, dim, acc = th.bg, th.panel, th.border, th.fg, th.dim, th.accent
        frame = mix(panel, fg, 0.06)
        colors = {
            C.text: v4(fg), C.text_disabled: v4(dim),
            C.window_bg: v4(panel), C.child_bg: v4(panel, 0.0), C.popup_bg: v4(mix(panel, fg, 0.03), 0.98),
            C.border: v4(border), C.border_shadow: v4(bg, 0.0),
            C.frame_bg: v4(frame), C.frame_bg_hovered: v4(mix(frame, acc, 0.18)), C.frame_bg_active: v4(mix(frame, acc, 0.30)),
            C.title_bg: v4(bg), C.title_bg_active: v4(bg), C.title_bg_collapsed: v4(bg),
            C.menu_bar_bg: v4(bg),
            C.scrollbar_bg: v4(panel, 0.0), C.scrollbar_grab: v4(mix(panel, fg, 0.18)),
            C.scrollbar_grab_hovered: v4(mix(panel, fg, 0.28)), C.scrollbar_grab_active: v4(acc, 0.8),
            C.check_mark: v4(acc), C.slider_grab: v4(acc, 0.85), C.slider_grab_active: v4(acc),
            C.button: v4(mix(frame, fg, 0.04)), C.button_hovered: v4(mix(frame, acc, 0.30)), C.button_active: v4(mix(frame, acc, 0.50)),
            C.header: v4(mix(panel, acc, 0.22)), C.header_hovered: v4(mix(panel, acc, 0.32)), C.header_active: v4(mix(panel, acc, 0.45)),
            C.separator: v4(border), C.separator_hovered: v4(acc, 0.7), C.separator_active: v4(acc),
            C.resize_grip: v4(acc, 0.15), C.resize_grip_hovered: v4(acc, 0.5), C.resize_grip_active: v4(acc, 0.8),
            C.tab: v4(bg), C.tab_hovered: v4(mix(panel, acc, 0.30)), C.tab_selected: v4(panel),
            C.tab_selected_overline: v4(acc), C.tab_dimmed: v4(bg), C.tab_dimmed_selected: v4(panel),
            C.tab_dimmed_selected_overline: v4(acc, 0.35),
            C.docking_preview: v4(acc, 0.45), C.docking_empty_bg: v4(bg),
            C.table_header_bg: v4(mix(panel, fg, 0.05)), C.table_border_strong: v4(border), C.table_border_light: v4(mix(panel, border, 0.6)),
            C.table_row_bg: v4(panel, 0.0), C.table_row_bg_alt: v4(fg, 0.025),
            C.text_selected_bg: v4(th.accent2, 0.35), C.drag_drop_target: v4(acc), C.nav_cursor: v4(acc),
            C.modal_window_dim_bg: v4(bg, 0.6), C.plot_lines: v4(acc), C.plot_histogram: v4(acc),
            C.text_link: v4(th.accent2), C.input_text_cursor: v4(acc),
        }
        for idx, col in colors.items():
            style.set_color_(idx, col)
        style.window_rounding = 6.0
        style.child_rounding = 4.0
        style.frame_rounding = 4.0
        style.popup_rounding = 6.0
        style.grab_rounding = 4.0
        style.scrollbar_rounding = 6.0
        style.tab_rounding = 4.0
        style.window_border_size = 1.0
        style.frame_border_size = 0.0
        style.popup_border_size = 1.0
        style.tab_border_size = 0.0
        style.window_padding = ImVec2(8, 6)
        style.frame_padding = ImVec2(7, 4)
        style.item_spacing = ImVec2(7, 5)
        style.item_inner_spacing = ImVec2(5, 4)
        style.scrollbar_size = 12.0
        style.grab_min_size = 10.0
        style.window_title_align = ImVec2(0.0, 0.5)
        style.separator_text_border_size = 1.0
        style.docking_separator_size = 3.0
        style.tab_bar_overline_size = 2.0
        style.window_menu_button_position = imgui.Dir.none

    def measure(self) -> None:
        """Must be called with the mono font pushed."""
        self.char_w = imgui.calc_text_size("M").x
        self.line_h = float(int(imgui.get_font_size() * 1.28))
