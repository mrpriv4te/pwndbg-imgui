"""Direct GLFW access for the borderless main window (themed title bar)."""

from __future__ import annotations

import os

from imgui_bundle import hello_imgui


class NativeWindow:
    """Just enough of GLFW (through ctypes, using the library bundled with
    imgui_bundle) to drive a borderless main window: move, minimize, maximize."""

    MAXIMIZED = 0x00020008
    FOCUSED = 0x00020001
    PLATFORM_WAYLAND = 0x00060003

    def __init__(self) -> None:
        import ctypes

        import imgui_bundle

        folder = os.path.dirname(imgui_bundle.__file__)
        path = next((os.path.join(folder, n) for n in ("libglfw.so.3", "libglfw.so", "libglfw.3.dylib", "glfw3.dll")
                     if os.path.exists(os.path.join(folder, n))), None)
        if path is None:
            raise OSError("GLFW library not found")
        self.ct = ctypes
        lib = ctypes.CDLL(path)
        vp = ctypes.c_void_p
        pint = ctypes.POINTER(ctypes.c_int)
        pdbl = ctypes.POINTER(ctypes.c_double)
        for name, args, res in (
            ("glfwIconifyWindow", [vp], None), ("glfwMaximizeWindow", [vp], None),
            ("glfwRestoreWindow", [vp], None), ("glfwGetWindowAttrib", [vp, ctypes.c_int], ctypes.c_int),
            ("glfwGetWindowPos", [vp, pint, pint], None), ("glfwSetWindowPos", [vp, ctypes.c_int, ctypes.c_int], None),
            ("glfwGetCursorPos", [vp, pdbl, pdbl], None),
        ):
            fn = getattr(lib, name)
            fn.argtypes = args
            fn.restype = res
        self.lib = lib
        self.win = ctypes.c_void_p(hello_imgui.get_glfw_window_address())
        if not self.win.value:
            raise OSError("no GLFW window")
        self.can_move = True
        if hasattr(lib, "glfwGetPlatform"):
            lib.glfwGetPlatform.restype = ctypes.c_int
            self.can_move = lib.glfwGetPlatform() != self.PLATFORM_WAYLAND  # Wayland forbids it

    def iconify(self) -> None:
        self.lib.glfwIconifyWindow(self.win)

    def toggle_maximize(self) -> None:
        if self.maximized():
            self.lib.glfwRestoreWindow(self.win)
        else:
            self.lib.glfwMaximizeWindow(self.win)

    def maximized(self) -> bool:
        return bool(self.lib.glfwGetWindowAttrib(self.win, self.MAXIMIZED))

    def focused(self) -> bool:
        return bool(self.lib.glfwGetWindowAttrib(self.win, self.FOCUSED))

    def pos(self) -> tuple[int, int]:
        x, y = self.ct.c_int(), self.ct.c_int()
        self.lib.glfwGetWindowPos(self.win, self.ct.byref(x), self.ct.byref(y))
        return x.value, y.value

    def set_pos(self, x: int, y: int) -> None:
        self.lib.glfwSetWindowPos(self.win, int(x), int(y))

    def cursor(self) -> tuple[float, float]:
        """Cursor position in screen coordinates."""
        cx, cy = self.ct.c_double(), self.ct.c_double()
        self.lib.glfwGetCursorPos(self.win, self.ct.byref(cx), self.ct.byref(cy))
        wx, wy = self.pos()
        return wx + cx.value, wy + cy.value
