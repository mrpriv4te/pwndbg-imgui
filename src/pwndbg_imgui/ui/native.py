"""Direct GLFW access for the borderless main window (themed title bar)."""

from __future__ import annotations

import ctypes
import os

from imgui_bundle import hello_imgui


def capsule_pointer(capsule) -> int | None:
    """The pointer inside a PyCapsule (how imgui-bundle exposes Viewport.platform_handle)."""
    if capsule is None:
        return None
    api = ctypes.pythonapi
    api.PyCapsule_GetName.restype = ctypes.c_char_p
    api.PyCapsule_GetName.argtypes = [ctypes.py_object]
    api.PyCapsule_GetPointer.restype = ctypes.c_void_p
    api.PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
    try:
        return api.PyCapsule_GetPointer(capsule, api.PyCapsule_GetName(capsule))
    except (ValueError, TypeError):
        return None


class XClientMessageEvent(ctypes.Structure):
    """Xlib's XClientMessageEvent, padded to sizeof(XEvent) (24 longs)."""

    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p), ("window", ctypes.c_ulong), ("message_type", ctypes.c_ulong),
                ("format", ctypes.c_int), ("l", ctypes.c_long * 5), ("pad", ctypes.c_long * 12)]


class NativeWindow:
    """Just enough of GLFW (through ctypes, using the library bundled with
    imgui_bundle) to drive a borderless main window: move, minimize, maximize."""

    MAXIMIZED = 0x00020008
    FOCUSED = 0x00020001
    PLATFORM_WAYLAND = 0x00060003
    PLATFORM_X11 = 0x00060004

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
        # present at runtime, missing from imgui-bundle's type stubs
        self.win = ctypes.c_void_p(hello_imgui.get_glfw_window_address())  # pyright: ignore[reportAttributeAccessIssue]
        if not self.win.value:
            raise OSError("no GLFW window")
        self.can_move = True
        self.platform = 0
        if hasattr(lib, "glfwGetPlatform"):
            lib.glfwGetPlatform.restype = ctypes.c_int
            self.platform = lib.glfwGetPlatform()
            self.can_move = self.platform != self.PLATFORM_WAYLAND  # Wayland forbids it
        self._x11 = None  # (libX11, Display*, Window, root, _NET_WM_MOVERESIZE atom), set up on first use
        self._keycodes: dict[str, list[int]] | None = None  # modifiers_down(): X keycodes, once

    def _x11_setup(self) -> bool:
        """Resolve libX11, the X display / window and the _NET_WM_MOVERESIZE atom, once."""
        if self.platform != self.PLATFORM_X11:
            return False
        if self._x11 is not None:
            return True
        ct = self.ct
        try:
            import ctypes.util

            x11 = ct.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
            self.lib.glfwGetX11Display.restype = ct.c_void_p
            self.lib.glfwGetX11Window.restype = ct.c_ulong
            self.lib.glfwGetX11Window.argtypes = [ct.c_void_p]
            x11.XInternAtom.restype = ct.c_ulong
            x11.XInternAtom.argtypes = [ct.c_void_p, ct.c_char_p, ct.c_int]
            x11.XDefaultRootWindow.restype = ct.c_ulong
            x11.XDefaultRootWindow.argtypes = [ct.c_void_p]
            x11.XUngrabPointer.argtypes = [ct.c_void_p, ct.c_ulong]
            x11.XSendEvent.argtypes = [ct.c_void_p, ct.c_ulong, ct.c_int, ct.c_long, ct.c_void_p]
            x11.XFlush.argtypes = [ct.c_void_p]
            dpy = self.lib.glfwGetX11Display()
            if not dpy:
                return False
            self._x11 = (x11, dpy, x11.XDefaultRootWindow(dpy), x11.XInternAtom(dpy, b"_NET_WM_MOVERESIZE", 0))
        except (OSError, AttributeError):
            return False
        return True

    # X keysyms of each modifier ImGui tracks (AltGr counts as Alt, as GLFW reports it)
    MODIFIER_KEYSYMS = {"ctrl": (0xFFE3, 0xFFE4), "shift": (0xFFE1, 0xFFE2),
                        "alt": (0xFFE9, 0xFFEA, 0xFE03), "super": (0xFFEB, 0xFFEC)}

    def modifiers_down(self) -> dict[str, bool] | None:
        """Which modifiers are physically held right now, from the X server (None without
        X11). GLFW only learns of a release through a key event, and a desktop shortcut
        (Super+…, Alt+Tab) can swallow it: ImGui then thinks the key is still down."""
        if not self._x11_setup() or self._x11 is None:
            return None
        ct = self.ct
        x11, dpy = self._x11[0], self._x11[1]
        try:
            if self._keycodes is None:
                x11.XQueryKeymap.argtypes = [ct.c_void_p, ct.c_char_p]
                x11.XKeysymToKeycode.restype = ct.c_ubyte
                x11.XKeysymToKeycode.argtypes = [ct.c_void_p, ct.c_ulong]
                self._keycodes = {m: [x11.XKeysymToKeycode(dpy, k) for k in syms]
                                  for m, syms in self.MODIFIER_KEYSYMS.items()}
            keys = ct.create_string_buffer(32)
            x11.XQueryKeymap(dpy, keys)
            bits = keys.raw  # a bit per keycode
            return {m: any(c and bits[c >> 3] & (1 << (c & 7)) for c in codes)
                    for m, codes in self._keycodes.items()}
        except (OSError, AttributeError):
            return None

    def wm_move(self, win=None) -> bool:
        """Hand a title-bar drag to the window manager (X11 `_NET_WM_MOVERESIZE`), as a
        native title bar does: the WM then moves the window itself, so it can leave the
        screen and edge tiling / snapping work (a window moved by the app is constrained
        and never tiled). win: a GLFWwindow* (a detached ImGui viewport), default the main
        window. Returns False when unavailable; the caller moves it instead."""
        if not self._x11_setup() or self._x11 is None:
            return False
        ct = self.ct
        try:
            x11, dpy, root, atom = self._x11
            win = ct.c_void_p(win) if isinstance(win, int) else (win or self.win)
            xwin = self.lib.glfwGetX11Window(win)
            if not xwin:
                return False

            x, y = self.cursor(win)
            ev = XClientMessageEvent(type=33, send_event=1, display=dpy, window=xwin, message_type=atom, format=32)
            ev.l[:] = [int(x), int(y), 8, 1, 1]  # root x/y, _NET_WM_MOVERESIZE_MOVE, button 1, from an app
            x11.XUngrabPointer(dpy, 0)  # the WM can only grab the pointer if we let it go
            mask = (1 << 20) | (1 << 19)  # SubstructureRedirectMask | SubstructureNotifyMask
            x11.XSendEvent(dpy, root, 0, mask, ct.byref(ev))
            x11.XFlush(dpy)
            return True
        except (OSError, AttributeError):
            return False

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

    def pos(self, win=None) -> tuple[int, int]:
        x, y = self.ct.c_int(), self.ct.c_int()
        self.lib.glfwGetWindowPos(win or self.win, self.ct.byref(x), self.ct.byref(y))
        return x.value, y.value

    def set_pos(self, x: int, y: int) -> None:
        self.lib.glfwSetWindowPos(self.win, int(x), int(y))

    def cursor(self, win=None) -> tuple[float, float]:
        """Cursor position in screen coordinates (win: a GLFWwindow*, default the main one)."""
        cx, cy = self.ct.c_double(), self.ct.c_double()
        self.lib.glfwGetCursorPos(win or self.win, self.ct.byref(cx), self.ct.byref(cy))
        wx, wy = self.pos(win)
        return wx + cx.value, wy + cy.value
