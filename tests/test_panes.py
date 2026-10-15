import pytest

pytest.importorskip("imgui_bundle")  # the panes are GUI code; only their logic is tested here

from pwndbg_imgui.ui.panes import VmmapPane  # noqa: E402

PAGES = [
    (0x400000, 0x401000, "r--p", 0, "/home/u/chall", "code"),
    (0x7FFFF7C00000, 0x7FFFF7C28000, "r-xp", 0x28000, "/usr/lib/libc.so.6", "code"),
    (0x7FFFFFFDE000, 0x7FFFFFFFF000, "rw-p", 0, "[stack]", "stack"),
]


@pytest.mark.parametrize("flt,expected", [
    ("", [0, 1, 2]),
    ("LIBC", [1]),                # name, case-insensitive
    ("rw-", [2]),                 # permissions
    ("stack", [2]),               # region kind
    ("0x7ffff7c10000", [1]),      # an address inside a region
    ("0x400fff", [0]),            # last byte of a region
    ("0x401000", []),             # end is exclusive
    ("0xzz", []),                 # not hex: matched as text, finds nothing
])
def test_vmmap_filter(flt, expected):
    pane = VmmapPane(app=None)  # type: ignore[arg-type]  # matches() doesn't use the app
    pane.filter = flt
    assert [i for i, p in enumerate(PAGES) if pane.matches(p)] == expected


def test_x11_client_message_has_the_size_of_xevent():
    import ctypes

    from pwndbg_imgui.ui.native import XClientMessageEvent

    assert ctypes.sizeof(XClientMessageEvent) == 24 * ctypes.sizeof(ctypes.c_long)  # sizeof(XEvent)
    assert XClientMessageEvent.l.offset == 7 * ctypes.sizeof(ctypes.c_long)  # data.l, as in <X11/Xlib.h>
