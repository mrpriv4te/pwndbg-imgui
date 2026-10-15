#!/usr/bin/env python3
"""Headless-ish GUI test driver for pwndbg-imgui (dev tool, not shipped).

Runs the real GUI (it needs a display) against a real gdb, executes timed steps
and saves screenshots, so a change can be checked without a human clicking.

    python tools/guitest.py STEPS_FILE [--out DIR] [--keep-config] [-- PWNDBG-IMGUI ARGS...]

STEPS_FILE has one step per line, `<seconds-since-start> <kind> <arg>`:

    2   cmd   b main            # type a command in the gdb console
    3   cmd   run
    6   py    assert app.state.get("alive"), app.state
    6.5 shot  stopped           # save DIR/stopped.png
    8   quit

Kinds: `cmd` (console command), `py` (exec'd with `app`, `imgui`, `hello_imgui` in
scope; an exception fails the run), `shot` (screenshot), `quit`. Blank lines and
`#` comments are ignored. A final screenshot `final.png` is always written.

Needs an interpreter with pwndbg_imgui importable plus numpy, e.g. the pipx env
after `pipx inject pwndbg-imgui numpy`. Config goes to a fresh temporary
XDG_CONFIG_HOME unless --keep-config. Exit status is 1 if a `py` step failed or the
app closed before the last step, else the app's own (e.g. 130 after a SIGINT step).
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import time
import traceback
import zlib


def parse_steps(path: str) -> list[tuple[float, str, str]]:
    steps = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            t, kind, *rest = line.split(None, 2)
            if kind not in ("cmd", "py", "shot", "quit"):
                sys.exit(f"guitest: unknown step kind {kind!r} in: {line}")
            steps.append((float(t), kind, rest[0] if rest else ""))
    return sorted(steps, key=lambda s: s[0])


def write_png(path: str, arr) -> None:
    h, w, ch = arr.shape
    raw = b"".join(b"\x00" + arr[y].tobytes() for y in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6 if ch == 4 else 2, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def front_buffer():
    """Read the just-presented frame with glReadPixels (final_app_window_screenshot()
    only has data once the app has exited, so mid-run shots read GL directly)."""
    import ctypes
    import ctypes.util

    import numpy as np
    from imgui_bundle import imgui

    gl = ctypes.CDLL(ctypes.util.find_library("GL") or "libGL.so.1")
    io = imgui.get_io()
    w = int(io.display_size.x * io.display_framebuffer_scale.x)
    h = int(io.display_size.y * io.display_framebuffer_scale.y)
    buf = np.empty((h, w, 3), dtype=np.uint8)
    gl.glReadBuffer(0x0404)  # GL_FRONT: the frame that was just swapped in
    gl.glPixelStorei(0x0D05, 1)  # GL_PACK_ALIGNMENT
    gl.glReadPixels(0, 0, w, h, 0x1907, 0x1401, buf.ctypes.data_as(ctypes.c_void_p))  # GL_RGB, GL_UNSIGNED_BYTE
    gl.glReadBuffer(0x0405)  # back to GL_BACK
    return np.ascontiguousarray(buf[::-1])


def main(argv: list[str]) -> int:
    gui_args: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, gui_args = argv[:i], argv[i + 1:]
    out, keep_config, steps_file = ".", False, None
    it = iter(argv)
    for a in it:
        if a == "--out":
            out = next(it)
        elif a == "--keep-config":
            keep_config = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            steps_file = a
    if not steps_file:
        sys.exit(__doc__)
    steps = parse_steps(steps_file)
    os.makedirs(out, exist_ok=True)
    if not keep_config:
        os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="pwndbg-imgui-test-")

    from imgui_bundle import hello_imgui, imgui
    import pwndbg_imgui.cli as cli
    import pwndbg_imgui.ui.app as app_mod

    App = app_mod.App
    run = {"t0": None, "i": 0, "shots": [], "failed": False}

    def screenshot(name: str, arr=None) -> None:
        if arr is None:
            arr = front_buffer()
        write_png(os.path.join(out, name + ".png"), arr)
        print(f"guitest: saved {os.path.join(out, name + '.png')}")

    def drive(self) -> None:
        now = time.monotonic()
        if run["t0"] is None:
            run["t0"] = now
        while run["i"] < len(steps) and now - run["t0"] >= steps[run["i"]][0]:
            t, kind, arg = steps[run["i"]]
            run["i"] += 1
            if kind == "cmd":
                self.send_console(arg)
            elif kind == "py":
                try:
                    exec(arg, {"app": self, "imgui": imgui, "hello_imgui": hello_imgui})
                except Exception:
                    run["failed"] = True
                    print(f"guitest: step at {t}s failed: {arg}", file=sys.stderr)
                    traceback.print_exc()
            elif kind == "shot":
                run["shots"].append(arg or f"shot{run['i']}")
            elif kind == "quit":
                hello_imgui.get_runner_params().app_shall_exit = True

    build_runner = App.build_runner

    def patched_build_runner(self):
        # hook the runner rather than App.run, so the real run() (signals, shutdown) is exercised
        rp = build_runner(self)
        rp.app_window_params.restore_previous_geometry = False
        rp.app_window_params.window_geometry.size = (1600, 960)
        pre = rp.callbacks.pre_new_frame

        def pre_new_frame() -> None:
            pre()
            drive(self)

        def after_swap() -> None:
            while run["shots"]:
                screenshot(run["shots"].pop(0))

        rp.callbacks.pre_new_frame = pre_new_frame
        rp.callbacks.after_swap = after_swap
        rp.fps_idling.enable_idling = False  # keep frames (and the step clock) ticking
        return rp

    App.build_runner = patched_build_runner
    rc = cli.main(gui_args)
    screenshot("final", hello_imgui.final_app_window_screenshot())
    if run["i"] < len(steps):
        print(f"guitest: exited before step {run['i'] + 1}/{len(steps)} (exit status {rc})", file=sys.stderr)
        run["failed"] = True
    return 1 if run["failed"] else rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
