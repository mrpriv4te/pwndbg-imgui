"""`--profile`: where pwndbg-imgui spends its time (GUI side; the agent has its own half).

Per frame: the time in our Python GUI code and in rendering; per window: its gui
function; per agent op: the round trip as the GUI sees it (sent → reply handled, so it
includes the wait for gdb and for the next frame). Plus a cProfile of the GUI thread.
`write()` saves `gui.prof` (for `python -m pstats` / snakeviz) and `report.txt`.
Standard library only, so it is testable without imgui."""

from __future__ import annotations

import collections
import cProfile
import io
import os
import pstats
import time
from collections.abc import Callable


class Stats:
    """Durations by name: count, total, max (seconds)."""

    def __init__(self) -> None:
        self.data: dict[str, list[float]] = {}

    def add(self, name: str, secs: float) -> None:
        d = self.data.get(name)
        if d is None:
            self.data[name] = [1, secs, secs]
        else:
            d[0] += 1
            d[1] += secs
            d[2] = max(d[2], secs)

    def rows(self) -> list[tuple[str, int, float, float, float]]:
        """(name, count, total ms, mean ms, max ms), the biggest total first."""
        rows = [(n, int(c), t * 1000, t * 1000 / c, m * 1000) for n, (c, t, m) in self.data.items()]
        return sorted(rows, key=lambda r: -r[2])

    def clear(self) -> None:
        self.data.clear()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


class Profiler:
    FRAMES = 600  # frame times kept for the graph and the percentiles

    def __init__(self, out_dir: str) -> None:
        self.out_dir = out_dir
        self.cprof = cProfile.Profile()
        self.windows = Stats()
        self.rpc = Stats()
        self.code_ms: collections.deque[float] = collections.deque(maxlen=self.FRAMES)  # our GUI code
        self.render_ms: collections.deque[float] = collections.deque(maxlen=self.FRAMES)  # ImGui render + swap
        self.frames = 0
        self.t_start = time.monotonic()
        self._t_frame: float | None = None
        self._t_render: float | None = None

    # -- recording ------------------------------------------------------------
    def frame_begin(self) -> None:
        self._t_frame = time.perf_counter()

    def render_begin(self) -> None:
        if self._t_frame is not None:
            self._t_render = time.perf_counter()
            self.code_ms.append((self._t_render - self._t_frame) * 1000)

    def frame_end(self) -> None:
        if self._t_render is not None:
            self.render_ms.append((time.perf_counter() - self._t_render) * 1000)
            self.frames += 1
        self._t_frame = self._t_render = None

    def timed(self, name: str, fn: Callable[[], object]) -> Callable[[], None]:
        def run() -> None:
            t0 = time.perf_counter()
            try:
                fn()
            finally:
                self.windows.add(name, time.perf_counter() - t0)

        return run

    def reset(self) -> None:
        self.cprof.disable()
        self.cprof = cProfile.Profile()
        self.cprof.enable()
        for s in (self.windows, self.rpc):
            s.clear()
        self.code_ms.clear()
        self.render_ms.clear()
        self.frames = 0
        self.t_start = time.monotonic()

    # -- reporting --------------------------------------------------------------
    def report(self, agent: dict | None = None) -> str:
        """A plain-text summary; `agent` is the agent's `profile` stats, if it answered."""
        out = io.StringIO()
        secs = time.monotonic() - self.t_start
        code, render = list(self.code_ms), list(self.render_ms)
        out.write(f"pwndbg-imgui profile: {self.frames} frames in {secs:.1f} s\n\n")
        out.write(f"Frame time, last {len(code)} frames (ms)     median    p95    max\n")
        for name, vals in (("GUI code (our Python)", code), ("render + swap", render)):
            out.write(f"  {name:<36}{percentile(vals, 50):8.2f}{percentile(vals, 95):7.2f}"
                      f"{max(vals, default=0):7.2f}\n")
        sections = [("Windows (time in each gui function)", self.windows.rows()),
                    ("Agent ops, round trip seen by the GUI", self.rpc.rows())]
        if agent:
            sections.append(("Agent ops, time inside gdb", [tuple(r) for r in agent.get("ops", [])]))
        for title, rows in sections:
            out.write(f"\n{title}\n  {'name':<44}{'count':>7}{'total ms':>11}{'mean ms':>10}{'max ms':>9}\n")
            for name, count, total, mean, mx in rows[:40]:
                out.write(f"  {name[:44]:<44}{count:>7}{total:>11.1f}{mean:>10.2f}{mx:>9.2f}\n")
        out.write("\nGUI process, top functions by cumulative time (full data: gui.prof). Python >= 3.12\n"
                  "records every thread: time blocked in socket `recv` is the RPC reader waiting, not work.\n")
        stats = io.StringIO()
        try:
            pstats.Stats(self.cprof, stream=stats).sort_stats("cumulative").print_stats(30)
        except TypeError:  # nothing recorded yet
            stats.write("  (no data)\n")
        out.write(stats.getvalue())
        return out.getvalue()

    def write(self, agent: dict | None = None) -> str:
        """Save gui.prof and report.txt into out_dir; returns the report's path."""
        os.makedirs(self.out_dir, exist_ok=True)
        self.cprof.disable()
        try:
            self.cprof.dump_stats(os.path.join(self.out_dir, "gui.prof"))
            path = os.path.join(self.out_dir, "report.txt")
            with open(path, "w") as f:
                f.write(self.report(agent))
        finally:
            self.cprof.enable()
        return path


def default_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "pwndbg-imgui", "profile-" + time.strftime("%Y%m%d-%H%M%S"))
