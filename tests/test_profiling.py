import os
import pstats

from pwndbg_imgui import cli
from pwndbg_imgui.profiling import Profiler, Stats, percentile


def test_stats_rows_biggest_total_first():
    s = Stats()
    for name, secs in (("a", 0.001), ("b", 0.010), ("a", 0.003)):
        s.add(name, secs)
    (n1, c1, t1, m1, x1), (n2, c2, *_rest) = s.rows()
    assert (n1, c1) == ("b", 1) and (n2, c2) == ("a", 2)
    assert abs(t1 - 10) < 1e-9 and abs(m1 - 10) < 1e-9 and abs(x1 - 10) < 1e-9


def test_percentile():
    assert percentile([], 50) == 0.0
    assert percentile([5, 1, 3], 50) == 3
    assert percentile(list(range(101)), 95) == 95


def test_frames_windows_and_report(tmp_path):
    p = Profiler(str(tmp_path / "prof"))
    p.cprof.enable()
    for _ in range(3):
        p.frame_begin()
        p.timed("Disassembly", lambda: sum(range(1000)))()
        p.render_begin()
        p.frame_end()
    p.rpc.add("vmmap", 0.004)
    p.cprof.disable()
    assert p.frames == 3 and len(p.code_ms) == 3 and len(p.render_ms) == 3
    agent = {"active": True, "ops": [["vmmap", 2, 1.0, 0.5, 0.7]]}
    text = p.report(agent)
    for part in ("3 frames", "GUI code (our Python)", "Disassembly", "round trip", "time inside gdb", "vmmap"):
        assert part in text, part
    path = p.write(agent)
    assert open(path).read().startswith("pwndbg-imgui profile")
    pstats.Stats(os.path.join(p.out_dir, "gui.prof"))  # a valid pstats file


def test_timed_records_even_when_the_window_raises():
    p = Profiler("unused")

    def boom():
        raise RuntimeError

    try:
        p.timed("Heap", boom)()
    except RuntimeError:
        pass
    assert p.windows.data["Heap"][0] == 1


def test_profile_flag(tmp_path, monkeypatch):
    assert cli.parse_args(["./bin"]).profile is None
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    default = cli.parse_args(["--profile", "./bin"]).profile or ""
    assert default.startswith(f"{tmp_path}/pwndbg-imgui/profile-")  # a new folder per run
    assert (cli.parse_args(["--profile=", "./bin"]).profile or "").startswith(f"{tmp_path}/pwndbg-imgui/profile-")
    cfg = cli.parse_args([f"--profile={tmp_path}/p", "./bin"])
    assert cfg.profile == f"{tmp_path}/p" and cfg.gdb_args == ["./bin"]
