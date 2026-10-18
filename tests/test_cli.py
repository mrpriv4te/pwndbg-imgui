import os
import re

import pytest

from pwndbg_imgui import cli
from pwndbg_imgui.agent import ENV_DEBUG
from pwndbg_imgui.theme import THEMES


def test_binary_and_gdb_args_pass_through():
    cfg = cli.parse_args(["-q", "-ex", "b main", "./bin"])
    assert cfg.gdb_args == ["-q", "-ex", "b main", "./bin"]
    assert cfg.binary == "./bin"


def test_args_stops_option_parsing():
    cfg = cli.parse_args(["--maximize", "--args", "./bin", "--theme", "nope", "-x"])
    assert cfg.maximize
    assert cfg.gdb_args == ["--args", "./bin", "--theme", "nope", "-x"]
    assert cfg.binary == "./bin"


@pytest.mark.parametrize("argv", [["-p", "1234"], ["--pid=1234"], ["-ex", "run"]])
def test_no_binary(argv):
    assert cli.parse_args(argv).binary is None


def test_eval_command_with_equals_is_skipped():
    assert cli.parse_args(["--eval-command=b main", "./bin"]).binary == "./bin"


def test_theme_is_case_insensitive_and_validated():
    name = next(iter(THEMES))
    assert cli.parse_args([f"--theme={name.upper()}"]).theme == name
    assert cli.parse_args(["--theme", name.lower()]).theme == name
    with pytest.raises(SystemExit):
        cli.parse_args(["--theme", "no-such-theme"])


def test_option_missing_value_exits():
    with pytest.raises(SystemExit):
        cli.parse_args(["--gdb"])


def test_pwndbg_loading_modes(tmp_path):
    assert cli.parse_args([]).init == "auto"
    assert cli.parse_args(["--no-pwndbg"]).init == "none"
    assert cli.parse_args(["--init-cmd", "init-pwndbg"]).init == "cmd:init-pwndbg"
    assert cli.parse_args(["--pwndbg", str(tmp_path)]).init == f"source:{tmp_path / 'gdbinit.py'}"
    assert cli.parse_args(["--pwndbg", "/x/gdbinit.py"]).init == "source:/x/gdbinit.py"


def test_attach_disables_program_io():
    cfg = cli.parse_args(["--attach", "5", "--gdb-pid", "42"])
    assert (cfg.attach_fd, cfg.gdb_pid, cfg.no_io) == (5, 42, True)


def test_terminal_io_uses_the_launching_terminal(monkeypatch):
    monkeypatch.setattr(cli, "launch_terminal", lambda: "/dev/pts/7")
    cfg = cli.parse_args(["--terminal-io", "./bin"])
    assert cfg.terminal_io == "/dev/pts/7" and cfg.no_io and cfg.gdb_args == ["./bin"]
    monkeypatch.setattr(cli, "launch_terminal", lambda: None)  # e.g. started from a desktop launcher
    with pytest.raises(SystemExit):
        cli.parse_args(["--terminal-io", "./bin"])


def test_debug_flag_sets_env(monkeypatch):
    monkeypatch.delenv(ENV_DEBUG, raising=False)
    cli.parse_args(["--debug"])
    assert os.environ[ENV_DEBUG] == "1"


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("pwndbg-imgui ")


def test_default_debugger(monkeypatch):
    monkeypatch.setenv("PWNDBG_IMGUI_GDB", "/opt/gdb")
    assert cli.default_debugger() == "/opt/gdb"
    monkeypatch.delenv("PWNDBG_IMGUI_GDB")
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/pwndbg" if name == "pwndbg" else None)
    assert cli.default_debugger() == "/usr/bin/pwndbg"
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert cli.default_debugger() == "gdb"


def test_exploit_writes_file_and_refuses_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.parse_args(["--exploit", "x.py"])
    path = tmp_path / "x.py"
    assert "from pwn import" in path.read_text()
    assert os.stat(path).st_mode & 0o111
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(["--exploit", "x.py"])
    assert "already exists" in str(exc.value.code)


def test_exploit_prints_when_piped(capsys):
    with pytest.raises(SystemExit):
        cli.parse_args(["--exploit"])  # pytest's stdout is not a tty
    assert "from pwn import" in capsys.readouterr().out


def test_every_public_option_is_documented():
    import inspect

    handled = set(re.findall(r'"(--[a-z-]+)"', inspect.getsource(cli.parse_args)))
    hidden = {"--attach", "--gdb-pid", "--args", "--help"}  # internal, or gdb's own
    documented = set(re.findall(r"(--[a-z-]+)", cli.usage()))
    assert handled - hidden <= documented


def test_child_pids_finds_a_child():
    import subprocess
    import sys

    from pwndbg_imgui.transport import child_pids

    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        assert p.pid in child_pids(os.getpid())
    finally:
        p.kill()
        p.wait()
    assert child_pids(2**22 + 12345) == []  # no such process
