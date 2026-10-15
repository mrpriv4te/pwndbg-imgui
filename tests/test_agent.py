"""The agent runs inside gdb, so only its gdb-independent parts are tested here."""

import ast
import sys
from pathlib import Path

from pwndbg_imgui import agent

AGENT_SRC = Path(agent.__file__).read_text()


def test_agent_imports_only_the_standard_library():
    # agent.py is loaded by path into gdb's own Python, where only the stdlib and
    # pwndbg/gdb exist: a third-party import would break every user (see CLAUDE.md)
    allowed = set(sys.stdlib_module_names) | {"gdb", "pwndbg", "__main__"}
    for node in ast.walk(ast.parse(AGENT_SRC)):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names = [node.module]
        else:
            assert not (isinstance(node, ast.ImportFrom) and node.level), "relative import in agent.py"
            continue
        for name in names:
            assert name.split(".")[0] in allowed, f"agent.py imports {name!r}"


def test_debug_is_silent_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv(agent.ENV_DEBUG, raising=False)
    try:
        raise ValueError("boom")
    except ValueError:
        agent.debug("somewhere")
    assert not Path(agent.debug_log_path()).exists()


def test_debug_logs_traceback_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv(agent.ENV_DEBUG, "1")
    try:
        raise ValueError("boom")
    except ValueError:
        agent.debug("somewhere")
    log = Path(agent.debug_log_path()).read_text()
    assert "[gui " in log and "somewhere" in log
    assert "ValueError: boom" in log
