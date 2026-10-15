# CLAUDE.md — project notes for Claude Code

User-facing docs are in `README.md`. This file is the context an AI session needs to
work on the code without re-deriving it.

## What this is

`pwndbg-imgui`: a dockable Dear ImGui GUI front-end for **pwndbg**, Ghidra/IDA style.
A thin GUI that drives the user's existing **gdb + pwndbg** — it does not bundle pwndbg.
Linux, x86-64, Python ≥ 3.10. Installed with pipx. Single dependency: `imgui-bundle`.

## Architecture (the important part)

Two Python worlds that must not mix:

- **GUI side** — runs in pwndbg-imgui's own (pipx) environment with `imgui-bundle`.
- **Agent side** (`agent.py`) — runs inside **gdb's embedded Python** (pwndbg's interpreter).

They talk over a `socketpair` with newline-delimited JSON (`transport.Rpc` on the GUI side;
`Agent` in `agent.py`). The agent routes each pwndbg context section to the GUI via
`contextoutput(<section>, <callable>, ...)` and answers requests (memory, vmmap,
breakpoints, completion, decompilation, console…).

**Hard constraints — do not break these:**

- `agent.py` is loaded into gdb **by file path** (see `App.spawn_gdb`), never imported from
  the pipx env, so the pipx environment never shadows pwndbg's pinned deps. Therefore
  `agent.py` must use the **standard library only** — no third-party imports.
- The GUI prefers the official **`pwndbg` launcher** as the debugger binary when it is on
  `PATH` (`cli.default_debugger`), falling back to `gdb` + loading pwndbg from the user's
  gdbinit / an `init-pwndbg` command / known paths (`agent.load_pwndbg`). Keep both paths
  working.

**Two launch modes, one agent:**

- Launched by the GUI: `pwndbg-imgui ./bin` → GUI spawns the debugger, PTYs for the gdb
  console and the program.
- Attached: `init-pwndbg-imgui` inside an existing gdb (gdbinit snippet from
  `pwndbg-imgui --gdbinit`) → `agent.attach()` launches the GUI over a socketpair; the gdb
  keeps its terminal. Used by pwntools (`exploit.py -d ui`, or `context.gdb_binary`).

## Layout

```
src/pwndbg_imgui/
  cli.py        entry point / option parsing; imports the GUI only at launch
  agent.py      gdb side (stdlib only); loaded by path into gdb's Python
  transport.py  RPC client + PTYs
  term.py       small ANSI terminal emulator (Term, Line, styles)
  theme.py      colors + 13 themes
  settings.py   ~/.config/pwndbg-imgui/settings.json
  fonts.py      fontconfig discovery + glyph fallbacks
  payload.py    cyclic / payload expressions / hexdump
  templates/exploit.tmpl   template emitted by `--exploit`
  ui/
    app.py        App: state, gdb process, events, hello_imgui runner (core)
    chrome.py     menus, toolbar/title/status bar, palette, dialogs (mixin)
    panels.py     tool windows: console, I/O, vmmap, breakpoints, config… (mixin)
    sections.py   per-context-section behavior / gutters / menus (mixin)
    views.py      CmdView, DecompView, MemoryView
    widgets.py    TextView (the core text pane) + helpers
    appearance.py fonts + apply_theme (mixin)
    native.py     GLFW-via-ctypes window control (themed title bar)
    catalog.py    SECTION_META, TOOL_PRESETS, AUTOFIT_HEIGHT
tools/guitest.py  GUI test driver (dev only, not shipped) + tools/smoke.steps
```
`App` is composed of mixins: `class App(SectionsMixin, AppearanceMixin, PanelsMixin,
ChromeMixin)`; `ui/app.py` holds the core methods, the others are the mixins.

## Dev workflow

- Install for development: `pipx install -e .` (gives the `pwndbg-imgui` command).
- Lint: `python -m pyflakes $(find src/pwndbg_imgui tools tests -name '*.py')` — keep it clean.
- Unit tests: `python -m pytest` (`tests/`, config in `pyproject.toml`). They cover the
  stdlib-only modules (`term`, `payload`, `cli`, `settings`, agent helpers) and need no
  imgui-bundle or display. `test_agent.py` enforces the agent's stdlib-only rule. Add a
  test with any change to those modules; GUI behavior is checked with `tools/guitest.py`.
- CI (`.github/workflows/ci.yml`): lint + pytest on Python 3.10–3.14, plus a packaging
  job (`pip install .`, entry-point smoke checks). It doesn't run the GUI.
- Debugging: `--debug` / `PWNDBG_IMGUI_DEBUG=1` logs every swallowed exception (GUI and
  agent side) with a traceback to `~/.cache/pwndbg-imgui-debug.log` via `agent.debug()`.
  When adding an `except Exception` that hides an error, call `debug("<where>")` in it.
- Not on PyPI: install from a clone or `pipx install git+https://github.com/mrpriv4te/pwndbg-imgui`. `.tmpl` isn't a module (ignore its `from pwn import *` warnings).
- Config lives in `~/.config/pwndbg-imgui/` (`settings.json`, `layout.ini`).
- Versioning is **git tags via hatch-vcs** — never hardcode a version. `__version__`
  resolves from `importlib.metadata` / the generated `_version.py` (gitignored). Release =
  `git tag vX.Y.Z`.
- Packaging: hatchling + hatch-vcs, PEP 639 `license = "MIT"`.

### Testing the GUI

It's a GUI, so it needs a display. Test changes without a human with `tools/guitest.py`
(dev-only, not in the wheel): it runs the real GUI + gdb, executes timed steps from a file
(`cmd` console command, `py` assertion `exec`'d with `app` in scope, `shot` screenshot,
`quit`), writes PNGs, and exits 1 if a `py` step raised. It uses a fresh
`XDG_CONFIG_HOME` unless `--keep-config`. See its docstring and `tools/smoke.steps`:

```
cd examples/creneau-serre
python ../../tools/guitest.py ../../tools/smoke.steps --out /tmp/shots -- ./chall
```
The interpreter needs `pwndbg_imgui` importable plus `numpy` (e.g. `PYTHONPATH=src` in a
venv with imgui-bundle + numpy, or the pipx env after `pipx inject pwndbg-imgui numpy`).
Read the PNGs back to check visually; assert on `app.state`, `app.is_stopped()`,
`app.sections[...]`, `app.settings[...]`.

Useful flags while testing: `--reset-layout`, `--no-viewports`, `--no-io`, `--no-pwndbg`;
`python -m pwndbg_imgui` works too (`__main__.py`). `--agent-path` prints the agent file
attached mode loads.

Gotchas when testing:
- `examples/creneau-serre/chall` has `RUNPATH ./`, so run it **from that directory** or the
  loader can't find `libc.so.6` / `ld-linux-x86-64.so.2` (exit code 127).
- Simulated mouse/keyboard input is unreliable; prefer calling `app.*` methods directly and
  asserting state. Screenshots are the best visual check.
- Each GUI run spawns a real gdb; verify no stray `pwndbg_imgui_agent` / gdb processes after
  (check the parent PID: the user may have their own instance open).
- `hello_imgui.final_app_window_screenshot()` is only filled once the app exits; mid-run
  shots read the GL front buffer instead (done in `guitest.py`).

## Extending (where things plug in)

- **New agent op:** add `op_<name>(self, ...)` to `Agent` in `agent.py`; `handle()`
  dispatches by name and replies `{id, ok, res|err}`. Call it from the GUI with
  `self.rpc.request("<name>", cb=..., err=..., **kwargs)`. Callbacks run on the GUI thread
  (the inbox is drained each frame).
- **New agent → GUI event:** `self.send({"ev": "<name>", ...})` in the agent; the GUI
  dispatches it to `on_<name>(self, msg)` on `App`. A handler exception becomes a toast,
  never a crash.
- **Threading (agent):** requests are read on the `imgui-agent` thread and executed on
  gdb's thread via `gdb.post_event`. Any new code that touches the gdb API must go through
  that path — never call gdb from the reader thread.
- **New setting:** add the key to `Settings.DEFAULTS`; saved files are merged over the
  defaults, so code can index `settings[key]` directly.
- **New context section:** add it to `SECTIONS` in `agent.py` (routed via `contextoutput`)
  and to `catalog.SECTION_META` (label, icon, follow mode, default visibility, dock space).

## Known pitfalls (each cost real debugging time)

- gdb fires `breakpoint_deleted` **before** removing the breakpoint, hence
  `send_breakpoints(exclude=num)`.
- `save_breakpoints` only writes when `bps_dirty` is set, so a session that never loaded or
  created breakpoints can't wipe the saved list. Restoring is opt-in (a toast).
- ImGui IDs: labels in loops / context menus need unique `##id` suffixes or they collide.
- Loading pwndbg by `runpy`/file sets `__file__` and `sys.argv[0]`, which confuses pwndbg;
  `load_pwndbg` blanks both while loading and restores them after.
- Sliders that change fonts/sizes must apply on release (`is_item_deactivated_after_edit`),
  not every frame, or the UI shakes.
- ImGui ini settings can't be loaded mid-frame: "Restore my layout" stores the ini and
  applies it in `pre_new_frame`.
- Program I/O is disabled on purpose for remote targets (gdbserver) — the program's I/O isn't
  ours (`target_is_remote`, `state["remote"]`). Not a bug.
- pwndbg config persistence skips `App.PWNDBG_CONFIG_DENY` (`context-sections`,
  `context-output`, `context-reserve-lines`), which the GUI itself controls.

## Release checklist

1. Lint clean and `pytest` green (commands above); CI green on `main`.
2. `tools/guitest.py` smoke run passes; look at the screenshots.
3. Commit (only when asked), then `git tag -a vX.Y.Z -m "pwndbg-imgui X.Y.Z"` and push the
   branch **and** the tag.
4. The tag's CI run publishes the GitHub Release automatically (`release` job: notes from
   `tools/release-notes.sh` = commit subjects since the previous tag, wheel + sdist
   attached; a tag with letters, e.g. `v1.4.0rc1`, becomes a prerelease). So commit
   subjects are the changelog — keep them meaningful. Not published to PyPI (yet).
   Check it with `gh run watch` / `gh release view vX.Y.Z`.

## Conventions

- **README and all docs in English.**
- Commit messages: `pwndbg_imgui: <lowercase summary>` for code, `docs: …`, `examples: …`.
  Keep a short body explaining the why.
- **Commit and push only when the user explicitly asks** ("commit this", "commit and
  push"). The repo is public (`git@github.com:mrpriv4te/pwndbg-imgui.git`), default branch
  `main`.
- Git identity uses the noreply email (set globally); do not reintroduce a real email.
- Prefer editing in place; match the surrounding style (compact, few comments that explain
  *why*).

## Platform notes

- GLFW (from imgui-bundle) uses the **X11 backend**; on Wayland it runs via XWayland. Native
  Wayland restricts programmatic window move (themed title bar drag) and multi-viewport —
  `native.py` detects this and the app degrades gracefully (offer the system title bar).
- pwndbg can be installed many ways (the `pwndbg` launcher, sourced from a gdbinit, or a
  user-defined `init-pwndbg` gdb command); the GUI handles all of them, so don't assume one.
  Machine-specific setup belongs in `CLAUDE.local.md` (gitignored), not here.
