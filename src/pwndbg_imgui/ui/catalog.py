"""Static descriptions: context sections and pwndbg tool presets."""

from __future__ import annotations

SECTION_META = {
    # name: (label, icon attr, follow, visible by default, dock space; see DOCK_SPLITS)
    "regs": ("Registers", "MICROCHIP", "top", True, "Top"),
    "disasm": ("Disassembly", "CODE", "pc", True, "MainDockSpace"),
    "code": ("Source", "FILE_CODE", "pc", True, "MainDockSpace"),
    "stack": ("Stack", "LAYER_GROUP", "top", True, "Right"),
    "backtrace": ("Backtrace", "SHOE_PRINTS", "top", True, "RightBottom"),
    "args": ("Arguments", "LIST_OL", "top", False, "Right"),
    "expressions": ("Watch", "EYE", "top", True, "Right"),
    "threads": ("Threads", "BARS_STAGGERED", "top", True, "RightBottom"),
    "heap_tracker": ("Heap Tracker", "CUBES", "top", False, "RightBottom"),
    "last_signal": ("Last Signal", "BOLT", "top", False, "RightBottom"),
}

# The built-in layout (first run, View > Reset to built-in layout), as proportions:
#   Registers across the top; below, a left column (code views over Console / Program I/O)
#   and a right column (Stack / Heap / Watch over Breakpoints / Backtrace / VMMap...).
# (parent dock space, new dock space, side, ratio of the parent taken by the new one)
DOCK_SPLITS = [
    ("MainDockSpace", "Top", "up", 0.22),
    ("MainDockSpace", "Right", "right", 0.43),
    ("MainDockSpace", "Bottom", "down", 0.47),
    ("Right", "RightBottom", "down", 0.29),
]

# Tab order inside each dock space: context sections by name, tool windows by label (without
# their icon). Windows not listed keep their place after these.
TAB_ORDER = [
    "disasm", "code", "Decompiler", "Memory", "Commands", "pwndbg Config",
    "stack", "Heap", "expressions", "args",
    "Breakpoints", "backtrace", "VMMap", "threads", "Pattern (cyclic)", "last_signal", "heap_tracker",
    "Preferences",
    "Console", "Program I/O",
    "regs",
]


# Registers worth following in the Memory view, by gdb architecture name (first match wins;
# "i386:x86-64" before "i386"). Mostly the first argument registers of the calling convention.
ARG_REGS = [
    ("i386:x86-64", ("$rdi", "$rsi", "$rdx", "$rax")),
    ("i386", ("$eax", "$ecx", "$edx", "$esi")),
    ("aarch64", ("$x0", "$x1", "$x2", "$x30")),
    ("arm", ("$r0", "$r1", "$r2", "$lr")),
    ("mips", ("$a0", "$a1", "$a2", "$v0")),
    ("riscv", ("$a0", "$a1", "$a2", "$ra")),
    ("powerpc", ("$r3", "$r4", "$r5", "$lr")),
]


def arg_regs(arch: str | None) -> tuple[str, ...]:
    for prefix, regs in ARG_REGS:
        if arch and arch.startswith(prefix):
            return regs
    return ()


AUTOFIT_HEIGHT = {"disasm", "stack", "threads", "code", "backtrace"}


TOOL_PRESETS = [
    ("Heap", [("heap", "heap"), ("bins", "bins"), ("vis_heap_chunks", "vis-heap-chunks"),
              ("arena", "arena"), ("arenas", "arenas"), ("tcachebins", "tcachebins"),
              ("fastbins", "fastbins"), ("unsortedbin", "unsortedbin"), ("smallbins", "smallbins"),
              ("largebins", "largebins"), ("top_chunk", "top-chunk"), ("mp", "mp")]),
    ("Memory", [("telescope $sp 48", "telescope"), ("hexdump $sp 256", "hexdump"),
                ("probeleak $sp 0x200", "probeleak"), ("leakfind $sp", "leakfind"),
                ("stack 40", "stack"), ("retaddr", "retaddr"), ("canary", "canary")]),
    ("Binary", [("checksec", "checksec"), ("elfsections", "elfsections"), ("got", "got"),
                ("plt", "plt"), ("piebase", "piebase"), ("libcinfo", "libcinfo"),
                ("linkmap", "linkmap"), ("aslr", "aslr")]),
    ("Process", [("procinfo", "procinfo"), ("auxv", "auxv"), ("envp", "envp"), ("argv", "argv"),
                 ("tls", "tls"), ("errno", "errno"), ("info sharedlibrary", None),
                 ("info signals", None)]),
    ("Code", [("nearpc 40", "nearpc"), ("emulate 30", "emulate"), ("info functions", None),
              ("rop --grep 'pop rdi'", "rop")]),
]
