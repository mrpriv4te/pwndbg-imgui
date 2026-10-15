"""Static descriptions: context sections and pwndbg tool presets."""

from __future__ import annotations

SECTION_META = {
    # name: (label, icon attr, follow, visible by default, dock space)
    "regs": ("Registers", "MICROCHIP", "top", True, "Right"),
    "disasm": ("Disassembly", "CODE", "pc", True, "MainDockSpace"),
    "code": ("Source", "FILE_CODE", "pc", True, "MainDockSpace"),
    "stack": ("Stack", "LAYER_GROUP", "top", True, "RightMid"),
    "backtrace": ("Backtrace", "SHOE_PRINTS", "top", True, "RightBottom"),
    "args": ("Arguments", "LIST_OL", "top", False, "RightMid"),
    "expressions": ("Watch", "EYE", "top", True, "RightMid"),
    "threads": ("Threads", "BARS_STAGGERED", "top", True, "RightBottom"),
    "heap_tracker": ("Heap Tracker", "CUBES", "top", False, "RightBottom"),
    "last_signal": ("Last Signal", "BOLT", "top", False, "RightBottom"),
}


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
