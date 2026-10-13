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
