"""Exploitation helpers: cyclic patterns, payload expressions, hexdumps."""

from __future__ import annotations

import re


def de_bruijn(alphabet: bytes, n: int):
    k = len(alphabet)
    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


def cyclic(length: int, n: int = 4) -> bytes:
    out = bytearray()
    for b in de_bruijn(b"abcdefghijklmnopqrstuvwxyz", n):
        if len(out) >= length:
            break
        out.append(b)
    return bytes(out)


def cyclic_find(needle: bytes, n: int = 4) -> int:
    needle = needle[:n]
    if len(needle) < n:
        return -1
    pattern = cyclic(min(26**n, 1 << 20) + n, n)
    return pattern.find(needle)


def parse_bytes_input(text: str, mode: str) -> bytes:
    """Interpret Program I/O input according to the selected mode."""
    if mode == "hex":
        clean = re.sub(r"(0x|\\x|[\s,:])", "", text)
        return bytes.fromhex(clean)
    if mode == "python":
        import ast

        value = ast.literal_eval(text)
        if isinstance(value, str):
            return value.encode("latin-1")
        return bytes(value)
    return text.encode("utf-8", errors="surrogateescape")


def eval_payload(expr: str, word: int = 8, endian: str = "little") -> bytes:
    """Evaluate a pwntools-like payload expression for Program I/O.

    `word` (pointer size in bytes) and `endian` describe the target, like pwntools'
    context: they set what flat() and a bare integer pack to, and p16..p64 / u32 / u64
    byte order (e.g. word=4, endian="big" for MIPS32 big-endian)."""
    order = "big" if endian == "big" else "little"

    def p(bits):
        return lambda v: (v & ((1 << bits) - 1)).to_bytes(bits // 8, order)

    def u(size):
        return lambda b: int.from_bytes(b[:size].ljust(size, b"\0") if order == "little"
                                        else b[:size].rjust(size, b"\0"), order)

    pword = p(8 * word)

    def flat(*items):
        out = b""
        for it in items:
            if isinstance(it, (list, tuple)):
                out += flat(*it)
            elif isinstance(it, int):
                out += pword(it)
            elif isinstance(it, str):
                out += it.encode("latin-1")
            else:
                out += bytes(it)
        return out

    env = {
        "__builtins__": {"bytes": bytes, "bytearray": bytearray, "int": int, "len": len, "range": range,
                         "chr": chr, "ord": ord, "hex": hex, "str": str, "list": list, "sum": sum},
        "p8": p(8), "p16": p(16), "p32": p(32), "p64": p(64), "flat": flat,
        "u32": u(4), "u64": u(8),
        "cyclic": lambda n, k=4: cyclic(n, k),
    }
    value = eval(expr, env)  # the user's own payload expression
    if isinstance(value, str):
        return value.encode("latin-1")
    if isinstance(value, int):
        return pword(value)
    if isinstance(value, (list, tuple)):
        return flat(*value)
    return bytes(value)


def hexdump_ansi(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = []
        for i, b in enumerate(chunk):
            h = f"{b:02x}"
            if b == 0:
                h = f"\x1b[90m{h}\x1b[0m"
            elif 0x20 <= b < 0x7F:
                h = f"\x1b[32m{h}\x1b[0m"
            hexes.append(h + (" " if i != 7 else "  "))
        pad = "   " * (16 - len(chunk)) + (" " if len(chunk) <= 8 else "")
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "\x1b[90m.\x1b[0m" for b in chunk)
        lines.append(f"\x1b[33m{off:08x}\x1b[0m  {''.join(hexes)}{pad} │{asc}│")
    return "\n".join(lines) + ("\n" if lines else "")
