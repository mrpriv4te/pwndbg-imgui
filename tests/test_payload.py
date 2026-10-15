import pytest

from pwndbg_imgui.payload import cyclic, cyclic_find, eval_payload, hexdump_ansi, parse_bytes_input
from pwndbg_imgui.term import strip_ansi


def test_cyclic_matches_pwntools():
    assert cyclic(20) == b"aaaabaaacaaadaaaeaaa"
    assert cyclic(16, n=8) == b"aaaaaaaabaaaaaaa"


def test_cyclic_subsequences_are_unique():
    pattern = cyclic(4000)
    grams = [pattern[i:i + 4] for i in range(len(pattern) - 3)]
    assert len(grams) == len(set(grams))


def test_cyclic_find():
    assert cyclic_find(b"faaa") == 20
    assert cyclic_find(cyclic(600)[512:516]) == 512
    assert cyclic_find(b"ab") == -1  # shorter than n


@pytest.mark.parametrize("text,mode,expected", [
    ("41 42\\x43 0x44", "hex", b"ABCD"),
    ("41:42,43", "hex", b"ABC"),
    ("b'A\\x00'", "python", b"A\x00"),
    ("'\\xff'", "python", b"\xff"),
    ("[65, 66]", "python", b"AB"),
    ("héllo", "text", "héllo".encode()),
])
def test_parse_bytes_input(text, mode, expected):
    assert parse_bytes_input(text, mode) == expected


def test_eval_payload_pwntools_style():
    assert eval_payload("b'A' * 4 + p64(0xdeadbeef)") == b"AAAA" + (0xDEADBEEF).to_bytes(8, "little")
    assert eval_payload("p32(-1)") == b"\xff" * 4
    assert eval_payload("flat([1, b'x', 'y'])") == (1).to_bytes(8, "little") + b"xy"
    assert eval_payload("cyclic(8)") == b"aaaabaaa"
    assert eval_payload("0x41") == b"A" + b"\0" * 7  # a bare int is packed as p64
    assert eval_payload("'str'") == b"str"


def test_eval_payload_has_no_dangerous_builtins():
    with pytest.raises(NameError):
        eval_payload("__import__('os')")
    with pytest.raises(NameError):
        eval_payload("open('/etc/passwd')")


def test_hexdump():
    out = strip_ansi(hexdump_ansi(b"AB\x00" + bytes(range(0x30, 0x3E))))
    first, second = out.splitlines()
    assert first.startswith("00000000  41 42 00 30")
    assert first.endswith("│AB.0123456789:;<│")
    assert second.startswith("00000010  3d")
    assert hexdump_ansi(b"") == ""


def test_eval_payload_follows_the_target():
    # 32-bit big-endian (e.g. MIPS32): flat() and bare ints pack to 4 bytes, MSB first
    assert eval_payload("flat([0x41424344, b'x'])", word=4, endian="big") == b"ABCDx"
    assert eval_payload("0x10", word=4, endian="big") == b"\0\0\0\x10"
    assert eval_payload("p16(0x4142)", word=4, endian="big") == b"AB"
    assert eval_payload("u32(b'ABCD')", word=4, endian="big") == b"ABCD"  # round-trips through p32
    # 32-bit little-endian (ARM, i386)
    assert eval_payload("flat(1)", word=4) == b"\1\0\0\0"
