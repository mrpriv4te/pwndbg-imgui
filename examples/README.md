# Examples

Small programs to try pwndbg-imgui's features in a few seconds. Only the sources are
committed: build them with `make` in this folder.

| Example | Shows | Needs |
|---|---|---|
| [`heap/`](heap) | the **Heap** view: chunks, tcache / unsorted bins, the top chunk; the message for a non-glibc program | `cc` (and `zig` for the musl variant) |
| [`multiarch/`](multiarch) | debugging **AArch64, ARM and big-endian MIPS** targets under qemu-user: Memory view words and byte order, per-architecture registers, payloads, cyclic lookups | `zig`, `qemu-user`, `gdb-multiarch` |
| [`creneau-serre/`](creneau-serre) | a real **CTF challenge** (404CTF 2026), with a pwntools `exploit.py` using `-d ui` | pwntools |

## Build

```bash
make              # everything your tools allow (zig parts are skipped without zig)
make heap         # heap/heapdemo only
make clean
```

On Debian/Ubuntu: `sudo apt install build-essential qemu-user gdb-multiarch`, and
[zig](https://ziglang.org/download/) for the static cross-compiled binaries (it needs no
cross toolchain).

## Replay the checks

Each demo has a `.steps` file: the script of GUI actions and assertions used to test the
feature with [`tools/guitest.py`](../tools/guitest.py). `check.sh` replays them all (real GUI
and gdb, so it needs a display) and reports pass / fail / skip:

```bash
make && PYTHON=/path/to/python ./check.sh   # a Python with imgui-bundle and numpy
```
