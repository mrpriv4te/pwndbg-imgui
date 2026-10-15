# multiarch: non-x86 targets

[`hello.c`](hello.c) built statically for **AArch64**, **ARM** (32-bit) and **MIPS**
(32-bit, big-endian), to debug under qemu-user's gdbserver with a multi-arch gdb.

```bash
make multiarch                # from examples/ (needs zig)
./run.sh aarch64              # or arm, mips; extra arguments go to pwndbg-imgui
```

`run.sh` starts `qemu-<arch> -g 1234 ./hello-<arch>` and opens
`pwndbg-imgui --gdb gdb-multiarch -ex 'target remote :1234' ./hello-<arch>`. Then:
`b work`, `continue`. The program's own input/output stay in the terminal where you ran
`run.sh`: type a line there when it asks.

## What to look at

- **Status bar**: the target's architecture (`aarch64`, `armv7`, `mips:isa32r2`).
- **Registers**: the target's registers, changed ones tinted after a step.
- **Memory** → mode **qwords / dwords**: pointer-sized words in the target's byte order
  (dwords on ARM and MIPS, big-endian on MIPS). The **follow** list offers that
  architecture's argument registers (`$x0`, `$r0`, `$a0`…): at `work()`, they hold its
  arguments.
- **Program I/O**: disabled, with a note. The program runs under qemu, so its I/O is in
  qemu's terminal.
- **Pattern (cyclic)**: `n` is `auto` (4 on 32-bit, 8 on 64-bit), and offsets are
  found in the target's byte order.

## Automated check

[`multiarch.steps`](multiarch.steps) checks the pointer size and byte order, that the Memory
view reads the same word at `$sp` as gdb, payload packing and a cyclic lookup.
[`../check.sh`](../check.sh) runs it for the three targets.
