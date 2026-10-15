# threads: the Backtrace and Threads views

[`threads.c`](threads.c) starts two named worker threads, then calls
`depth1()` → `depth2()` → `depth3()` from the main thread.

```bash
make threads                  # from examples/
cd threads && pwndbg-imgui ./threads
```

Then: `b depth3`, `run`.

## What to look at

- **Backtrace**: a table of the main thread's frames (`depth3`, `depth2`, `depth1`, `main`,
  then libc's start code), with address, function+offset and `file:line`. Click a frame to
  select it: the Source, Disassembly, Registers and Stack panes follow. Right-click for
  "finish up to here", disassemble, memory, copy.
- **Threads**: `main-thread`, `worker-a` and `worker-b` with TID, state and where each one
  is (the workers wait in a syscall). Click one to switch to it; the Backtrace follows.
- **pwndbg text**: the button above each table switches back to pwndbg's own output.

## Automated check

[`threads.steps`](threads.steps) asserts the frames, frame selection, the thread names and
thread switching; [`../check.sh`](../check.sh) runs it.
