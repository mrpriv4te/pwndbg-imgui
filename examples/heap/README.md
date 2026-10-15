# heap: the Heap view

[`heapdemo.c`](heapdemo.c) makes a few allocations and frees, then calls
`heap_snapshot()`, a function that exists only to stop in.

```bash
make heap                     # from examples/
cd heap && pwndbg-imgui ./heapdemo
```

Then, in the console: `b heap_snapshot`, `run`, and open **View → Heap**.

## What you should see

| Chunk | Size | State |
|---|---|---|
| `small[0]`, `small[1]` | 0x30 | **tcache** (freed) |
| `small[2]` | 0x30 | in use |
| `big` | 0x510 | **unsorted** (freed, too large for tcache) |
| `guard` | 0x20 | in use: keeps `big` from merging into the top chunk |
| | | **top** |

Below the chunks: the tcache 0x30 bin (count 2) and the unsorted bin with their chains. Click
an address to open it in the Memory view. The libc may add chunks of its own (e.g. stdio
buffers), and the exact list depends on the glibc version.

## Memory tab (vis-heap-chunks)

The **Memory** tab draws the same chunks as pwndbg's `vis-heap-chunks`: the words of
each chunk, colored per chunk, with the bins annotated (`<-- tcachebins[0x30][0/2]`,
`<-- unsortedbin[all][0]`…). With a chunk selected in the **Chunks** tab (or right-click it →
*Visualize from here*), it starts at that chunk. Options: how many chunks (0 = all), don't
collapse repeated rows, don't truncate large chunks.

## Not glibc

`make heap-musl` builds the same program statically against musl (with zig). The Heap view
then explains that it shows glibc's allocator only. pwndbg's heap commands are glibc-only
too.

## Automated check

[`heap.steps`](heap.steps) and [`heap-musl.steps`](heap-musl.steps) assert the above with
`tools/guitest.py`; [`../check.sh`](../check.sh) runs them.
