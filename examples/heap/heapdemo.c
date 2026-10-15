/*
 * heapdemo: a few allocations and frees to look at in pwndbg-imgui's Heap view.
 *
 *   make heap                    (from examples/)
 *   pwndbg-imgui ./heapdemo      then: b heap_snapshot, run, View -> Heap
 *
 * At heap_snapshot() the heap holds, in order:
 *   two freed 0x30 chunks   -> tcache bin 0x30
 *   one 0x30 chunk in use
 *   a freed 0x510 chunk     -> unsorted bin (too large for tcache)
 *   a 0x20 "guard" chunk in use (keeps the 0x510 one from merging into top)
 *   the top chunk
 * (plus whatever the libc allocated for itself, e.g. stdio buffers)
 */
#include <stdio.h>
#include <stdlib.h>

/* Break here to inspect the heap; noinline so it exists as a real function. */
__attribute__((noinline)) void heap_snapshot(void) {
    puts("heap_snapshot: look at the Heap view now");
}

int main(void) {
    void *small[3], *big, *guard;

    for (int i = 0; i < 3; i++)
        small[i] = malloc(0x28); /* 0x30-byte chunks */
    big = malloc(0x500);         /* a 0x510-byte chunk */
    guard = malloc(0x18);

    free(small[0]);
    free(small[1]);
    free(big);

    heap_snapshot();

    free(guard);
    free(small[2]);
    return 0;
}
