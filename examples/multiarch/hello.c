/*
 * hello: a tiny program to debug non-x86 targets (AArch64, ARM, MIPS…) with pwndbg-imgui,
 * through qemu-user's gdbserver. Built statically for each target by `make multiarch`.
 *
 *   ./run.sh aarch64             (or arm, mips) then: b work, continue
 *
 * work() takes two arguments, so at its start they sit in the target's argument
 * registers ($x0/$x1, $r0/$r1, $a0/$a1…), which the Memory view offers to follow.
 */
#include <stdio.h>
#include <unistd.h>

static char buf[64];

__attribute__((noinline)) int work(int a, int b) {
    return a * 31 + b;
}

int main(void) {
    puts("hello from the target: type a line");
    long n = read(0, buf, sizeof buf - 1);
    printf("read %ld bytes, work=%d\n", n, work((int)n, 7));
    return 0;
}
