/*
 * threads: three named threads and a few nested calls, for the Backtrace and Threads views.
 *
 *   make threads                 (from examples/)
 *   pwndbg-imgui ./threads       then: b depth3, run
 *
 * At depth3() the main thread is 4 calls deep (depth3 <- depth2 <- depth1 <- main) and
 * the two workers are parked in pause().
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_barrier_t ready;

__attribute__((noinline)) int depth3(int x) { return x + 1; }
__attribute__((noinline)) int depth2(int x) { return depth3(x * 2); }
__attribute__((noinline)) int depth1(int x) { return depth2(x + 3); }

static void *worker(void *arg) {
    pthread_barrier_wait(&ready);
    for (;;)
        pause();
    return arg;
}

int main(void) {
    pthread_t a, b;

    pthread_barrier_init(&ready, NULL, 3);
    pthread_setname_np(pthread_self(), "main-thread");
    pthread_create(&a, NULL, worker, NULL);
    pthread_setname_np(a, "worker-a");
    pthread_create(&b, NULL, worker, NULL);
    pthread_setname_np(b, "worker-b");
    pthread_barrier_wait(&ready); /* both workers are running from here */

    printf("%d\n", depth1(1));
    return 0;
}
