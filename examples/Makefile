# Build the demo programs (sources only are committed; see README.md).
#   make            everything that can be built here
#   make heap       heap/heapdemo (native cc, glibc)
#   make threads    threads/threads (native cc, pthreads)
#   make curses     curses/cursesdemo (native cc, ncurses headers: libncurses-dev)
#   make heap-musl  heap/heapdemo-musl (static musl, needs zig)
#   make multiarch  multiarch/hello-{aarch64,arm,mips} (static, needs zig)
CC ?= cc
ZIG ?= zig
CFLAGS = -g -O0
ARCHES = aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi

.PHONY: all heap heap-musl threads curses multiarch clean
HAVE_CURSES := $(shell echo '\#include <curses.h>' | $(CC) -E - > /dev/null 2>&1 && echo yes)
all: heap threads $(if $(HAVE_CURSES),curses) $(if $(shell command -v $(ZIG)),heap-musl multiarch)

heap: heap/heapdemo
heap/heapdemo: heap/heapdemo.c
	$(CC) $(CFLAGS) -o $@ $<

threads: threads/threads
threads/threads: threads/threads.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

curses: curses/cursesdemo
curses/cursesdemo: curses/cursesdemo.c
	$(CC) $(CFLAGS) -o $@ $< -lncurses

heap-musl: heap/heapdemo-musl
heap/heapdemo-musl: heap/heapdemo.c
	$(ZIG) cc -target x86_64-linux-musl -static $(CFLAGS) -o $@ $<

# hello-aarch64, hello-arm, hello-mips (the target's first word names the binary)
multiarch: $(foreach t,$(ARCHES),multiarch/hello-$(firstword $(subst -, ,$(t))))
multiarch/hello-%: multiarch/hello.c
	$(ZIG) cc -target $(filter $*-%,$(ARCHES)) -static $(CFLAGS) -o $@ $< 2>&1 | grep -v "is not a recognized feature" || true

clean:
	rm -f heap/heapdemo heap/heapdemo-musl threads/threads curses/cursesdemo multiarch/hello-aarch64 multiarch/hello-arm multiarch/hello-mips
