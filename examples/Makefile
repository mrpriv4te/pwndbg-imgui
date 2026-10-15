# Build the demo programs (sources only are committed; see README.md).
#   make            everything that can be built here
#   make heap       heap/heapdemo (native cc, glibc)
#   make heap-musl  heap/heapdemo-musl (static musl, needs zig)
#   make multiarch  multiarch/hello-{aarch64,arm,mips} (static, needs zig)
CC ?= cc
ZIG ?= zig
CFLAGS = -g -O0
ARCHES = aarch64-linux-musl arm-linux-musleabihf mips-linux-musleabi

.PHONY: all heap heap-musl multiarch clean
all: heap $(if $(shell command -v $(ZIG)),heap-musl multiarch)

heap: heap/heapdemo
heap/heapdemo: heap/heapdemo.c
	$(CC) $(CFLAGS) -o $@ $<

heap-musl: heap/heapdemo-musl
heap/heapdemo-musl: heap/heapdemo.c
	$(ZIG) cc -target x86_64-linux-musl -static $(CFLAGS) -o $@ $<

# hello-aarch64, hello-arm, hello-mips (the target's first word names the binary)
multiarch: $(foreach t,$(ARCHES),multiarch/hello-$(firstword $(subst -, ,$(t))))
multiarch/hello-%: multiarch/hello.c
	$(ZIG) cc -target $(filter $*-%,$(ARCHES)) -static $(CFLAGS) -o $@ $< 2>&1 | grep -v "is not a recognized feature" || true

clean:
	rm -f heap/heapdemo heap/heapdemo-musl multiarch/hello-aarch64 multiarch/hello-arm multiarch/hello-mips
