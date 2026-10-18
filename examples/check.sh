#!/bin/sh
# Replay every demo's steps with tools/guitest.py (real GUI + gdb, needs a display) and
# report pass / fail / skip. Parts whose tools aren't installed are skipped.
#   ./check.sh                 screenshots go to $OUT (default: a temporary directory)
# PYTHON: an interpreter with imgui-bundle and numpy (default: python3); the package is
# taken from ../src. Build the programs first: make
set -u
cd "$(dirname "$0")"
here=$(pwd)
root=$(cd .. && pwd)
python=${PYTHON:-python3}
out=${OUT:-$(mktemp -d)}
mkdir -p "$out"
pass=0 fail=0 skip=0

guitest() {  # guitest NAME STEPS DIR GUI-ARGS...
    name=$1 steps=$2 dir=$3
    shift 3
    if (cd "$dir" && PYTHONPATH="$root/src" "$python" "$root/tools/guitest.py" "$here/$steps" \
            --out "$out/$name" -- "$@" > "$out/$name.log" 2>&1); then
        echo "pass  $name"; pass=$((pass + 1))
    else
        echo "FAIL  $name   (log: $out/$name.log)"; fail=$((fail + 1))
    fi
}
skipped() { echo "skip  $1   ($2)"; skip=$((skip + 1)); }

if [ -x heap/heapdemo ]; then guitest heap heap/heap.steps heap ./heapdemo
else skipped heap "not built: make heap"; fi

if [ -x heap/heapdemo-musl ]; then guitest heap-musl heap/heap-musl.steps heap ./heapdemo-musl
else skipped heap-musl "not built: make heap-musl (needs zig)"; fi

if [ -x threads/threads ]; then guitest threads threads/threads.steps threads ./threads
else skipped threads "not built: make threads"; fi

# --terminal-io needs a terminal to start from: check.py runs guitest in a pseudo-terminal
if [ -x curses/cursesdemo ]; then
    if PYTHONPATH="$root/src" "$python" curses/check.py "$out/curses" > "$out/curses.log" 2>&1; then
        echo "pass  curses"; pass=$((pass + 1))
    else
        echo "FAIL  curses   (log: $out/curses.log)"; fail=$((fail + 1))
    fi
else skipped curses "not built: make curses (needs libncurses-dev)"; fi

port=23990
for spec in aarch64:8:little arm:4:little mips:4:big; do
    arch=${spec%%:*}
    if [ ! -x "multiarch/hello-$arch" ]; then skipped "multiarch-$arch" "not built: make multiarch (needs zig)"; continue; fi
    if ! command -v "qemu-$arch" > /dev/null || ! command -v gdb-multiarch > /dev/null; then
        skipped "multiarch-$arch" "needs qemu-$arch and gdb-multiarch"; continue
    fi
    port=$((port + 1))
    "qemu-$arch" -g "$port" "multiarch/hello-$arch" < /dev/null > /dev/null 2>&1 &
    qemu=$!
    sleep 0.5
    EXPECT=${spec#*:} guitest "multiarch-$arch" multiarch/multiarch.steps multiarch \
        --gdb gdb-multiarch -ex "target remote :$port" "./hello-$arch"
    kill "$qemu" 2> /dev/null
    wait "$qemu" 2> /dev/null
done

echo "$pass passed, $fail failed, $skip skipped  (screenshots and logs: $out)"
[ "$fail" -eq 0 ]
