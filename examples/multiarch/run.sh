#!/bin/sh
# Start hello-ARCH under qemu-user's gdbserver and open pwndbg-imgui attached to it.
#   ./run.sh aarch64|arm|mips [pwndbg-imgui options]
# The program's input/output stay in this terminal (qemu's), not in the GUI.
# PORT (default 1234), GDB (default gdb-multiarch) and PWNDBG_IMGUI override the defaults.
set -eu
arch=${1:?usage: ./run.sh aarch64|arm|mips [pwndbg-imgui options]}
shift
cd "$(dirname "$0")"
bin=./hello-$arch
[ -x "$bin" ] || { echo "$bin not built: run 'make multiarch' in examples/" >&2; exit 1; }
port=${PORT:-1234}

# the program's stdin is this terminal: a background job would get /dev/null (and dash
# ignores `<&0`), so hand it over through another descriptor
exec 3<&0
qemu-"$arch" -g "$port" "$bin" <&3 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true' EXIT
${PWNDBG_IMGUI:-pwndbg-imgui} --gdb "${GDB:-gdb-multiarch}" -ex "target remote :$port" "$@" "$bin"
