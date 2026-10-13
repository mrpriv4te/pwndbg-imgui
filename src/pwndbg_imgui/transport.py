"""GUI side plumbing: RPC client over the socketpair, and PTYs."""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
import time

from . import APP_NAME
from .term import Term
import socket


class Rpc:
    def __init__(self, sock: socket.socket) -> None:
        import queue

        self.sock = sock
        self.inbox: "queue.Queue[dict]" = queue.Queue()
        self.callbacks: dict[int, tuple] = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.connected = True
        threading.Thread(target=self._reader, name="rpc-reader", daemon=True).start()

    def _reader(self) -> None:
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(1 << 20)
            except OSError:
                chunk = b""
            if not chunk:
                self.connected = False
                self.inbox.put({"ev": "disconnected"})
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    self.inbox.put(json.loads(line))
                except ValueError:
                    pass

    def request(self, op: str, cb=None, err=None, **args) -> None:
        with self.lock:
            rid = self.next_id
            self.next_id += 1
            self.callbacks[rid] = (cb, err)
        data = (json.dumps({"id": rid, "op": op, "args": args}) + "\n").encode()
        try:
            self.sock.sendall(data)
        except OSError:
            self.callbacks.pop(rid, None)

    def resolve(self, msg: dict) -> None:
        cb, err = self.callbacks.pop(msg["id"], (None, None))
        if msg.get("ok"):
            if cb:
                cb(msg.get("res"))
        elif err:
            err(msg.get("err", "error"))


class Pty:
    """A pseudo-terminal whose output is decoded into a Term by a reader thread."""

    def __init__(self, term: Term, raw: bool = False, keep_bytes: int = 0) -> None:
        import pty
        import tty

        self.term = term
        self.master, self.slave = pty.openpty()
        self.path = os.ttyname(self.slave)
        if raw:
            tty.setraw(self.slave)
        self.raw = raw
        self.keep_bytes = keep_bytes
        self.raw_bytes = bytearray()
        self.bytes_version = 0
        self.size = (0, 0)
        import codecs

        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="surrogateescape")
        threading.Thread(target=self._reader, name=f"pty-{self.path}", daemon=True).start()

    def _reader(self) -> None:
        import select

        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.5)
                if not ready:
                    continue
                data = os.read(self.master, 1 << 16)
            except OSError:
                return
            if not data:
                return
            try:
                if self.keep_bytes:
                    with self.term.lock:
                        self.raw_bytes += data
                        if len(self.raw_bytes) > self.keep_bytes:
                            del self.raw_bytes[: len(self.raw_bytes) - self.keep_bytes]
                        self.bytes_version += 1
                self.term.feed(self.decoder.decode(data))
            except Exception as e:  # keep draining the PTY whatever happens
                sys.stderr.write(f"{APP_NAME}: terminal error: {e!r}\n")
                self.term.pending = ""

    def write(self, data: bytes) -> None:
        while data:
            try:
                n = os.write(self.master, data)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                return
            data = data[n:]

    def set_raw(self, raw: bool) -> None:
        import termios
        import tty

        if raw:
            tty.setraw(self.slave)
        else:
            attrs = termios.tcgetattr(self.slave)
            attrs[0] |= termios.ICRNL
            attrs[1] |= termios.OPOST | termios.ONLCR
            attrs[3] |= termios.ICANON | termios.ISIG | termios.IEXTEN
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.raw = raw

    def resize(self, rows: int, cols: int) -> None:
        import fcntl
        import termios

        if (rows, cols) == self.size or rows <= 0 or cols <= 0:
            return
        self.size = (rows, cols)
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass
