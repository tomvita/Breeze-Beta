#!/usr/bin/env python3
"""Client for Breeze PC connect (Settings > PC connect). See pcconnect.md.

Interactive:   python pcconnect.py 192.168.1.65 1234
One command:   python pcconnect.py 192.168.1.65 1234 state
Library:       from pcconnect import Breeze; b = Breeze(ip, code); b.state()
"""
import json
import socket
import sys

PORT = 6801
# Replies that continue past the first line until a lone '.'.
MULTILINE = {"help", "watch", "holds", "maps", "refs", "chain"}
# Replies whose header line is followed by raw bytes (bytes=<n>).
BINARY = {"tail", "capture", "saveshot", "fsget"}


class Breeze:
    def __init__(self, host, code=None, port=PORT, timeout=15):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.events = []
        self.banner = self._line()
        if code is not None:
            reply = self.cmd("auth %s" % code)
            if not reply.startswith("+OK"):
                raise RuntimeError(reply)

    def _line(self):
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1:]
                text = line.decode("utf-8", "replace")
                if text.startswith("*EVENT "):
                    self.events.append(text)
                    continue
                return text
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("Breeze closed the connection")
            self.buf += chunk

    def _raw(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("Breeze closed the connection")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def cmd(self, line):
        """Sends one command. Returns the reply text; for tail/capture returns
        (header, bytes); for multi-line replies the lines joined with newlines."""
        self.sock.sendall((line + "\n").encode())
        name = line.split(" ", 1)[0].lower()
        first = self._line()
        if not first.startswith("+OK"):
            return first
        if name in BINARY:
            n = int(first.split("bytes=")[1].split()[0])
            return first, self._raw(n)
        words = line.strip().lower().split()
        if name in MULTILINE or words == ["cheats"] or words[:2] == ["cheats", "get"]:
            lines = [first]
            while True:
                l = self._line()
                if l == ".":
                    break
                lines.append(l)
            return "\n".join(lines)
        return first

    def json(self, line):
        reply = self.cmd(line)
        if not reply.startswith("+OK "):
            raise RuntimeError(reply)
        return json.loads(reply[4:])

    def state(self, rows=60):
        return self.json("state %d" % rows)

    def peek(self, addr, n):
        reply = self.cmd("peek %x %d" % (addr, n))
        if not reply.startswith("+OK "):
            raise RuntimeError(reply)
        return bytes.fromhex(reply[4:])

    def cheats_add(self, text, on=False):
        """Adds cheats written as in a cheat file ([name] then words; line
        breaks are fine). Returns the new ids. Breeze's Cheats screen is
        refreshed in the same step."""
        flat = " ".join(text.split())
        reply = self.cmd("cheats add %s%s" % ("on " if on else "", flat))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        return [int(x) for x in reply.split("ids=")[1].split()]

    def cheats_get(self, *ids):
        """[(id, enabled, "[name] words...")]"""
        reply = self.cmd("cheats get %s" % " ".join(str(i) for i in ids))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        out = []
        for l in reply.split("\n")[1:]:
            i, state, text = l.split(" ", 2)
            out.append((int(i), state == "on", text))
        return out

    def refs(self, addr, rng=0, max_hits=64, seconds=30):
        """Who points at addr (or up to rng bytes below it). addr: int or 'main+X'."""
        a = addr if isinstance(addr, str) else "%x" % addr
        reply = self.cmd("refs %s %x %d %d" % (a, rng, max_hits, seconds))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        lines = reply.split("\n")
        return lines[0], lines[1:]

    def chain(self, base, *offsets):
        """chain('main+6DDAF60', 0xB8, 0, '+58'): the cheat VM's walk, every hop."""
        offs = " ".join(o if isinstance(o, str) else "%x" % o for o in offsets)
        reply = self.cmd("chain %s %s" % (base, offs))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        return reply.split("\n")

    # ---- files (see pcconnect.md, "Files")
    FILE_PIECE = 1 << 20

    def fs_roots(self):
        return self.json("fs roots")["roots"]

    def fs_ls(self, path):
        """[(name, is_dir, size)], folders first."""
        return [(n, bool(d), s) for n, d, s in self.json("fs ls " + path)["entries"]]

    def fs_do(self, line):
        reply = self.cmd("fs " + line)
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)

    def fs_get(self, path, offset, n):
        """(bytes, whole file size)"""
        reply = self.cmd("fsget %d %d %s" % (offset, n, path))
        if not isinstance(reply, tuple):
            raise RuntimeError(reply)
        return reply[1], int(reply[0].split("size=")[1].split()[0])

    def fs_put(self, path, offset, data):
        self.sock.sendall(("fsput %d %d %s\n" % (offset, len(data), path)).encode() + data)
        reply = self._line()
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)

    def watch(self, addr, n, hz, ms):
        reply = self.cmd("watch %x %d %d %d" % (addr, n, hz, ms))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        lines = reply.split("\n")
        return lines[0], [bytes.fromhex(l) for l in lines[1:]]


def show_state(s):
    m = s.get("menu", {})
    print("Breeze %s  overlay=%s  menu=%s id=%s" % (s.get("breeze"), s.get("overlay"), m.get("kind"), m.get("menu_id")))
    for key in ("left_title", "left_status", "right_title", "right_status", "text", "subtext", "context_help"):
        if m.get(key):
            print("  %-13s %s" % (key, m[key]))
    if "rows" in m:
        start = m.get("rows_start", 0)
        print("  rows %d, cursor %s" % (m.get("row_count", 0), m.get("index")))
        for i, r in enumerate(m["rows"]):
            mark = ">" if start + i == m.get("index") else " "
            print("  %s%4d %s" % (mark, start + i, r))
    for b in m.get("buttons", []):
        mark = "*" if b["selected"] else " "
        print("  %s[%2d] %s%s" % (mark, b["id"], b["text"], "" if b["enabled"] else "  (disabled)"))
    if "keyboard" in s:
        print("  keyboard: %s | %s | %r" % (s["keyboard"]["header"], s["keyboard"]["subheader"], s["keyboard"]["text"]))
    if s.get("game", {}).get("attached"):
        g = s["game"]
        print("  game %s main %s heap %s" % (g.get("title_id"), g.get("main"), g.get("heap")))


def run(b, line):
    name = line.split(" ", 1)[0].lower()
    reply = b.cmd(line)
    if isinstance(reply, tuple):
        header, data = reply
        print(header)
        if name == "capture":
            out = "capture.raw" if " raw " in header else "capture.jpg"
            with open(out, "wb") as f:
                f.write(data)
            print("saved " + out)
        else:
            sys.stdout.write(data.decode("utf-8", "replace"))
            print()
    elif name == "state" and reply.startswith("+OK "):
        show_state(json.loads(reply[4:]))
    else:
        print(reply)
    for e in b.events:
        print(e[:300])
    b.events.clear()


def main():
    # Button labels carry Switch button glyphs (private-use code points).
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return
    b = Breeze(sys.argv[1], sys.argv[2])
    print(b.banner)
    if len(sys.argv) > 3:
        run(b, " ".join(sys.argv[3:]))
        return
    while True:
        try:
            line = input("breeze> ").strip()
        except EOFError:
            break
        if not line:
            continue
        run(b, line)
        if line == "quit":
            break


if __name__ == "__main__":
    main()
