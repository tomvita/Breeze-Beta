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
MULTILINE = {"help", "watch", "probe", "holds", "maps", "refs", "chain", "xref"}
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

    def files(self):
        """The running game's folder: every file with its size, age, kind and,
        for the ones Breeze knows, what it is for. Fetch one with get_file."""
        return self.json("files")

    def get_file(self, name, local_path=None):
        """A whole file of the game folder (or any sdmc:/ path), in pieces.
        Returns the bytes, and writes them to local_path when given."""
        path = name if ":/" in name else self.files()["dir"] + name
        data = b""
        while True:
            piece, size = self.fs_get(path, len(data), 1 << 20)
            data += piece
            if not piece or len(data) >= size:
                break
        if local_path:
            with open(local_path, "wb") as f:
                f.write(data)
        return data

    def prep(self, job=None):
        """prep() lists the preparation jobs for the running game's engine, with
        the one running and how the last ended. prep("il2cpp_fields") starts one
        and returns the reply line; follow it with prep()."""
        if job is None:
            return self.json("prep")
        return self.cmd("prep %s" % job)

    def prep_wait(self, job, poll_s=5, timeout_s=1800):
        """Starts a job and waits for it. Returns its 'last' entry. A job that
        holds Breeze's UI thread is still followed: prep is answered on the
        network thread."""
        import time
        reply = self.prep(job)
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        end = time.time() + timeout_s
        while time.time() < end:
            time.sleep(poll_s)
            status = self.prep()
            if status.get("running") is None:
                return status.get("last")
        raise RuntimeError("prep %s still running after %d s" % (job, timeout_s))

    def gen2(self, *args):
        """gen2() is the watch gen2 holds; gen2("rows") adds the captured rows;
        gen2("watch", "21A4C3E144", "w", 4) starts a memory watch; gen2("stop")
        detaches. Needs Breeze's UI thread."""
        return self.json(" ".join(["gen2"] + [str(a) for a in args]))

    def fieldwatch(self, *args):
        """fieldwatch() is the field watch's state with the accessed byte runs
        and fields; fieldwatch("start", "21A4C3E000", "F0", "w") watches an
        instance; then "sweep", "stop", "clear", "mark"."""
        return self.json(" ".join(["fieldwatch"] + [str(a) for a in args]))

    def methodwatch(self, *args):
        """methodwatch() is the method watch's state and list (state, name, the
        first caller); methodwatch("start", "PlayerStats::") breaks once on every
        method whose name in the function map contains the text; then "stop",
        "clear" (start again with every method waiting)."""
        return self.json(" ".join(["methodwatch"] + [str(a) for a in args]))

    def instances(self, klass_pointer=None):
        """instances(ptr) starts Breeze's scan for the live objects of a Unity
        class (ptr is the first word of any object of it); instances() is the
        scan's state: done, progress, objects."""
        if klass_pointer is None:
            return self.json("instances")
        return self.cmd("instances %X" % klass_pointer)

    def probe(self, ms, hz, values, press=None, at_ms=0, hold_ms=100):
        """Samples several values on one clock, and can press game buttons at
        a set moment of the same run.

        values: [(addr, len), ...], up to 16, len 1 to 16.
        press:  game buttons ("B", "ZL+ZR"), pressed at at_ms for hold_ms.
        Returns [(t_ms, [bytes or None, ...]), ...].
        """
        line = "probe %d %d %s" % (ms, hz, " ".join("%X:%d" % v for v in values))
        if press:
            line += " press %s %d %d" % (press, at_ms, hold_ms)
        reply = self.cmd(line)
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        out = []
        for row in reply.split("\n")[1:]:
            parts = row.split()
            out.append((int(parts[0]), [None if x == "?" else bytes.fromhex(x) for x in parts[1:]]))
        return out

    def cheats_state(self):
        """{id: True/False} for every cheat. Keep it before a test and hand it
        to cheats_set_state afterwards: the list is then exactly as found."""
        reply = self.cmd("cheats state")
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        return {int(x.split(":")[0]): x.endswith(":on") for x in reply.split()[1:]}

    def cheats_set_state(self, state):
        """Makes each cheat in {id: True/False} on or off; others are left alone."""
        if not state:
            return "+OK"
        reply = self.cmd("cheats state " + " ".join("%d:%s" % (i, "on" if on else "off") for i, on in sorted(state.items())))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        return reply

    def xref_call(self, addr):
        """Offsets into main of every b / bl whose target is addr."""
        reply = self.cmd("xref call %X" % addr)
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        return [int(l.split()[0][2:], 16) for l in reply.split("\n")[1:]]

    def xref_insn(self, mask, value, lo=0, hi=0, limit=512):
        """(offset, word) of every instruction in main's code with
        (word & mask) == value; lo / hi limit it to that stretch of main."""
        reply = self.cmd("xref insn %X %X %X %X %d" % (mask, value, lo, hi, limit))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        out = []
        for l in reply.split("\n")[1:]:
            off, word = l.split()
            out.append((int(off[2:], 16), int(word, 16)))
        return out

    def notes(self):
        """The game folder's ai_notes.md -- what earlier sessions established --
        or '' when there is none."""
        files = self.files()
        if not any(f["name"] == "ai_notes.md" for f in files["files"]):
            return ""
        return self.get_file("ai_notes.md").decode("utf-8", "replace")

    def write_notes(self, text):
        """Replaces ai_notes.md in the game folder. Write what the next session
        needs: the route to the player, layouts, controls, what failed."""
        return self.fs_put(self.files()["dir"] + "ai_notes.md", 0, text.encode("utf-8"))

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
