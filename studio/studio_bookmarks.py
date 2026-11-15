"""Bookmarks and stat views over PC connect: a generic viewer, the game in a text file.

    python studio_bookmarks.py [host=127.0.0.1] [code=1234] [port=6801] [--file views.txt]

Works with the emulator's PC connect and with Breeze's on a Switch (it uses only peek, poke,
hold, unhold, freeze, resume, meta and cheats add; peekb when the other side has it).

The game file (views/<title id>.txt next to this script, or --file) says where things are:

    title 04007EF01F8AE000           the game it is for (checked against the running one)
    build DB93B0125F485060           optional: main offsets are only right for one build

    root units = [[main+220A350]+38] a named address; [x] reads the pointer at x
    struct Unit 8B0                  a record and its size (hex)
        1EC s16 HP                   offset (hex), type, name, then flags:
        874 u32 Side enum 0=Enemy,1=Yours     hex  hide  ro  enum v=name,v=name
    table Party units Unit 250 where OnMap==1 Side==1
                                     count records from the root, filtered by fields
    group Money                      plain bookmarks:
        Gold = [main+1234]+40 u32

Expressions: main heap alias aslr, hex numbers, root names, + and -, [ ] to follow a pointer;
no spaces inside one. Types: u8 s8 u16 s16 u32 s32 u64 s64 f32 f64 ptr.

In a view: double-click a value to change it; right-click for Hold / Unhold (dmnt's frozen
addresses), Make cheat (adds a cheat, off, that writes the value through the pointer chain),
Copy address, Copy expression.
"""
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from studio_search import Client  # noqa: E402
from game_title import window_title  # noqa: E402

TYPES = {  # name: (struct format, size)
    "u8": ("<B", 1), "s8": ("<b", 1), "u16": ("<H", 2), "s16": ("<h", 2),
    "u32": ("<I", 4), "s32": ("<i", 4), "u64": ("<Q", 8), "s64": ("<q", 8),
    "f32": ("<f", 4), "f64": ("<d", 8), "ptr": ("<Q", 8),
}
REGIONS = {"main": 0, "heap": 1, "alias": 2, "aslr": 3}


# ---- expressions -----------------------------------------------------------------------------

class Expr:
    """('num', n) ('region', name) ('root', name) ('add', a, b) ('sub', a, b) ('deref', a)"""

    def __init__(self, node):
        self.node = node


def parse_expr(text):
    toks = re.findall(r"\[|\]|\+|-|[A-Za-z_][A-Za-z0-9_]*|(?:0x)?[0-9A-Fa-f]+", text)
    if "".join(toks) != text.replace(" ", ""):
        raise ValueError("cannot read %r" % text)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def term():
        t = take() if peek() is not None else None
        if t is None:
            raise ValueError("%r ends too soon" % text)
        if t == "[":
            e = expr()
            if take() != "]":
                raise ValueError("%r: a [ is not closed" % text)
            return ("deref", e)
        if t in REGIONS:
            return ("region", t)
        if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", t) and not (t[0].isalpha() and not re.fullmatch(r"[0-9A-Fa-f]+", t)):
            if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", t):
                return ("num", int(t, 16))
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t):
            return ("root", t)
        raise ValueError("%r: unexpected %r" % (text, t))

    def expr():
        e = term()
        while peek() in ("+", "-"):
            op = take()
            e = ("add" if op == "+" else "sub", e, term())
        return e

    e = expr()
    if pos[0] != len(toks):
        raise ValueError("%r: unexpected %r" % (text, toks[pos[0]]))
    return e


def add_offset(node, off):
    return node if off == 0 else ("add", node, ("num", off))


def expr_text(node):
    k = node[0]
    if k == "num":
        return "%X" % node[1]
    if k in ("region", "root"):
        return node[1]
    if k == "deref":
        return "[%s]" % expr_text(node[1])
    return "%s%s%s" % (expr_text(node[1]), "+" if k == "add" else "-", expr_text(node[2]))


# ---- Breeze's own bookmarks ------------------------------------------------------------------

BMK_TYPES = ["u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "f32", "f64", "ptr", "u64"]
BMK_REGIONS = ["main", "heap", "alias", "aslr"]


def bmk_items(data):
    """The records of a Breeze .bmk file as (label, expression text, type). A record is a label,
    a type and a pointer chain from a region's base: 184 bytes with 16 offsets (BREEZE00F), 160
    with 13 before that."""
    at = data.find(b"HEADER@\0")
    if at < 0:
        return []
    body = data[at + 8:]
    size, slots = (184, 16) if data[:9] == b"BREEZE00F" or len(body) % 184 == 0 else (160, 13)
    out = []
    for i in range(0, len(body) - size + 1, size):
        rec = body[i:i + size]
        label = rec[:19].split(b"\0")[0].decode("utf-8", "replace").strip() or "#%d" % (i // size)
        type_, = struct.unpack_from("<I", rec, 20)
        depth, = struct.unpack_from("<Q", rec, 24)
        offsets = struct.unpack_from("<%dq" % slots, rec, 32)
        tail = 32 + 8 * slots
        heap, = struct.unpack_from("<I", rec, tail)
        from_main, deleted = rec[tail + 4] != 0, rec[tail + 16] != 0
        if deleted or depth >= slots or heap >= len(BMK_REGIONS) or type_ >= len(BMK_TYPES):
            continue
        order = offsets[:depth + 1] if from_main else offsets[depth::-1]
        text = BMK_REGIONS[heap]
        for n, off in enumerate(order):
            text += ("+%X" % off) if off >= 0 else ("-%X" % -off)
            if n < depth:
                text = "[%s]" % text
        out.append((label, text, BMK_TYPES[type_]))
    return out


def unique(label, group):
    """Breeze lets several bookmarks share a label; a view's rows go by name."""
    names = {n for n, _e, _f in group.items}
    out, n = label, 2
    while out in names:
        out, n = "%s (%d)" % (label, n), n + 1
    return out


def chain_of(node, roots):
    """An expression as Breeze's bookmark has it: (region, [offsets, the region's first]); None
    when it is not a plain pointer chain."""
    k = node[0]
    if k == "region":
        return node[1], [0]
    if k == "root":
        return chain_of(roots[node[1]], roots) if node[1] in roots else None
    if k in ("add", "sub") and node[2][0] == "num":
        c = chain_of(node[1], roots)
        if c is not None:
            c[1][-1] += node[2][1] if k == "add" else -node[2][1]
        return c
    if k == "deref":
        c = chain_of(node[1], roots)
        if c is not None:
            c[1].append(0)
        return c
    return None


# ---- the game file -------------------------------------------------------------------------

class Field:
    def __init__(self, off, typ, name, flags):
        self.off, self.type, self.name = off, typ, name
        self.hex = "hex" in flags or typ == "ptr"
        self.hide = "hide" in flags
        self.ro = "ro" in flags
        self.enum = {}
        if "enum" in flags:
            spec = flags[flags.index("enum") + 1] if flags.index("enum") + 1 < len(flags) else ""
            for part in spec.split(","):
                if "=" in part:
                    v, n = part.split("=", 1)
                    self.enum[int(v, 0)] = n

    @property
    def size(self):
        return TYPES[self.type][1]


class Struct:
    def __init__(self, name, size):
        self.name, self.size, self.fields = name, size, []

    def field(self, name):
        for f in self.fields:
            if f.name == name:
                return f
        return None


class Table:
    def __init__(self, name, base, struct_, count, where):
        self.name, self.base, self.struct, self.count, self.where = name, base, struct_, count, where


class Group:
    def __init__(self, name):
        self.name, self.items = name, []  # (name, expr node, Field)


class GameFile:
    def __init__(self):
        self.title = self.build = None
        self.roots, self.structs, self.views = {}, {}, []
        self.path = None

    @staticmethod
    def load(path):
        g = GameFile()
        g.path = path
        cur = None
        for n, raw in enumerate(open(path, encoding="utf-8"), 1):
            line = re.split(r"\s[#;]|^[#;]", raw.rstrip("\n"), maxsplit=1)[0].rstrip()
            if not line.strip():
                continue
            indented = line[0] in " \t"
            w = line.split()
            try:
                if indented:
                    if isinstance(cur, Struct):
                        if w[1] not in TYPES:
                            raise ValueError("unknown type %s" % w[1])
                        cur.fields.append(Field(int(w[0], 16), w[1], w[2], w[3:]))
                    elif isinstance(cur, Group):
                        # Name = expr type [flags]
                        m = re.match(r"\s*(.+?)\s*=\s*(\S+)\s+(\S+)\s*(.*)$", line)
                        if not m or m.group(3) not in TYPES:
                            raise ValueError("expected: name = expression type [flags]")
                        f = Field(0, m.group(3), m.group(1), m.group(4).split())
                        cur.items.append((m.group(1), parse_expr(m.group(2)), f))
                    else:
                        raise ValueError("an indented line outside a struct or group")
                    continue
                cur = None
                if w[0] == "title":
                    g.title = w[1].upper()
                elif w[0] == "build":
                    g.build = w[1].upper()
                elif w[0] == "root":
                    m = re.match(r"root\s+(\w+)\s*=\s*(\S+)\s*$", line)
                    if not m:
                        raise ValueError("expected: root name = expression")
                    g.roots[m.group(1)] = parse_expr(m.group(2))
                elif w[0] == "struct":
                    cur = Struct(w[1], int(w[2], 16))
                    g.structs[w[1]] = cur
                elif w[0] == "table":
                    if w[3] not in g.structs:
                        raise ValueError("no struct %s above this line" % w[3])
                    where = []
                    if len(w) > 5 and w[5] == "where":
                        for c in w[6:]:
                            m = re.match(r"(\w+)(==|!=|>=|<=|>|<)(-?(?:0x)?[0-9A-Fa-f]+)$", c)
                            if not m:
                                raise ValueError("cannot read the condition %s" % c)
                            where.append((m.group(1), m.group(2), int(m.group(3), 0)))
                    g.views.append(Table(w[1], parse_expr(w[2]), g.structs[w[3]], int(w[4], 0), where))
                elif w[0] == "group":
                    cur = Group(" ".join(w[1:]))
                    g.views.append(cur)
                else:
                    raise ValueError("unknown line")
            except (ValueError, IndexError) as e:
                raise ValueError("%s line %d: %s" % (os.path.basename(path), n, e))
        for t in g.views:
            if isinstance(t, Table):
                for name, _, _ in t.where:
                    if t.struct.field(name) is None:
                        raise ValueError("table %s: %s is not a field of %s" % (t.name, name, t.struct.name))
        return g

    def inline(self, node, depth=0):
        """The expression with root names replaced by their expressions."""
        if depth > 20:
            raise ValueError("roots refer to each other in a circle")
        k = node[0]
        if k == "root":
            if node[1] not in self.roots:
                raise ValueError("no root named %s" % node[1])
            return self.inline(self.roots[node[1]], depth + 1)
        if k == "deref":
            return ("deref", self.inline(node[1], depth))
        if k in ("add", "sub"):
            return (k, self.inline(node[1], depth), self.inline(node[2], depth))
        return node


# ---- reading the game --------------------------------------------------------------------------

class Game:
    def __init__(self, client):
        self.c = client
        self.has_peekb = True
        self.meta = {}

    def refresh_meta(self):
        r = self.c.cmd("meta")
        if not r.startswith("+OK"):
            raise RuntimeError(r)
        self.meta = json.loads(r[4:])
        self.bases = {k: int(self.meta[k], 16) for k in REGIONS if k in self.meta}

    def read(self, addr, n):
        """Bytes at addr, or None. peekb in one go where it exists, else 4096-byte peeks."""
        if n <= 0:
            return b""
        if self.has_peekb:
            with self.c.lock:
                self.c.sock.sendall(("peekb %X %d\n" % (addr, n)).encode())
                hdr = self.c._line()
                if hdr.startswith("+OK"):
                    want = int(hdr.split("bytes=")[1].split()[0])
                    while len(self.c.buf) < want:
                        d = self.c.sock.recv(1 << 20)
                        if not d:
                            raise ConnectionError("PC connect closed the connection")
                        self.c.buf += d
                    out, self.c.buf = self.c.buf[:want], self.c.buf[want:]
                    return out if len(out) == n else None
            if "unknown" in hdr.lower() or "usage" in hdr.lower():
                self.has_peekb = False
            else:
                return None
        out = b""
        while len(out) < n:
            k = min(4096, n - len(out))
            r = self.c.cmd("peek %X %d" % (addr + len(out), k))
            if not r.startswith("+OK"):
                return None
            out += bytes.fromhex(r[4:].strip())
        return out

    def eval(self, node):
        k = node[0]
        if k == "num":
            return node[1]
        if k == "region":
            return self.bases.get(node[1])
        if k in ("add", "sub"):
            a, b = self.eval(node[1]), self.eval(node[2])
            if a is None or b is None:
                return None
            return (a + b if k == "add" else a - b) & 0xFFFFFFFFFFFFFFFF
        if k == "deref":
            a = self.eval(node[1])
            if not a:
                return None
            d = self.read(a, 8)
            return struct.unpack("<Q", d)[0] if d else None
        raise ValueError(node)


def decode(field, data, at):
    fmt, size = TYPES[field.type]
    if data is None or at + size > len(data):
        return None
    return struct.unpack_from(fmt, data, at)[0]


def show(field, v):
    if v is None:
        return "?"
    if field.enum and v in field.enum:
        return "%s (%d)" % (field.enum[v], v)
    if field.type in ("f32", "f64"):
        return "%.6g" % v
    if field.hex:
        return "%X" % v
    return str(v)


def encode(field, text):
    """The value as bytes, from what a person typed (dec, 0x hex, an enum name, a float)."""
    fmt, _ = TYPES[field.type]
    t = text.strip()
    for v, n in field.enum.items():
        if t.lower() == n.lower():
            return struct.pack(fmt, v)
    if field.type in ("f32", "f64"):
        return struct.pack(fmt, float(t))
    v = int(t, 16) if field.hex and not t.lower().startswith("0x") else int(t, 0)
    if field.type.startswith("u") or field.type == "ptr":
        v &= (1 << (8 * TYPES[field.type][1])) - 1
    return struct.pack(fmt, v)


def passes(where, struct_, data, at):
    ops = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b, ">": lambda a, b: a > b,
           "<": lambda a, b: a < b, ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b}
    for name, op, val in where:
        v = decode(struct_.field(name), data, at + struct_.field(name).off)
        if v is None or not ops[op](v, val):
            return False
    return True


# ---- cheats from a pointer chain ---------------------------------------------------------------

def cheat_code(node, field, raw):
    """dmnt words writing raw (bytes of field's type) at the address node names.

    Static addresses use one type 0 store; a chain loads R15 through it (type 5), adds the last
    offset (type 7) and stores through R15 (type 6). Returns the words, or raises ValueError."""
    width = TYPES[field.type][1]
    value = int.from_bytes(raw, "little")

    def static(n):
        """(region, offset) when n needs no pointer read."""
        k = n[0]
        if k == "region":
            return (REGIONS[n[1]], 0)
        if k == "num":
            return None
        if k in ("add", "sub") and n[2][0] == "num":
            s = static(n[1])
            if s is not None:
                return (s[0], s[1] + n[2][1] if k == "add" else s[1] - n[2][1])
        return None

    words = []

    def load(n):
        """Leaves the address n names in R15, plus an offset still to add; returns that offset."""
        k = n[0]
        if k in ("add", "sub") and n[2][0] == "num":
            off = load(n[1])
            return off + n[2][1] if k == "add" else off - n[2][1]
        if k == "deref":
            s = static(n[1])
            if s is not None:
                region, off = s
                words.extend([0x58000000 | (region << 20) | (0xF << 16) | ((off >> 32) & 0xFF),
                              off & 0xFFFFFFFF])
                return 0
            off = load(n[1])
            words.extend([0x580F1000 | ((off >> 32) & 0xFF), off & 0xFFFFFFFF])
            return 0
        raise ValueError("this address cannot be written as a cheat (%s)" % expr_text(n))

    s = static(node)
    if s is not None:
        region, off = s
        words = [(width << 24) | (region << 20) | ((off >> 32) & 0xFF), off & 0xFFFFFFFF]
        words += [value & 0xFFFFFFFF] if width < 8 else [value >> 32, value & 0xFFFFFFFF]
        return words
    off = load(node)
    if off:
        if not 0 <= off <= 0xFFFFFFFF:
            raise ValueError("offset %X out of range" % off)
        words.extend([0x780F0000, off])
    words.extend([0x600F0000 | (width << 24), value >> 32, value & 0xFFFFFFFF])
    return words


# ---- the window --------------------------------------------------------------------------------

class App:
    def __init__(self, root, client, path):
        self.root, self.game = root, Game(client)
        self.c = client
        self.gf = None
        self.path = path
        self.results = queue.Queue()
        self.rows = {}        # view name: list of row infos
        self.trees = {}
        self.interval = tk.DoubleVar(value=0.5)
        self.paused_reads = False
        self.stop = False

        root.title("Bookmarks")
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=4, pady=4)
        ttk.Button(bar, text="Open file...", command=self.open_file).pack(side="left")
        ttk.Button(bar, text="Reload", command=self.reload).pack(side="left", padx=2)
        ttk.Button(bar, text="Edit file", command=self.edit_file).pack(side="left")
        ttk.Button(bar, text="Add bookmark...", command=self.add_bookmark).pack(side="left", padx=8)
        self.pause_btn = ttk.Button(bar, text="Pause game", command=self.toggle_pause)
        self.pause_btn.pack(side="right")
        ttk.Label(bar, text="refresh s").pack(side="right", padx=(8, 2))
        ttk.Spinbox(bar, from_=0.1, to=10, increment=0.1, width=5,
                    textvariable=self.interval).pack(side="right")
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True, padx=4)
        self.status = tk.StringVar()
        ttk.Label(root, textvariable=self.status, anchor="w").pack(fill="x", padx=4, pady=2)

        self.menu = tk.Menu(root, tearoff=0)
        self.menu.add_command(label="Edit value...", command=lambda: self.on_edit(None))
        self.menu.add_command(label="Hold at its value", command=self.on_hold)
        self.menu.add_command(label="Unhold", command=self.on_unhold)
        self.menu.add_command(label="Make cheat...", command=self.on_make_cheat)
        self.menu.add_command(label="Add to Breeze's bookmarks (a Switch)", command=self.on_to_breeze)
        self.menu.add_separator()
        self.menu.add_command(label="Copy address", command=lambda: self.on_copy(False))
        self.menu.add_command(label="Copy expression", command=lambda: self.on_copy(True))
        self.ctx = None  # (view, row index, field) the menu is for

        self.reload()
        threading.Thread(target=self.reader, daemon=True).start()
        root.after(100, self.drain)
        root.protocol("WM_DELETE_WINDOW", self.close)

    # -- the file
    def default_path(self):
        try:
            self.game.refresh_meta()
            tid = self.game.meta.get("title_id", "")
            return os.path.join(HERE, "views", "%s.txt" % tid.upper())
        except Exception:
            return None

    def reload(self):
        if not self.path:
            self.path = self.default_path()
        note = ""
        if not self.path or not os.path.exists(self.path):
            gf = GameFile()
            note = "No game file %s (Open file..., or make one: see the top of this tool's file)" % (self.path or "")
        else:
            try:
                gf = GameFile.load(self.path)
            except (ValueError, OSError) as e:
                messagebox.showerror("Bookmarks", str(e))
                return
            note = "Loaded %s" % self.path
        note += self.add_breeze_bookmarks(gf)
        self.gf = gf
        self.build_tabs()
        self.status.set(note)

    def add_breeze_bookmarks(self, gf):
        """Breeze's bookmark files for the running build, each as a view. Returns what to say."""
        # A Switch: through Breeze, which keeps the file open (`bookmark list`).
        try:
            reply = self.c.cmd("bookmark list")
        except Exception as e:  # noqa: BLE001
            return "  |  Breeze's bookmarks not read: %s" % str(e)[:80]
        if reply.startswith("+OK"):
            group = Group("Breeze")
            for x in json.loads(reply[4:]).get("bookmarks", []):
                if x.get("deleted") or x.get("region") not in REGIONS:
                    continue
                text = x["region"]
                for n, off in enumerate(x["offsets"]):
                    text += off if off.startswith("-") else "+" + off
                    if n < len(x["offsets"]) - 1:
                        text = "[%s]" % text
                type_ = x["type"] if x["type"] in TYPES else "u64"
                label = unique(x["label"], group)
                group.items.append((label, parse_expr(text), Field(0, type_, label, [])))
            if group.items:
                gf.views.append(group)
            return "  |  %d of Breeze's bookmarks" % len(group.items)
        # Another host: the file, where there is one (Breeze run inside the Lichii fork writes it).
        try:
            sys.path.insert(0, os.path.join(HERE, ".."))
            from pcconnect import Breeze
            b = Breeze("%s:%d" % (self.c.host, self.c.port), self.c.code, timeout=30, connect_timeout=5)
            try:
                files = b.files()
                bid = files.get("build_id", "").upper()[:16]
                names = sorted(f["name"] for f in files.get("files", [])
                               if f["name"].endswith(".bmk") and f["name"].upper().startswith(bid) and bid)
                count = 0
                for name in names:
                    group = Group("Breeze " + name[16:-4].strip("()") if name[16:-4] else "Breeze")
                    for label, text, type_ in bmk_items(b.get_file(files.get("dir", "") + name)):
                        label = unique(label, group)
                        group.items.append((label, parse_expr(text), Field(0, type_, label, [])))
                    if group.items:
                        gf.views.append(group)
                        count += len(group.items)
                return "  |  %d of Breeze's bookmarks (%s)" % (count, ", ".join(names)) if names else "  |  no Breeze bookmark file for this build"
            finally:
                b.close()
        except Exception as e:  # noqa: BLE001 - the host has no `files`, or the file is not there
            return "  |  Breeze's bookmarks not read: %s" % str(e)[:80]

    def on_to_breeze(self):
        """The row as one more record of Breeze's bookmark file (a Switch: `bookmark add`)."""
        view, row, f = self.ctx
        addr, node, f = self.target()
        chain = chain_of(node, self.gf.roots)
        if chain is None:
            self.status.set("not a plain pointer chain: Breeze's bookmarks cannot hold it")
            return
        who = (row.get("name") or f.name or "PC")[:18]
        line = "bookmark add %s %s %s %s" % (f.type, chain[0], ",".join(
            ("%X" % o) if o >= 0 else ("-%X" % -o) for o in chain[1]), who)
        self.status.set("%s  ->  %s" % (line, self.c.cmd(line)))

    def open_file(self):
        p = filedialog.askopenfilename(initialdir=os.path.join(HERE, "views"),
                                       filetypes=[("Game files", "*.txt"), ("All", "*.*")])
        if p:
            self.path = p
            self.reload()

    def edit_file(self):
        if self.path and os.path.exists(self.path):
            os.startfile(self.path) if hasattr(os, "startfile") else None

    def add_bookmark(self):
        if not self.path:
            return
        name = simpledialog.askstring("Add bookmark", "Name:", parent=self.root)
        if not name:
            return
        expr = simpledialog.askstring("Add bookmark", "Address (e.g. main+1234, [main+1234]+40, "
                                      "or a hex address):", parent=self.root)
        if not expr:
            return
        typ = simpledialog.askstring("Add bookmark", "Type (%s):" % " ".join(TYPES),
                                     initialvalue="u32", parent=self.root)
        if typ not in TYPES:
            return
        try:
            parse_expr(expr)
        except ValueError as e:
            messagebox.showerror("Bookmarks", str(e))
            return
        text = open(self.path, encoding="utf-8").read() if os.path.exists(self.path) else ""
        if not re.search(r"^group Bookmarks\s*$", text, re.M):
            text = text.rstrip("\n") + "\n\ngroup Bookmarks\n"
        # Append under the Bookmarks group (at its end).
        lines = text.split("\n")
        at = next(i for i, l in enumerate(lines) if re.match(r"group Bookmarks\s*$", l)) + 1
        while at < len(lines) and lines[at][:1] in (" ", "\t"):
            at += 1
        lines.insert(at, "    %s = %s %s" % (name, expr.replace(" ", ""), typ))
        open(self.path, "w", encoding="utf-8").write("\n".join(lines).rstrip("\n") + "\n")
        self.reload()

    def build_tabs(self):
        for t in self.tabs.tabs():
            self.tabs.forget(t)
        self.trees.clear()
        for v in self.gf.views:
            frame = ttk.Frame(self.tabs)
            if isinstance(v, Table):
                cols = ["#", "address"] + [f.name for f in v.struct.fields if not f.hide]
            else:
                cols = ["name", "address", "value", "type"]
            tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
            for c in cols:
                tree.heading(c, text=c)
                tree.column(c, width=60 if c == "#" else (130 if c in ("address", "name") else 90),
                            anchor="w" if c in ("name", "address") else "e", stretch=False)
            sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=sb.set)
            tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            tree.bind("<Double-1>", lambda e, v=v, t=tree: self.on_click(e, v, t, edit=True))
            tree.bind("<Button-3>", lambda e, v=v, t=tree: self.on_click(e, v, t, edit=False))
            self.tabs.add(frame, text=v.name)
            self.trees[v.name] = (v, tree, cols)

    # -- reading, on a thread
    def reader(self):
        while not self.stop:
            t0 = time.time()
            gf = self.gf
            if gf is not None:
                try:
                    self.results.put(("data", gf, self.read_all(gf)))
                except (OSError, ConnectionError, RuntimeError, ValueError) as e:
                    self.results.put(("error", gf, str(e)))
            time.sleep(max(0.05, float(self.interval.get() or 0.5) - (time.time() - t0)))

    def read_all(self, gf):
        g = self.game
        g.refresh_meta()
        out = {}
        for v in gf.views:
            rows = []
            if isinstance(v, Table):
                node = gf.inline(v.base)
                base = g.eval(node)
                if base:
                    st = v.struct
                    span = v.count * st.size
                    data = g.read(base, span) if g.has_peekb else None
                    for i in range(v.count):
                        if data is not None:
                            rec, at = data, i * st.size
                        else:  # one record at a time from the first field to the last
                            lo = min(f.off for f in st.fields)
                            hi = max(f.off + f.size for f in st.fields)
                            part = g.read(base + i * st.size + lo, hi - lo)
                            rec, at = (b"\0" * lo + part if part else None), 0
                        if rec is None or not passes(v.where, st, rec, at):
                            continue
                        rows.append({"index": i, "addr": base + i * st.size,
                                     "node": add_offset(node, i * st.size),
                                     "values": [decode(f, rec, at + f.off) for f in st.fields]})
            else:
                for name, node0, f in v.items:
                    node = gf.inline(node0)
                    a = g.eval(node)
                    d = g.read(a, f.size) if a else None
                    rows.append({"name": name, "addr": a, "node": node, "field": f,
                                 "values": [decode(f, d, 0)]})
            out[v.name] = rows
        return out

    def drain(self):
        try:
            while True:
                kind, gf, payload = self.results.get_nowait()
                if gf is not self.gf:
                    continue
                if kind == "error":
                    self.status.set("Reading: %s" % payload)
                    continue
                self.show(payload)
        except queue.Empty:
            pass
        title = window_title("Bookmarks", self.game.meta)  # the reader refreshes meta
        if title != self.root.title():
            self.root.title(title)
        if not self.stop:
            self.root.after(100, self.drain)

    def show(self, data):
        self.rows = data
        for name, (v, tree, cols) in self.trees.items():
            rows = data.get(name, [])
            keep = tree.selection()
            want = []
            for r in rows:
                if isinstance(v, Table):
                    vals = [r["index"], "%X" % r["addr"]] + [
                        show(f, x) for f, x in zip(v.struct.fields, r["values"]) if not f.hide]
                    iid = "r%d" % r["index"]
                else:
                    f = r["field"]
                    vals = [r["name"], "%X" % r["addr"] if r["addr"] else "?", show(f, r["values"][0]),
                            f.type]
                    iid = "b" + r["name"]
                want.append((iid, vals))
            ids = [i for i, _ in want]
            for old in tree.get_children():
                if old not in ids:
                    tree.delete(old)
            for pos, (iid, vals) in enumerate(want):
                if tree.exists(iid):
                    if list(tree.item(iid, "values")) != [str(x) for x in vals]:
                        tree.item(iid, values=vals)
                    if tree.index(iid) != pos:
                        tree.move(iid, "", pos)
                else:
                    tree.insert("", pos, iid=iid, values=vals)
            if keep and tree.exists(keep[0]):
                tree.selection_set(keep[0])
        meta = self.game.meta
        self.status.set("%s  %s  main %s%s" % (
            meta.get("title_id", "?"), meta.get("build_id", "?"), meta.get("main", "?"),
            "" if not self.gf.title or self.gf.title == meta.get("title_id", "").upper()
            else "   (this file is for %s!)" % self.gf.title))

    # -- clicking
    def on_click(self, event, view, tree, edit):
        iid = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        if not iid:
            return
        tree.selection_set(iid)
        cols = self.trees[view.name][2]
        name = cols[int(col[1:]) - 1] if col else None
        rows = self.rows.get(view.name, [])
        row = next((r for r in rows if ("r%d" % r.get("index", -1)) == iid or ("b" + r.get("name", "")) == iid), None)
        if row is None:
            return
        if isinstance(view, Table):
            field = view.struct.field(name) if name not in ("#", "address") else None
            if field is None:
                field = next((f for f in view.struct.fields if not f.hide), None)
        else:
            field = row["field"]
        self.ctx = (view, row, field)
        if edit:
            self.on_edit(None)
        else:
            self.menu.tk_popup(event.x_root, event.y_root)

    def target(self):
        """(address, expression node, Field) the context menu is on."""
        view, row, f = self.ctx
        if isinstance(view, Table):
            return row["addr"] + f.off, add_offset(row["node"], f.off), f
        return row["addr"], row["node"], f

    def current(self, f, row):
        if isinstance(self.ctx[0], Table):
            return row["values"][self.ctx[0].struct.fields.index(f)]
        return row["values"][0]

    def on_edit(self, _):
        if not self.ctx:
            return
        view, row, f = self.ctx
        addr, _, f = self.target()
        if f.ro:
            self.status.set("%s is read-only (ro in the game file)" % f.name)
            return
        label = "%s %s" % (row.get("name", "#%s" % row.get("index")), f.name)
        if f.enum:
            label += " (" + ", ".join("%d=%s" % kv for kv in sorted(f.enum.items())) + ")"
        text = simpledialog.askstring("Edit", label, initialvalue=show(f, self.current(f, row)).split(" (")[0],
                                      parent=self.root)
        if text is None:
            return
        try:
            raw = encode(f, text)
        except ValueError:
            messagebox.showerror("Edit", "Not a %s: %s" % (f.type, text))
            return
        r = self.c.cmd("poke %X %s" % (addr, raw.hex()))
        self.status.set("%s = %s: %s" % (label, text, r))

    def on_hold(self):
        addr, _, f = self.target()
        self.status.set(self.c.cmd("hold %X %d" % (addr, f.size)))

    def on_unhold(self):
        addr, _, _ = self.target()
        self.status.set(self.c.cmd("unhold %X" % addr))

    def on_copy(self, expression):
        addr, node, _ = self.target()
        self.root.clipboard_clear()
        self.root.clipboard_append(expr_text(node) if expression else "%X" % addr)

    def on_make_cheat(self):
        view, row, f = self.ctx
        addr, node, f = self.target()
        who = row.get("name") or "#%d" % row["index"]
        text = simpledialog.askstring(
            "Make cheat", "Value to write for %s %s (the cheat is added off):" % (who, f.name),
            initialvalue=show(f, self.current(f, row)).split(" (")[0], parent=self.root)
        if text is None:
            return
        try:
            raw = encode(f, text)
            words = cheat_code(node, f, raw)
        except ValueError as e:
            messagebox.showerror("Make cheat", str(e))
            return
        name = "%s %s = %s" % (who if isinstance(view, Group) else "%s %s" % (view.name, who), f.name, text)
        line = "[%s] %s" % (name.replace("[", "(").replace("]", ")")[:60],
                            " ".join("%08X" % w for w in words))
        r = self.c.cmd("cheats add " + line)
        self.status.set("Make cheat: %s  (%s)" % (r, expr_text(node)))

    def toggle_pause(self):
        st = self.c.cmd("state")
        paused = st.startswith("+OK") and json.loads(st[4:]).get("paused")
        r = self.c.cmd("resume" if paused else "freeze")
        self.pause_btn.configure(text="Pause game" if paused else "Resume game")
        self.status.set(r)

    def close(self):
        self.stop = True
        self.root.destroy()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = None
    if "--file" in sys.argv:
        path = sys.argv[sys.argv.index("--file") + 1]
        args = [a for a in args if a != path]
    host = args[0] if len(args) > 0 else "127.0.0.1"
    code = args[1] if len(args) > 1 else "1234"
    port = int(args[2]) if len(args) > 2 else 6801
    root = tk.Tk()
    root.geometry("1100x520")
    try:
        client = Client(host, port, code)
    except (OSError, RuntimeError) as e:
        messagebox.showerror("Bookmarks", "Cannot connect to %s:%d: %s" % (host, port, e))
        return
    App(root, client, path)
    root.mainloop()


if __name__ == "__main__":
    main()
