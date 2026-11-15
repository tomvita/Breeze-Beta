"""Breeze Studio: the game's objects by class and field, live (Unity / IL2CPP).

    python studio_objects.py [address] [code]

It reads il2cpp_field_map.txt from the game's folder (Breeze makes it: Main > Unity on a Switch,
`il2cppmap` on an emulator host) and the game's memory, nothing else, so it works on every host.

  * Left: the classes, filtered as you type; "with statics" keeps the ones that have static
    fields, which is where a walk through the game's objects starts.
  * Pick a class: its static fields with their values now, then its own fields (and its
    parents') as a layout. A pointer's row shows what it points at.
  * Double-click a pointer to open that object: its fields with live values. Back returns.
    Arrays and List<T> show their elements; a string shows its text; a struct inside an object
    is shown field by field.
  * Double-click a number to change it. Right-click: Copy address, Copy chain (the pointer
    chain from main, in the Bookmarks tab's notation), Hold / Unhold, Add to bookmarks.
  * "Object at" opens any address as an object of the class picked on the left.

Python 3 with tkinter only.
"""
import os
import queue
import re
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import simpledialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from pcconnect import Breeze, game_caption  # noqa: E402

CACHE = os.path.join(os.path.expanduser("~"), ".breeze_pc_cache")
MAP = "il2cpp_field_map.txt"
PRIM = {  # C# name: (struct format, size)
    "bool": ("<?", 1), "byte": ("<B", 1), "sbyte": ("<b", 1), "char": ("<H", 2),
    "short": ("<h", 2), "ushort": ("<H", 2), "int": ("<i", 4), "uint": ("<I", 4),
    "long": ("<q", 8), "ulong": ("<Q", 8), "float": ("<f", 4), "double": ("<d", 8),
    "IntPtr": ("<Q", 8), "UIntPtr": ("<Q", 8),
}
BOOKMARK_TYPE = {"bool": "u8", "byte": "u8", "sbyte": "s8", "char": "u16", "short": "s16", "ushort": "u16",
                 "int": "s32", "uint": "u32", "long": "s64", "ulong": "u64", "float": "f32", "double": "f64"}
OBJECT_HEADER = 0x10      # klass + monitor: a value type's fields are listed past it
STATICS = 0xB8            # klass -> its static block (the map's header says so; read from there when it differs)
ARRAY_LEN, ARRAY_DATA = 0x18, 0x20
MAX_ELEMENTS = 200
MAX_DEPTH = 3             # structs inside structs


class Field:
    def __init__(self, name, offset, type_, static):
        self.name, self.offset, self.type, self.static = name, offset, type_, static


class Klass:
    def __init__(self, name, parent, slot):
        self.name, self.parent, self.slot = name, parent, slot
        self.fields = []


def parse_map(text):
    """{class name: Klass}, and the offset of the static block in a klass."""
    classes, statics = {}, STATICS
    head = re.compile(r"^(\S.*?) : (.*?)\s+klass=\[main\+0x([0-9A-Fa-f]+)\]")
    for line in text.splitlines():
        if line.startswith("#"):
            m = re.search(r"static block = \[klass\+0x([0-9A-Fa-f]+)\]", line)
            if m:
                statics = int(m.group(1), 16)
            continue
        name, sep, rest = line.partition(" = ")
        if sep and "::" in name:
            cls, _, fname = name.rpartition("::")
            m = re.match(r"(static )?\+0x([0-9A-Fa-f]+) (.*)$", rest)
            if m and cls in classes:
                classes[cls].fields.append(Field(fname, int(m.group(2), 16), m.group(3).strip(), bool(m.group(1))))
            continue
        m = head.match(line)
        if m:
            classes.setdefault(m.group(1), Klass(m.group(1), m.group(2).strip(), int(m.group(3), 16)))
    return classes, statics


def base_type(type_):
    """'List`1<Foo>*' -> ('List`1', True): the class to look up, and whether it is a pointer."""
    pointer = type_.endswith("*")
    t = type_[:-1] if pointer else type_
    cut = t.find("<")
    return (t[:cut] if cut > 0 else t), pointer


class Row:
    """One line of the view: a field (or an element) and where it is."""

    def __init__(self, label, type_, address, chain, depth=0, offset=None, note=""):
        self.label, self.type, self.address, self.chain = label, type_, address, chain
        self.depth, self.offset, self.note = depth, offset, note
        self.value, self.raw, self.target = "", b"", 0


class Game:
    """The connection, the map and the reading. Worker thread only."""

    def __init__(self, address, code):
        self.b = Breeze(address, code, timeout=60, connect_timeout=5)
        self.meta = self.b.json("meta")
        self.main = int(self.meta["main"], 16)
        self.classes, self.statics, self.note = {}, STATICS, ""
        self.short = {}       # last part of a class name -> full names
        self.pages = {}
        self.load()

    def load(self):
        files = self.b.files()
        have = {f["name"]: f.get("size", 0) for f in files.get("files", [])}
        if MAP not in have:
            self.note = "no %s in the game's folder: make it (Breeze: Main > Unity; an emulator host: il2cppmap)" % MAP
            return
        folder = os.path.join(CACHE, "%s_%s" % (self.meta["title_id"], self.meta["build_id"].upper()))
        os.makedirs(folder, exist_ok=True)
        local = os.path.join(folder, MAP)
        if os.path.exists(local) and os.path.getsize(local) == have[MAP]:
            data = open(local, "rb").read()
        else:
            data = self.b.get_file(files.get("dir", "") + MAP, local)
        self.classes, self.statics = parse_map(data.decode("utf-8", "replace"))
        for name in self.classes:
            self.short.setdefault(name.rpartition(".")[2], []).append(name)
        self.note = "%d classes, %d with static fields" % (
            len(self.classes), sum(any(f.static for f in k.fields) for k in self.classes.values()))

    # ------------------------------------------------------------ memory
    def fresh(self):
        """Forgets what was read: the next view reads the game again."""
        self.pages = {}

    def read(self, address, n):
        # A view reads many small fields of the same few objects: each 4 KB page is fetched
        # once per view (one command instead of one per field).
        out = b""
        while len(out) < n:
            at = address + len(out)
            page = at & ~0xFFF
            data = self.pages.get(page)
            if data is None:
                try:
                    data = self.b.peek(page, 4096)
                except Exception:  # noqa: BLE001 - the page is not all mapped: read just what is asked
                    return out + self.b.peek(at, n - len(out))
                self.pages[page] = data
            piece = data[at - page:at - page + n - len(out)]
            if not piece:
                break
            out += piece
        return out

    def u64(self, address):
        try:
            return struct.unpack("<Q", self.read(address, 8))[0]
        except Exception:  # noqa: BLE001 - not mapped
            return 0

    def cstring(self, address, limit=96):
        try:
            data = self.read(address, limit)
        except Exception:  # noqa: BLE001
            return ""
        end = data.find(b"\0")
        text = data[:end if end >= 0 else limit]
        return text.decode("ascii", "replace") if text and all(32 <= c < 127 for c in text) else ""

    def find_class(self, name, near=""):
        """A class by the name a field or a parent gives it. A name without a namespace (the map
        writes parents that way) is looked for among the classes that end with it, the one in the
        namespace of `near` first; a full name that is not in the map is not guessed at."""
        if name in self.classes:
            return self.classes[name]
        if "." in name:
            return None
        hits = self.short.get(name, [])
        space = near.rpartition(".")[0]
        same = [h for h in hits if h.rpartition(".")[0] == space]
        if len(same) == 1:
            return self.classes[same[0]]
        return self.classes[hits[0]] if len(hits) == 1 else None

    def class_of(self, obj, declared):
        """The object's own class when its klass names one in the map, else the declared one."""
        klass = self.u64(obj)
        if klass:
            name, space = self.cstring(self.u64(klass + 0x10)), self.cstring(self.u64(klass + 0x18))
            # With a namespace the name is exact: a System.Object is not the UnityEngine.Object
            # that happens to be the only "Object" in the map.
            k = self.classes.get(space + "." + name) if space else (self.find_class(name) if name else None)
            if k is not None or space:
                return k
        return self.find_class(declared)

    def instance_fields(self, k):
        """Its fields and its parents', the parents' first."""
        chain, seen = [], set()
        while k is not None and k.name not in seen:
            seen.add(k.name)
            chain.append(k)
            k = self.find_class(base_type(k.parent)[0], k.name)
        out = []
        for c in reversed(chain):
            out += [(c, f) for f in c.fields if not f.static]
        return out

    # ------------------------------------------------------------ views
    def describe(self, row):
        """Fills value / target / note of a row from memory."""
        base, pointer = base_type(row.type)
        try:
            if pointer or base in ("object", "string") or row.type.endswith("[]"):
                row.raw = self.read(row.address, 8)
                row.target = struct.unpack("<Q", row.raw)[0]
                row.value = "%X" % row.target if row.target else "null"
                if row.target and base in ("string", "System.String", "String"):
                    row.note = '"%s"' % self.string(row.target)
                return
            if base in PRIM:
                fmt, size = PRIM[base]
                row.raw = self.read(row.address, size)
                v = struct.unpack(fmt, row.raw)[0]
                if base.endswith("IntPtr"):
                    row.value = "%X" % v
                    return
                row.value = ("%.7g" % v) if isinstance(v, float) else str(int(v) if isinstance(v, bool) else v)
                return
            # An enum or a struct the map does not describe: four bytes as they are.
            row.raw = self.read(row.address, 4)
            row.value = "%d (0x%X)" % (struct.unpack("<i", row.raw)[0], struct.unpack("<I", row.raw)[0])
        except Exception as e:  # noqa: BLE001 - shown in the row
            row.value, row.raw = "(%s)" % (str(e)[:40] or "not readable"), b""

    def string(self, obj):
        try:
            n = struct.unpack("<i", self.read(obj + 0x10, 4))[0]
            if not 0 <= n < 4096:
                return "?"
            return self.read(obj + 0x14, min(n, 120) * 2).decode("utf-16-le", "replace") + ("..." if n > 120 else "")
        except Exception:  # noqa: BLE001
            return "?"

    def rows_for_fields(self, fields, address, chain, depth=0, shift=0):
        """Rows of an object's (or a struct's) fields at address; a struct field is opened in place."""
        rows = []
        for cls, f in fields:
            at = address + f.offset - shift
            base, pointer = base_type(f.type)
            row = Row(("    " * depth) + f.name, f.type, at, "%s+%X" % (chain, f.offset - shift), depth, f.offset - shift,
                      cls.name.rpartition(".")[2])
            inner = None if pointer or base in PRIM else self.find_class(base)
            inner_fields = [(inner, x) for x in inner.fields if not x.static] if inner is not None else []
            # A generic struct's fields have no real offsets or types in the map (Nullable`1: T).
            usable = all(x.offset >= OBJECT_HEADER and x.type not in ("T", "TKey", "TValue") for _c, x in inner_fields)
            if inner_fields and usable and depth < MAX_DEPTH and not (len(inner_fields) == 1 and inner_fields[0][1].name == "value__"):
                row.value, row.note = "", "struct"
                rows.append(row)
                rows += self.rows_for_fields(inner_fields, at, row.chain, depth + 1, OBJECT_HEADER)
            else:
                self.describe(row)
                rows.append(row)
        return rows

    def view_class(self, name):
        """A class: its static fields live, then its layout."""
        self.fresh()
        k = self.classes[name]
        rows, title = [], "%s : %s" % (k.name, k.parent)
        statics = [f for f in k.fields if f.static]
        klass = self.u64(self.main + k.slot)
        if statics:
            block = self.u64(klass + self.statics) if klass else 0
            chain = "[[main+%X]+%X]" % (k.slot, self.statics)
            if block:
                for f in statics:
                    row = Row(f.name, f.type, block + f.offset, "%s+%X" % (chain, f.offset), 0, f.offset, "static")
                    self.describe(row)
                    rows.append(row)
            else:
                title += "   (not in use yet: its statics are not there)"
                rows += [Row(f.name, f.type, 0, "", 0, f.offset, "static") for f in statics]
        for cls, f in self.instance_fields(k):
            rows.append(Row(f.name, f.type, 0, "", 0, f.offset, cls.name.rpartition(".")[2]))
        return title, rows

    def view_object(self, obj, declared, chain):
        """An object at obj: an array's or a list's elements, or its fields."""
        self.fresh()
        base, _ = base_type(declared)
        if declared.rstrip("*").endswith("[]"):
            return self.view_array(obj, declared.rstrip("*")[:-2], chain, "%s  at %X" % (declared, obj))
        k = self.class_of(obj, base)
        title = "%s  at %X" % (k.name if k is not None else declared, obj)
        if base.endswith("List`1") or (k is not None and k.name.endswith("List`1")):
            items = self.u64(obj + 0x10)
            size = struct.unpack("<i", self.read(obj + 0x18, 4))[0]
            inner = declared[declared.find("<") + 1:declared.rfind(">")] if "<" in declared else "object"
            return self.view_array(items, inner, "[%s+10]" % chain, "%s  at %X  (%d items)" % (declared, obj, size), size)
        if k is None:
            # The map has the classes whose code has run and that Breeze could name: for another
            # one, the object as 8-byte values, each pointer still to be opened.
            rows = []
            for off in range(0, 0x100, 8):
                row = Row("+%X" % off, "object*" if off >= OBJECT_HEADER else "IntPtr", obj + off, "%s+%X" % (chain, off), 0, off)
                self.describe(row)
                rows.append(row)
            return title + "   (this class is not in the map: raw values)", rows
        return title, self.rows_for_fields(self.instance_fields(k), obj, chain)

    def view_array(self, array, element, chain, title, count=None):
        if not array:
            return title + "  (null)", []
        n = struct.unpack("<Q", self.read(array + ARRAY_LEN, 8))[0]
        n = min(n if count is None else count, 1 << 20)
        ebase, _ = base_type(element)
        k = None if ebase in PRIM else self.find_class(ebase)
        value_type = k is not None and self.is_value_type(k)
        if ebase in PRIM:
            size = PRIM[ebase][1]
        elif ebase == "valuetype":
            size = 4      # an enum the map does not name
        elif value_type:
            fields = [f for f in k.fields if not f.static]
            size = max((f.offset - OBJECT_HEADER + self.size_of(f.type) for f in fields), default=4)
            size = (size + 3) & ~3
        else:
            size, element = 8, element if element.endswith("*") else element + "*"
        rows = []
        for i in range(min(n, MAX_ELEMENTS)):
            at = array + ARRAY_DATA + i * size
            row = Row("[%d]" % i, element, at, "%s+%X" % (chain, ARRAY_DATA + i * size), 0, ARRAY_DATA + i * size)
            if value_type and len(fields) > 1:
                row.note = "struct"
                rows.append(row)
                rows += self.rows_for_fields([(k, f) for f in fields], at, row.chain, 1, OBJECT_HEADER)
            else:
                self.describe(row)
                rows.append(row)
        return "%s  %d elements%s" % (title, n, ", first %d shown" % MAX_ELEMENTS if n > MAX_ELEMENTS else ""), rows

    def is_value_type(self, k):
        seen = set()
        while k is not None and k.name not in seen:
            seen.add(k.name)
            if k.parent in ("System.ValueType", "System.Enum"):
                return True
            k = self.find_class(base_type(k.parent)[0], k.name)
        return False

    def size_of(self, type_):
        base, pointer = base_type(type_)
        if pointer:
            return 8
        if base in PRIM:
            return PRIM[base][1]
        k = self.find_class(base)
        if k is not None and self.is_value_type(k):
            fields = [f for f in k.fields if not f.static]
            return max((f.offset - OBJECT_HEADER + self.size_of(f.type) for f in fields), default=4)
        return 8 if k is not None else 4

    def refresh(self, rows):
        self.fresh()
        for row in rows:
            if row.address and row.note != "struct":
                self.describe(row)
        return rows

    def write(self, row, text):
        base, pointer = base_type(row.type)
        if pointer:
            data = struct.pack("<Q", int(text, 16))
        elif base in PRIM:
            fmt, _ = PRIM[base]
            data = struct.pack(fmt, float(text) if fmt in ("<f", "<d") else int(text, 0))
        else:
            data = struct.pack("<i", int(text, 0))
        reply = self.b.cmd("poke %X %s" % (row.address, data.hex()))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        self.fresh()
        self.describe(row)
        return row


class App:
    def __init__(self, root, address, code, port=None):
        self.root = root
        self.address = address if port is None or ":" in address else "%s:%d" % (address, port)
        self.code = code
        self.game = None
        self.names, self.rows, self.view = [], [], None   # view: ("class", name) or ("object", addr, type, chain)
        self.history = []
        self.jobs, self.out = queue.Queue(), queue.Queue()
        self.stop = False
        root.title("Objects")
        root.geometry("1200x800")

        bar = ttk.Frame(root, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Back", command=self.back).pack(side="left")
        ttk.Button(bar, text="Reload map", command=self.reload).pack(side="left", padx=4)
        ttk.Label(bar, text="Object at").pack(side="left", padx=(12, 2))
        self.at = ttk.Entry(bar, width=16)
        self.at.pack(side="left")
        self.at.bind("<Return>", lambda e: self.open_at())
        ttk.Button(bar, text="Open as the picked class", command=self.open_at).pack(side="left", padx=4)
        self.live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="live values", variable=self.live).pack(side="left", padx=12)
        self.status = tk.StringVar(value="connecting...")
        ttk.Label(bar, textvariable=self.status, foreground="#555").pack(side="left", padx=8)

        panes = ttk.PanedWindow(root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        left = ttk.Frame(panes)
        self.filter = tk.StringVar()
        ttk.Entry(left, textvariable=self.filter).pack(fill="x")
        self.filter.trace_add("write", lambda *a: self.fill_classes())
        self.only_static = tk.BooleanVar(value=True)
        ttk.Checkbutton(left, text="with statics", variable=self.only_static, command=self.fill_classes).pack(anchor="w")
        self.count = tk.StringVar()
        ttk.Label(left, textvariable=self.count, foreground="#555").pack(anchor="w")
        lf = ttk.Frame(left)
        lf.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(lf)
        sb.pack(side="right", fill="y")
        self.list = tk.Listbox(lf, width=52, activestyle="none", exportselection=False, yscrollcommand=sb.set, font=("Consolas", 10))
        self.list.pack(side="left", fill="both", expand=True)
        sb.config(command=self.list.yview)
        self.list.bind("<<ListboxSelect>>", self.on_pick)
        panes.add(left, weight=1)

        right = ttk.Frame(panes)
        self.title = tk.StringVar()
        ttk.Label(right, textvariable=self.title, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tf = ttk.Frame(right)
        tf.pack(fill="both", expand=True)
        cols = ("offset", "type", "value", "what", "address", "from")
        self.tree = ttk.Treeview(tf, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="field")
        self.tree.column("#0", width=260)
        for c, w in zip(cols, (60, 260, 150, 240, 110, 130)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        sb2 = ttk.Scrollbar(tf, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb2.set)
        sb2.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-Button-1>", self.on_double)
        self.tree.bind("<Button-3>", self.on_menu)
        panes.add(right, weight=3)

        self.menu = tk.Menu(root, tearoff=0)
        self.menu.add_command(label="Open (a pointer)", command=lambda: self.open_row(self.picked()))
        self.menu.add_command(label="Edit value...", command=lambda: self.edit_row(self.picked()))
        self.menu.add_separator()
        self.menu.add_command(label="Copy address", command=lambda: self.copy(lambda r: "%X" % r.address))
        self.menu.add_command(label="Copy chain", command=lambda: self.copy(lambda r: r.chain))
        self.menu.add_command(label="Hold at its value", command=lambda: self.hold(True))
        self.menu.add_command(label="Unhold", command=lambda: self.hold(False))
        self.menu.add_command(label="Add to bookmarks", command=self.bookmark)
        self.menu.add_command(label="Add to Breeze's bookmarks (a Switch)", command=self.to_breeze)

        threading.Thread(target=self.worker, daemon=True).start()
        self.job(lambda g: g, self.on_game)
        root.after(50, self.pump)
        root.after(1000, self.tick)
        root.protocol("WM_DELETE_WINDOW", self.close)

    # ------------------------------------------------------------ plumbing
    def worker(self):
        while not self.stop:
            fn, done = self.jobs.get()
            if fn is None:
                break
            try:
                if self.game is None:
                    self.game = Game(self.address, self.code)
                self.out.put((done, fn(self.game), None))
            except Exception as e:  # noqa: BLE001 - shown in the status line
                self.out.put((done, None, e))
                if isinstance(e, (OSError, ConnectionError)) and self.game is not None:
                    self.game.b.close()
                    self.game = None
        if self.game is not None:
            self.game.b.close()

    def job(self, fn, done):
        self.jobs.put((fn, done))

    def pump(self):
        if self.stop:
            return
        try:
            while True:
                done, result, error = self.out.get_nowait()
                if error is not None:
                    self.status.set("%s: %s" % (type(error).__name__, error))
                elif done is not None:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(50, self.pump)

    def tick(self):
        if self.stop:
            return
        if self.live.get() and self.rows and self.jobs.empty():
            rows = self.rows
            self.job(lambda g: g.refresh(rows), lambda r: self.update_values(r))
        self.root.after(1000, self.tick)

    def close(self):
        self.stop = True
        self.jobs.put((None, None))
        self.root.destroy()

    # ------------------------------------------------------------ classes
    def on_game(self, g):
        self.status.set("%s  |  %s" % (game_caption(g.meta), g.note))
        self.names = sorted(g.classes)
        self.with_static = {n for n, k in g.classes.items() if any(f.static for f in k.fields)}
        self.fill_classes()

    def reload(self):
        def again(g):
            g.load()
            return g
        self.job(again, self.on_game)

    def fill_classes(self):
        words = self.filter.get().lower().split()
        only = self.only_static.get()
        self.shown = [n for n in self.names if (not only or n in self.with_static) and all(w in n.lower() for w in words)]
        self.list.delete(0, "end")
        for n in self.shown[:3000]:
            self.list.insert("end", n)
        self.count.set("%d classes%s" % (len(self.shown), ", first 3000 shown" if len(self.shown) > 3000 else ""))

    def picked_class(self):
        sel = self.list.curselection()
        return self.shown[sel[0]] if sel else None

    def on_pick(self, _e=None):
        name = self.picked_class()
        if name:
            self.go(("class", name))

    # ------------------------------------------------------------ views
    def go(self, view, record=True):
        if record and self.view is not None and self.view != view:
            self.history.append(self.view)

        def load(g):
            if view[0] == "class":
                return g.view_class(view[1])
            return g.view_object(view[1], view[2], view[3])

        def done(result):
            self.view = view
            self.title.set(result[0])
            self.show_rows(result[1])

        self.job(load, done)

    def back(self):
        if self.history:
            self.go(self.history.pop(), record=False)

    def open_at(self):
        name = self.picked_class()
        try:
            addr = int(self.at.get().strip(), 16)
        except ValueError:
            self.status.set("Object at: a hex address")
            return
        if not name:
            self.status.set("pick the class on the left first")
            return
        self.go(("object", addr, name + "*", "%X" % addr))

    def show_rows(self, rows):
        self.rows = rows
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(rows):
            self.tree.insert("", "end", iid=str(i), text=r.label, values=(
                "" if r.offset is None else "+%X" % r.offset, r.type, r.value,
                "" if r.note in ("static", "struct") or not r.note.startswith('"') else r.note,
                "%X" % r.address if r.address else "", r.note if not r.note.startswith('"') else ""))

    def update_values(self, rows):
        if rows is not self.rows:
            return
        for i, r in enumerate(rows):
            if r.address and self.tree.exists(str(i)):
                self.tree.set(str(i), "value", r.value)
                if r.note.startswith('"'):
                    self.tree.set(str(i), "what", r.note)

    def picked(self):
        sel = self.tree.selection()
        return self.rows[int(sel[0])] if sel else None

    def on_double(self, e):
        row_id = self.tree.identify_row(e.y)
        if not row_id:
            return
        r = self.rows[int(row_id)]
        base, pointer = base_type(r.type)
        if r.target and (pointer or base in ("object",)) and base not in ("string", "System.String"):
            self.open_row(r)
        elif r.address and r.note != "struct":
            self.edit_row(r)

    def open_row(self, r):
        if r is None or not r.target:
            self.status.set("nothing to open: not a pointer, or null")
            return
        self.go(("object", r.target, r.type, "[%s]" % r.chain if r.chain else "%X" % r.target))

    def edit_row(self, r):
        if r is None or not r.address:
            return
        text = simpledialog.askstring("Edit", "%s (%s) at %X:" % (r.label.strip(), r.type, r.address),
                                      initialvalue=r.value.split(" ")[0], parent=self.root)
        if text is None:
            return
        self.job(lambda g: g.write(r, text.strip()), lambda _r: self.update_values(self.rows))

    def on_menu(self, e):
        row_id = self.tree.identify_row(e.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.menu.tk_popup(e.x_root, e.y_root)

    def copy(self, text_of):
        r = self.picked()
        if r is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text_of(r))
            self.status.set("copied " + text_of(r))

    def hold(self, on):
        r = self.picked()
        if r is None or not r.address:
            return
        width = len(r.raw) if len(r.raw) in (1, 2, 4, 8) else 4
        line = ("hold %X %d" % (r.address, width)) if on else ("unhold %X" % r.address)
        self.job(lambda g: g.b.cmd(line), lambda reply: self.status.set(reply))

    def to_breeze(self):
        """The row as one more record of Breeze's own bookmark file (a Switch: `bookmark add`)."""
        r = self.picked()
        line = breeze_bookmark_line(r) if r is not None else None
        if line is None:
            self.status.set("this row has no pointer chain from main")
            return
        self.job(lambda g: g.b.cmd(line), lambda reply: self.status.set("%s  ->  %s" % (line, reply)))

    def bookmark(self):
        """Adds the row to the game's bookmark file (the Bookmarks tab reads it)."""
        r = self.picked()
        if r is None or not r.chain or self.game is None:
            return
        base, pointer = base_type(r.type)
        type_ = "ptr" if pointer else BOOKMARK_TYPE.get(base, "s32")
        path = os.path.join(HERE, "views", "%s.txt" % self.game.meta["title_id"].upper())
        name = re.sub(r"\W+", "_", r.label.strip()) or "value"
        new = not os.path.exists(path)
        text = open(path, encoding="utf-8").read() if not new else "title %s\n" % self.game.meta["title_id"].upper()
        if "\ngroup Objects" not in text:
            text = text.rstrip("\n") + "\n\ngroup Objects\n"
        text = text.rstrip("\n") + "\n    %s = %s %s\n" % (name, r.chain, type_)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.status.set("added %s to %s" % (name, path))


def breeze_bookmark_line(row):
    """`bookmark add ...` for a row: its chain as Breeze's bookmark holds it; None when it has none."""
    import studio_bookmarks as sb
    if not row.chain:
        return None
    chain = sb.chain_of(sb.parse_expr(row.chain), {})
    if chain is None:
        return None
    base, pointer = base_type(row.type)
    type_ = "ptr" if pointer else BOOKMARK_TYPE.get(base, "s32")
    label = (re.sub(r"\s+", "", row.label) or "PC")[:18]
    return "bookmark add %s %s %s %s" % (type_, chain[0], ",".join(("%X" % o) if o >= 0 else ("-%X" % -o) for o in chain[1]), label)


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "1234"
    root = tk.Tk()
    App(root, address, code)
    root.mainloop()


if __name__ == "__main__":
    main()
