"""Breeze Studio: the game's objects by class and field, live (Unity / IL2CPP and Unreal).

    python studio_objects.py [address] [code]

Unity: it reads il2cpp_field_map.txt from the game's folder (Breeze makes it: Main > Unity on a
Switch, `il2cppmap` on an emulator host) and the game's memory, nothing else, so it works on every
host. Unreal: it reads ue_profile.ini (Main > Unreal; `uemap`) and the game's own reflection data
(studio_ue.py): the list starts with the engine route (GWorld to the player's pawn) and gets every
class with its objects once the object list is read; "with instances" keeps the classes that
have an object besides their default one.

"Build map" has the host make the file that is missing (or make it again): the field map for a
Unity game, the profile for an Unreal one; see build_map.

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
  * "has field" under the class filter keeps the classes with a field of that name (Unreal:
    the fields of the structs inside a class count too, as Struct.Field).
  * Right-click > Find chain to this object (Unreal): the pointer chains from main to an
    object taken from a class's list, which has none of its own.
  * Right-click > Make cheat...: the row's chain and a value as cheat code, to copy or to add
    to the game's cheats (off).

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
from tkinter import messagebox, simpledialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from pcconnect import Breeze, game_caption  # noqa: E402

CACHE = os.path.join(os.path.expanduser("~"), ".breeze_pc_cache")
MAP = "il2cpp_field_map.txt"
UE_PROFILE = "ue_profile.ini"
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


def cache_folder(meta):
    return os.path.join(CACHE, "%s_%s" % (meta["title_id"], meta["build_id"].upper()))


def scan_engine(b, files):
    """The engine the engine scan named ('' when there is no scan, or it named none)."""
    engine = files.get("engine", "")
    if not engine and any(f["name"] == "engine_scan.txt" for f in files.get("files", [])):
        try:
            text = b.get_file(files.get("dir", "") + "engine_scan.txt").decode("utf-8", "replace")
            engine = (re.search(r"^#engine=(.*)$", text, re.M) or [0, ""])[1].strip()
        except Exception as e:  # noqa: BLE001 - no scan to read; a lost connection is passed on
            if isinstance(e, (OSError, ConnectionError)):
                raise
    return engine


def build_map(address, code, engine, say):
    """Has the host make the file the Objects tab reads: il2cpp_field_map.txt (Unity) or
    ue_profile.ini (Unreal). engine: "Unity", "Unreal", or "" to go by the engine scan.
    say(text) is called with progress. Returns the host's last line about the job.

    An emulator host builds it itself (`il2cppmap`: the field map and the function map;
    `uemap profile`) and answers when it
    is done. A Switch runs Breeze's own job (`prep il2cpp_fields`, `prep ue_profile`), which is
    followed with `prep`; Breeze stops the game for the job and lets it run again after."""
    b = Breeze(address, code, timeout=3600, connect_timeout=5)
    try:
        caps = b.caps()
        if not engine:
            files = b.files()
            if "jobs" in caps and not any(f["name"] == "engine_scan.txt" for f in files.get("files", [])):
                b.cmd("enginescan")
                files = b.files()
            engine = scan_engine(b, files)
        unity, unreal = "Unity" in engine, "Unreal" in engine
        if not unity and not unreal:
            raise RuntimeError("%s: there is a map to build for Unity and Unreal games only"
                               % (engine or "the engine scan names no engine"))
        started = time.time()
        if "jobs" in caps:
            # Unity: the function map too (names for the Watch tab); the class scan is the cost
            # and both maps share it (Overcooked! 2: 1.5 s for both).
            line = "il2cppmap" if unity else "uemap profile"
            say("building on the host (%s)..." % line)
            reply = b.cmd(line)
            if not reply.startswith("+OK"):
                raise RuntimeError(reply)
            return "%s  (%d s)" % (reply[4:].split(" -> ")[0][:160], time.time() - started)
        if "prep" not in caps:
            raise RuntimeError("this host has no command that builds the map")
        job = "il2cpp_fields" if unity else "ue_profile"
        reply = b.cmd("prep " + job)
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        # The Unity job runs in slices and reports progress; the Unreal one holds Breeze's UI
        # thread to its end, and is asked about less often.
        pause = 5 if unity else 15
        while True:
            time.sleep(pause)
            status = b.json("prep")
            running = status.get("running")
            if not running:
                last = status.get("last") or {}
                if last.get("job") != job or not last.get("ok"):
                    raise RuntimeError("%s: %s" % (job, last.get("result") or "it did not finish"))
                return "%s  (%d s)" % (str(last.get("result", ""))[:160], last.get("seconds", 0))
            say("Breeze is building (%s): %d s  %s" % (job, running.get("seconds", 0), str(running.get("progress", ""))[:120]))
    finally:
        b.close()


def open_game(address, code):
    """The reader for the running game: Unreal when its folder has the Unreal profile, else Unity."""
    b = Breeze(address, code, timeout=60, connect_timeout=5)
    try:
        meta, files = b.json("meta"), b.files()
        names = {f["name"] for f in files.get("files", [])}
        if UE_PROFILE in names and MAP not in names:
            import studio_ue
            return studio_ue.UeGame(b, meta, files, cache_folder(meta))
        return Game(address, code, b, meta, files)
    except Exception:
        b.close()
        raise


class Game:
    """The connection, the map and the reading. Worker thread only."""
    star_label = "with statics"

    def __init__(self, address, code, b=None, meta=None, files=None):
        self.b = b if b is not None else Breeze(address, code, timeout=60, connect_timeout=5)
        self.meta = meta if meta is not None else self.b.json("meta")
        self.main = int(self.meta["main"], 16)
        self.classes, self.statics, self.note = {}, STATICS, ""
        self.starred = set()
        self.short = {}       # last part of a class name -> full names
        self.pages = {}
        self.load(files)

    def load(self, files=None):
        files = files if files is not None else self.b.files()
        have = {f["name"]: f.get("size", 0) for f in files.get("files", [])}
        self.classes, self.short, self.starred = {}, {}, set()
        self.engine = "Unity"
        if MAP not in have:
            self.engine = engine = scan_engine(self.b, files)
            if "Unreal" in engine:
                self.note = "%s: no %s in the game's folder yet: press Build map" % (engine, UE_PROFILE)
            elif engine and "Unity" not in engine:
                self.note = "%s: the Objects tab reads Unity and Unreal games only" % engine
            else:
                self.note = "no %s in the game's folder yet: press Build map" % MAP
            return
        folder = cache_folder(self.meta)
        os.makedirs(folder, exist_ok=True)
        local = os.path.join(folder, MAP)
        if os.path.exists(local) and os.path.getsize(local) == have[MAP]:
            data = open(local, "rb").read()
        else:
            data = self.b.get_file(files.get("dir", "") + MAP, local)
        self.classes, self.statics = parse_map(data.decode("utf-8", "replace"))
        for name in self.classes:
            self.short.setdefault(name.rpartition(".")[2], []).append(name)
        self.starred = {n for n, k in self.classes.items() if any(f.static for f in k.fields)}
        self.note = "%d classes, %d with static fields" % (len(self.classes), len(self.starred))

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

    def locate(self, address):
        """The object that holds an address: (object, its class name), or None. An object starts
        with its klass, so the 8-aligned words before the address are tried, nearest first."""
        self.fresh()
        at = address & ~7
        for back in range(0, 0x4000, 8):
            klass = self.u64(at - back)
            if klass < 0x10000 or klass & 7:
                continue
            name = self.cstring(self.u64(klass + 0x10))
            if not name:
                continue
            space = self.cstring(self.u64(klass + 0x18))
            k = self.classes.get(space + "." + name if space else name) or (None if space else self.find_class(name))
            # The klass points at itself through its own fields in no way a number does: a name
            # that is a class of the map, at a klass that says so, is an object's first word.
            if k is not None:
                fields = self.instance_fields(k)
                end = max([f.offset + 8 for f in fields] or [OBJECT_HEADER])
                return (at - back, k.name) if back < max(end, 0x18) else None
        return None

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

    def encode(self, row, text):
        """A typed value as the bytes of this row's field."""
        base, pointer = base_type(row.type)
        if pointer:
            return struct.pack("<Q", int(text, 16))
        if base in PRIM:
            fmt, _ = PRIM[base]
            return struct.pack(fmt, float(text) if fmt in ("<f", "<d") else int(text, 0))
        return struct.pack("<i", int(text, 0))

    def write(self, row, text):
        data = self.encode(row, text)
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
        self.refreshing = False
        self.jobs, self.out = queue.Queue(), queue.Queue()
        self.stop = False
        root.title("Objects")
        root.geometry("1200x800")

        bar = ttk.Frame(root, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Back", command=self.back).pack(side="left")
        ttk.Button(bar, text="Reload map", command=self.reload).pack(side="left", padx=4)
        self.build_btn = ttk.Button(bar, text="Build map", command=self.build)
        self.build_btn.pack(side="left")
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
        ff = ttk.Frame(left)
        ff.pack(fill="x")
        ttk.Label(ff, text="has field").pack(side="left")
        self.field_filter = tk.StringVar()
        ttk.Entry(ff, textvariable=self.field_filter).pack(side="left", fill="x", expand=True)
        self.field_filter.trace_add("write", lambda *a: self.fill_classes())
        self.only_static = tk.BooleanVar(value=True)
        self.star_box = ttk.Checkbutton(left, text="with statics", variable=self.only_static, command=self.fill_classes)
        self.star_box.pack(anchor="w")
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
        self.menu.add_command(label="Open (a pointer, an array)", command=lambda: self.open_row(self.picked()))
        self.menu.add_command(label="Edit value...", command=lambda: self.edit_row(self.picked()))
        self.menu.add_separator()
        self.menu.add_command(label="Copy address", command=lambda: self.copy(lambda r: "%X" % r.address))
        self.menu.add_command(label="Copy chain", command=lambda: self.copy(lambda r: r.chain))
        self.menu.add_command(label="Hold at its value", command=lambda: self.hold(True))
        self.menu.add_command(label="Unhold", command=lambda: self.hold(False))
        self.menu.add_command(label="Add to bookmarks", command=self.bookmark)
        self.menu.add_command(label="Add to Breeze's bookmarks (a Switch)", command=self.to_breeze)
        self.menu.add_command(label="Open in Memory", command=lambda: self.link("Memory", "goto"))
        self.menu.add_command(label="Watch this address (who reads or writes it)", command=lambda: self.link("Watch", "watch_address"))
        self.menu.add_separator()
        self.menu.add_command(label="Find chain to this object", command=self.find_chain)
        self.menu.add_command(label="Make cheat...", command=self.make_cheat)

        threading.Thread(target=self.worker, daemon=True).start()
        self.job(lambda g: g, self.on_game)
        root.after(50, self.pump)
        root.after(1000, self.tick)
        root.protocol("WM_DELETE_WINDOW", self.close)

    # ------------------------------------------------------------ plumbing
    def worker(self):
        while not self.stop:
            # A reader with work of its own (Unreal: reading the object list) does a slice of it
            # whenever no view is asked for.
            busy = self.game is not None and getattr(self.game, "wants_idle", lambda: False)()
            try:
                fn, done = self.jobs.get(timeout=0.005) if busy else self.jobs.get()
            except queue.Empty:
                fn, done = (lambda g: g.idle()), self.on_idle
            if fn is None:
                break
            try:
                if self.game is None:
                    self.game = open_game(self.address, self.code)
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
                    self.refreshing = False
                    if done == self.built:
                        self.build_btn.config(state="normal")
                    self.status.set("%s: %s" % (type(error).__name__, error))
                elif done is not None:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(50, self.pump)

    def tick(self):
        if self.stop:
            return
        if self.live.get() and self.rows and self.jobs.empty() and not self.refreshing:
            self.refreshing = True
            rows = self.rows
            self.job(lambda g: g.refresh(rows), self.refreshed)
        self.root.after(1000, self.tick)

    def refreshed(self, rows):
        self.refreshing = False
        self.update_values(rows)

    def close(self):
        self.stop = True
        self.jobs.put((None, None))
        self.root.destroy()

    # ------------------------------------------------------------ classes
    def on_game(self, g):
        built = getattr(self, "built_note", "")
        self.status.set("%s  |  %s%s" % (game_caption(g.meta), g.note, "  |  built: " + built if built else ""))
        self.names = sorted(g.classes)
        g.say = lambda text: self.out.put((self.status.set, text, None))
        self.with_static = g.starred
        self.star_box.config(text=g.star_label)
        self.fill_classes()
        first = getattr(g, "first_view", None)
        if first and self.view is None and first in g.classes:
            self.go(("class", first))

    def on_idle(self, result):
        """A slice of the reader's own work is done: its progress, and the class list when it grew."""
        text, changed = result
        if changed and self.game is not None:
            keep = self.picked_class()
            self.on_game(self.game)
            if keep in self.shown[:3000]:
                self.list.selection_set(self.shown.index(keep))
        elif text:
            self.count.set(text)

    def reload(self):
        def again(g):
            # Opened again, not only read again: a build may have made the other engine's file.
            g.b.close()
            self.game = None
            self.game = open_game(self.address, self.code)
            return self.game
        self.view = None
        self.rows = []
        self.job(again, self.on_game)

    def build(self):
        """Has the host make the map (Unity) or the profile (Unreal), then reads it."""
        g = self.game
        engine = getattr(g, "engine", "") if g is not None else ""
        if g is not None and len(g.classes) > 0:
            what = UE_PROFILE if "Unreal" in engine else MAP
            if not messagebox.askokcancel("Build map", "The game's folder has %s already.\n\nBuild it again? On a Switch "
                                          "a Unity map takes a few minutes, and the game is stopped meanwhile." % what,
                                          parent=self.root):
                return
        self.build_btn.config(state="disabled")
        self.built_note = ""
        self.status.set("starting the build...")

        def run():
            try:
                result = build_map(self.address, self.code, engine, lambda text: self.out.put((self.status.set, text, None)))
                self.out.put((self.built, result, None))
            except Exception as e:  # noqa: BLE001 - shown in the status line
                self.out.put((self.built, None, e))

        threading.Thread(target=run, daemon=True).start()

    def built(self, result):
        self.build_btn.config(state="normal")
        self.built_note = result
        self.reload()

    def fill_classes(self):
        words = self.filter.get().lower().split()
        fields = self.field_filter.get().lower().split()
        only = self.only_static.get() and not fields       # a field search looks at every class
        self.shown = [n for n in self.names if (not only or n in self.with_static) and all(w in n.lower() for w in words)
                      and (not fields or self.has_field(n, fields))]
        self.list.delete(0, "end")
        for n in self.shown[:3000]:
            self.list.insert("end", n)
        self.count.set("%d classes%s" % (len(self.shown), ", first 3000 shown" if len(self.shown) > 3000 else ""))

    def has_field(self, name, words):
        """Does the class have a field whose name holds every word?"""
        g = self.game
        if g is None:
            return False
        own = getattr(g, "own", None)
        names = own.get(name, ()) if own is not None else [f.name for f in g.classes[name].fields]
        return any(all(w in n.lower() for w in words) for n in names)

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
            if view[0] == "object":
                return g.view_object(view[1], view[2], view[3])
            return g.view_other(view)

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
                "" if r.offset is None else "+%X" % r.offset, r.type, r.value, what_of(r),
                "%X" % r.address if r.address else "", r.note if not r.note.startswith('"') else ""))
        # Field view of an address: the row that holds it is shown and picked.
        want, self.pick_address = getattr(self, "pick_address", None), None
        if want is not None:
            best = None
            for i, r in enumerate(rows):
                if r.address and r.address <= want and r.note != "struct" and (best is None or r.address >= rows[best].address):
                    best = i
            if best is not None:
                self.tree.selection_set(str(best))
                self.tree.see(str(best))
                return
        # A field search: the first field it found is shown and picked.
        words = [w.split(".")[-1] for w in self.field_filter.get().lower().split()]
        if words:
            for i, r in enumerate(rows):
                if r.note != "instance" and all(w in r.label.lower() for w in words):
                    self.tree.selection_set(str(i))
                    self.tree.see(str(i))
                    break

    def update_values(self, rows):
        if rows is not self.rows:
            return
        for i, r in enumerate(rows):
            if r.address and self.tree.exists(str(i)):
                self.tree.set(str(i), "value", r.value)
                self.tree.set(str(i), "what", what_of(r))

    def picked(self):
        sel = self.tree.selection()
        return self.rows[int(sel[0])] if sel else None

    def on_double(self, e):
        row_id = self.tree.identify_row(e.y)
        if not row_id:
            return
        r = self.rows[int(row_id)]
        base, pointer = base_type(r.type)
        if getattr(r, "open", None):      # an array or a struct with a view of its own
            self.go(r.open)
        elif r.target and (pointer or base in ("object",)) and base not in ("string", "System.String"):
            self.open_row(r)
        elif r.address and r.note != "struct":
            self.edit_row(r)

    def open_row(self, r):
        if r is not None and getattr(r, "open", None):
            self.go(r.open)
            return
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

    def link(self, tab, method):
        """The picked row's address, handed to another tab."""
        r = self.picked()
        if r is None or not r.address:
            self.status.set("pick a row with an address")
            return
        import studio_link
        width = len(r.raw) if len(r.raw) in (1, 2, 4, 8) else 4
        note = studio_link.send(self.root, tab, method, r.address, *([width] if method == "watch_address" else []))
        if note:
            self.status.set(note)

    def field_view(self, address):
        """Opens the object that holds the address, with the field at it picked. (Other tabs call this.)"""
        self.status.set("Field view: looking for the object that holds %X..." % address)

        def done(found):
            if found is None:
                self.status.set("Field view: no object of a known class holds %X%s" % (
                    address, "" if self.names and len(self.names) > 1 else " (the class list is not read yet)"))
                return
            obj, type_ = found
            self.status.set("Field view: %X is +%X in the object at %X" % (address, address - obj, obj))
            self.pick_address = address
            self.go(("object", obj, type_, "%X" % obj))
        self.job(lambda g: g.locate(address), done)

    def find_chain(self):
        r = self.picked()
        if r is None or not r.target:
            self.status.set("Find chain: pick a row that points at an object")
            return
        if not hasattr(self.game, "find_chains"):
            self.status.set("Find chain is for Unreal games here; Unity: Breeze's Main > Unity > Find chain")
            return
        self.status.set("Find chain: looking for who points at %X..." % r.target)
        self.go(("chains", r.target))

    def make_cheat(self):
        r = self.picked()
        if r is None or not r.address or r.note == "struct":
            self.status.set("Make cheat: pick a row with a value")
            return
        try:
            cheat_lines(r, r.raw)
        except (ValueError, RuntimeError) as e:
            self.status.set("Make cheat: %s" % e)
            return
        self.cheat_box = CheatBox(self, r)

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
        type_ = getattr(r, "bm", None) or ("ptr" if pointer else BOOKMARK_TYPE.get(base, "s32"))
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


def cheat_lines(row, data):
    """The cheat code that writes data at the row's place: its chain from main, then the store."""
    import studio_bookmarks as sb
    if not row.chain:
        raise ValueError("this row has no chain from main (an object from a class's list: Find chain first)")
    try:
        chain = sb.chain_of(sb.parse_expr(row.chain), {})
    except ValueError:
        chain = None
    if chain is None or chain[0] != "main":
        raise ValueError("this row has no chain from main (an object from a class's list: Find chain first)")
    offsets = chain[1]
    if len(data) not in (1, 2, 4, 8):
        raise ValueError("a value of %d bytes is not written by one store" % len(data))
    if any(o < 0 or o >> 32 for o in offsets[1:]) or offsets[0] < 0 or offsets[0] >> 40:
        raise ValueError("an offset of this chain does not fit a cheat")
    value = int.from_bytes(data, "little")
    width = len(data)
    if len(offsets) == 1:      # a static in main: one store, no register
        head = "0%d000000 %08X" % (width, offsets[0]) if not offsets[0] >> 32 else "0%d0000%02X %08X" % (width, offsets[0] >> 32, offsets[0] & 0xFFFFFFFF)
        return [head + (" %08X %08X" % (value >> 32, value & 0xFFFFFFFF) if width == 8 else " %08X" % value)]
    lines = ["580F00%02X %08X" % (offsets[0] >> 32, offsets[0] & 0xFFFFFFFF)]
    lines += ["580F1000 %08X" % o for o in offsets[1:-1]]
    lines.append("400E0000 %08X %08X" % (value >> 32, value & 0xFFFFFFFF))
    lines.append("A%dEF0200 %08X" % (width, offsets[-1]))
    return lines


class CheatBox:
    """Make cheat: a name and a value for the picked row, the code, Copy and Add."""

    def __init__(self, app, row):
        self.app, self.row = app, row
        w = self.win = tk.Toplevel(app.root)
        w.title("Make cheat")
        w.transient(app.root)
        f = ttk.Frame(w, padding=8)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="%s (%s)   %s" % (row.label.strip(), row.type, row.chain), wraplength=560).grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(f, text="Name").grid(row=1, column=0, sticky="w", pady=4)
        self.name = tk.StringVar(value=row.label.strip())
        ttk.Entry(f, textvariable=self.name, width=40).grid(row=1, column=1, columnspan=3, sticky="we")
        ttk.Label(f, text="Value").grid(row=2, column=0, sticky="w")
        self.value = tk.StringVar(value=row.value.split(" ")[0])
        ttk.Entry(f, textvariable=self.value, width=20).grid(row=2, column=1, sticky="w")
        ttk.Label(f, text="written again and again while the cheat is on", foreground="#555").grid(row=2, column=2, columnspan=2, sticky="w", padx=8)
        self.text = tk.Text(f, width=60, height=14, font=("Consolas", 10))
        self.text.grid(row=3, column=0, columnspan=4, pady=6, sticky="nsew")
        self.note = tk.StringVar()
        ttk.Label(f, textvariable=self.note, foreground="#555", wraplength=560).grid(row=4, column=0, columnspan=4, sticky="w")
        ttk.Button(f, text="Copy", command=self.copy).grid(row=5, column=1, sticky="e", pady=(6, 0))
        ttk.Button(f, text="Add to the game's cheats (off)", command=self.add).grid(row=5, column=2, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(f, text="Close", command=w.destroy).grid(row=5, column=3, sticky="e", pady=(6, 0))
        f.columnconfigure(1, weight=1)
        f.rowconfigure(3, weight=1)
        self.name.trace_add("write", lambda *a: self.fill())
        self.value.trace_add("write", lambda *a: self.fill())
        self.fill()

    def lines(self):
        g = self.app.game
        text = self.value.get().strip()
        if g is None:
            raise RuntimeError("not connected")
        data = g.encode(self.row, text) if hasattr(g, "encode") else self.row.raw
        return cheat_lines(self.row, data)

    def fill(self):
        try:
            body = "[%s]\n%s\n" % (self.name.get().strip() or "cheat", "\n".join(self.lines()))
            self.note.set("")
        except (ValueError, RuntimeError, struct.error) as e:
            body = ""
            self.note.set(str(e) or "not a value of this type")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", body)

    def copy(self):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(self.text.get("1.0", "end").strip() + "\n")
        self.note.set("copied")

    def add(self):
        # What is in the box is what is added: it may have been edited by hand.
        text = self.text.get("1.0", "end").strip()
        m = re.match(r"\[([^\]]+)\]\s*([0-9A-Fa-f\s]+)$", text)
        if not m:
            self.note.set("the box must hold one cheat: [name], then its code")
            return
        line = "cheats add [%s] %s" % (m.group(1), " ".join(m.group(2).split()))
        self.app.job(lambda g: g.b.cmd(line), lambda reply: self.note.set(
            reply + ("   (in memory: the Cheats tab's Save writes the file)" if reply.startswith("+OK") else "")))


def what_of(row):
    """The "what" column: what a pointer points at, a string's text, an enum value's name."""
    return getattr(row, "what", "") or (row.note if row.note.startswith('"') else "")


def breeze_bookmark_line(row):
    """`bookmark add ...` for a row: its chain as Breeze's bookmark holds it; None when it has none."""
    import studio_bookmarks as sb
    if not row.chain:
        return None
    chain = sb.chain_of(sb.parse_expr(row.chain), {})
    if chain is None:
        return None
    base, pointer = base_type(row.type)
    type_ = getattr(row, "bm", None) or ("ptr" if pointer else BOOKMARK_TYPE.get(base, "s32"))
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
