"""Breeze Studio: an Unreal game's objects, read from the game's memory (used by studio_objects).

It needs ue_profile.ini from the game's folder (Breeze makes it: Main > Unreal on a Switch,
`uemap` on an emulator host): where GWorld and the name pool are. Everything else is read from
the game's own reflection data and checked against the profile's offsets:

  * names: the name pool (4.23+), or the older GNames table;
  * a class's properties: FProperty (4.25+) or UProperty, with the parents';
  * every object: GUObjectArray, found once in main's data and kept by its offset;
  * the chain to an object: a search backwards with `refs`, a level at a time, from the object
    to a static slot in main or to an object of the engine route.

Python 3 only; no window of its own.
"""
import bisect
import os
import re
import struct
import time

ROUTE = "(engine route)"
GAS = "(attributes, GAS)"
GAS_KIND = "GasAttribute"   # a Prop kind of our own: an FGameplayAttributeData, Base +8, Current +C
MAX_ELEMENTS = 200
MAX_INSTANCES = 400
MAX_DEPTH = 2
MAX_STRUCT_ROWS = 40      # a bigger struct is opened on its own
SCAN_SLICE = 0.2          # seconds of the object scan between two views
CHAIN_LEVELS = 6          # pointers between a root and the object, at most
CHAIN_WIDTH = 16          # holders looked up per level
CHAIN_RESULTS = 12
BUFFER_RANGE = 0x800      # how far before a place its array's start is looked for
LOCATE_RANGE = 0x4000     # the same, for Field view of an address in no object

NUMBERS = {  # property type: (struct format, C-like name, bookmark type)
    "Int8Property": ("<b", "int8", "s8"), "Int16Property": ("<h", "int16", "s16"),
    "IntProperty": ("<i", "int", "s32"), "Int64Property": ("<q", "int64", "s64"),
    "ByteProperty": ("<B", "uint8", "u8"), "UInt16Property": ("<H", "uint16", "u16"),
    "UInt32Property": ("<I", "uint32", "u32"), "UInt64Property": ("<Q", "uint64", "u64"),
    "FloatProperty": ("<f", "float", "f32"), "DoubleProperty": ("<d", "double", "f64"),
}
OBJECT_KINDS = ("ObjectProperty", "ObjectPtrProperty", "ClassProperty", "ClassPtrProperty", "InterfaceProperty")


def ident(text):
    return bool(text) and len(text) <= 1024 and all(32 <= ord(c) < 127 for c in text)


def cap_of(name, names):
    """The attribute of the same set that caps this one, or None. Games name it every way:
    HealthMax, MaxHealth, CurrentAmmo / MaxAmmo, HealthPower / MaxHealth (Revenge of the Mage).
    Breeze's ue_gas.cpp max_sibling keeps the same rules."""
    if name.startswith("Max") or name.endswith("Max"):
        return None                     # a cap itself
    stems = [name]
    if name.startswith("Current") and len(name) > 7:
        stems.append(name[7:])
    stems += [name[:-len(s)] for s in ("Power", "Points", "Value", "Amount") if name.endswith(s) and len(name) > len(s)]
    have = set(names)
    for stem in stems:
        for want in (stem + "Max", "Max" + stem):
            if want != name and want in have:
                return want
    return None


def kind_of_attribute(name, gas, caps=()):
    """What a cheat on it should do: fill (from its cap), cap (of another attribute here),
    multiplier, set, or avoid (the game changes it: Current differs from Base, nothing caps it)."""
    if gas.get("cap"):
        return "fill from cap"
    if name in caps:
        return "cap"
    if "Multiplier" in name:
        return "multiplier"
    if abs(gas.get("base", 0) - gas.get("cur", 0)) > 1e-4:
        return "changed by the game"
    return "set"


class Prop:
    """One reflected property of a class or a struct."""

    def __init__(self, name, kind, offset, size, dim, owner):
        self.name, self.kind, self.offset, self.size, self.dim, self.owner = name, kind, offset, size, dim, owner
        self.type = kind
        self.target = 0       # the class of an object pointer, the struct, or the enum
        self.inner = None     # an array's element, a set's element, a map's key
        self.value = None     # a map's value (its .offset = where the value sits in an entry)
        self.entry = 0        # the size of one entry of a map or a set
        self.mask, self.byte = 0xFF, 0
        self.fmt = None
        self.bm = "s32"


class Row:
    """One line of the view (studio_objects shows it)."""

    def __init__(self, label, prop, address, chain, depth=0, offset=None, note=""):
        self.label, self.prop, self.address, self.chain = label, prop, address, chain
        self.type = prop.type if prop is not None else ""
        self.depth, self.offset, self.note = depth, offset, note
        self.value, self.raw, self.target, self.what = "", b"", 0, ""
        self.open = None      # the view a double-click opens, when it is not a plain pointer
        self.named = None     # the target `what` was last made for
        self.bm = prop.bm if prop is not None else "s32"


class Entry:
    """What the class list holds: studio_objects asks for .fields of a class."""
    fields = ()

    def __init__(self, ptr):
        self.ptr = ptr
        self.objects = []     # (item address, object, name index, name number)


class UeGame:
    """The connection, the profile and the reading. Worker thread only."""
    star_label = "with instances"
    engine = "Unreal"

    def __init__(self, b, meta, files, cache):
        self.b, self.meta, self.cache = b, meta, cache
        self.main, self.main_size = int(meta["main"], 16), int(meta["main_size"], 16)
        self.first_view = ROUTE
        self.load(files)

    # ------------------------------------------------------------ set-up
    def load(self, files=None):
        files = files if files is not None else self.b.files()
        self.dir = files.get("dir", "")
        self.have = {f["name"]: f.get("size", 0) for f in files.get("files", [])}
        self.pages, self.keep, self.names = {}, {}, {}
        self.layouts, self.enums, self.kinds = {}, {}, {}
        self.classes, self.starred = {ROUTE: Entry(0), GAS: Entry(0)}, {ROUTE, GAS}
        self.regions, self.region_starts = [], []
        self.scan, self.array = None, None
        self.own = {}             # class name -> its own property names (and its structs'), for "has field"
        self.index, self.index_starts = [], []    # every object (address, class, its place in the list)
        self.say = None           # set by the window: progress of a long job
        self.profile = {}
        text = self.b.get_file(self.dir + "ue_profile.ini").decode("utf-8", "replace")
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and not line.startswith("#"):
                value = value.strip()
                try:
                    self.profile[key.strip()] = self.main + int(value[5:], 16) if value.startswith("main+") else int(value, 16)
                except ValueError:
                    pass
        self.gworld = self.profile.get("j_UWorld_pointer", 0)
        self.name_off = self.profile.get("UObject.NamePrivate", 0x18) or 0x18
        if not self.gworld or not self.profile.get("NamePoolData"):
            raise RuntimeError("ue_profile.ini has no GWorld or no name pool: run the profile scan again (Breeze: Main > Unreal)")
        self.setup_names()
        self.calibrate()
        self.note = "Unreal: %s properties, names %s" % ("FProperty" if self.ffield else "UProperty",
                                                          "from GNames" if self.legacy else "from the name pool")
        self.scan = {"stage": "start"}

    def setup_names(self):
        pool = self.profile["NamePoolData"]
        self.legacy = self.profile.get("NameLayout", 0) == 1
        if not self.legacy:
            self.pool = pool + (self.profile.get("NamePoolBlocksOffset", 0) or 0x10)
            block = self.u64(self.pool)
            head = struct.unpack("<H", self.read(block, 2))[0] if block else 0
            self.shift = next((s for s in (6, 1) if head >> s == 4), 0)
            if not self.shift or self.name_at(0) != "None":
                raise RuntimeError("the name pool in ue_profile.ini does not read as one (name 0 is not None): run the profile scan again")
            return
        # GNames: a table of chunks of entry pointers; the profile has the table or the pointer to it.
        for table in (pool, self.u64(pool)):
            for chars in (0x10, 0xC):
                self.pool, self.chars = table, chars
                self.names = {}
                if table and self.name_at(0) == "None":
                    return
        raise RuntimeError("GNames in ue_profile.ini does not read as a name table: run the profile scan again")

    def calibrate(self):
        """The reflection offsets of this build, each found on the World class and checked by name."""
        world = self.u64(self.gworld)
        cls = self.u64(world + 0x10) if world else 0
        if not cls or self.obj_name(cls) != "World":
            raise RuntimeError("GWorld holds no World object now (the game is still starting?): try Reload")
        self.super_off = next((o for o in (0x40, 0x30, 0x48, 0x38, 0x28) if self.obj_name(self.u64(cls + o)) == "Object"), None)
        if self.super_off is None:
            raise RuntimeError("could not find the parent class in the World class")
        want = self.profile.get("UWorld.OwningGameInstance", 0)
        self.ffield = False
        anchor = None
        for child in (0x50, 0x48, 0x58, 0x60):
            for nxt, name in ((0x20, 0x28), (0x18, 0x20)):
                self.child_off, self.next_off, self.fname_off, self.ffield = child, nxt, name, True
                anchor = self.find_node(cls, "OwningGameInstance")
                if anchor:
                    break
            if anchor:
                break
        if not anchor:      # before 4.25: the properties are objects in the Children list
            self.ffield, self.child_off, self.next_off, self.fname_off = False, self.super_off + 8, 0x28, self.name_off
            anchor = self.find_node(cls, "OwningGameInstance")
        if not anchor:
            raise RuntimeError("could not read the World class's properties")
        slots = (0x4C, 0x44, 0x48, 0x50, 0x54, 0x40, 0x58, 0x5C)
        self.slot = next((s for s in slots if want and self.u32(anchor + s) == want), 0x4C if self.ffield else 0x44)
        self.size_off = next((self.slot - d for d in (0x14, 0x10, 0xC, 0x8) if self.u32(anchor + self.slot - d) == 8), self.slot - 0x14)
        self.type_off = next((self.slot + d for d in (0x2C, 0x24, 0x34, 0x3C, 0x1C)
                              if self.obj_name(self.u64(anchor + self.slot + d)) == "GameInstance"), self.slot + 0x2C)

    def find_node(self, cls, name):
        try:
            for node, n in self.nodes(cls):
                if n == name:
                    return node
        except Exception:  # noqa: BLE001 - a wrong guess of the layout
            pass
        return 0

    # ------------------------------------------------------------ memory
    def fresh(self):
        self.pages = {}

    def page(self, page, cache):
        if page not in cache:
            try:
                cache[page] = self.b.peek(page, 4096)
            except Exception as e:  # noqa: BLE001 - not mapped; a lost connection is passed on
                if isinstance(e, (OSError, ConnectionError)):
                    raise
                cache[page] = b""
        return cache[page]

    def read(self, address, n, cache=None):
        cache = self.pages if cache is None else cache
        out = b""
        while len(out) < n:
            at = address + len(out)
            data = self.page(at & ~0xFFF, cache)
            piece = data[at & 0xFFF:(at & 0xFFF) + n - len(out)]
            if not piece:
                raise RuntimeError("%X is not readable" % at)
            out += piece
        return out

    def u64(self, address, cache=None):
        if address < 0x10000 or address >> 48:
            return 0
        try:
            return struct.unpack("<Q", self.read(address, 8, cache))[0]
        except RuntimeError:
            return 0

    def u32(self, address, cache=None):
        if address < 0x10000 or address >> 48:
            return 0
        try:
            return struct.unpack("<I", self.read(address, 4, cache))[0]
        except RuntimeError:
            return 0

    def bulk(self, address, n):
        """n bytes in as few commands as the host allows."""
        if getattr(self, "no_peekb", False) is False:
            try:
                reply = self.b.cmd("peekb %x %d" % (address, n))
                if isinstance(reply, tuple) and len(reply[1]) == n:
                    return reply[1]
            except (OSError, ConnectionError):
                raise
            except Exception:  # noqa: BLE001 - a console has no peekb
                pass
            self.no_peekb = True
        out = b""
        while len(out) < n:
            out += self.b.peek(address + len(out), min(4096, n - len(out)))
        return out

    # ------------------------------------------------------------ names
    def name_at(self, index, number=0):
        base = self.names.get(index)
        if base is None:
            base = self.names[index] = self.decode_name(index)
        return base if not number or not base else "%s_%d" % (base, number - 1)

    def decode_name(self, index):
        # The pool only grows, so its pages are kept; a page read before a name was added is read again.
        for again in (False, True):
            try:
                if self.legacy:
                    entry = self.u64(self.u64(self.pool + (index >> 14) * 8, self.keep) + (index & 0x3FFF) * 8, self.keep)
                    if not entry:
                        raise RuntimeError("no entry")
                    wide = self.u32(entry + (8 if self.chars == 0xC else 0), self.keep) & 1
                    data = self.read(entry + self.chars, 128, self.keep)
                    if wide:
                        text = data.decode("utf-16-le", "replace").split("\0")[0]
                    else:
                        text = data.split(b"\0")[0].decode("latin-1")
                else:
                    block = self.u64(self.pool + (index >> 16) * 8, self.keep)
                    entry = block + (index & 0xFFFF) * 2
                    head = struct.unpack("<H", self.read(entry, 2, self.keep))[0]
                    n = head >> self.shift
                    if not block or not n:
                        raise RuntimeError("no entry")
                    if head & 1:
                        text = self.read(entry + 2, n * 2, self.keep).decode("utf-16-le", "replace")
                    else:
                        text = self.read(entry + 2, n, self.keep).decode("latin-1")
                if ident(text):
                    return text
            except RuntimeError:
                pass
            if not again:
                self.keep = {}
        return ""

    def fname(self, address, cache=None):
        try:
            index, number = struct.unpack("<II", self.read(address, 8, cache))
        except RuntimeError:
            return ""
        return self.name_at(index, number) if index < 0x4000000 else ""

    def obj_name(self, obj, cache=None):
        if obj < 0x10000 or obj >> 48 or obj & 7:
            return ""
        return self.fname(obj + self.name_off, cache)

    def class_name(self, obj):
        return self.obj_name(self.u64(obj + 0x10))

    def describe_object(self, obj):
        """'Name (Class)' of an object, '' when it is not one."""
        name = self.obj_name(obj)
        cls = self.class_name(obj) if name else ""
        return "%s (%s)" % (name, cls) if cls else ""

    # ------------------------------------------------------------ reflection
    def nodes(self, struct_ptr):
        """(node, name) of a class's own properties, in the order the engine links them."""
        node, seen = self.u64(struct_ptr + self.child_off), 0
        while node and seen < 4000:
            name = self.fname(node + self.fname_off)
            if not name:
                raise RuntimeError("a property without a name")
            yield node, name
            node = self.u64(node + self.next_off)
            seen += 1

    def kind_of(self, node):
        if self.ffield:
            fclass = self.u64(node + 8)
            kind = self.kinds.get(fclass)
            if kind is None:
                # FFieldClass: the name first, or (UE 5.8, Revenge of the Mage) a vtable and then it.
                off = getattr(self, "fclass_name_off", None)
                if off is None:
                    off = next((o for o in (0, 8) if self.fname(fclass + o).endswith("Property")), None)
                    if off is not None:
                        self.fclass_name_off = off
                kind = self.kinds[fclass] = self.fname(fclass + (off or 0))
            return kind
        return self.class_name(node)

    def make_prop(self, node, name, owner):
        kind = self.kind_of(node)
        if not kind.endswith("Property"):
            return None       # a function or an enum in a pre-4.25 Children list
        p = Prop(name, kind, self.u32(node + self.slot), self.u32(node + self.size_off),
                 max(1, self.u32(node + self.size_off - 4)), owner)
        extra = self.u64(node + self.type_off)
        if kind in NUMBERS:
            p.fmt, p.type, p.bm = NUMBERS[kind]
            if kind == "ByteProperty" and extra and self.obj_name(extra):
                p.target, p.type = extra, "enum %s (uint8)" % self.obj_name(extra)
        elif kind == "BoolProperty":
            _size, byte, mask, field = struct.unpack("<4B", self.read(node + self.type_off, 4))
            p.byte, p.mask = byte, mask or 0xFF
            p.type, p.bm = ("bool" if field == 0xFF else "bool :%02X" % p.mask), "u8"
        elif kind in OBJECT_KINDS:
            p.target, p.bm = extra, "ptr"
            p.type = (self.obj_name(extra) or "Object") + "*"
        elif kind == "StructProperty":
            p.target, p.type = extra, "struct " + (self.obj_name(extra) or "?")
        elif kind == "EnumProperty":
            p.target = self.u64(node + self.type_off + 8)
            under = self.kind_of(extra) if extra else ""
            p.fmt, _t, p.bm = NUMBERS.get(under, NUMBERS["ByteProperty" if p.size == 1 else "IntProperty"])
            p.type = "enum " + (self.obj_name(p.target) or "?")
        elif kind == "ArrayProperty":
            p.inner = self.make_prop(extra, "", owner) if extra else None
            p.type, p.bm = "TArray<%s>" % (p.inner.type if p.inner is not None else "?"), "ptr"
        elif kind == "MapProperty":
            # KeyProp, ValueProp, then FScriptMapLayout: ValueOffset, HashNextIdOffset, HashIndexOffset, Size
            # (measured on UE 4.27: an enum -> int map has entries of 16, the value at +4).
            value = self.u64(node + self.type_off + 8)
            p.inner = self.make_prop(extra, "key", owner) if extra else None
            p.value = self.make_prop(value, "value", owner) if value else None
            p.entry = self.u32(node + self.type_off + 0x1C)
            p.type, p.bm = "TMap<%s, %s>" % (p.inner.type if p.inner is not None else "?",
                                             p.value.type if p.value is not None else "?"), "ptr"
        elif kind == "SetProperty":
            # ElementProp, then FScriptSetLayout: HashNextIdOffset, HashIndexOffset, Size (not measured)
            p.inner = self.make_prop(extra, "element", owner) if extra else None
            p.entry = self.u32(node + self.type_off + 0x10)
            p.type, p.bm = "TSet<%s>" % (p.inner.type if p.inner is not None else "?"), "ptr"
        elif kind == "NameProperty":
            p.type = "FName"
        elif kind == "StrProperty":
            p.type, p.bm = "FString", "ptr"
        else:
            p.type = kind[:-8]
        return p

    def supers(self, struct_ptr):
        chain = []
        while struct_ptr and len(chain) < 64 and struct_ptr not in chain:
            chain.append(struct_ptr)
            struct_ptr = self.u64(struct_ptr + self.super_off)
        return chain

    def props(self, struct_ptr):
        """The properties of a class or a struct with its parents', by offset."""
        out = self.layouts.get(struct_ptr)
        if out is None:
            out = []
            for s in reversed(self.supers(struct_ptr)):
                owner = self.obj_name(s)
                try:
                    for node, name in self.nodes(s):
                        p = self.make_prop(node, name, owner)
                        if p is not None:
                            out.append(p)
                except RuntimeError:
                    pass
            out.sort(key=lambda p: (p.offset, p.mask))
            self.layouts[struct_ptr] = out
        return out

    def enum_name(self, enum, value):
        names = self.enums.get(enum)
        if names is None:
            names = self.enums[enum] = {}
            for off in (0x40, 0x48, 0x50, 0x38):
                data, n, cap = self.u64(enum + off), self.u32(enum + off + 8), self.u32(enum + off + 12)
                if not data or not 0 < n <= cap <= 4096:
                    continue
                try:
                    raw = self.read(data, n * 16)
                except RuntimeError:
                    continue
                found = {}
                for i in range(n):
                    index, number, v = struct.unpack_from("<IIq", raw, i * 16)
                    text = self.name_at(index, number) if index < 0x4000000 else ""
                    if not text:
                        found = {}
                        break
                    found.setdefault(v, text.rpartition("::")[2])
                if found:
                    names.update(found)
                    break
        return names.get(value, "")

    # ------------------------------------------------------------ values
    def describe(self, row):
        p = row.prop
        if p is None or not row.address:
            return
        try:
            if p.kind == GAS_KIND:      # row.address = CurrentValue, BaseValue 4 before it
                raw = self.read(row.address - 4, 8)
                base, cur = struct.unpack("<ff", raw)
                row.raw = raw[4:]
                row.value = "%.7g" % cur
                gas = row.gas
                gas["base"], gas["cur"] = base, cur
                what = "base %.7g" % base if base != cur else ""
                if gas.get("cap"):
                    what = ("cap %s" % gas["cap"]) + ("   " + what if what else "")
                row.what = what
            elif p.bm == "ptr" and p.kind in OBJECT_KINDS:
                row.raw = self.read(row.address, 8)
                row.target = struct.unpack("<Q", row.raw)[0]
                row.value = "%X" % row.target if row.target else "null"
                if row.named != row.target:
                    row.named, row.what = row.target, self.describe_object(row.target) if row.target else ""
            elif p.fmt is not None:
                row.raw = self.read(row.address, struct.calcsize(p.fmt))
                v = struct.unpack(p.fmt, row.raw)[0]
                row.value = ("%.7g" % v) if isinstance(v, float) else str(v)
                if p.target and not isinstance(v, float):
                    row.what = self.enum_name(p.target, v)
            elif p.kind == "BoolProperty":
                row.raw = self.read(row.address, 1)
                row.value = "1" if row.raw[0] & p.mask else "0"
            elif p.kind == "NameProperty":
                row.raw = self.read(row.address, 8)
                index, number = struct.unpack("<II", row.raw)
                row.value, row.what = "%d" % index, '"%s"' % self.name_at(index, number)
            elif p.kind == "StrProperty":
                row.raw = self.read(row.address, 8)
                row.target = 0
                data, n = struct.unpack("<Q", row.raw)[0], self.u32(row.address + 8)
                row.value = "%X" % data if data else "null"
                row.what = '"%s"' % self.read(data, min(n, 120) * 2).decode("utf-16-le", "replace").rstrip("\0") if data and 0 < n < 4096 else ""
            elif p.kind == "ArrayProperty":
                row.raw = self.read(row.address, 8)
                data, n = struct.unpack("<Q", row.raw)[0], self.u32(row.address + 8)
                row.value = "%d items" % n if data else "empty"
                row.target = 0
                row.open = ("array", data, n, p.inner, "[%s]" % row.chain if row.chain else "%X" % data, row.label.strip()) \
                    if data and p.inner is not None and 0 < n <= 0x100000 else None
            elif p.kind in ("MapProperty", "SetProperty"):
                row.raw = self.read(row.address, 8)
                data, n = struct.unpack("<Q", row.raw)[0], self.u32(row.address + 8)
                row.value = "%d entries" % (n - self.u32(row.address + 0x34)) if data else "empty"
                row.target = 0
                row.open = ("map", row.address, p, "[%s]" % row.chain if row.chain else "%X" % data, row.label.strip()) \
                    if data and p.inner is not None and p.entry and 0 < n <= 0x100000 else None
            elif p.kind == "WeakObjectProperty":
                row.raw = self.read(row.address, 8)
                index, serial = struct.unpack("<II", row.raw)
                row.value = "object #%d" % index if serial else "null"
            else:
                row.raw = self.read(row.address, min(max(p.size, 1), 8))
                row.value = row.raw[::-1].hex().upper()
        except RuntimeError as e:
            row.value, row.raw = "(%s)" % str(e)[:40], b""

    def rows_for(self, props, address, chain, depth=0):
        rows = []
        for p in props:
            for i in range(min(p.dim, 16)):
                off = p.offset + i * p.size
                at = address + off + (p.byte if p.kind == "BoolProperty" else 0)
                label = ("    " * depth) + p.name + ("[%d]" % i if p.dim > 1 else "")
                step = off + (p.byte if p.kind == "BoolProperty" else 0)
                row = Row(label, p, at if address else 0, "%s+%X" % (chain, step) if chain else "", depth, off, p.owner)
                rows.append(row)
                if p.kind == "StructProperty" and p.target:
                    inner = self.props(p.target)
                    row.note = "struct"
                    if depth < MAX_DEPTH and len(inner) <= MAX_STRUCT_ROWS:
                        rows += self.rows_for(inner, at if address else 0, row.chain, depth + 1)
                    elif address:
                        row.value = "%d fields" % len(inner)
                        row.open = ("struct", at, p.target, row.chain, label.strip())
                elif address:
                    self.describe(row)
        return rows

    def refresh(self, rows):
        self.fresh()
        for row in rows:
            if row.address and row.note != "struct":
                self.describe(row)
        return rows

    def write(self, row, text):
        p = row.prop
        if p is None or not row.address:
            raise RuntimeError("this row has no value to change")
        at = row.address
        if p.kind == GAS_KIND:      # Base and Current together, or the next recompute undoes it
            data, at = struct.pack("<ff", float(text), float(text)), row.address - 4
        elif p.kind in OBJECT_KINDS:
            data = struct.pack("<Q", int(text, 16))
        elif p.fmt is not None:
            data = struct.pack(p.fmt, float(text) if p.fmt in ("<f", "<d") else int(text, 0))
        elif p.kind == "BoolProperty":
            self.fresh()
            old = self.read(row.address, 1)[0]
            on = text.strip().lower() not in ("0", "false", "no", "off", "")
            data = bytes([(old | p.mask) if on else (old & ~p.mask & 0xFF)])
        else:
            raise RuntimeError("a %s is not changed from here" % p.type)
        reply = self.b.cmd("poke %X %s" % (at, data.hex()))
        if not reply.startswith("+OK"):
            raise RuntimeError(reply)
        self.fresh()
        self.describe(row)
        return row

    # ------------------------------------------------------------ views
    def pointer_row(self, label, address, chain, note=""):
        p = Prop(label, "ObjectProperty", 0, 8, 1, note)
        p.bm = "ptr"
        row = Row(label, p, address, chain, 0, None, note)
        self.describe(row)
        cls = self.class_name(row.target) if row.target else ""
        row.type = p.type = (cls or "Object") + "*"
        return row

    def view_route(self):
        """GWorld to the player's pawn, by the profile's offsets: where a walk starts."""
        pr = self.profile
        rows = [self.pointer_row("GWorld", self.gworld, "main+%X" % (self.gworld - self.main), "static")]
        steps = [("OwningGameInstance", pr.get("UWorld.OwningGameInstance", 0), False),
                 ("LocalPlayers[0]", pr.get("UGameInstance.LocalPlayers", 0), True),
                 ("PlayerController", pr.get("UPlayer.PlayerController", 0), False),
                 ("AcknowledgedPawn", pr.get("APlayerController.AcknowledgedPawn", 0), False),
                 ("CharacterMovement", pr.get("ACharacter.CharacterMovement", 0), False)]
        for label, off, array in steps:
            last = rows[-1]
            if not last.target or not off:
                break
            chain, at = "[%s]+%X" % (last.chain, off), last.target + off
            if array:        # the first element of a TArray
                chain, at = "[%s]+0" % chain, self.u64(at)
                if not at:
                    break
            rows.append(self.pointer_row(label, at, chain, self.class_name(last.target)))
        return "Engine route: double-click a row to open that object", rows

    # ------------------------------------------------------------ GAS attributes
    def is_a(self, cls, name):
        return any(self.obj_name(s) == name for s in self.supers(cls)) if cls else False

    def prop_named(self, cls, name):
        return next((p for p in self.props(cls) if p.name == name), None)

    def gas_file(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "views",
                            "%s_gas.txt" % self.meta.get("title_id", "game").upper())

    def gas_settings(self):
        """{"cap": {attribute: its cap}, "set": {index: class}}: the overrides and the set classes
        that cheats were made with, from views/<TID>_gas.txt."""
        out = {"cap": {}, "set": {}}
        try:
            for line in open(self.gas_file(), encoding="utf-8"):
                m = re.match(r"\s*(cap|set)\s+(\S+)\s*=\s*(\S*)", line)
                if m:
                    out[m.group(1)][m.group(2)] = m.group(3)
        except OSError:
            pass
        return out

    def save_gas_setting(self, kind, key, value):
        s = self.gas_settings()
        s[kind][str(key)] = value
        path = self.gas_file()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Breeze Studio, Objects > %s: cap <attribute> = <its cap> (empty: none),\n"
                    "# set <index> = the set class cheats were made with (checked on every view)\n" % GAS)
            for k in ("cap", "set"):
                for name, v in sorted(s[k].items()):
                    f.write("%s %s = %s\n" % (k, name, v))

    def find_asc(self):
        """(ASC object, its chain, how it was found) from the engine route, or raises."""
        route = {r.label: r for r in self.view_route()[1]}
        pawn, pc = route.get("AcknowledgedPawn"), route.get("PlayerController")
        tried = []
        holders = [(n, r) for n, r in (("pawn", pawn), ("controller", pc)) if r is not None and r.target]
        for holder_name, holder in holders:
            cls = self.u64(holder.target + 0x10)
            for p in self.props(cls):
                if p.kind in OBJECT_KINDS and p.kind not in ("ClassProperty", "ClassPtrProperty") and \
                        self.is_a(p.target, "AbilitySystemComponent"):
                    asc = self.u64(holder.target + p.offset)
                    if asc:
                        return asc, "[%s]+%X" % (holder.chain, p.offset), "%s.%s" % (holder_name, p.name)
            tried.append(holder_name)
            # Many games keep the ASC on the PlayerState, so it survives a respawn.
            ps = self.prop_named(cls, "PlayerState")
            state = self.u64(holder.target + ps.offset) if ps is not None else 0
            if state:
                scls = self.u64(state + 0x10)
                for p in self.props(scls):
                    if p.kind in OBJECT_KINDS and self.is_a(p.target, "AbilitySystemComponent"):
                        asc = self.u64(state + p.offset)
                        if asc:
                            return asc, "[[%s]+%X]+%X" % (holder.chain, ps.offset, p.offset), \
                                "%s.PlayerState.%s" % (holder_name, p.name)
        if pawn is None or not pawn.target:
            raise RuntimeError("no pawn on the engine route now (in a menu or loading?): try again in game")
        raise RuntimeError("no AbilitySystemComponent property on the %s or its PlayerState: not a GAS game"
                           % " or ".join(tried))

    def is_attribute_struct(self, struct_ptr):
        return self.is_a(struct_ptr, "GameplayAttributeData")

    def gas_sets(self):
        """[(index, set object, its chain, class name, [(prop, offset)])] and how the ASC was found."""
        asc, asc_chain, how = self.find_asc()
        spawned = self.prop_named(self.u64(asc + 0x10), "SpawnedAttributes")
        if spawned is None:
            raise RuntimeError("the AbilitySystemComponent has no SpawnedAttributes property")
        data, n = self.u64(asc + spawned.offset), self.u32(asc + spawned.offset + 8)
        sets = []
        for i in range(min(n, 64)):
            obj = self.u64(data + i * 8)
            if not obj:
                continue
            cls = self.u64(obj + 0x10)
            attrs = [p for p in self.props(cls) if p.kind == "StructProperty" and self.is_attribute_struct(p.target)]
            sets.append((i, obj, "[[%s]+%X]+%X" % (asc_chain, spawned.offset, i * 8), self.obj_name(cls), attrs))
        return sets, "%s, SpawnedAttributes +%X" % (how, spawned.offset)

    def view_gas(self, show_all=False):
        self.fresh()
        sets, how = self.gas_sets()
        settings = self.gas_settings()
        rows, hidden, moved = [], 0, []
        for i, obj, chain, cname, attrs in sets:
            head = self.pointer_row("SpawnedAttributes[%d]" % i, 0, chain, "set")
            head.address, head.target, head.type = 0, obj, cname + "*"
            head.value, head.what = "%X" % obj, "%s, %d attributes" % (cname, len(attrs))
            head.gas_set = (i, cname)
            rows.append(head)
            want = settings["set"].get(str(i))
            if want and want != cname:
                moved.append("[%d] was %s when cheats were made, now %s" % (i, want, cname))
            names = [p.name for p in attrs]
            offsets = {p.name: p.offset for p in attrs}
            raw = self.read(obj, max(p.offset for p in attrs) + 0x10) if attrs else b""
            gas_rows = []
            for p in attrs:
                base, cur = struct.unpack_from("<ff", raw, p.offset + 8)
                if not show_all and base == 0 and cur == 0:
                    hidden += 1
                    continue
                cap = settings["cap"].get(p.name, None)
                cap = (cap or None) if cap is not None else cap_of(p.name, names)
                a = Prop(p.name, GAS_KIND, p.offset, 0x10, 1, cname)
                a.type, a.bm, a.fmt = "attribute", "f32", None
                row = Row("    " + p.name, a, obj + p.offset + 0xC, "[%s]+%X" % (chain, p.offset + 0xC), 1, p.offset)
                row.gas = {"set": i, "set_class": cname, "offset": p.offset, "cap": cap,
                           "cap_offset": offsets.get(cap) if cap else None, "chain": chain}
                self.describe(row)
                gas_rows.append(row)
            caps = {r.gas["cap"] for r in gas_rows if r.gas["cap"]}
            for row in gas_rows:
                row.note = kind_of_attribute(row.prop.name, row.gas, caps)
            rows += gas_rows
        if hidden:
            more = Row("(%d attributes at 0 hidden: double-click to show them)" % hidden, None, 0, "")
            more.open = ("gas", True)
            rows.append(more)
        title = "GAS attributes: %d sets (%s). Edit writes Base and Current; select several, then Make cheats" % (len(sets), how)
        if moved:
            title = "SET MOVED: " + "; ".join(moved) + "   " + title
        return title, rows

    def view_class(self, name):
        self.fresh()
        if name == ROUTE:
            return self.view_route()
        if name == GAS:
            return self.view_gas()
        entry = self.classes[name]
        chain = [self.obj_name(s) for s in self.supers(entry.ptr)]
        objects = sorted(entry.objects, key=lambda o: self.name_at(o[2]).startswith("Default__"))
        rows = []
        for item, obj, index, number in objects[:MAX_INSTANCES]:
            p = Prop("", "ObjectProperty", 0, 8, 1, "")
            p.type, p.bm = name.split(" ")[0] + "*", "ptr"
            row = Row(self.name_at(index, number) or "?", p, item, "", 0, None, "instance")
            self.describe(row)
            if row.target != obj:
                row.note = "gone"
            else:        # objects of one class often share a name: say whose each one is
                outer = self.obj_name(self.u64(obj + self.name_off + 8))
                row.what = "in " + outer if outer else row.what
            rows.append(row)
        rows += self.rows_for(self.props(entry.ptr), 0, "")
        more = ", first %d shown" % MAX_INSTANCES if len(objects) > MAX_INSTANCES else ""
        return "%s   %d objects%s, then the layout" % (" : ".join(chain) or name, len(objects), more), rows

    def view_object(self, obj, declared, chain):
        self.fresh()
        cls = self.u64(obj + 0x10)
        cname = self.obj_name(cls) if self.obj_name(obj) else ""
        if not cname:
            p = Prop("", "UInt64Property", 0, 8, 1, "")
            p.fmt, p.type, p.bm = "<Q", "uint64", "u64"
            rows = []
            for off in range(0, 0x100, 8):
                row = Row("+%X" % off, p, obj + off, "%s+%X" % (chain, off), 0, off)
                self.describe(row)
                row.value = "%X" % struct.unpack("<Q", row.raw)[0] if row.raw else row.value
                rows.append(row)
            return "%X is not an Unreal object: raw values" % obj, rows
        parents = " : ".join(self.obj_name(s) for s in self.supers(cls))
        outer = self.obj_name(self.u64(obj + self.name_off + 8))
        title = "%s  (%s)  at %X%s" % (self.obj_name(obj), parents, obj, "   in " + outer if outer else "")
        return title, self.rows_for(self.props(cls), obj, chain)

    # ------------------------------------------------------------ the chain to an object
    def object_at(self, address):
        """(object, class, its place in the object list) of the object that holds this address, or None."""
        i = bisect.bisect_right(self.index_starts, address) - 1
        if i < 0:
            return None
        obj, cls, item = self.index[i]
        # PropertiesSize follows the property list's head in a UStruct.
        size = self.u32(cls + self.child_off + 8)
        return (obj, cls, item) if address < obj + min(max(size, 0x28), 0x10000) else None

    def locate(self, address):
        """The object that holds an address: (object, its class name + "*"), or None."""
        if not self.index:
            raise RuntimeError("the object list is not read yet: try again in a moment")
        self.fresh()
        holder = self.object_at(address)
        if holder is None:
            return self.container_holding(address)
        return holder[0], (self.obj_name(holder[1]) or "Object") + "*"

    def container_prop(self, struct_ptr, off, depth=0):
        """(property, its offset) of the TArray / TMap / TSet field whose data pointer is at off, or None.
        Looks into struct fields too."""
        for p in self.props(struct_ptr):
            for i in range(min(p.dim, 16)):
                at = p.offset + i * p.size
                if p.kind in ("ArrayProperty", "MapProperty", "SetProperty") and at == off:
                    return p, at
                if p.kind == "StructProperty" and p.target and depth < 3 and at <= off < at + p.size:
                    found = self.container_prop(p.target, off - at, depth + 1)
                    if found:
                        return found[0], at + found[1]
        return None

    def container_holding(self, address):
        """For an address in no object: the object whose TArray, TMap or TSet has its memory there.
        Returns (object, its class + "*", the view of that container), or None."""
        for w, v in self.refs(address, LOCATE_RANGE):
            holder = self.object_at(w)
            if holder is None:
                continue
            obj, cls, _item = holder
            found = self.container_prop(cls, w - obj)
            if found is None:
                continue
            p, off = found
            n = self.u32(w + 8)
            chain = "[%X+%X]" % (obj, off)
            if p.kind == "ArrayProperty":
                if p.inner is None or not 0 < n <= 0x100000 or address - v >= n * max(p.inner.size, 1):
                    continue
                view = ("array", v, n, p.inner, chain, p.name)
            else:
                if p.inner is None or not p.entry or not 0 < n <= 0x100000 or address - v >= n * p.entry:
                    continue
                view = ("map", w, p, chain, p.name)
            return obj, (self.obj_name(cls) or "Object") + "*", view
        return None

    def refs(self, address, back=0):
        """[(where, value)]: the places in writable memory that point at address, or up to `back` before it."""
        reply = self.b.cmd("refs %X %X 400 30" % (address, back))
        if not reply.startswith("+OK"):
            raise RuntimeError("refs: " + reply[:100])
        out = []
        for line in reply.splitlines()[1:]:
            m = re.match(r"([0-9A-Fa-f]+) \S+ -> ([0-9A-Fa-f]+)", line)
            if m:
                out.append((int(m.group(1), 16), int(m.group(2), 16)))
        return out

    def step_name(self, cls, off):
        """The property of a class that holds offset off; the bare offset when none does."""
        best = None
        for p in self.props(cls):
            if p.offset <= off < p.offset + max(p.size * p.dim, 1):
                best = p
        if best is None:
            return "+%X" % off
        return best.name if off == best.offset else "%s+%X" % (best.name, off - best.offset)

    def find_chains(self, target):
        """Pointer chains from main to the object at target: [(chain of the place that holds it, the path in words)].

        Backwards, a level at a time. Who points at the object? A holder inside another object
        is reached through that object; a holder in no object (the memory of an array or a
        map) through whoever points a little before it with a count and a size behind the
        pointer. A chain ends at a static slot in main or in an object of the engine route.
        Every chain returned was walked forwards again and reached the object."""
        if not self.index:
            raise RuntimeError("the object list is not read yet")
        say = self.say or (lambda text: None)
        self.fresh()
        roots = {}       # an object of the engine route -> (its offsets from main, its label)
        for r in self.view_route()[1]:
            if r.target:
                roots.setdefault(r.target, (self.offsets_of(r.chain) + [0], r.label))
        link = {}        # a place -> (the place it leads to or None, the offset added to its value, its name)
        results = []

        def emit(place, offsets, names, route=False):
            # offsets: main's, then one per pointer; the last is the place's own
            while True:
                nxt, off, name = link[place]
                if name:
                    names.append(name)
                if nxt is None:
                    break
                if not link[nxt][2]:
                    names.append("[+%X]" % off)
                offsets = offsets + [off]
                place = nxt
            at = self.main + offsets[0]
            for off in offsets[1:]:
                at = self.u64(at) + off
            if self.u64(at) == target:
                expr = "main+%X" % offsets[0]
                for off in offsets[1:]:
                    expr = "[%s]+%X" % (expr, off)
                results.append((not route, len(offsets), expr, " > ".join(names), at))

        level, seen, first = [(None, target)], {target}, None
        for depth in range(CHAIN_LEVELS):
            nxt_level = []
            for n, (place, obj) in enumerate(level[:CHAIN_WIDTH]):
                say("Find chain: level %d, look-up %d of %d, %d found" % (depth + 1, n + 1, min(len(level), CHAIN_WIDTH), len(results)))
                if obj is not None:
                    own = self.object_at(obj)
                    hits = [(w, place - obj if place else 0) for w, _v in self.refs(obj) if own is None or w != own[2]]
                else:
                    hits = []
                    for w, v in self.refs(place, BUFFER_RANGE):
                        num, cap = struct.unpack("<II", self.read(w + 8, 8))
                        if 0 < num <= cap <= 0x100000 and place - v < cap * 0x200:
                            hits.append((w, place - v))
                for w, off in hits:
                    if w in link:
                        continue
                    if self.main <= w < self.main + self.main_size:
                        link[w] = (place, off, "")
                        emit(w, [w - self.main], ["main+%X" % (w - self.main)])
                        continue
                    holder = self.object_at(w)
                    if holder is None:
                        link[w] = (place, off, "")
                        nxt_level.append((w, None))
                        continue
                    o, cls, item = holder
                    link[w] = (place, off, self.step_name(cls, w - o))
                    if o in roots:
                        offsets, label = roots[o]
                        emit(w, offsets[:-1] + [w - o], [label], True)
                    elif o not in seen and not self.obj_name(o).startswith("Default__"):
                        seen.add(o)
                        nxt_level.append((w, o))
            level = nxt_level
            # A static slot found first may be a table the engine keeps for itself: two more
            # levels are given to a chain through the engine route's named fields.
            if results and first is None:
                first = depth
            if not level or any(not r[0] for r in results) or (first is not None and depth >= first + 2):
                break
        results.sort()
        return results[:CHAIN_RESULTS]

    def offsets_of(self, chain):
        """A row's chain as offsets: main's first, then one per pointer."""
        import studio_bookmarks as sb
        c = sb.chain_of(sb.parse_expr(chain), {})
        if c is None or c[0] != "main":
            raise RuntimeError("not a chain from main: " + chain)
        return list(c[1])

    def view_chains(self, target):
        found = self.find_chains(target)
        rows = []
        for static, steps, expr, path, at in found:
            row = self.pointer_row(path, at, expr, "%d pointers, %s" % (steps - 1, "static slot" if static else "engine route"))
            rows.append(row)
        what = self.describe_object(target)
        if self.say:
            self.say("Find chain: %d found" % len(rows))
        if not rows:
            return "No chain found to %s at %X (within %d pointers)" % (what, target, CHAIN_LEVELS), rows
        return "Chains to %s: double-click one to open the object with that chain" % what, rows

    def encode(self, row, text):
        """A typed value as the bytes of this row's field."""
        p = row.prop
        if p is None:
            raise RuntimeError("this row has no value")
        if p.kind == GAS_KIND:
            return struct.pack("<f", float(text))
        if p.kind in OBJECT_KINDS:
            return struct.pack("<Q", int(text, 16))
        if p.fmt is not None:
            return struct.pack(p.fmt, float(text) if p.fmt in ("<f", "<d") else int(text, 0))
        if p.kind == "BoolProperty":
            old = row.raw[0] if row.raw else 0
            on = text.strip().lower() not in ("0", "false", "no", "off", "")
            return bytes([(old | p.mask) if on else (old & ~p.mask & 0xFF)])
        raise RuntimeError("a %s is not written by a cheat from here" % p.type)

    def view_other(self, view):
        self.fresh()
        if view[0] == "gas":
            return self.view_gas(view[1])
        if view[0] == "chains":
            return self.view_chains(view[1])
        if view[0] == "struct":
            _k, at, struct_ptr, chain, label = view
            return "%s  struct %s  at %X" % (label, self.obj_name(struct_ptr), at), self.rows_for(self.props(struct_ptr), at, chain)
        if view[0] == "map":
            return self.view_map(view)
        _k, data, n, inner, chain, label = view
        rows = []
        size = max(inner.size, 1)
        for i in range(min(n, MAX_ELEMENTS)):
            at = data + i * size
            row = Row("[%d]" % i, inner, at, "%s+%X" % (chain, i * size), 0, i * size)
            rows.append(row)
            if inner.kind == "StructProperty" and inner.target:
                row.note = "struct"
                fields = self.props(inner.target)
                if len(fields) <= MAX_STRUCT_ROWS:
                    rows += self.rows_for(fields, at, row.chain, 1)
                else:
                    row.value, row.open = "%d fields" % len(fields), ("struct", at, inner.target, row.chain, "%s[%d]" % (label, i))
            else:
                self.describe(row)
        shown = ", first %d shown" % MAX_ELEMENTS if n > MAX_ELEMENTS else ""
        return "%s  %s  %d elements%s  at %X" % (label, "TArray<%s>" % inner.type, n, shown, data), rows

    def map_entries(self, address):
        """(data, [index of every entry in use]) of the TMap or TSet at address.

        TSparseArray: Data +0, ArrayNum +8, ArrayMax +C, then the allocation bits (TBitArray with
        4 dwords inline at +10, SecondaryData +20, NumBits +28, MaxBits +2C), FirstFreeIndex +30,
        NumFreeIndices +34. A freed entry stays in Data; only its bit says so."""
        head = self.read(address, 0x38)
        data, n, _cap = struct.unpack_from("<QII", head, 0)
        max_bits = struct.unpack_from("<I", head, 0x2C)[0]
        n = min(n, 0x100000)
        if max_bits > 128:
            bits = self.read(struct.unpack_from("<Q", head, 0x20)[0], (n + 7) // 8)
        else:
            bits = head[0x10:0x20]
        return data, [i for i in range(n) if i // 8 < len(bits) and bits[i // 8] >> (i % 8) & 1]

    def view_map(self, view):
        _k, address, p, chain, label = view
        data, used = self.map_entries(address)
        rows = []
        parts = [("key", p.inner, p.inner.offset)]
        if p.value is not None:
            parts.append(("value", p.value, p.value.offset))
        for i in used[:MAX_ELEMENTS]:
            base = data + i * p.entry
            for word, part, off in parts:
                at = base + off
                row = Row("[%d] %s" % (i, word), part, at, "%s+%X" % (chain, i * p.entry + off), 0, i * p.entry + off)
                rows.append(row)
                if part.kind == "StructProperty" and part.target:
                    row.note = "struct"
                    fields = self.props(part.target)
                    if len(fields) <= MAX_STRUCT_ROWS:
                        rows += self.rows_for(fields, at, row.chain, 1)
                    else:
                        row.value, row.open = "%d fields" % len(fields), ("struct", at, part.target, row.chain, "%s[%d]" % (label, i))
                else:
                    self.describe(row)
        shown = ", first %d shown" % MAX_ELEMENTS if len(used) > MAX_ELEMENTS else ""
        return "%s  %s  %d entries%s, %d bytes each  at %X" % (label, p.type, len(used), shown, p.entry, data), rows

    # ------------------------------------------------------------ every object (GUObjectArray)
    def wants_idle(self):
        return self.scan is not None

    def idle(self):
        """A slice of the object scan. Returns (text for the list's count line, whether the list changed)."""
        s = self.scan
        try:
            if s["stage"] == "start":
                self.load_regions()
                rva = self.saved_array()
                if rva and self.probe(self.main + rva):
                    s["stage"] = "objects"
                else:
                    s.update(stage="find", todo=[r for r in self.regions if r[2] and self.main <= r[0] < self.main + self.main_size],
                             at=0, done=0)
                    s["total"] = sum(r[1] for r in s["todo"])
                return "looking for the object list...", False
            if s["stage"] == "find":
                return self.find_slice(s)
            if s["stage"] == "objects":
                s.update(stage="walk", index=0, by={}, pages={})
                return "reading %d objects..." % self.array["num"], False
            if s["stage"] == "props":
                return self.props_slice(s)
            return self.walk_slice(s)
        except (OSError, ConnectionError):
            raise
        except Exception as e:  # noqa: BLE001 - the list stays as it is; the route still works
            self.scan = None
            return "no object list: %s" % (str(e)[:80] or type(e).__name__), False

    def load_regions(self):
        self.regions = []
        for line in self.b.cmd("maps").splitlines():
            m = re.match(r"([0-9A-Fa-f]+) ([0-9A-Fa-f]+) (\S+)", line)
            if m:
                self.regions.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3).startswith("rw")))
        self.regions.sort()
        self.region_starts = [r[0] for r in self.regions]

    def writable(self, address):
        i = bisect.bisect_right(self.region_starts, address) - 1
        return i >= 0 and self.regions[i][2] and address < self.regions[i][0] + self.regions[i][1]

    def array_file(self):
        return os.path.join(self.cache, "ue_object_array.txt")

    def saved_array(self):
        """The array's offset in main, from an earlier scan here or from Breeze's own file."""
        text = ""
        if os.path.exists(self.array_file()):
            text = open(self.array_file()).read()
        elif "ue_object_array.txt" in self.have:
            text = self.b.get_file(self.dir + "ue_object_array.txt").decode("ascii", "replace")
        m = re.match(r"\s*([0-9A-Fa-f]+) ([0-9A-Fa-f]+)", text)
        return int(m.group(2), 16) if m and int(m.group(1), 16) == self.main_size else 0

    def items_ok(self, items, stride, obj_off, cache):
        good = set()
        for i in range(16):
            obj = self.u64(items + i * stride + obj_off, cache)
            # An object knows its own place in the list (InternalIndex): other tables of pointers do not pass.
            if obj and not obj & 7 and self.writable(obj) and self.writable(self.u64(obj + 0x10, cache))                     and self.u32(obj + 0xC, cache) == i:
                good.add(obj)
        return len(good) >= 12

    def probe(self, addr, cache=None):
        """Is the object array's header at addr? Fills self.array. (Breeze: probe_object_array_at.)"""
        cache = {} if cache is None else cache
        try:
            objects, a, b_, c, d = struct.unpack("<Q4I", self.read(addr, 24, cache))
            e, f = struct.unpack("<II", self.read(addr + 24, 8, cache))
        except RuntimeError:
            return False
        if not objects or objects & 7 or not self.writable(objects):
            return False
        if 0x1000 <= a <= 0x4000000 and 1000 <= b_ <= a:        # flat (before 4.20): Objects, Max, Num
            for stride in (24, 32, 16):
                if self.items_ok(objects, stride, 0, cache):
                    self.array = dict(addr=addr, objects=objects, num_off=0xC, num=b_, stride=stride, obj_off=0, per_chunk=0)
                    return True
        chunk0 = self.u64(objects, cache)
        if not chunk0 or not self.writable(chunk0):
            return False
        # Chunked: Objects, PreAllocated, Max, Num, MaxChunks, NumChunks - or Objects, Num, Max, NumChunks, MaxChunks.
        for cap, num, max_chunks, num_chunks, num_off in ((c, d, e, f, 0x14), (b_, a, d, c, 0x08)):
            if not (0x1000 <= cap <= 0x4000000 and 1000 <= num <= cap and 1 <= num_chunks <= max_chunks <= 0x4000):
                continue
            per = cap // max_chunks
            if not per or per * max_chunks != cap or (num + per - 1) // per > num_chunks:
                continue
            for obj_off in (0, 8):
                for stride in (24, 32, 16):
                    if stride > obj_off and self.items_ok(chunk0, stride, obj_off, cache):
                        self.array = dict(addr=addr, objects=objects, num_off=num_off, num=num, stride=stride,
                                          obj_off=obj_off, per_chunk=per)
                        return True
        return False

    def find_slice(self, s):
        end = time.time() + SCAN_SLICE
        cache = {}
        while s["todo"] and time.time() < end:
            start, size, _rw = s["todo"][0]
            n = min(0x100000, size - s["at"])
            data = self.bulk(start + s["at"], n)
            for i in range(0, n - 0x1F, 8):
                value = struct.unpack_from("<Q", data, i)[0]
                if value and not value & 7 and not value >> 47 and self.writable(value) and self.probe(start + s["at"] + i, cache):
                    os.makedirs(self.cache, exist_ok=True)
                    with open(self.array_file(), "w") as f:
                        f.write("%X %X\n# module_size, GUObjectArray::ObjObjects RVA (found by Breeze Studio)\n"
                                % (self.main_size, self.array["addr"] - self.main))
                    s["stage"] = "objects"
                    return "found the object list", False
            s["at"] += n
            s["done"] += n
            if s["at"] >= size:
                s["todo"].pop(0)
                s["at"] = 0
        if not s["todo"]:
            raise RuntimeError("it was not found in main's data")
        return "looking for the object list... %d%%" % (100 * s["done"] // max(s["total"], 1)), False

    def walk_slice(self, s):
        a = self.array
        end = time.time() + SCAN_SLICE
        total = self.u32(a["addr"] + a["num_off"], {}) or a["num"]
        while s["index"] < total and time.time() < end:
            if a["per_chunk"]:
                chunk = self.u64(a["objects"] + (s["index"] // a["per_chunk"]) * 8, {})
                first = s["index"] % a["per_chunk"]
                count = min(2048, a["per_chunk"] - first, total - s["index"])
            else:
                chunk, first, count = a["objects"], s["index"], min(2048, total - s["index"])
            if chunk:
                data = self.bulk(chunk + first * a["stride"], count * a["stride"])
                pages = s["pages"]
                for i in range(count):
                    obj = struct.unpack_from("<Q", data, i * a["stride"] + a["obj_off"])[0]
                    if not obj or obj & 7:
                        continue
                    try:
                        cls, index, number = struct.unpack("<QII", self.read(obj + 0x10, 16, pages))
                    except RuntimeError:
                        continue
                    if cls:
                        s["by"].setdefault(cls, []).append((chunk + (first + i) * a["stride"] + a["obj_off"], obj, index, number))
                if len(pages) > 20000:
                    s["pages"] = {}
            s["index"] += count
        if s["index"] < total:
            return "reading objects... %d of %d" % (s["index"], total), False
        self.finish(s["by"])
        self.scan = {"stage": "props", "todo": [n for n in self.classes if n != ROUTE], "done": 0}
        return "", True

    def own_names(self, struct_ptr, own, prefix="", depth=0):
        out = []
        for p in self.props(struct_ptr):
            if depth == 0 and p.owner != own:
                continue
            out.append(prefix + p.name)
            if p.kind == "StructProperty" and p.target and depth < 2:
                inner = self.props(p.target)
                if len(inner) <= 200:
                    out += self.own_names(p.target, own, prefix + p.name + ".", depth + 1)
        return out

    def props_slice(self, s):
        """Every class's own property names, with those of the structs in it: for "has field"."""
        end = time.time() + SCAN_SLICE
        self.fresh()
        while s["todo"] and time.time() < end:
            name = s["todo"].pop()
            e = self.classes.get(name)
            if e is not None:
                try:
                    self.own[name] = self.own_names(e.ptr, self.obj_name(e.ptr))
                except RuntimeError:
                    self.own[name] = []
            s["done"] += 1
        if s["todo"]:
            return "reading the classes' fields... %d of %d" % (s["done"], s["done"] + len(s["todo"])), False
        self.scan = None
        return "", True

    def finish(self, by):
        classes, starred = {ROUTE: Entry(0)}, {ROUTE}
        count = {}
        named = [(self.obj_name(cls), cls) for cls in by]
        for name, _cls in named:
            count[name] = count.get(name, 0) + 1
        for name, cls in named:
            if not name:
                continue
            if count[name] > 1:      # the same class name in two packages
                name = "%s  in %s" % (name, self.obj_name(self.u64(cls + self.name_off + 8)) or "%X" % cls)
            while name in classes:
                name += "'"
            e = classes[name] = Entry(cls)
            e.objects = by[cls]
            if any(not self.name_at(o[2]).startswith("Default__") for o in e.objects[:4]):
                starred.add(name)
        self.classes, self.starred = classes, starred
        self.index = sorted((o[1], cls, o[0]) for cls, objects in by.items() for o in objects)
        self.index_starts = [x[0] for x in self.index]
        self.note = "Unreal: %d objects of %d classes" % (sum(len(v) for v in by.values()), len(classes) - 1)
