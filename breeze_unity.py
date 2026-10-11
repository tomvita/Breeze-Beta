"""Unity (IL2CPP) objects by name, over PC connect.

Breeze's two maps for a Unity game -- il2cpp_field_map.txt and
il2cpp_function_map.txt, made by `prep il2cpp_fields` / `prep il2cpp_functions`
-- name every class, field and method. This reads them on the PC and joins
them to the running game through `peek`, so a session works with names:

    from pcconnect import Breeze
    from breeze_unity import Unity

    u = Unity(Breeze("192.168.1.65", "0303"))
    u.describe(0x643EAE000)                       # the object there: class, every field, live values
    r = u.resolve("ServiceLocator._services[CharacterSelectionService]._currentPlayerObject.Cheats._isGodModeOn")
    print(hex(r.address), r.type)                 # where the path ends now
    print(u.cheat(r, 1))                          # the cheat that writes 1 there
    u.instances("PlayerStats")                    # live objects of a class
    u.method(0x27A4518)                           # 'AgentStats::ReceiveHealthDamage+0xB8'

Nothing here writes to the game. The maps are fetched once per build into
~/.breeze_pc/<title id>_<build id>/ and fetched again when the Switch has a
newer one.

Layout facts used (64-bit IL2CPP, as Breeze's own tools use them):
  object: klass pointer at +0, fields from +0x10
  klass:  name at +0x10, namespace at +0x18, static block at +0xB8
  string: length at +0x10, UTF-16 text at +0x14
  array:  length at +0x18, elements from +0x20
  List<T>:        _items at +0x10, _size at +0x18
  Dictionary<K,V>: _entries at +0x18, _count at +0x20; an entry of two
                   references is 0x18 bytes: hash, next, key (+8), value (+0x10)
"""
import bisect
import json
import os
import re
import struct

STATIC_BLOCK = 0xB8

_SIZES = {
    "bool": 1, "byte": 1, "sbyte": 1, "char": 2, "short": 2, "ushort": 2, "int": 4, "uint": 4, "float": 4,
    "long": 8, "ulong": 8, "double": 8,
}
_FORMATS = {
    "bool": "<?", "byte": "<B", "sbyte": "<b", "char": "<H", "short": "<h", "ushort": "<H", "int": "<i", "uint": "<I",
    "float": "<f", "long": "<q", "ulong": "<Q", "double": "<d",
}


class Field:
    def __init__(self, owner, name, offset, type_name, static):
        self.owner, self.name, self.offset, self.type, self.static = owner, name, offset, type_name, static

    @property
    def short(self):
        """'Cheats' for '<Cheats>k__BackingField'."""
        m = re.match(r"<(.+)>k__BackingField$", self.name)
        return m.group(1) if m else self.name

    @property
    def is_pointer(self):
        return self.type.endswith("*") or self.type.endswith("[]") or self.type == "string"

    @property
    def size(self):
        if self.is_pointer:
            return 8
        return _SIZES.get(self.type, 4)  # an unnamed value type is most often an enum

    def __repr__(self):
        return "%s::%s = %s+0x%X %s" % (self.owner, self.name, "static " if self.static else "", self.offset, self.type)


class Klass:
    def __init__(self, name, parent, slot):
        self.name, self.parent, self.slot, self.fields = name, parent, slot, []

    @property
    def short(self):
        return self.name.split("<")[0].rsplit(".", 1)[-1] + ("<" + self.name.split("<", 1)[1] if "<" in self.name else "")


class Resolved:
    """Where a path ends: the address now, the field's type, and the hops a
    cheat needs to get there again."""

    def __init__(self):
        self.slot = None       # main+slot holds the root class pointer
        self.hops = []         # offsets dereferenced in turn after [main+slot]
        self.last = 0          # offset added, not dereferenced
        self.address = 0
        self.type = ""
        self.trail = []        # (text, address) of every step, for showing

    def __repr__(self):
        return "<%s at 0x%X via main+0x%X %s +0x%X>" % (self.type, self.address, self.slot or 0,
                                                       " ".join("%X" % h for h in self.hops), self.last)


class Unity:
    def __init__(self, breeze, cache_dir=None, fetch=True):
        self.b = breeze
        meta = json.loads(breeze.cmd("meta")[4:])
        self.main = int(meta["main"], 16)
        tag = "%s_%s" % (meta.get("title_id", "game"), meta.get("build_id", "build"))
        self.dir = cache_dir or os.path.join(os.path.expanduser("~"), ".breeze_pc", tag)
        os.makedirs(self.dir, exist_ok=True)
        if fetch:
            self._fetch()
        self.classes = {}
        self._short = {}
        self._load_fields()
        self._method_addrs, self._method_names = [], []
        self._methods_loaded = False

    # ------------------------------------------------------------ the maps

    def _fetch(self):
        have = {f["name"]: f for f in self.b.files()["files"]}
        for name in ("il2cpp_field_map.txt", "il2cpp_function_map.txt"):
            if name not in have:
                continue
            local = os.path.join(self.dir, name)
            if not os.path.exists(local) or os.path.getsize(local) != have[name].get("size"):
                self.b.get_file(name, local)

    def _load_fields(self):
        path = os.path.join(self.dir, "il2cpp_field_map.txt")
        if not os.path.exists(path):
            raise RuntimeError("no il2cpp_field_map.txt: run prep il2cpp_fields on the Switch first")
        field_re = re.compile(r"^(.*)::(\S+) = (static )?\+0x([0-9A-Fa-f]+) (.*)$")
        class_re = re.compile(r"^(.*?) : (.*?)(?:  klass=\[main\+0x([0-9A-Fa-f]+)\])?(?:  implements=.*)?$")
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line or line[0] == "#":
                    continue
                m = field_re.match(line)
                if m:
                    k = self.classes.get(m.group(1))
                    if k is None:
                        k = self.classes[m.group(1)] = Klass(m.group(1), None, None)
                    k.fields.append(Field(m.group(1), m.group(2), int(m.group(4), 16), m.group(5), bool(m.group(3))))
                    continue
                m = class_re.match(line)
                if m and "::" not in m.group(1):
                    k = self.classes.get(m.group(1))
                    if k is None:
                        k = self.classes[m.group(1)] = Klass(m.group(1), None, None)
                    k.parent = m.group(2).strip() or None
                    k.slot = int(m.group(3), 16) if m.group(3) else None
        for name in self.classes:
            base = name.split("<")[0].rsplit(".", 1)[-1]
            self._short.setdefault(base, []).append(name)

    def cls(self, name):
        """A class by full name, or by its last part when that is unique."""
        if name in self.classes:
            return self.classes[name]
        found = self._short.get(name.split("<")[0].rsplit(".", 1)[-1], [])
        if "." in name:  # the end of a full name: 'Players.PlayerController'
            found = [n for n in found if n.split("<")[0].endswith("." + name)]
        plain = [n for n in found if "<" not in n] or found
        if len(plain) == 1:
            return self.classes[plain[0]]
        if not plain:
            raise KeyError("no class named %s in the field map" % name)
        raise KeyError("%s is one of several: %s" % (name, ", ".join(plain[:8])))

    def fields(self, klass, static=False):
        """Fields of a class and its parents, by offset."""
        out, seen = [], set()
        k = klass if isinstance(klass, Klass) else self.cls(klass)
        while k is not None and k.name not in seen:
            seen.add(k.name)
            out.extend(f for f in k.fields if f.static == static)
            if static:
                break  # a parent's statics live in the parent's block
            parent = k.parent
            k = self.classes.get(parent) or (self.classes.get(parent.split("<")[0]) if parent else None)
        return sorted(out, key=lambda f: f.offset)

    def field(self, klass, name, static=False):
        for f in self.fields(klass, static):
            if f.name == name or f.short == name:
                return f
        k = klass if isinstance(klass, Klass) else self.cls(klass)
        raise KeyError("%s has no %sfield %s" % (k.name, "static " if static else "", name))

    # ------------------------------------------------------------ live memory

    def u64(self, addr):
        return struct.unpack("<Q", self.b.peek(addr, 8))[0]

    def u32(self, addr):
        return struct.unpack("<I", self.b.peek(addr, 4))[0]

    def cstr(self, addr, n=96):
        return self.b.peek(addr, n).split(b"\0")[0].decode("ascii", "replace")

    def klass_name(self, obj):
        """Full class name of the object at obj, read from its klass."""
        k = self.u64(obj)
        name = self.cstr(self.u64(k + 0x10))
        space = self.cstr(self.u64(k + 0x18))
        return (space + "." + name) if space else name

    def klass_of(self, obj):
        """The map's class for a live object, or None when the map lacks it."""
        try:
            full = self.klass_name(obj)
        except Exception:
            return None
        if full in self.classes:
            return self.classes[full]
        try:
            return self.cls(full.rsplit(".", 1)[-1])
        except KeyError:
            return None

    def statics(self, klass):
        """Address of a class's static block."""
        k = klass if isinstance(klass, Klass) else self.cls(klass)
        if k.slot is None:
            raise RuntimeError("%s has no class slot in the map: its code has not run yet" % k.name)
        return self.u64(self.u64(self.main + k.slot) + STATIC_BLOCK)

    def string(self, addr):
        if addr == 0:
            return None
        n = min(self.u32(addr + 0x10), 200)
        return self.b.peek(addr + 0x14, n * 2).decode("utf-16-le", "replace") if n else ""

    def value(self, raw, field):
        """A field's value from the object's bytes, as Python would show it."""
        piece = raw[field.offset:field.offset + field.size]
        if len(piece) < field.size:
            return None
        if field.is_pointer:
            return struct.unpack("<Q", piece)[0]
        fmt = _FORMATS.get(field.type)
        return struct.unpack(fmt, piece)[0] if fmt else struct.unpack("<I", piece)[0]

    def obj(self, addr, size=None):
        """{'class': name, 'fields': [(Field, value)]} for the object at addr."""
        k = self.klass_of(addr)
        if k is None:
            raise RuntimeError("0x%X does not start with a class the map knows (%s)" % (addr, self._try(self.klass_name, addr)))
        fields = self.fields(k)
        size = size or (max((f.offset + f.size for f in fields), default=0x10))
        raw = b""
        while len(raw) < size:
            raw += self.b.peek(addr + len(raw), min(4096, size - len(raw)))
        return {"class": k.name, "address": addr, "fields": [(f, self.value(raw, f)) for f in fields]}

    @staticmethod
    def _try(fn, *args):
        try:
            return fn(*args)
        except Exception as e:
            return "unreadable: %s" % e

    def describe(self, addr):
        """Prints the object: one line per field with its live value. A
        reference shows the class of what it points at."""
        o = self.obj(addr)
        print("%s at 0x%X" % (o["class"], addr))
        for f, v in o["fields"]:
            if f.is_pointer and v:
                if f.type in ("string", "System.String*"):
                    shown = "0x%X %r" % (v, self._try(self.string, v))
                else:
                    shown = "0x%X %s" % (v, self._try(self.klass_name, v))
            elif f.is_pointer:
                shown = "null"
            elif isinstance(v, float):
                shown = "%g" % v
            elif isinstance(v, bool):
                shown = str(v).lower()
            else:
                shown = "%s" % v if f.type in _SIZES else "0x%X" % v
            print("  +0x%04X %-44s %-34.34s %s" % (f.offset, f.short, f.type, shown))

    def instances(self, klass=None, like=None, limit=64, seconds=30):
        """Live objects of a class: every place in the game's writable memory
        that holds the class pointer where an object would start.

        The map gives a class pointer only for classes that have a slot. For
        the others pass like=<address of one object of the class>: the others
        of its kind are found from it.
        """
        if like is not None:
            pointer = self.u64(like)
        else:
            k = klass if isinstance(klass, Klass) else self.cls(klass)
            if k.slot is None:
                raise RuntimeError("%s has no class slot in the map: pass like=<an object of it>" % k.name)
            pointer = self.u64(self.main + k.slot)
        # Breeze's own scan (objects of the class and of its subclasses, ~5 s),
        # where this Breeze has the command.
        reply = self.b.cmd("instances %X" % pointer)
        if reply.startswith("+OK"):
            import time
            end = time.time() + max(seconds, 60)
            while time.time() < end:
                time.sleep(1.0)
                state = json.loads(self.b.cmd("instances")[4:])
                if state["done"]:
                    return [int(x, 16) for x in state["objects"]][:limit]
            raise RuntimeError("the instance scan did not finish: %s" % state.get("progress"))
        # An older Breeze: every reference to the class pointer, filtered down
        # to what looks like an object. Slower, and it stops at a time limit.
        reply = self.b.cmd("refs %X 0 %d %d" % (pointer, max(limit * 8, 512), seconds))
        out = []
        for line in reply.split("\n")[1:]:
            m = re.match(r"\s*([0-9A-Fa-f]{8,})", line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            # The class pointer is also held by the class itself and by its
            # method and type tables. An object's second word is its lock
            # word, null unless something is waiting on it; in those tables
            # the next word is another pointer.
            if pointer <= addr < pointer + 0x200:
                continue
            try:
                if self.u64(addr + 8) != 0:
                    continue
            except Exception:
                continue
            out.append(addr)
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------ paths

    def resolve(self, path):
        """Walks 'Class.staticField.field[index].field' through live memory.

        The first name is a class, the second one of its static fields. Each
        further '.name' is a field of the object reached (looked up in the
        class the object really is, so a field declared as a base class works).
        '[3]' indexes a List or an array. '[SomeClass]' on a Dictionary picks
        the entry whose value is an object of that class. The last field is
        the target and is not followed.
        """
        tokens = re.findall(r"[^.\[\]]+|\[[^\]]+\]", path)
        if len(tokens) < 2:
            raise ValueError("a path is Class.staticField[.field...]")
        r = Resolved()
        k = self.cls(tokens[0])
        if k.slot is None:
            raise RuntimeError("%s has no class slot in the map" % k.name)
        r.slot = k.slot
        f = self.field(k, tokens[1], static=True)
        base = self.statics(k)
        r.hops = [STATIC_BLOCK]
        r.last, r.address, r.type = f.offset, base + f.offset, f.type
        r.trail.append(("%s.%s" % (k.short, f.short), r.address))
        for token in tokens[2:]:
            # Follow the reference just reached, then step inside it.
            target = self.u64(r.address)
            if target == 0:
                raise RuntimeError("%s is null" % r.trail[-1][0])
            r.hops.append(r.last)
            if token[0] == "[":
                key = token[1:-1]
                if "Dictionary" in r.type:
                    entries = self.u64(target + 0x18)
                    count = self.u32(target + 0x20)
                    found = None
                    for i in range(count):
                        value = self.u64(entries + 0x20 + i * 0x18 + 0x10)
                        if value and self._try(self.klass_name, value).rsplit(".", 1)[-1] == key:
                            found = i
                            break
                    if found is None:
                        raise KeyError("no entry of %s holds a %s" % (r.trail[-1][0], key))
                    r.hops.append(0x18)
                    r.last = 0x20 + found * 0x18 + 0x10
                    r.address = entries + r.last
                    r.type = key + "*"
                else:
                    index = int(key, 0)
                    array = target
                    if "List" in r.type:
                        array = self.u64(target + 0x10)
                        r.hops.append(0x10)
                    r.last = 0x20 + index * 8
                    r.address = array + r.last
                    r.type = "object*"
                r.trail.append((token, r.address))
                continue
            live = self.klass_of(target)
            if live is None:
                raise RuntimeError("%s points at something the map has no class for" % r.trail[-1][0])
            f = self.field(live, token)
            r.last, r.address, r.type = f.offset, target + f.offset, f.type
            r.trail.append(("%s.%s" % (live.short, f.short), r.address))
        return r

    def cheat(self, resolved, value, name=None):
        """Cheat VM words that walk the path and write value there. The width
        comes from the field's type; a float is written as its bit pattern."""
        r = resolved if isinstance(resolved, Resolved) else self.resolve(resolved)
        width = 8 if r.type.endswith("*") else _SIZES.get(r.type, 4)
        if isinstance(value, float) or r.type in ("float",):
            bits = struct.unpack("<I", struct.pack("<f", float(value)))[0]
        else:
            bits = int(value) & (0xFFFFFFFFFFFFFFFF if width == 8 else 0xFFFFFFFF)
        words = ["580F0000 %08X" % r.slot]
        for h in r.hops:
            words.append("580F1000 %08X" % h)
        words.append("780F0000 %08X" % r.last)
        words.append("6%d0F0000 %08X %08X" % (width, bits >> 32, bits & 0xFFFFFFFF))
        text = " ".join(words)
        return "[%s] %s" % (name, text) if name else text

    def dry_run(self, words):
        """The address a pointer cheat's chain ends on right now and what is
        there, read the way the VM reads -- before the cheat is switched on."""
        w = [x for x in words.split() if not x.startswith("[")]
        if "]" in words:
            w = words.split("]", 1)[1].split()
        reg, i, steps = 0, 0, []
        while i < len(w):
            op = w[i]
            arg = int(w[i + 1], 16)
            if op == "580F0000":
                reg = self.u64(self.main + arg)
                steps.append("[main+%X] = %X" % (arg, reg))
            elif op == "580F1000":
                at = reg + arg
                reg = self.u64(at)
                steps.append("[%X] = %X" % (at, reg))
            elif op == "780F0000":
                reg += arg
                steps.append("+%X = %X" % (arg, reg))
                width = int(w[i + 2][1]) if i + 2 < len(w) else 4
                return {"address": reg, "steps": steps, "now": self.b.peek(reg, width).hex(), "width": width}
            else:
                raise ValueError("dry_run reads plain pointer chains only; met %s" % op)
            i += 2
        return {"address": reg, "steps": steps}

    # ------------------------------------------------------------ methods

    def _load_methods(self):
        if self._methods_loaded:
            return
        self._methods_loaded = True
        path = os.path.join(self.dir, "il2cpp_function_map.txt")
        if not os.path.exists(path):
            return
        rows = []
        pat = re.compile(r"^(.*?) = main\+0x([0-9A-Fa-f]+)")
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pat.match(line)
                if m:
                    rows.append((int(m.group(2), 16), m.group(1)))
        rows.sort()
        self._method_addrs = [a for a, _ in rows]
        self._method_names = [n for _, n in rows]

    def method(self, offset):
        """'Class::Method+0x1C' for an offset into main (or 'M+27A4518'). The
        map lists named methods only, so a match far below is marked."""
        if isinstance(offset, str):
            offset = int(offset.split("+")[1], 16)
        self._load_methods()
        i = bisect.bisect_right(self._method_addrs, offset) - 1
        if i < 0:
            return "?"
        d = offset - self._method_addrs[i]
        return "%s+0x%X%s" % (self._method_names[i], d, " (far)" if d > 0x2000 else "")

    def callers(self, method):
        """Who calls a method: [(offset, 'Class::Method+0x..')] for every b / bl
        to it in main. method is a name from the function map or an offset.
        None found does not make it dead: a small method is often inlined, and
        virtual and delegate calls go through a pointer."""
        if isinstance(method, str):
            found = [a for a, n in self.methods(method) if n == method or n.endswith("::" + method) or n.endswith("." + method)]
            if len(found) != 1:
                raise KeyError("%s matches %d methods in the function map" % (method, len(found)))
            method = found[0]
        return [(off, self.method(off)) for off in self.b.xref_call(self.main + method)]

    def field_users(self, offset, within, store=None):
        """Code that loads or stores a field at this offset, inside the methods
        whose names contain `within` (an offset alone matches far too much).
        store: True for writes only, False for reads only.
        Returns [(code offset, 'Class::Method+0x..', 'load' or 'store', bytes)].
        Covers the plain [reg, #offset] form; pairs and register-offset
        accesses are not looked for."""
        self._load_methods()
        out = []
        ranges = []
        for a, n in self.methods(within):
            i = bisect.bisect_right(self._method_addrs, a)
            end = self._method_addrs[i] if i < len(self._method_addrs) else a + 0x1000
            ranges.append((a, min(end, a + 0x4000)))
        for lo, hi in ranges:
            for size in range(4):
                if offset % (1 << size) or (offset >> size) > 0xFFF:
                    continue
                # size:111:V:01:opc:imm12:Rn:Rt -- unsigned offset, any register, V and opc free
                value = (size << 30) | 0x39000000 | ((offset >> size) << 10)
                for off, word in self.b.xref_insn(0xFB3FFC00, value, lo, hi):
                    is_store = ((word >> 22) & 3) == 0
                    if store is not None and store != is_store:
                        continue
                    out.append((off, self.method(off), "store" if is_store else "load", 1 << size))
        return sorted(set(out))

    def fieldwatch(self, addr, access="w"):
        """Starts a field watch on the object at addr, sized from its class."""
        k = self.klass_of(addr)
        if k is None:
            raise RuntimeError("0x%X is not an object the map knows" % addr)
        size = (max(f.offset + f.size for f in self.fields(k)) + 7) & ~7
        return self.b.fieldwatch("start", "%X" % addr, "%X" % size, access)

    def fieldwatch_fields(self):
        """The running (or last) field watch with its accessed bytes named:
        [(Field, first accessed offset)]. Bytes no field covers come back as
        (None, offset)."""
        state = self.b.fieldwatch()
        if state.get("state") == "none":
            return []
        k = self.klass_of(int(state["base"], 16))
        fields = self.fields(k) if k else []
        out, seen = [], set()
        for start, length in state["bytes"]:
            for off in range(start, start + length):
                owner = next((f for f in fields if f.offset <= off < f.offset + f.size), None)
                key = owner.offset if owner else ("raw", off & ~3)
                if key in seen:
                    continue
                seen.add(key)
                out.append((owner, off))
        return out

    def methods(self, text):
        """(offset, name) of every method whose name contains text."""
        self._load_methods()
        return [(a, n) for a, n in zip(self._method_addrs, self._method_names) if text in n]
