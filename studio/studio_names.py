"""Breeze Studio: class names and field labels for a game whose engine Studio does not know.

Two files in the game's folder (sdmc:/switch/breeze/cheats/<title id>/, the folder `files` names):

object_names.txt - how an object of this game names its class, in a few rules:

    v1
    type +0              the object's type pointer is its qword at +0
    name [+8] +2 ::      from the type: read the pointer at +8, add 2, the text up to "::"
    back 800             (hex) how far back from an address its object may start

  `name` is a walk from the type pointer: `[+X]` reads the pointer at the current address + X,
  `+X` adds X, and the last word is the text that ends the name (`::`, or `\\0` for the end of
  the string). A name has to look like one (letters, digits, `_`, 2 to 120 characters), so a
  pointer that only happens to lead to text is not taken for a type. Lines after `;` are notes.

field_annotations.txt - Breeze's own field labels (`v1`, then class, offset hex, label, type
  hint, tab separated), the same file Breeze's field views read and write.

All reads go through the caller's connection; names are cached per type pointer and per object.
"""
import re
import struct

NAME_OK = re.compile(r"[A-Za-z_][A-Za-z0-9_$<>.,`]{1,119}")


def parse_rules(text):
    """{'type': 0, 'walk': [('read', 8), ('add', 2)], 'end': b'::', 'back': 0x800} or None."""
    rules = {"type": 0, "walk": None, "end": b"\0", "back": 0x800}
    lines = text.splitlines()
    if not lines or not lines[0].strip().startswith("v1"):
        return None
    for line in lines[1:]:
        words = line.split(";", 1)[0].split()
        if not words:
            continue
        key, args = words[0].lower(), words[1:]
        if key == "type" and args:
            rules["type"] = int(args[0].lstrip("+"), 16)
        elif key == "back" and args:
            rules["back"] = int(args[0], 16)
        elif key == "name" and args:
            walk, end = [], b"\0"
            for i, w in enumerate(args):
                m = re.fullmatch(r"\[\+?([0-9A-Fa-f]+)\]", w)
                if m:
                    walk.append(("read", int(m.group(1), 16)))
                elif re.fullmatch(r"\+[0-9A-Fa-f]+", w):
                    walk.append(("add", int(w[1:], 16)))
                elif i == len(args) - 1:
                    end = b"\0" if w in ("\\0", "0") else w.encode()
                else:
                    raise ValueError("object_names.txt: cannot read %r in %r" % (w, line))
            rules["walk"], rules["end"] = walk, end
    return rules if rules["walk"] is not None else None


def parse_labels(text):
    """{class: {offset: (label, type_hint)}} from field_annotations.txt."""
    out = {}
    lines = text.splitlines()
    if not lines or not lines[0].startswith("v1"):
        return out
    for line in lines[1:]:
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) >= 4 and parts[0] and parts[2]:
            try:
                out.setdefault(parts[0], {})[int(parts[1], 16)] = (parts[2], parts[3])
            except ValueError:
                pass
    return out


class GameNames:
    def __init__(self):
        self.dir = ""
        self.rules = None
        self.labels = {}
        self.note = ""
        self.type_names = {}     # type pointer -> name or None
        self.object_types = {}   # object -> type pointer or None
        self.mapped = None       # address -> bool (the Memory tab's map), to skip non-pointers

    # ------------------------------------------------------------ files
    def load(self, b):
        """Reads both files from the game's folder. Missing files leave names off."""
        self.type_names.clear()
        self.object_types.clear()
        self.rules, self.labels, self.note = None, {}, ""
        try:
            self.dir = b.files()["dir"]
        except Exception as e:  # noqa: BLE001 - a host without files: no names
            self.note = "no game folder (%s)" % e
            return self
        for name in ("object_names.txt", "field_annotations.txt"):
            try:
                text = b.get_file(self.dir + name).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - the file is not there
                continue
            try:
                if name == "object_names.txt":
                    self.rules = parse_rules(text)
                else:
                    self.labels = parse_labels(text)
            except ValueError as e:
                self.note = str(e)
        if self.rules is None and not self.note:
            self.note = "no object_names.txt in %s" % self.dir
        return self

    def save_label(self, b, cls, offset, label, type_hint):
        """Adds (or with an empty label removes) a label and writes field_annotations.txt."""
        if label:
            self.labels.setdefault(cls, {})[offset] = (label, type_hint)
        else:
            self.labels.get(cls, {}).pop(offset, None)
        rows = ["v1"]
        for c in sorted(self.labels):
            for off in sorted(self.labels[c]):
                lab, hint = self.labels[c][off]
                rows.append("%s\t%X\t%s\t%s" % (c, off, lab, hint))
        b.fs_put(self.dir + "field_annotations.txt", 0, ("\n".join(rows) + "\n").encode("utf-8"))

    # ------------------------------------------------------------ names
    def type_name(self, b, t):
        """The class name a type pointer leads to, or None."""
        if self.rules is None or t < 0x10000 or t & 3:
            return None
        if self.mapped is not None and not self.mapped(t):
            return None
        if t in self.type_names:
            return self.type_names[t]
        name = None
        try:
            at = t
            for op, x in self.rules["walk"]:
                at = struct.unpack("<Q", b.peek(at + x, 8))[0] if op == "read" else at + x
            raw = b.peek(at, 128)
            cut = raw.find(self.rules["end"])
            text = raw[:cut if cut >= 0 else len(raw)].split(b"\0")[0].decode("latin1")
            name = text if NAME_OK.fullmatch(text) else None
        except Exception:  # noqa: BLE001 - unreadable: not a type
            name = None
        self.type_names[t] = name
        return name

    def class_of(self, b, obj):
        """The class of the object at obj, or None."""
        if self.rules is None or obj < 0x10000 or obj & 7:
            return None
        if obj not in self.object_types:
            try:
                self.object_types[obj] = struct.unpack("<Q", b.peek(obj + self.rules["type"], 8))[0]
            except Exception:  # noqa: BLE001
                self.object_types[obj] = None
        t = self.object_types[obj]
        return self.type_name(b, t) if t else None

    def owner(self, b, address):
        """(object, class) the address is best described by: the nearest object start at or
        below it, unless an object further out has a label at that offset (an object can hold
        others inline, each with its own type: Fast Fusion's sPlayer has sVehicleStats at +38
        and sSeriesResult at +1C0, and boost, sPlayer+384, is also sSeriesResult+1C4)."""
        return self.best(self.owners(b, address), address)

    def best(self, candidates, address):
        for obj, cls in candidates:
            if self.label(cls, address - obj):
                return obj, cls
        return candidates[0] if candidates else None

    def owners(self, b, address):
        """Every (object, class) starting up to `back` below address, nearest first."""
        found = []
        if self.rules is None:
            return found
        top = address & ~7
        lo = max(top - self.rules["back"], 0)
        at = top
        while at >= lo:
            start = max(lo, at - 0xFF8) & ~7
            data = b.peek(start, at - start + 8)
            for i in range(len(data) - 8, -1, -8):
                obj = start + i - self.rules["type"]
                t = struct.unpack_from("<Q", data, i)[0]
                if t >= 0x10000 and not t & 3:
                    cls = self.type_name(b, t)
                    if cls:
                        found.append((obj, cls))
            at = start - 8
        return found

    def page(self, b, start, data):
        """For a page of memory: ({pointer: class} for the qwords that point at a named object,
        [(object, class)] for the objects that start in it or before it, in address order)."""
        ptrs, heads = {}, []
        if self.rules is None:
            return ptrs, heads
        heads.extend(self.owners(b, start))
        for i in range(-start & 7, len(data) - 7, 8):
            q = struct.unpack_from("<Q", data, i)[0]
            if self.mapped is not None and not self.mapped(q):
                continue
            cls = self.class_of(b, q)
            if cls:
                ptrs[q] = cls
            if i >= self.rules["type"]:
                name = self.type_name(b, q)
                obj = start + i - self.rules["type"]
                if name:
                    heads.append((obj, name))
        return ptrs, sorted(set(heads))

    def label(self, cls, offset):
        lab = self.labels.get(cls, {}).get(offset)
        return lab[0] if lab else ""

    def describe(self, cls, offset):
        """'sPlayer+20 coins'"""
        lab = self.label(cls, offset)
        return "%s+%X%s" % (cls, offset, " " + lab if lab else "")
