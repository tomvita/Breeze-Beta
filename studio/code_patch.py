"""Code-patch cheats with their originals in a block that never runs: Python copy of
core/code_patch.hpp (keep the two the same).

    [Name]
    C046E5E0                       if R14 != R14: never true, so the block never runs
    04000000 AAAAAAAA ORIGINAL_A   the game's instruction at A
    04000000 BBBBBBBB ORIGINAL_B
    20000000                       end of the block
    04000000 AAAAAAAA HACK_A       what the cheat writes
    04000000 BBBBBBBB HACK_B

The block comes first (a keypress conditional may wrap the whole cheat). It holds only 4-byte
code stores, main relative (04000000) or R1 relative (04010000), each address once, and every
address in it is written again later in the cheat. Breeze puts the originals back when the cheat
is turned off; every cheat VM skips the block.
"""
import re

NEVER = 0xC046E5E0
END = 0x20000000


class Patch:
    __slots__ = ("header", "offset", "original", "hack")

    def __init__(self, header, offset, original=0, hack=0):
        self.header, self.offset, self.original, self.hack = header, offset, original, hack

    @property
    def rel(self):
        return ((self.header & 0xFF) << 32) | self.offset

    @property
    def r1(self):
        return bool((self.header >> 16) & 1)

    def same_address(self, other):
        return self.header == other.header and self.offset == other.offset

    @property
    def label(self):
        """M+1234, or R1+1234 for a patch in the loaded module R1 points at."""
        return "%s+%X" % ("R1" if self.r1 else "M", self.rel)

    def address(self, main, r1=0):
        """Where it is in the game; None for an R1 patch with no R1 known."""
        if self.r1:
            return main + r1 + self.rel if r1 else None
        return main + self.rel

    def __repr__(self):
        return "Patch(%s %08X -> %08X)" % (self.label, self.original, self.hack)


def is_code_store(w):
    return (w & 0xFFFEFF00) == 0x04000000


def store_header(rel, r1=False):
    return 0x04000000 | (0x00010000 if r1 else 0) | ((rel >> 32) & 0xFF)


def opcode_words(op, i):
    """Words the opcode at op[i] takes, as the cheat VM decodes it; 0 for unknown or truncated."""
    left = len(op) - i
    if left <= 0:
        return 0
    w = op[i]
    t, width = w >> 28, (w >> 24) & 0xF
    vm_int = lambda bits: 2 if bits == 8 else 1  # noqa: E731
    if t in (0x0, 0x1):
        n = 2 + vm_int(width)
    elif t == 0x2 or t == 0x8:
        n = 1
    elif t == 0x3:
        n = 2 if width == 0 else 1
    elif t in (0x4, 0x6):
        n = 3
    elif t in (0x5, 0x7):
        n = 2
    elif t == 0x9:
        n = 1 + (vm_int(width) if (w >> 8) & 0xF else 0)
    elif t == 0xA:
        n = 2 if (w >> 8) & 0xF in (2, 4, 5) else 1
    elif t == 0xC:
        sub = (w >> 24) & 0xF
        if sub == 0:
            x = (w >> 8) & 0xF
            n = 1 + vm_int((w >> 20) & 0xF) if x == 4 else (2 if x in (0, 2) else 1)
        elif sub in (1, 2, 3):
            n = 1
        elif sub == 4:
            n = 3
        else:
            return 0
    elif t == 0xF:
        if (w >> 24) & 0xF != 0xF:
            return 0
        sub = (w >> 20) & 0xF
        if sub in (0, 1):
            n = 1
        elif sub == 0xF:
            n = 2 if (w >> 8) & 0xF in (0, 2) else 1
        else:
            return 0
    else:
        return 0
    return n if n <= left else 0


def parse(op):
    """(key, [Patch]) for a cheat in this form (key 0 for none), else None."""
    i, key = 0, 0
    if op and op[0] >> 28 == 0x8:
        key, i = op[0], 1
    if i >= len(op) or op[i] != NEVER:
        return None
    i += 1
    patches = []
    while i < len(op) and op[i] != END:
        if i + 3 > len(op) or not is_code_store(op[i]):
            return None
        p = Patch(op[i], op[i + 1], op[i + 2])
        if any(p.same_address(q) for q in patches):
            return None
        patches.append(p)
        i += 3
    if i >= len(op) or not patches:
        return None
    i += 1
    written = [False] * len(patches)
    while i < len(op):
        n = opcode_words(op, i)
        if n == 0:
            return None
        if n == 3 and is_code_store(op[i]):
            for k, p in enumerate(patches):
                if p.header == op[i] and p.offset == op[i + 1]:
                    p.hack = op[i + 2]
                    written[k] = True
        i += n
    return (key, patches) if all(written) else None


def build(patches, key=0):
    """The cheat's words: block, then the hacks in the same order; key wraps the whole cheat."""
    ops = [key] if key else []
    ops.append(NEVER)
    for p in patches:
        ops += [p.header, p.offset, p.original]
    ops.append(END)
    for p in patches:
        ops += [p.header, p.offset, p.hack]
    if key:
        ops.append(END)
    return ops


def restore_ops(patches):
    """The "<name> - restore" cheat for players whose cheat tool does not read the block: plain
    stores of the originals."""
    ops = []
    for p in patches:
        ops += [p.header, p.offset, p.original]
    return ops


def with_restore_cheats(cheats):
    """cheats ([(name, words)]) with a "<name> - restore" cheat after each code-patch cheat that
    has none of that name, as Breeze writes the atm file: for sharing with players who do not use
    Breeze. (name, words) of the master cheat are passed through as they are."""
    names = {label_key(n) for n, _w in cheats}
    out = []
    for name, words in cheats:
        out.append((name, words))
        got = parse(words)
        rname = label_key(name) + " - restore"
        if got and rname not in names:
            out.append((rname, restore_ops(got[1])))
            names.add(rname)
    return out


def merge(to, frm):
    """to with frm's patches added (an address already there takes the new hack); None when an
    address is in both with a different original."""
    out = [Patch(p.header, p.offset, p.original, p.hack) for p in to]
    for p in frm:
        for q in out:
            if q.same_address(p):
                if q.original != p.original:
                    return None
                q.hack = p.hack
                break
        else:
            out.append(Patch(p.header, p.offset, p.original, p.hack))
    return out


def cheat_patches(cid, cheats, read_word):
    """(key, [Patch], restore_id) of cheat cid, as Breeze's Merge into reads it:
      - the block form as it is;
      - the old pair: its first two stores hit one address and there is nothing else;
      - nothing but code stores: the originals from "<name> - restore" when that covers every
        address (restore_id is then its id), else from the game (read_word(patch) -> word, None
        when it cannot be read, e.g. an R1 patch with no R1 known) or from another cheat's block.
    cheats: [(id, on, "[name] words...")] as cheats_get gives them. Raises ValueError(why)."""
    by_id = {c[0]: c for c in cheats}
    if cid not in by_id:
        raise ValueError("no cheat %d" % cid)
    name, op = split_cheat(by_id[cid][2])
    got = parse(op)
    if got:
        return got[0], got[1], 0
    key, i, end = 0, 0, len(op)
    if op and op[0] >> 28 == 0x8:
        if end < 2 or op[-1] != END:
            raise ValueError("%s has more than code patches in it" % name)
        key, i, end = op[0], 1, end - 1
    stores = []
    while i < end:
        if i + 3 > end or not is_code_store(op[i]):
            raise ValueError("%s has more than code patches in it (an ASM cave, a pointer or a data write)" % name)
        stores.append(Patch(op[i], op[i + 1], 0, op[i + 2]))
        i += 3
    if not stores:
        raise ValueError("%s has no code patch in it" % name)
    if len(stores) == 2 and stores[0].same_address(stores[1]):
        p = stores[1]
        p.original = stores[0].hack
        return key, [p], 0
    for a in range(len(stores)):
        for b in range(a + 1, len(stores)):
            if stores[a].same_address(stores[b]):
                raise ValueError("%s writes %s twice" % (name, stores[a].label))
    restore_name = label_key(name) + " - restore"
    for rid, _on, text in cheats:
        rname, rop = split_cheat(text)
        if rid == cid or label_key(rname) != restore_name:
            continue
        found = {}
        for j in range(0, len(rop) - 2, 3):
            if not is_code_store(rop[j]):
                break
            found[(rop[j], rop[j + 1])] = rop[j + 2]
        if all((p.header, p.offset) in found for p in stores):
            for p in stores:
                p.original = found[(p.header, p.offset)]
            return key, stores, rid
    for p in stores:
        p.original = recorded_original(p.rel, cheats, skip_id=cid, r1=p.r1)
        if p.original is None:
            p.original = read_word(p)
        if p.original is None:
            raise ValueError("cannot read %s%s" % (p.label, " (no master cheat sets R1)" if p.r1 else ""))
        if p.original == p.hack:
            raise ValueError("%s holds the patch already and nothing records the game's instruction; turn %s off "
                             "and put the game's code back (restart the game) first" % (p.label, name))
    return key, stores, 0


def recorded_original(rel, cheats, skip_id=None, r1=False):
    """The game's instruction at main+rel (R1+rel with r1) as a cheat records it (its block, or an
    old pair's first store), or None."""
    for cid, _on, text in cheats:
        if cid == skip_id:
            continue
        _name, op = split_cheat(text)
        got = parse(op)
        if got:
            for p in got[1]:
                if p.r1 == r1 and p.rel == rel:
                    return p.original
            continue
        i = 1 if op and op[0] >> 28 == 0x8 else 0
        if len(op) >= i + 6 and is_code_store(op[i]) and op[i] == op[i + 3] and op[i + 1] == op[i + 4] \
                and bool((op[i] >> 16) & 1) == r1 and (((op[i] & 0xFF) << 32) | op[i + 1]) == rel:
            return op[i + 2]
    return None


def cheat_text(name, ops):
    """A cheat as cheat-file text: [name] then three words to a line."""
    lines = ["[%s]" % name]
    i = 0
    while i < len(ops):
        n = opcode_words(ops, i) or 1
        lines.append(" ".join("%08X" % w for w in ops[i:i + n]))
        i += n
    return "\n".join(lines)


def split_cheat(text):
    """(name, [words]) of a cheat as `cheats get` gives it: "[name] w w w ..."."""
    name = ""
    if text.startswith("["):
        name, text = text[1:].split("]", 1)
    words = [int(w, 16) for w in text.split() if re.fullmatch(r"[0-9A-Fa-f]{8}", w)]
    return name.strip(), words


def label_key(name):
    """A cheat name as Breeze compares it (cave_label_key): without the key-hint glyphs and spaces
    the display writes in front of it."""
    i = 0
    while i < len(name) and (ord(name[i]) >= 0x80 or name[i] == " "):
        i += 1
    return name[i:]
