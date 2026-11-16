"""Breeze Studio: a cheat's opcodes in words, as Breeze's Edit Cheat screen shows them.

  explain(words, game, read, executable)   one entry per opcode:
      raw      the opcode's words
      text     what it does; a write of an instruction to the game's code is disassembled
      target   the address it reads or writes in the running game, or None (Jump to target)
      asm      the address when what it writes is code (Jump to ASM)

It is a dry run, read-only, like Breeze's Trace cheat: registers are followed down the cheat,
loads read the game's memory now, every condition is taken as true (its line says what the
game holds now), and a loop's body is gone through once.
Python 3 only (capstone is used for the instructions when installed).
"""
import struct

try:
    import capstone
    CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
except Exception:  # noqa: BLE001
    CS = None

REGIONS = ("main", "heap", "alias", "aslr")
COND = {1: ">", 2: ">=", 3: "<", 4: "<=", 5: "==", 6: "!="}
MATH = {0: "+", 1: "-", 2: "*", 3: "<<", 4: ">>", 5: "&", 6: "|", 7: "~", 8: "^", 9: "="}
KEYS = ["A", "B", "X", "Y", "LStick", "RStick", "L", "R", "ZL", "ZR", "Plus", "Minus", "Left", "Up", "Right",
        "Down", "LS-Left", "LS-Up", "LS-Right", "LS-Down", "RS-Left", "RS-Up", "RS-Right", "RS-Down", "SL", "SR"]


def asm(word, at):
    if CS is not None:
        for ins in CS.disasm(struct.pack("<I", word), at):
            return ("%s %s" % (ins.mnemonic, ins.op_str)).strip()
    return None


def explain(words, game, read, executable, opcode_len):
    """game: {"main": int, "heap": int, "alias": int, "aslr": int}. read(address, n) -> bytes
    (short or empty when it cannot). executable(address) -> True for the game's code."""
    reg = [0] * 16          # None: not known (a load that could not be read)
    saved = [0] * 16
    out = []

    def base(m):
        return game.get(REGIONS[m]) if m < len(REGIONS) else None

    def where(address):
        if address is None:
            return "?"
        main = game.get("main") or 0
        return "main+%X" % (address - main) if main and main <= address < main + 0x10000000 else "%X" % address

    def add(*terms):
        return None if any(t is None for t in terms) else sum(terms) & 0xFFFFFFFFFFFFFFFF

    def now(address, width):
        if address is None:
            return None
        d = read(address, width)
        return int.from_bytes(d, "little") if len(d) == width else None

    def held(value, width):
        return "?" if value is None else "%0*X" % (width * 2, value)

    i = 0
    while i < len(words):
        n = max(1, min(opcode_len(words, i), len(words) - i))
        w = words[i:i + n] + [0, 0, 0]
        e = {"raw": " ".join("%08X" % x for x in words[i:i + n]), "text": "", "target": None, "asm": None}
        t, width = w[0] >> 28, (w[0] >> 24) & 0xF
        m, r = (w[0] >> 20) & 0xF, (w[0] >> 16) & 0xF
        a40 = ((w[0] & 0xFF) << 32) | w[1]
        if t == 0x0:
            value = (w[2] << 32 | w[3]) if width == 8 else w[2]
            at = add(base(m), reg[r], a40)
            e["target"] = at
            place = "%s+%X%s" % (REGIONS[m] if m < 4 else "?", a40, "+R%d" % r if reg[r] else "")
            code = width == 4 and m == 0 and a40 % 4 == 0 and at is not None and executable(at) and asm(value, at)
            if code:
                e["asm"] = at
                cur = now(at, 4)
                there = ("on" if cur == value else "there now: %s" % (asm(cur, at) or held(cur, 4))) if cur is not None else "?"
                e["text"] = "%s:  %s      (%s)" % (place, code, there)
            else:
                e["text"] = "write %s (%d byte%s) to %s = %s      (holds %s)" % (
                    held(value, width), width, "" if width == 1 else "s", place, where(at), held(now(at, width), width))
        elif t == 0x1:
            c = (w[0] >> 16) & 0xF
            value = (w[2] << 32 | w[3]) if width == 8 else w[2]
            at = add(base(m), a40)
            e["target"] = at
            e["text"] = "if [%s+%X] %s %s      (holds %s)" % (REGIONS[m] if m < 4 else "?", a40, COND.get(c, "?"),
                                                            held(value, width), held(now(at, width), width))
        elif t == 0x2:
            e["text"] = "else" if width == 1 else "end if"
        elif t == 0x3:
            e["text"] = "end loop (R%d counts down)" % r if width == 1 else "loop %d times (count in R%d)" % (w[1], r)
            if width != 1:
                reg[r] = w[1]
        elif t == 0x4:
            reg[r] = w[1] << 32 | w[2]
            e["text"] = "R%d = %X" % (r, reg[r])
        elif t == 0x5:
            mode = (w[0] >> 12) & 0xF
            if mode == 0:
                at, text = add(base(m), a40), "[%s+%X]" % (REGIONS[m] if m < 4 else "?", a40)
            elif mode == 1:
                at, text = add(reg[r], a40), "[R%d+%X]" % (r, a40)
            else:
                s = (w[0] >> 8) & 0xF
                at, text = add(reg[s], a40), "[R%d+%X]" % (s, a40)
            e["target"] = at
            reg[r] = now(at, width)
            e["text"] = "R%d = %s (%d bytes) at %s      (now %s)" % (r, text, width, where(at), held(reg[r], width))
        elif t == 0x6:
            inc, use, o = (w[0] >> 12) & 0xF, (w[0] >> 8) & 0xF, (w[0] >> 4) & 0xF
            at = add(reg[r], reg[o]) if use else reg[r]
            e["target"] = at
            value = w[1] << 32 | w[2]
            e["text"] = "write %s (%d bytes) to [R%d%s] = %s      (holds %s)%s" % (
                held(value & ((1 << (8 * width)) - 1), width), width, r, "+R%d" % o if use else "", where(at),
                held(now(at, width), width), ", then R%d += %d" % (r, width) if inc else "")
            if inc and reg[r] is not None:
                reg[r] += width
        elif t == 0x7:
            op = (w[0] >> 12) & 0xF
            e["text"] = "R%d %s= %X" % (r, MATH.get(op, "?"), w[1])
            reg[r] = _math(op, reg[r], w[1], width)
        elif t == 0x8:
            mask = w[0] & 0x0FFFFFFF
            e["text"] = "if keys held: " + ("+".join(k for b, k in enumerate(KEYS) if mask >> b & 1) or "none")
        elif t == 0x9:
            op, s, imm, s2 = (w[0] >> 20) & 0xF, (w[0] >> 12) & 0xF, (w[0] >> 8) & 0xF, (w[0] >> 4) & 0xF
            if imm:
                value = (w[1] << 32 | w[2]) if width == 8 else w[1]
                e["text"] = "R%d = R%d %s %X" % (r, s, MATH.get(op, "?"), value)
                reg[r] = _math(op, reg[s], value, width)
            else:
                e["text"] = "R%d = R%d %s R%d" % (r, s, MATH.get(op, "?"), s2)
                reg[r] = _math(op, reg[s], reg[s2], width)
        elif t == 0xA:
            s, inc, o, x = (w[0] >> 20) & 0xF, (w[0] >> 12) & 0xF, (w[0] >> 8) & 0xF, (w[0] >> 4) & 0xF
            a36 = ((w[0] & 0xF) << 32) | w[1]
            if o == 0:
                at, text = reg[r], "[R%d]" % r
            elif o == 1:
                at, text = add(reg[r], reg[x]), "[R%d+R%d]" % (r, x)
            elif o == 2:
                at, text = add(reg[r], a36), "[R%d+%X]" % (r, a36)
            elif o == 3:
                at, text = add(base(x), reg[r]), "[%s+R%d]" % (REGIONS[x] if x < 4 else "?", r)
            elif o == 4:
                at, text = add(base(x), a36), "[%s+%X]" % (REGIONS[x] if x < 4 else "?", a36)
            else:
                at, text = add(base(x), a36, reg[r]), "[%s+%X+R%d]" % (REGIONS[x] if x < 4 else "?", a36, r)
            e["target"] = at
            e["text"] = "write R%d = %s (%d bytes) to %s = %s      (holds %s)%s" % (
                s, held(reg[s], width) if reg[s] is not None else "?", width, text, where(at),
                held(now(at, width), width), ", then R%d += %d" % (r, width) if inc and o < 3 else "")
            if inc and o < 3 and reg[r] is not None:
                reg[r] += width
        elif t == 0xC and width == 0:
            c, s, form = (w[0] >> 16) & 0xF, (w[0] >> 12) & 0xF, (w[0] >> 8) & 0xF
            wd = (w[0] >> 20) & 0xF
            if form == 4:
                value = (w[1] << 32 | w[2]) if wd == 8 else w[1]
                other = "%X" % value
            elif form == 5:
                other = "R%d" % ((w[0] >> 4) & 0xF)
            else:
                other = "memory (%s)" % e["raw"]
            e["text"] = "if R%d %s %s      (R%d is %s)" % (s, COND.get(c, "?"), other, s, held(reg[s], wd or 8))
        elif t == 0xC and width in (1, 2, 3):
            e["text"] = {1: "save or restore a register", 2: "save or restore registers by mask",
                         3: "read or write a static register"}[width]
            d, s, op = (w[0] >> 16) & 0xF, (w[0] >> 8) & 0xF, (w[0] >> 4) & 0xF
            if width == 1:
                if op == 0:
                    reg[d] = saved[s]
                    e["text"] = "R%d = saved %d" % (d, s)
                elif op == 1:
                    saved[d] = reg[s]
                    e["text"] = "saved %d = R%d" % (d, s)
                elif op == 2:
                    saved[d] = 0
                    e["text"] = "saved %d = 0" % d
                else:
                    reg[d] = 0
                    e["text"] = "R%d = 0" % d
        elif w[0] >> 20 == 0xFF0:
            e["text"] = "pause the game"
        elif w[0] >> 20 == 0xFF1:
            e["text"] = "resume the game"
        elif w[0] >> 20 == 0xFFF:
            e["text"] = "debug log"
        else:
            e["text"] = "(an opcode this view does not know)"
        out.append(e)
        i += n
    return out


def _math(op, a, b, width):
    if a is None or (b is None and op not in (7, 9)):
        return None
    mask = (1 << (8 * (width or 8))) - 1
    try:
        v = {0: lambda: a + b, 1: lambda: a - b, 2: lambda: a * b, 3: lambda: a << (b & 63), 4: lambda: a >> (b & 63),
             5: lambda: a & b, 6: lambda: a | b, 7: lambda: ~a, 8: lambda: a ^ b, 9: lambda: a}[op]()
    except KeyError:
        return None
    return v & mask
