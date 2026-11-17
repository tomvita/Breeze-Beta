"""Which registers a code cave may use without saving them.

    free_registers(read_word, rva) -> Result

`read_word(rva)` gives the 32-bit instruction at a main-relative address, or None where there
is no code. The answer holds at `rva` BEFORE the instruction there runs, which is where a
hook's cave code runs when it comes ahead of {original}.

The rule is the plain one, kept conservative: a register is free when, on every path the code
can take from here, it is written before it is read. The scan follows branches both ways. It
knows the calling convention at a call and at a return: x9-x17 and the flags do not survive
either, x0-x8 are taken as read (arguments, results), x19-x28 must be handed back.

Everything is decided from the disassembly TEXT, with one small table of instructions whose
first operand is only written. An instruction that is not in the table reads every register
it names, so an unknown instruction can only make the answer smaller, never wrong. Breeze's
on-device copy (source/freeregs.cpp) is the same rule on the same text.

x18 (the platform register), x29 and x30 are never offered: stack walkers read the last two
from a thread at any moment.
"""
import re
import struct

# First operand is written and not read (unless it is named again as a source).
PURE_DEST = set("""
mov movz movn mvn add adds sub subs neg negs mul madd msub mneg smull umull smulh umulh smaddl umaddl
smsubl umsubl smnegl umnegl sdiv udiv and ands orr orn eor eon bic bics lsl lsr asr ror lslv lsrv asrv rorv
ubfx sbfx ubfiz sbfiz ubfm sbfm sxtb sxth sxtw uxtb uxth uxtw extr clz cls rbit rev rev16 rev32
csel csinc csinv csneg cset csetm cinc cinv cneg adr adrp
ldr ldrb ldrh ldrsb ldrsh ldrsw ldur ldurb ldurh ldursb ldursh ldursw
fcvtzs fcvtzu fcvtas fcvtau fcvtms fcvtmu fcvtns fcvtnu fcvtps fcvtpu umov smov
""".split())
# fmov is a pure write of its first operand too; a vector first operand is simply not counted.
PURE_DEST.add("fmov")
PURE_DEST_2 = {"ldp", "ldpsw"}  # the first two operands
FLAG_WRITE = set("cmp cmn tst adds subs negs ands bics fcmp fcmpe".split())
FLAG_READ = set("""csel csinc csinv csneg cset csetm cinc cinv cneg adc adcs sbc sbcs ngc ngcs
ccmp ccmn fccmp fccmpe fcsel mrs msr cfinv axflag xaflag rmif setf8 setf16""".split())
CALL = {"bl", "blr", "blraa", "blraaz", "blrab", "blrabz"}
RETURN = {"ret", "retaa", "retab"}
COND = {"cbz", "cbnz", "tbz", "tbnz"}
STOP = {"br", "braa", "braaz", "brab", "brabz", "svc", "brk", "hvc", "smc", "udf", "eret", "drps", "hlt"}
NEVER = {18, 29, 30}

REG = re.compile(r"(?<![A-Za-z0-9_.])([xw])(\d{1,2})(?![A-Za-z0-9_])")
OVER, CONV, USED = 0, 1, 2  # overwritten before any read / dead by the calling convention / read


def regs_in(text):
    return {int(n) for _k, n in REG.findall(text) if int(n) <= 30}


def effects(mnem, ops):
    """(registers read, registers written without being read, reads flags, writes flags)."""
    mnem = mnem.lower()
    ops = ops.lower()
    parts = [p.strip() for p in ops.split(",")]
    written = set()
    rest = ops
    take = 2 if mnem in PURE_DEST_2 else 1 if mnem in PURE_DEST else 0
    if take and len(parts) > take:
        heads = parts[:take]
        if all(REG.fullmatch(h) for h in heads):
            written = {int(REG.fullmatch(h).group(2)) for h in heads}
            rest = ",".join(parts[take:])
    read = regs_in(rest)
    if "1716" in mnem:
        read |= {16, 17}
    written -= read
    flag_read = mnem in FLAG_READ or mnem.startswith("b.")
    flag_write = mnem in FLAG_WRITE and not flag_read
    return read, written, flag_read, flag_write


class Result:
    def __init__(self, state, flags, steps, complete):
        self.overwritten = sorted(r for r, s in state.items() if s == OVER)
        self.by_convention = sorted(r for r, s in state.items() if s == CONV)
        self.flags = flags  # OVER / CONV / USED
        self.steps = steps
        self.complete = complete  # False: the scan ran out of budget somewhere (those paths count as "read")

    @property
    def free(self):
        return sorted(self.overwritten + self.by_convention)

    def comment(self, mark="//"):
        """The lines for the top of a cave script."""
        names = lambda rs: " ".join("x%d" % r for r in rs)
        out = []
        if self.overwritten:
            out.append("%s free here (the game writes them before it reads them): %s" % (mark, names(self.overwritten)))
        if self.by_convention:
            out.append("%s free here (not read before the next call or return, or a function's start): %s" % (mark, names(self.by_convention)))
        if not self.free:
            out.append("%s no register is free here: save what you use (stp x16, x17, [sp, #-16]! ... ldp x16, x17, [sp], #16)" % mark)
        out.append("%s flags (cmp, tst, adds...): %s" % (mark, "free here" if self.flags != USED else
                                                          "IN USE here - do not change them before {original}"))
        return out


def special(w):
    """Pointer authentication forms an older disassembler does not know (Breeze's on-device one)."""
    if w in (0xD65F0BFF, 0xD65F0FFF):
        return "retab", ""
    if (w & 0xFFFFF81F) == 0xD63F081F or (w & 0xFFFFF800) == 0xD73F0800:  # blraaz / blraa
        return "blraa", "x%d, x%d" % ((w >> 5) & 31, (w & 31) if (w >> 24) & 1 else 31)
    if (w & 0xFFFFF81F) == 0xD61F081F or (w & 0xFFFFF800) == 0xD71F0800:  # braaz / braa
        return "braa", ""
    # Atomics (ARMv8.1 LSE), decoded here so the PC and Breeze's older on-device capstone agree.
    if (w & 0x3F200C00) == 0x38200000:  # ldadd / ldclr / ldeor / ldset / ld[su]max|min / swp / ldapr
        return "ldr", "x%d, [x%d], x%d" % (w & 31, (w >> 5) & 31, (w >> 16) & 31)
    if (w & 0x3FA07C00) == 0x08A07C00 or (w & 0xBFA07C00) == 0x08207C00:  # cas* / casp*: every register read
        pair = 0 if w & 0x00800000 else 1
        s_, t_ = (w >> 16) & 31, w & 31
        return "cas", "x%d, x%d, x%d, x%d, [x%d]" % (s_, s_ + pair, t_, t_ + pair, (w >> 5) & 31)
    if (w & 0xFF200400) == 0xF8200400:  # ldraa / ldrab: a load through xN
        return "ldr", "x%d, [x%d]" % (w & 31, (w >> 5) & 31)
    return None


ENTRY_WORDS = {0xD503233F, 0xD503237F, 0xD503245F, 0xD50324DF}  # paciasp, pacibsp, bti c, bti jc: only at a function's start


def free_registers(read_word, rva, disasm, budget=600, max_forks=24, first_word=0, entry=False):
    """`disasm(word, rva)` -> (mnemonic, op_str) or None for a word that is not an instruction.
    first_word, when not 0, stands in for the word at rva (a hook already in the game has a
    branch there). entry: rva is known to be a function's first instruction (a word of
    ENTRY_WORDS there says so too); x9-x17 and the flags are then free by the calling convention
    whatever the scan finds."""
    wanted = [r for r in range(31) if r not in NEVER]
    total = {r: OVER for r in wanted}  # the neutral element: joined with every path's verdict
    total_flags = [OVER]
    steps = [0]
    complete = [True]

    def join(state, flags):
        for r in wanted:
            total[r] = max(total[r], state.get(r, USED))
        total_flags[0] = max(total_flags[0], flags)

    def end(state, flags, verdict_low, verdict_callee, flag_verdict):
        """A path ends: what is still undecided gets the verdict of how it ended."""
        for r in wanted:
            if r not in state:
                state[r] = USED if r <= 8 else verdict_low if r <= 17 else verdict_callee
        join(state, flag_verdict if flags is None else flags)

    def walk(at, state, flags, seen, forks):
        while True:
            if len(state) == len(wanted) and flags is not None:
                return join(state, flags)
            if at in seen:  # a loop: where it goes on from here is already being walked
                return
            seen = seen | {at}
            steps[0] += 1
            word = first_word if at == rva and first_word else read_word(at)
            ins = (special(word) or disasm(word, at)) if word is not None else None
            if steps[0] > budget or ins is None:
                complete[0] = complete[0] and ins is not None
                return end(state, flags, USED, USED, USED)
            mnem, ops = ins[0].lower(), ins[1]
            read, written, flag_read, flag_write = effects(mnem, ops)
            for r in read:
                if r in total and r not in state:
                    state[r] = USED
            if flag_read and flags is None:
                flags = USED
            if mnem in RETURN:
                return end(state, flags, CONV, USED, CONV)
            if mnem in STOP:
                return end(state, flags, USED, USED, USED)
            if mnem in CALL:
                for r in wanted:
                    if r not in state and r <= 17:
                        state[r] = USED if r <= 8 else CONV
                if flags is None:
                    flags = CONV
                at += 4
                continue
            for r in written:
                if r in total and r not in state:
                    state[r] = OVER
            if flag_write and flags is None:
                flags = OVER
            target = None
            if mnem == "b" or mnem.startswith("b.") or mnem in COND:
                m = re.search(r"#(-?0x[0-9a-f]+|-?\d+)\s*$", ops.lower())
                if m is None:
                    return end(state, flags, USED, USED, USED)
                target = int(m.group(1), 0)
            if mnem == "b":
                at = target
                continue
            if target is not None:
                if forks >= max_forks:
                    complete[0] = False
                    return end(state, flags, USED, USED, USED)
                walk(target, dict(state), flags, seen, forks + 1)
                forks += 1
            at += 4

    walk(rva, {}, None, frozenset(), 0)
    if entry or (first_word or read_word(rva)) in ENTRY_WORDS:
        for r in range(9, 18):
            if total[r] == USED:
                total[r] = CONV
        total_flags[0] = min(total_flags[0], CONV)
    state = {r: s for r, s in total.items() if s != USED}
    return Result(state, total_flags[0], steps[0], complete[0])


def capstone_disasm():
    """disasm() over the capstone on this PC."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    def one(word, rva):
        for i in md.disasm(struct.pack("<I", word), rva):
            return i.mnemonic, i.op_str
        return None
    return one
