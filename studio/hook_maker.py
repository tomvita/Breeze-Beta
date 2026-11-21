"""Hook here: an ASM cheat made on the PC, for every host (Breeze on a Switch, the Lichii fork, emuhost).

The Code tab's right-click menu opens this on an instruction. The script starts as Breeze's
Add ASM template does - your code, then {original}, then `b code1+4` - with the registers the
cave may use without saving them written at the top (free_regs.py). Check assembles it on the
PC (keystone) and shows the cave; Add cheat adds it to the host's cheat list in Breeze's stored
form, which every host understands:

    04000000 HOOK ORIGINAL      the instruction it replaces (what goes back when it is off)
    04000000 HOOK BRANCH        the branch to the cave
    04000000 CAVE WORD ...      the cave

The cave goes in the unused end of main's code, above every cave the host's cheats already
write there. Names the script can use: code1 (the hook), cave_start, and {original}.
"""
import re
import struct
import tkinter as tk
from tkinter import ttk

import free_regs

try:
    import keystone
except ImportError:      # the dialog says so; the rest of the Code tab works without it
    keystone = None

TAIL_SCAN = 0x40000      # how much of the end of main's code is looked at for the cave
GAP = 0x10               # space kept between caves


def pc_relative(w):
    return ((w & 0x7C000000) == 0x14000000 or (w & 0xFF000010) == 0x54000000 or
            (w & 0x7E000000) in (0x34000000, 0x36000000) or (w & 0x1F000000) == 0x10000000 or
            (w & 0x3B000000) == 0x18000000)


def sanitize(src):
    """A literal such as `.float 00.5` hangs keystone for good (Breeze's sanitize_asm_literals)."""
    return re.sub(r"(?<![\w.$])0+(?=\d+\.)", "", src)


def cheat_words(text):
    """(word, the word before it) for every 8-digit word of a cheat."""
    words = [int(w, 16) for w in text.split("]", 1)[-1].split() if re.fullmatch(r"[0-9A-Fa-f]{8}", w)]
    return zip(words, [0] + words[:-1])


class Plan:
    """What the worker found for a hook at rva."""

    def __init__(self, game, rva, entry=False):
        b = game.b
        self.rva = rva
        self.word = struct.unpack("<I", b.peek(game.main + rva, 4))[0]
        if (self.word >> 26) == 5:
            raise RuntimeError("M+%X is already a branch (a hook of another cheat?)" % rva)
        dis = free_regs.capstone_disasm()
        ins = dis(self.word, rva)
        self.text = (ins[0] + " " + ins[1]).strip() if ins else ""
        cache = {}

        def word(r):
            if r < 0 or r >= game.text_size:
                return None
            k = r & ~0xFFF
            if k not in cache:
                cache[k] = b.peek(game.main + k, 0x1000)
            return struct.unpack_from("<I", cache[k], r & 0xFFF)[0]
        self.free = free_regs.free_registers(word, rva, dis, first_word=self.word, entry=entry)
        # the cave: the zero tail of main's code, above every cave a cheat already writes there
        end = game.text_size
        start = max(0, end - TAIL_SCAN)
        data = b""
        for a in range(start, end, 0x1000):
            data += b.peek(game.main + a, 0x1000)
        zero = len(data) - len(data.rstrip(b"\0"))
        lo = end - zero
        used = []
        # Any word of any cheat that reads as an address in that range counts as used, which can
        # only put the cave higher than it needs to be (decoding every opcode's length is not needed).
        for _id, _on, text in b.cheats_get():
            for w, before in cheat_words(text):
                if start <= w < end:
                    used.append(w + (8 if (before >> 24) == 0x08 else 4))
        if used:
            lo = max(lo, max(used))
        self.cave = (lo + GAP + 15) & ~15
        self.cave_end = end
        if self.cave >= end - 0x20:
            raise RuntimeError("no room left at the end of main's code (M+%X..M+%X)" % (lo, end))
        if abs(self.cave - rva) > 0x7FFFFFC:
            raise RuntimeError("the cave at M+%X is out of a branch's reach from M+%X" % (self.cave, rva))

    def original_line(self):
        """{original}: as a word unless it depends on where it runs (keystone 0.9.2 has no PAC instructions)."""
        if self.text and pc_relative(self.word):
            return self.text
        return ".word 0x%08X%s" % (self.word, " /* %s */" % self.text if self.text else "")

    def template(self):
        return "\n".join(self.free.comment() + ["", "// your code here", "", "{original}", "b code1+4", ""])

    def assemble(self, script):
        if keystone is None:
            raise RuntimeError("keystone is not installed on this PC (pip install keystone-engine)")
        body = script.replace("{original}", self.original_line())
        src = "code1 = 0x%X\ncave_start = 0x%X\n%s\n" % (self.rva, self.cave, sanitize(body))
        ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        try:
            enc, _n = ks.asm(src, self.cave)
        except keystone.KsError as e:
            raise RuntimeError("assembler: %s" % e)
        code = bytes(enc or b"")
        if not code or len(code) % 4:
            raise RuntimeError("the script assembles to nothing")
        if self.cave + len(code) > self.cave_end:
            raise RuntimeError("the cave (%d bytes) runs past the end of main's code" % len(code))
        words = list(struct.unpack("<%dI" % (len(code) // 4), code))
        branch = 0x14000000 | (((self.cave - self.rva) >> 2) & 0x3FFFFFF)
        return words, branch

    @staticmethod
    def store(at, value):
        return "%08X %08X %08X" % (0x04000000 | ((at >> 32) & 0xFF), at & 0xFFFFFFFF, value)

    @staticmethod
    def store64(at, low, high):
        """Two instructions in one type-0 store: the VM takes the value as first << 32 | second."""
        return "%08X %08X %08X %08X" % (0x08000000 | ((at >> 32) & 0xFF), at & 0xFFFFFFFF, high, low)

    def cheat_text(self, name, words, branch):
        # The cave in 64-bit stores (4 words per 2 instructions, not 6): a cheat holds 256 words,
        # and a 100-instruction cave as 32-bit stores needs over 300 (found on Dreamlight Valley).
        lines = ["[%s]" % name, self.store(self.rva, self.word), self.store(self.rva, branch)]
        i = 0
        while i < len(words):
            at = self.cave + 4 * i
            if i + 1 < len(words) and at % 8 == 0:
                lines.append(self.store64(at, words[i], words[i + 1]))
                i += 2
            else:
                lines.append(self.store(at, words[i]))
                i += 1
        n = sum(len(l.split()) for l in lines[1:])
        if n > 256:
            raise RuntimeError("the cheat would be %d words; a cheat holds 256 (make the cave shorter)" % n)
        return "\n".join(lines)


class HookMaker:
    """The dialog. `job(fn, done)` runs fn(game) on the Code tab's worker and done(result) here."""

    def __init__(self, parent, job, rva, title="", entry=False):
        self.job = job
        self.plan = None
        self.win = tk.Toplevel(parent)
        self.win.title("Hook here: M+%X" % rva)
        self.win.geometry("820x620")
        top = tk.Frame(self.win)
        top.pack(fill="x", padx=6, pady=4)
        tk.Label(top, text="Cheat name:").pack(side="left")
        self.name = tk.StringVar(value="asm %s" % (title or "M+%X" % rva))
        tk.Entry(top, textvariable=self.name, width=40).pack(side="left", padx=4)
        self.on_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="turn it on", variable=self.on_var).pack(side="left")
        self.info = tk.Label(self.win, text="reading the code...", anchor="w", justify="left", fg="#555")
        self.info.pack(fill="x", padx=6)
        panes = tk.PanedWindow(self.win, orient="vertical", sashwidth=6)
        panes.pack(fill="both", expand=True, padx=6)
        self.script = tk.Text(panes, wrap="none", font=("Consolas", 11), undo=True, height=16)
        panes.add(self.script, minsize=120)
        self.out = tk.Text(panes, wrap="none", font=("Consolas", 10), height=10, bg="#f4f4f4")
        panes.add(self.out, minsize=60)
        bar = tk.Frame(self.win)
        bar.pack(fill="x", padx=6, pady=4)
        tk.Button(bar, text="Check", width=10, command=self.on_check).pack(side="left")
        self.add_btn = tk.Button(bar, text="Add cheat", width=10, command=self.on_add, state="disabled")
        self.add_btn.pack(side="left", padx=4)
        tk.Button(bar, text="Close", width=10, command=self.win.destroy).pack(side="right")
        self.status = tk.Label(bar, text="", anchor="w", fg="#555")
        self.status.pack(side="left", fill="x", expand=True, padx=8)
        self.job(lambda game: self.safe(lambda: Plan(game, rva, entry)), self.on_plan)

    @staticmethod
    def safe(fn):
        try:
            return fn()
        except Exception as e:      # shown in the dialog, not the Code tab's status line
            return e

    def alive(self):
        return self.win.winfo_exists()

    def on_plan(self, plan):
        if not self.alive():
            return
        if isinstance(plan, Exception):
            self.info.config(text="Cannot hook here: %s" % plan, fg="#b00")
            return
        self.plan = plan
        self.info.config(text="Hook M+%X  %s\nCave at M+%X (the end of main's code, after the caves of the cheats in the list)%s"
                         % (plan.rva, plan.text or ".word 0x%08X" % plan.word, plan.cave,
                            "" if plan.free.complete else "\nThe register scan stopped early on some paths: those count as in use."))
        self.script.insert("1.0", plan.template())
        self.add_btn.config(state="normal")

    def show(self, words, branch):
        dis = free_regs.capstone_disasm()
        p = self.plan
        rows = ["M+%-9X %08X  %s   (the hook)" % (p.rva, branch, "b #0x%X" % p.cave)]
        for i, w in enumerate(words):
            ins = dis(w, p.cave + 4 * i)
            rows.append("M+%-9X %08X  %s" % (p.cave + 4 * i, w, (ins[0] + " " + ins[1]) if ins else ".word"))
        self.out.delete("1.0", "end")
        self.out.insert("1.0", "\n".join(rows))

    def assemble(self):
        if self.plan is None:
            return None
        try:
            words, branch = self.plan.assemble(self.script.get("1.0", "end"))
        except Exception as e:
            self.status.config(text=str(e), fg="#b00")
            return None
        self.show(words, branch)
        self.status.config(text="%d instructions, cave M+%X..M+%X" % (len(words), self.plan.cave, self.plan.cave + 4 * len(words)), fg="#555")
        return words, branch

    def on_check(self):
        self.assemble()

    def on_add(self):
        got = self.assemble()
        if got is None:
            return
        name = self.name.get().strip() or "asm M+%X" % self.plan.rva
        try:
            text = self.plan.cheat_text(name, *got)
        except RuntimeError as e:
            self.status.config(text=str(e), fg="#b00")
            return
        on = bool(self.on_var.get())
        self.add_btn.config(state="disabled")

        def add(game):
            return self.safe(lambda: game.b.cheats_add(text, on))

        def done(ids):
            if not self.alive():
                return
            self.add_btn.config(state="normal")
            if isinstance(ids, Exception):
                self.status.config(text="not added: %s" % ids, fg="#b00")
                return
            self.status.config(text="added as cheat %s (%s). The Cheats tab saves it to the game's cheat file." %
                               (" ".join(map(str, ids)), "on" if on else "off"), fg="#060")
        self.job(add, done)
