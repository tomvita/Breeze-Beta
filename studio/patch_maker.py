"""Patch this instruction: a code-patch cheat made on the PC, keeping the game's instruction.

The Code tab's right-click menu opens this on an instruction. You pick (or type) what the
instruction becomes; the dialog assembles it at that address, shows the words, and adds one
cheat in the form of code_patch.py (core/code_patch.hpp):

    [name]
    C046E5E0                       a block that never runs, holding
    04000000 M+ADDR ORIGINAL       the game's instruction
    20000000
    04000000 M+ADDR NEW            the patch

In the loaded module the master cheat's R1 points at (Breeze's meta gives r1), the stores are
R1 relative (04010000) like Breeze's ASM Explorer makes them.

A patch stays in the game's code after its cheat is turned off; Breeze reads the block and puts
the game's instruction back (the second press on a green cheat). Several instructions may be
typed (one per line); they replace that many instructions from the picked one. Naming a cheat
that is already a code patch adds this patch to it, so one cheat can patch many places.

The suggestions are the usual cheat moves, worked out from the instruction:
  sub / subs w8, w8, w23     -> subtract zero (the value does not go down), or add instead
  cset w0, le                -> always 1 (always true) / always 0 (always false)
  b.cond / cbz / tbz ...     -> always jump / never jump (nop)
  ldr w0, [...] in a getter  -> mov w0, #<value>
  any instruction            -> nop
"""
import json
import re
import struct
import tkinter as tk
from tkinter import ttk

import code_patch
import free_regs

try:
    import keystone
except ImportError:
    keystone = None


def store(at, value):
    return "%08X %08X %08X" % (0x04000000 | ((at >> 32) & 0xFF), at & 0xFFFFFFFF, value)


def suggestions(mnem, ops, rva):
    """[(label, replacement asm)] for an instruction."""
    out = []
    ops_l = [o.strip() for o in ops.split(",")] if ops else []
    if mnem in ("sub", "subs") and len(ops_l) == 3 and re.fullmatch(r"[wx]\d+|[wx]zr", ops_l[2]):
        zr = "wzr" if ops_l[0].startswith("w") else "xzr"
        out.append(("subtract nothing (the value does not go down)", "%s %s, %s, %s" % (mnem, ops_l[0], ops_l[1], zr)))
        out.append(("add instead (spending gives)", "%s %s, %s, %s" % ("adds" if mnem == "subs" else "add",
                                                                        ops_l[0], ops_l[1], ops_l[2])))
    if mnem in ("add", "adds") and len(ops_l) == 3 and re.fullmatch(r"[wx]\d+", ops_l[2]):
        out.append(("add twice as much", "%s %s, %s, %s, lsl #1" % (mnem, ops_l[0], ops_l[1], ops_l[2])))
        out.append(("add nothing", "%s %s, %s, %s" % (mnem, ops_l[0], ops_l[1], "wzr" if ops_l[0][0] == "w" else "xzr")))
    if mnem in ("cset", "csetm") and ops_l:
        out.append(("always 1 (always true)", "mov %s, #1" % ops_l[0]))
        out.append(("always 0 (always false)", "mov %s, #0" % ops_l[0]))
    if mnem.startswith("b.") or mnem in ("cbz", "cbnz", "tbz", "tbnz"):
        target = ops_l[-1].lstrip("#") if ops_l else ""
        if target:
            out.append(("always jump", "b %s" % target))
        out.append(("never jump", "nop"))
    if mnem.startswith("ldr") and ops_l and re.fullmatch(r"[wx]\d+", ops_l[0]):
        out.append(("load a fixed value instead", "mov %s, #999" % ops_l[0]))
    if mnem.startswith("str") and not out:
        out.append(("do not store (the value is not written)", "nop"))
    out.append(("nothing (nop)", "nop"))
    seen, uniq = set(), []
    for label, asm in out:
        if asm not in seen:
            seen.add(asm)
            uniq.append((label, asm))
    return uniq


def main_writes(text):
    """[(main offset, 4-byte value)] a cheat stores into main's code with code type 0 (04000000 ...)."""
    words = [int(w, 16) for w in text.split("]", 1)[-1].split() if re.fullmatch(r"[0-9A-Fa-f]{8}", w)]
    out, i = [], 0
    while i + 2 < len(words):
        w = words[i]
        if (w & 0xFFF00000) == 0x04000000 and (w & 0x000FFF00) == 0:
            out.append((((w & 0xFF) << 32) | words[i + 1], words[i + 2]))
            i += 3
        else:
            i += 1
    return out


class Plan:
    """The instruction at rva and what it can become (worker thread)."""

    def __init__(self, game, rva):
        self.rva = rva
        self.main = game.main
        self.read = lambda at, n: game.b.peek(game.main + at, n)
        # In the loaded module the master cheat's R1 points at, the stores are R1 relative
        # (04010000), as Breeze's ASM Explorer makes them: the module has no fixed place.
        try:
            meta = json.loads(game.b.cmd("meta")[4:])
        except Exception:  # noqa: BLE001 - a host without meta
            meta = {}
        self.r1 = int(meta.get("r1", "0"), 16)
        r1_size = int(meta.get("r1_size", "0"), 16)
        self.in_r1 = bool(self.r1) and self.r1 <= rva < self.r1 + r1_size
        self.base = self.r1 if self.in_r1 else 0     # rva - base is the store's offset
        self.words = list(struct.unpack("<16I", self.read(rva, 64)))
        self.live = self.words[0]
        # Another cheat may have patched this already: then the live word is its patch, not the
        # game's. The game's word is the one a cheat that is off writes there (its restore).
        self.touching = []          # (id, on, name, value) of every cheat writing this word
        self.original = self.words[0]
        self.original_known = True
        try:
            cheats = game.b.cheats_get()
        except Exception:  # noqa: BLE001 - a host without cheats
            cheats = []
        self.cheats = cheats
        # A cheat in the code-patch form (or an old pair) records the game's instruction: that is
        # the original, whatever the game holds now.
        recorded = [code_patch.recorded_original(rva - self.base + 4 * i, cheats, r1=self.in_r1)
                    for i in range(len(self.words))]
        for i, rec in enumerate(recorded):
            if rec is not None:
                self.words[i] = rec
        # Code-patch cheats this patch can go into, by name.
        self.patch_cheats = []
        for _cid, _on, text in cheats:
            cname, op = code_patch.split_cheat(text)
            if code_patch.parse(op):
                self.patch_cheats.append(code_patch.label_key(cname))
        for cid, on, text in cheats:
            name = text.split("]", 1)[0].lstrip("[") if text.startswith("[") else ""
            for at, value in main_writes(text):
                if at == rva:
                    self.touching.append((cid, on, name, value))
        patched_by = [t for t in self.touching if t[1] and t[3] == self.words[0]]
        if recorded[0] is not None:
            self.original = recorded[0]
        elif patched_by:
            others = {t[3] for t in self.touching if t[3] != self.words[0]}
            if len(others) == 1:
                self.original = others.pop()
                self.words[0] = self.original
            else:
                self.original_known = False

        # The suggestions are worked out from the game's own instruction, not from a cheat's patch.
        dis = free_regs.capstone_disasm()
        ins = dis(self.words[0], rva)
        self.mnem, self.ops = (ins[0], ins[1]) if ins else (".word", "0x%08X" % self.words[0])
        # capstone writes branch targets as absolute addresses; the asm here is assembled at rva
        self.text = ("%s %s" % (self.mnem, self.ops)).strip()
        self.choices = suggestions(self.mnem, self.ops, rva)

    def assemble(self, asm):
        if keystone is None:
            raise RuntimeError("keystone is not installed on this PC (pip install keystone-engine)")
        src = "\n".join(l.split("//")[0] for l in asm.strip().splitlines())
        ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        try:
            enc, _n = ks.asm(src, self.rva)
        except keystone.KsError as e:
            raise RuntimeError("assembler: %s" % e)
        code = bytes(enc or b"")
        if not code or len(code) % 4:
            raise RuntimeError("it assembles to nothing")
        n = len(code) // 4
        if n > len(self.words):
            raise RuntimeError("at most %d instructions" % len(self.words))
        if not self.original_known:
            raise RuntimeError("a cheat that is on has already patched this instruction and no cheat says what "
                               "the game's own instruction was: turn that cheat off and restore it first")
        return list(struct.unpack("<%dI" % n, code))

    def cheat(self, name, new):
        """(cheat text, ids it replaces, how many patches) for the instructions new from rva.
        A name that is already a code-patch cheat (or an older patch cheat, see
        code_patch.cheat_patches) takes these patches into it."""
        rel = self.rva - self.base
        patches = [code_patch.Patch(code_patch.store_header(rel + 4 * i, self.in_r1), (rel + 4 * i) & 0xFFFFFFFF,
                                    self.words[i], w) for i, w in enumerate(new)]
        key, replaces = 0, []
        into = None
        for cid, _on, text in self.cheats:
            if code_patch.label_key(code_patch.split_cheat(text)[0]) == code_patch.label_key(name):
                into = cid
        if into is not None:
            def read(p):
                at = p.address(0, self.r1)
                return None if at is None else struct.unpack("<I", self.read(at, 4))[0]
            try:
                key, have, restore_id = code_patch.cheat_patches(into, self.cheats, read)
            except ValueError as e:
                raise RuntimeError("cannot add to the cheat named %s: %s" % (name, e))
            merged = code_patch.merge(have, patches)
            if merged is None:
                raise RuntimeError("%s records another original for one of these addresses" % name)
            patches = merged
            replaces = [into] + ([restore_id] if restore_id else [])
        ops = code_patch.build(patches, key)
        if len(ops) > 0x100:
            raise RuntimeError("%d patches need %d opcodes; a cheat holds 256" % (len(patches), len(ops)))
        return code_patch.cheat_text(name, ops), replaces, len(patches)


class PatchMaker:
    """The dialog. `job(fn, done)` runs fn(game) on the Code tab's worker and done(result) here."""

    def __init__(self, parent, job, rva, title=""):
        self.job = job
        self.plan = None
        self.rva = rva
        self.win = tk.Toplevel(parent)
        self.win.title("Patch this instruction: M+%X" % rva)
        self.win.geometry("860x520")
        self.info = tk.Label(self.win, text="reading the code...", anchor="w", justify="left", fg="#555",
                             font=("Consolas", 10))
        self.info.pack(fill="x", padx=6, pady=(6, 2))

        row = tk.Frame(self.win)
        row.pack(fill="x", padx=6, pady=2)
        tk.Label(row, text="Becomes:").pack(side="left")
        self.pick = ttk.Combobox(row, width=60, state="readonly")
        self.pick.pack(side="left", padx=4)
        self.pick.bind("<<ComboboxSelected>>", self.on_pick)
        tk.Label(self.win, text="Instruction(s) - pick above or type (one per line, assembled at this address):",
                 anchor="w").pack(fill="x", padx=6)
        self.asm = tk.Text(self.win, height=4, font=("Consolas", 11), undo=True)
        self.asm.pack(fill="x", padx=6)

        row = tk.Frame(self.win)
        row.pack(fill="x", padx=6, pady=4)
        tk.Label(row, text="Cheat:").pack(side="left")
        self.name = tk.StringVar(value=title or "patch M+%X" % rva)
        self.name_box = ttk.Combobox(row, textvariable=self.name, width=46)
        self.name_box.pack(side="left", padx=4)
        self.name_box.bind("<<ComboboxSelected>>", lambda _e: self.on_check())
        self.on_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row, text="turn it on", variable=self.on_var).pack(side="left")
        self.save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row, text="save the cheat file", variable=self.save_var).pack(side="left")

        self.out = tk.Text(self.win, wrap="none", font=("Consolas", 10), height=12, bg="#f4f4f4")
        self.out.pack(fill="both", expand=True, padx=6)
        bar = tk.Frame(self.win)
        bar.pack(fill="x", padx=6, pady=4)
        tk.Button(bar, text="Check", width=10, command=self.on_check).pack(side="left")
        self.add_btn = tk.Button(bar, text="Add cheat", width=10, command=self.on_add, state="disabled")
        self.add_btn.pack(side="left", padx=4)
        tk.Button(bar, text="Close", width=10, command=self.win.destroy).pack(side="right")
        self.status = tk.Label(bar, text="", anchor="w", fg="#555")
        self.status.pack(side="left", fill="x", expand=True, padx=8)
        self.job(lambda game: self.safe(lambda: Plan(game, rva)), self.on_plan)

    @staticmethod
    def safe(fn):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - shown in the dialog
            return e

    def alive(self):
        return self.win.winfo_exists()

    def on_plan(self, plan):
        if not self.alive():
            return
        if isinstance(plan, Exception):
            self.info.config(text="Cannot read M+%X: %s" % (self.rva, plan), fg="#b00")
            return
        self.plan = plan
        note = ""
        if plan.touching:
            note = "\ncheats writing here: " + ", ".join(
                "%d %s (%s, %08X)" % (cid, name, "on" if on else "off", v) for cid, on, name, v in plan.touching)
            if plan.original_known and plan.original != plan.live:
                note += "\nthe live word %08X is a cheat's patch; the game's own is %08X (from the cheat that is off)" % (
                    plan.live, plan.original)
            elif not plan.original_known:
                note += "\nthe live word is a cheat's patch and no cheat says what the game's own was"
        self.info.config(text="M+%X  %08X  %s%s" % (plan.rva, plan.words[0], plan.text, note))
        self.name_box.config(values=plan.patch_cheats)
        self.pick.config(values=["%s:   %s" % (label, asm) for label, asm in plan.choices])
        self.pick.current(0)
        self.on_pick()
        self.add_btn.config(state="normal")

    def on_pick(self, _e=None):
        if self.plan is None:
            return
        label, asm = self.plan.choices[self.pick.current()]
        self.asm.delete("1.0", "end")
        self.asm.insert("1.0", asm)
        if code_patch.label_key(self.name.get()) not in self.plan.patch_cheats:  # leave a chosen cheat's name alone
            base = self.name.get().split(": ")[0].strip()
            self.name.set("%s: %s" % (base, label.split(" (")[0]))
        self.on_check()

    def build(self):
        if self.plan is None:
            return None
        try:
            new = self.plan.assemble(self.asm.get("1.0", "end"))
        except Exception as e:  # noqa: BLE001
            self.status.config(text=str(e), fg="#b00")
            return None
        name = self.name.get().strip() or "patch M+%X" % self.plan.rva
        try:
            text, replaces, count = self.plan.cheat(name, new)
        except Exception as e:  # noqa: BLE001
            self.status.config(text=str(e), fg="#b00")
            return None
        dis = free_regs.capstone_disasm()
        rows = []
        for i, w in enumerate(new):
            was = dis(self.plan.words[i], self.plan.rva + 4 * i)
            now = dis(w, self.plan.rva + 4 * i)
            rows.append("M+%-9X %08X %-28s -> %08X %s" % (
                self.plan.rva + 4 * i, self.plan.words[i], (" ".join(was)) if was else ".word",
                w, (" ".join(now)) if now else ".word"))
        self.out.delete("1.0", "end")
        self.out.insert("1.0", "\n".join(rows) + "\n\n" + text + "\n")
        if replaces:
            what = "replaces cheat %d (%d patches in all)" % (replaces[0], count)
            if len(replaces) > 1:
                what += " and removes its restore cheat %d" % replaces[1]
        else:
            what = "a new cheat"
        self.status.config(text="%d instruction(s): %s. Breeze restores the originals when it is turned off." % (
            len(new), what), fg="#555")
        return text, replaces

    def on_check(self):
        self.build()

    def on_add(self):
        got = self.build()
        if got is None:
            return
        text, replaces = got
        on, save = bool(self.on_var.get()), bool(self.save_var.get())
        self.add_btn.config(state="disabled")

        def add(game):
            def run():
                if replaces:
                    reply = game.b.cmd("cheats remove %s" % " ".join(map(str, replaces)))
                    if not reply.startswith("+OK"):
                        raise RuntimeError("cheats remove: %s" % reply)
                ids = game.b.cheats_add(text, False)
                if on and ids:
                    game.b.cmd("cheats on %d" % ids[0])
                saved = game.b.cmd("cheats save") if save else ""
                return ids, saved
            return self.safe(run)

        def done(r):
            if not self.alive():
                return
            self.add_btn.config(state="normal")
            if isinstance(r, Exception):
                self.status.config(text="not added: %s" % r, fg="#b00")
                return
            ids, saved = r
            self.status.config(text="added as cheat %s (%s)%s" % (
                " and ".join(map(str, ids)), "on" if on else "off",
                "; saved" if saved.startswith("+OK") else ("; save: " + saved if saved else "")), fg="#060")
        self.job(add, done)
