#!/usr/bin/env python3
"""Breeze PC disassembler: the running game's code, read through PC connect and disassembled on the PC.

Opened with "Disassembler" in pcconnect_app.py, or on its own:

    python pcconnect_asm.py [ip] [code]

It needs the capstone package (pip install capstone).

- The listing is one whole function at a time, however long, with the address
  as main+offset, the instruction word, and a comment column: the function a
  call goes to, where a branch lands, the address an adrp pair builds and what
  is there (a string, a pointer into the game, a number).
- Functions come from the game's function map when Breeze has made one
  (Unity, Unreal, GameMaker), and from its unwind table otherwise, where they
  are named func_<offset>; names from a script table are used when there are
  any. The list on the left filters as you type.
- Go takes an address (M+1CBC40, 1CBC40, or absolute) or part of a function's
  name. Double-click a line to follow its call, branch or data address; Back
  and Forward (Alt+Left / Alt+Right) retrace. Callers lists every b / bl to the
  function shown, found by Breeze on the console.
- "Code watch" on the left lists the functions the last code watch recorded,
  in the order they were first called, the ones after the mark first: the
  result is read where it is, on the PC, without paging through it on the
  Switch.
- Find searches the listing; Copy and Save take the selection or the whole
  function.
- Right-click > Patch this instruction: one instruction becomes another (nop, subtract
  nothing, always true, always jump, or typed), as a cheat that keeps the original in a block
  that never runs, so Breeze puts it back when the cheat is turned off; naming an existing
  code-patch cheat adds the patch to it (studio/patch_maker.py, studio/code_patch.py).
- Right-click > Hook here: make an ASM cheat (studio/hook_maker.py): a script
  editor that starts with the registers the cave may use without saving them
  and {original} / b code1+4, a cave picked in the unused end of main's code
  above the caves the cheats in the list already write, Check (assembled on
  the PC; needs the keystone-engine package) and Add cheat, in the stored
  form every host takes: Breeze on a Switch, the Lichii fork, emuhost.
- Decompile (F6) opens a pane beside the listing with the function as C, made
  by Ghidra's decompiler and kept in step with the listing (pcconnect_decomp.py;
  the first time it offers to download and set up Ghidra).

It is also a debugger, on the breakpoints of Breeze's Break and Trace (PC
connect's `dbg`), so a break set here and one set on the Switch are the same
breaks:

- Break (F9) sets or takes off a breakpoint on the line under the cursor; Run
  to (F4) runs the game to that line once. When the game stops, the listing
  goes to the line it stopped on and the panel on the right shows the
  registers, the ones that changed since the last stop marked, and the stack
  with each value that is an address named.
- Step (F11) runs one instruction, into a call; Over (F10) runs a call as one
  step; Continue (F5) lets the game run to the next break; Stop takes every
  breakpoint off and lets it run.
- Click a register to see the memory it points at; double-click to change its
  value. "Float" shows v0 to v31 in place of the general registers, each as
  a double, as a float, and as its 128 bits; the list beside it shows all
  four floats or both doubles of each register instead, lane 0 first.
  Double-click a value to change that one lane: the float or the double under
  the mouse, typed as a number, or as 0x and its bits.
- The memory panel shows the stack, or memory at whatever is typed into its
  box: an address, M+offset, heap+offset, a register, or a sum such as x0+48.
  The list beside it picks the format: 8-byte values with what each points
  at, 4-byte hex, signed, float, double, 2-byte, or bytes with their text.

Code is read 4 KB at a time and kept, so going back to a function is instant;
Reload reads it again (after a cheat or a hook has changed it). The window
uses a connection of its own.
"""
import bisect
import json
import os
import queue
import re
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import capstone
from capstone import arm64_const as A

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcconnect import Breeze, game_caption  # noqa: E402
import pcconnect_decomp  # noqa: E402
from pcconnect_decomp import CPane  # noqa: E402
sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), "studio"))
import code_modules  # noqa: E402

CONFIG = os.path.join(os.path.expanduser("~"), ".breeze_pc.json")
CACHE = os.path.join(os.path.expanduser("~"), ".breeze_pc")
PAGE = 0x1000
MAX_VIEW = 0x10000          # bytes of one function shown at most
MAX_DECOMP = 0x20000        # code loaded for the decompiler at most; Ghidra follows the code to find the end
LIST_MAX = 3000             # rows the function list shows at once
MAPS = ("il2cpp_function_map.txt", "ue_function_map.txt", "gm_function_map.txt")

BG, FG = "#1b2030", "#d8dce6"
FG_DIM, FG_ADDR, FG_CALL, FG_JUMP, FG_RET, FG_NOTE, FG_STR = (
    "#6f7890", "#8fa3c8", "#7fc8ff", "#ffd27f", "#ff8f8f", "#8fd08f", "#e0b0ff")
BG_CUR, BG_HIT, BG_PANEL = "#3a4a78", "#7a5a00", "#262c3f"
BG_PC, BG_BP, FG_CHANGED = "#1f6b3a", "#8a2a2a", "#ffb347"
BREAK_WORD = 0xE7FFFFFF     # what gen2 writes over an instruction it breaks on
BLOCK = 0x180               # bytes of memory the data panel shows
GEN2_PEEK = 64              # rows of an instruction watch whose address is read at each refresh
FORMATS = ("8 bytes + what it is", "4 bytes hex", "4 bytes signed", "float", "double", "2 bytes hex", "bytes + text")
VECTOR_VIEWS = ("d and s", "4 s", "2 d")      # how a vector register shows: its scalars, or every lane
REG_NAMES = ["x%d" % i for i in range(29)] + ["fp", "lr", "sp", "pc", "pstate"]

BRANCHES = {"b", "bl", "cbz", "cbnz", "tbz", "tbnz"}
CALLER_SAVED = set(range(A.ARM64_REG_X0, A.ARM64_REG_X0 + 19)) | {A.ARM64_REG_X29, A.ARM64_REG_X30}


def short(name):
    """'AgentHitbox::SolveDamage+C8' of 'Odaclick.TWD.Agents.Components.AgentHitbox::SolveDamage+C8': the
    namespace takes the width a list has."""
    cls, sep, method = name.partition("::")
    return cls.rsplit(".", 1)[-1] + sep + method


def map_names(text, text_size):
    """rva -> name from a function map. Unity and GameMaker write 'Name = main+0xRVA | ...'; Unreal writes
    '/Script/Module.Class.Function=main+0xRVA | abs=... class=Function ...', read the way Breeze's code watch
    reads it (gen2menu.cpp): functions as Module.Class::Function, a class's own row as its constructor, C++
    virtuals as named, and the script interpreter that every Blueprint function's row holds named once."""
    names, unreal = {}, []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        at = line.find(" = main+0x")
        if at >= 0:
            try:
                names.setdefault(int(line[at + 10:].split()[0].split("|")[0], 16), line[:at])
            except (ValueError, IndexError):
                pass
            continue
        at = line.find("=main+0x")
        if at < 0:
            continue
        try:
            rva = int(line[at + 8:].split()[0], 16)
        except (ValueError, IndexError):
            continue
        m = re.search(r" class=(\S+)", line[at:])
        unreal.append((line[:at], rva, m.group(1) if m else ""))
    shared = {}
    for _n, rva, kind in unreal:
        if kind == "Function":
            shared[rva] = shared.get(rva, 0) + 1
    shared = {rva: n for rva, n in shared.items() if n > 8}
    for name, rva, kind in unreal:
        if kind not in ("Function", "Class", "BlueprintGeneratedClass", "VTable") or rva & 3 or rva >= text_size:
            continue
        if rva in shared:
            if shared[rva]:
                names.setdefault(rva, "(Blueprint)::script interpreter, for %d Blueprint functions" % shared[rva])
                shared[rva] = 0
            continue
        if kind == "Function":
            owner, _dot, fn = name.rpartition(".")
            name = "%s::%s" % (owner, fn) if owner else name
        elif kind != "VTable":
            name += "::(constructor)"
        names.setdefault(rva, name)
    return names


FAR_NAME = 0x8000          # an offset past this from the nearest name is not that function (no unwind table)


class Game:
    """What is known about the running game, and its memory, read through one connection (worker thread only)."""

    def __init__(self, b):
        self.b = b
        g = b.state(1)["game"]
        if not g.get("attached"):
            raise RuntimeError("Breeze is not attached to a game")
        self.main = int(g["main"], 16)
        self.main_size = int(g["main_size"], 16)
        self.pid = g.get("pid")
        self.tid, self.bid = g["title_id"], g["build_id"].upper()
        self.caption = game_caption(g)
        self.heap, self.heap_size = int(g["heap"], 16), int(g["heap_size"], 16)
        self.pages = {}
        self.bp_words = {}           # main offset -> the instruction a breakpoint replaced, every one seen
        self.break_word = BREAK_WORD  # what the host writes for a breakpoint (an emulator host says its own)
        self.probe_debugger = None   # an emulator host whose probe has breakpoints (the Lichii fork)
        self.run_to = None           # the breakpoint a Run to put, taken off at the next stop
        self.console = "ui" in b.caps()   # Breeze on a Switch: the host with gen2's watches
        self.rw = None               # the instruction watch run from here on the Lichii fork's probe
        if not self.console and "debug" not in b.caps():
            r = b.cmd("probe held")
            self.probe_debugger = isinstance(r, str) and r.startswith("+OK")
        # emuhost: the instruction watch runs inside it (probe regwatch), a stub break stopping the game
        self.emu_regwatch = not self.console and "regwatch" in b.caps()
        self.mods = []               # every code module: (name, base, size), main named "M"
        self.text_size = self.find_text()
        self.dir = ""
        self.title = ""
        self.starts, self.names, self.source = [], {}, "no function list"
        self.load_functions()

    def find_text(self):
        """The size of the code region main starts with (and every code module, in self.mods)."""
        lines = self.b.cmd("maps").split("\n")[1:]
        self.mods = code_modules.code_modules(lines, self.main)
        for line in lines:
            p = line.split()
            if len(p) >= 3 and int(p[0], 16) == self.main and "x" in p[2]:
                return int(p[1], 16)
        return self.main_size

    # ------------------------------------------------------------ memory
    def read(self, addr, n):
        out = b""
        while n > 0:
            page = addr & ~(PAGE - 1)
            data = self.pages.get(page)
            if data is None:
                data = self.pages[page] = self.b.peek(page, PAGE)
            piece = data[addr - page:addr - page + n]
            if not piece:
                break
            out += piece
            addr += len(piece)
            n -= len(piece)
        return out

    def in_main(self, addr):
        return self.main <= addr < self.main + self.main_size

    def is_code(self, rva):
        """An offset from main that is code: main's, or another module's (rtld, subsdk, sdk)."""
        return 0 <= rva < self.text_size or code_modules.module_of(self.mods, self.main + rva) is not None

    def label(self, rva):
        """'M+1234' in main, 'sdk+5B1E78' in another module."""
        if 0 <= rva < self.main_size:
            return "M+%X" % rva
        return code_modules.label(self.mods, self.main + rva) or "%X" % (self.main + rva)

    def debug_where(self, rva):
        """An address as a debugger command takes it: M+ in main, absolute elsewhere."""
        return "M+%X" % rva if 0 <= rva < self.main_size else "%X" % (self.main + rva)

    # ------------------------------------------------------------ functions
    def cached_file(self, name, size):
        """A file of the game's folder, kept on the PC until its size changes."""
        folder = os.path.join(CACHE, "%s_%s" % (self.tid, self.bid))
        os.makedirs(folder, exist_ok=True)
        local = os.path.join(folder, name)
        if os.path.exists(local) and os.path.getsize(local) == size:
            with open(local, "rb") as f:
                return f.read()
        return self.b.get_file(self.dir + name, local)

    def load_functions(self):
        files = self.b.files()
        self.dir = files.get("dir", "")
        try:
            self.title = self.b.json("fs roots").get("title_name", "")
        except Exception:  # noqa: BLE001 - only a title for the window
            pass
        have = {f["name"]: f["size"] for f in files.get("files", []) if "size" in f}
        starts, names, source = set(), {}, []
        eh = "ehframe_%s.bin" % self.bid[:16]
        if eh in have:
            data = self.cached_file(eh, have[eh])
            if data[:8] == b"BZEHFR01":
                count = struct.unpack_from("<I", data, 48)[0]
                starts.update(struct.unpack_from("<%dI" % count, data, 56))
                source.append("%d from the unwind table" % count)
        if "script_functions.txt" in have:
            n = 0
            for line in self.cached_file("script_functions.txt", have["script_functions.txt"]).decode("utf-8", "replace").splitlines():
                p = line.split("\t")
                if len(p) == 2 and not line.startswith("#"):
                    try:
                        names[int(p[0], 16)] = p[1].strip()
                        n += 1
                    except ValueError:
                        pass
            if n:
                source.append("%d script names" % n)
        for name in MAPS:
            if name in have:
                found = map_names(self.cached_file(name, have[name]).decode("utf-8", "replace"), self.text_size)
                for rva, fname in found.items():
                    names.setdefault(rva, fname)
                source.append("%d names from %s" % (len(found), name))
                break
        starts.update(names)
        self.starts = sorted(x for x in starts if x < self.text_size)
        self.names = names
        # What the function list offers: the named ones when the game has names (a Unity game has
        # several times as many unnamed pieces of code), every function otherwise.
        listed = sorted(x for x in names if x < self.text_size) if len(names) > len(self.starts) // 20 else self.starts
        self.listed = [(x, self.name_of(x), self.name_of(x).lower()) for x in listed]
        if source:
            self.source = ", ".join(source)

    def name_of(self, rva):
        return self.names.get(rva) or "func_%X" % rva

    def func_of(self, rva):
        """(start, end) of the function holding rva, or None."""
        i = bisect.bisect_right(self.starts, rva) - 1
        if i < 0:
            return None
        end = self.starts[i + 1] if i + 1 < len(self.starts) else self.text_size
        return self.starts[i], end

    def where(self, rva):
        """'name+1C' for a code offset."""
        f = self.func_of(rva) if 0 <= rva < self.text_size else None
        if f is None:
            return ""
        # Without the unwind table a function's end is not known: code the map has no name for
        # (generic instances, compiler-made helpers) would take the nearest name below, however
        # far. Past FAR_NAME it is not that function.
        if rva - f[0] > FAR_NAME and self.source.find("unwind") < 0:
            return ""
        return self.name_of(f[0]) + ("+%X" % (rva - f[0]) if rva != f[0] else "")

    def describe(self, addr):
        """What an address a piece of code builds is: (kind, text)."""
        if not self.in_main(addr):
            if self.heap <= addr < self.heap + self.heap_size:
                return "data", "heap+%X" % (addr - self.heap)
            return "data", ""
        rva = addr - self.main
        if rva < self.text_size:
            return "code", self.where(rva)
        try:
            data = self.read(addr, 48)
        except Exception:  # noqa: BLE001 - an unmapped stretch of the module
            return "data", "(not readable)"
        end = data.find(b"\0")
        text = data[:end if end >= 0 else len(data)]
        if len(text) >= 4 and all(32 <= c < 127 for c in text):
            return "str", '"%s"%s' % (text.decode("ascii"), "" if end >= 0 else "...")
        q = struct.unpack_from("<Q", data)[0]
        if self.in_main(q):
            where = self.where(q - self.main) if q - self.main < self.text_size else ""
            return "data", "-> M+%X %s" % (q - self.main, where)
        if self.heap <= q < self.heap + self.heap_size:
            return "data", "-> heap+%X" % (q - self.heap)
        d = struct.unpack_from("<I", data)[0]
        f = struct.unpack_from("<f", data)[0]
        note = "= %X" % d
        if d and 1e-4 < abs(f) < 1e7:
            note += "  (%g)" % f
        return "data", note

    # ------------------------------------------------------------ disassembly
    def view(self, rva):
        """The function holding rva, disassembled: (start, end, title, lines)."""
        rva &= ~3
        f = self.func_of(rva)
        if f is None or rva >= self.text_size:
            m = code_modules.module_of(self.mods, self.main + rva)
            low, high = (m[1] - self.main, m[1] + m[2] - self.main) if m else (0, rva + 0x400)
            start, end = max(rva - 0x40, low), min(rva + 0x400, high)
            title = ("M+%X (no function here)" % rva if 0 <= rva < self.text_size
                     else "%s (no function list for this module)" % self.label(rva))
        else:
            start, end = f
            title = "%s   M+%X..%X  (%d bytes)" % (self.name_of(start), start, end, end - start)
            if end - start > MAX_VIEW:
                start = max(start, min(rva - 0x1000, end - MAX_VIEW))
                end = start + MAX_VIEW
                title += "   showing M+%X..%X" % (start, end)
        code = bytearray(self.read(self.main + start, end - start))
        # Under a breakpoint the game holds gen2's break word: show the instruction it replaced.
        for at, word in self.bp_words.items():
            if start <= at < end - 3 and struct.unpack_from("<I", code, at - start)[0] == self.break_word:
                struct.pack_into("<I", code, at - start, word)
        code = bytes(code)
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        lines, pages, local = [], {}, set()
        off = 0
        while off + 4 <= len(code):
            at = start + off
            word = struct.unpack_from("<I", code, off)[0]
            ins = next(md.disasm(code[off:off + 4], self.main + at), None)
            line = {"rva": at, "word": word, "mnem": ".word", "ops": "%08X" % word, "kind": "", "target": None, "note": ""}
            off += 4
            lines.append(line)
            if ins is None:
                pages.clear()
                continue
            line["mnem"], line["ops"] = ins.mnemonic, ins.op_str
            mnem = ins.mnemonic
            ops = ins.operands
            if mnem in BRANCHES or mnem.startswith("b."):
                target = ops[-1].imm - self.main
                line["target"] = target
                if mnem == "bl":
                    line["kind"] = "call"
                    line["note"] = short(self.where(target))
                else:
                    line["kind"] = "jump"
                    if start <= target < end:
                        local.add(target)
                        line["note"] = "down" if target > at else "up"
                    else:
                        line["note"] = "-> " + short(self.where(target))
                line["ops"] = line["ops"].replace("#0x%x" % ops[-1].imm, self.label(target))
            elif mnem in ("ret", "br"):
                line["kind"] = "ret"
            elif mnem == "blr":
                line["kind"] = "call"
            # Addresses built from adrp: follow the page through the registers.
            built = None
            if mnem == "adrp":
                pages[ops[0].reg] = ops[1].imm
                if self.in_main(ops[1].imm):
                    line["ops"] = line["ops"].replace("#0x%x" % ops[1].imm, "M+%X" % (ops[1].imm - self.main))
            elif mnem == "adr":
                built = ops[1].imm
            elif mnem == "add" and len(ops) == 3 and ops[1].type == A.ARM64_OP_REG and ops[2].type == A.ARM64_OP_IMM \
                    and ops[1].reg in pages:
                built = pages[ops[1].reg] + ops[2].imm
            else:
                for op in ops:
                    if op.type == A.ARM64_OP_MEM and op.mem.base in pages and op.mem.index == 0:
                        built = pages[op.mem.base] + op.mem.disp
            if mnem.startswith("ldr") and len(ops) == 2 and ops[1].type == A.ARM64_OP_IMM:
                built = ops[1].imm   # literal load
            if built is not None:
                line["addr"] = built
                kind, text = self.describe(built)
                if self.in_main(built):
                    line["target"] = built - self.main
                    line["note"] = ("M+%X  " % (built - self.main)) + text
                else:
                    line["note"] = ("%X  " % built) + text
                line["kind"] = line["kind"] or kind
            # Registers this instruction wrote no longer hold a page.
            try:
                written = ins.regs_access()[1]
            except capstone.CsError:
                written = []
            for reg in written:
                if A.ARM64_REG_W0 <= reg <= A.ARM64_REG_W28:
                    reg = reg - A.ARM64_REG_W0 + A.ARM64_REG_X0    # writing w8 ends what x8 held
                if not (mnem == "adrp" and reg == ops[0].reg):
                    pages.pop(reg, None)
            if mnem == "add" and built is not None and ops[0].type == A.ARM64_OP_REG:
                pages[ops[0].reg] = built    # adrp + add, then [reg, #off]
            if mnem in ("bl", "blr"):
                for reg in list(pages):
                    if reg in CALLER_SAVED:
                        del pages[reg]
        for line in lines:
            line["label"] = line["rva"] in local
            # A bl lands on a function's first instruction: where the unwind table is thin (an Unreal game
            # can list one function in ten), that is how the ones in between become functions of their own.
            t = line["target"]
            if line["mnem"] == "bl" and t is not None and 0 <= t < self.text_size:
                i = bisect.bisect_left(self.starts, t)
                if i == len(self.starts) or self.starts[i] != t:
                    self.starts.insert(i, t)
        return start, end, title, lines

    def code_page(self, rva):
        """A page of code as the game has it, with the instructions under breakpoints put back."""
        data = bytearray(self.read(self.main + rva, PAGE))
        for at, word in self.bp_words.items():
            if rva <= at < rva + len(data) - 3 and struct.unpack_from("<I", data, at - rva)[0] == self.break_word:
                struct.pack_into("<I", data, at - rva, word)
        return bytes(data)

    def decomp_input(self, rva):
        """What the decompiler needs for the function holding rva: its code, the names of what it calls and the
        strings it uses (see pcconnect_decomp.Engine)."""
        f = self.func_of(rva) if rva < self.text_size else None
        if f is None:
            raise RuntimeError("M+%X is not in a function: nothing to decompile" % rva)
        start, end = f
        capped = end > start + MAX_DECOMP
        end = min(end, start + MAX_DECOMP)
        pages = {self.main + p: self.code_page(p) for p in range(start & ~(PAGE - 1), end, PAGE)}
        callees, strings, ro = {}, {}, set()
        known = set(self.starts)
        for line in self.view(start)[3]:
            t = line["target"]
            if t is None or start <= t < end:
                continue
            if t < self.text_size:
                # A branch out of the function is a tail call even when no start is known there: without a
                # function at the target Ghidra follows it into memory it was not given ("bad instruction").
                if t in known and line["kind"] in ("call", "jump", "code"):
                    callees[self.main + t] = short(self.name_of(t))
                elif line["kind"] in ("call", "jump"):
                    callees[self.main + t] = "func_%X" % t
            elif line["kind"] == "str":
                data = self.read(self.main + t, 512)
                n = data.find(b"\0")
                if n < 0:
                    continue
                strings[self.main + t] = n
                for p in range(t & ~(PAGE - 1), t + n + 1, PAGE):
                    if self.main + p not in pages:
                        pages[self.main + p] = self.read(self.main + p, PAGE)
                        ro.add(self.main + p)
        return {"key": "%s_%s_%X" % (self.tid, self.bid, self.main), "main": self.main,
                "main_end": self.main + self.main_size, "start": self.main + start, "end": self.main + end,
                "end_is_next": not capped, "name": short(self.name_of(start)), "pages": pages, "ro": ro, "callees": callees, "strings": strings}

    # ------------------------------------------------------------ the debugger
    def live(self, addr, n):
        """Memory as it is now, not from the kept pages: the stack and data change."""
        out = b""
        while len(out) < n:
            out += self.b.peek(addr + len(out), min(n - len(out), PAGE))
        return out

    def block(self, addr, n=BLOCK):
        """Memory as it is now: {"addr", "data", "notes"}, the notes saying what each 8-byte value points at.
        "data" is empty where it cannot be read."""
        try:
            data = self.live(addr, n)
        except Exception as e:  # noqa: BLE001 - not mapped
            return {"addr": addr, "data": b"", "notes": {}, "error": str(e)}
        notes = {}
        for off in range(0, len(data) - 7, 8):
            v = struct.unpack_from("<Q", data, off)[0]
            if self.in_main(v):
                kind, text = self.describe(v)
                notes[off] = "M+%X %s" % (v - self.main, short(text) if kind == "code" else text)
            elif self.heap <= v < self.heap + self.heap_size:
                notes[off] = "heap+%X" % (v - self.heap)
            elif data[off] != 0 and all(32 <= c < 127 or c == 0 for c in data[off:off + 8]):
                notes[off] = '"%s"' % data[off:off + 8].split(b"\0")[0].decode("ascii")
        return {"addr": addr, "data": data, "notes": notes}

    def debug(self, args="", vectors=False):
        """Sends `dbg <args>` and returns where things stand, with the stack (and the vector registers
        when asked) when the game is stopped. A host without a debugger (an emulator) is not asked."""
        if "debug" not in self.b.caps():
            if self.probe_debugger is None:
                r = self.b.cmd("probe held")
                self.probe_debugger = isinstance(r, str) and r.startswith("+OK")
            if self.probe_debugger:
                return self.probe_debug(args, vectors)
            if args:
                raise RuntimeError("this host has no debugger (it answers `caps` without \"debug\")")
            return {"no_debugger": True}
        reply =self.b.cmd(("dbg " + args).strip())
        if not reply.startswith("+OK"):
            raise RuntimeError(reply[5:] if reply.startswith("-ERR ") else reply)
        st = json.loads(reply[4:])
        if "status" in st:
            st = st["status"]
        if "break_word" in st:
            self.break_word = int(st["break_word"], 16)
        for bp in st.get("bps", []):
            at = int(bp["at"], 16) - self.main
            word = int(bp["word"], 16)
            if word != self.break_word and word != 0:
                self.bp_words[at] = word
        st["stack"] = self.block(int(st["sp"], 16)) if st.get("stopped") else None
        if st.get("stopped") and vectors:
            reply = self.b.cmd("dbg v")
            if reply.startswith("+OK"):
                st.update(json.loads(reply[4:]))
        return st

    def probe(self, args):
        r = self.b.cmd("probe " + args)
        if not r.startswith("+OK"):
            raise RuntimeError(r[5:] if r.startswith("-ERR ") else r)
        return r.split("\n")

    def probe_debug(self, args, vectors=False):
        """The same on the Lichii fork: its probe's breakpoints (probe break / held / step / over /
        cont / setreg) in the shape `dbg` answers. One thread is held; the others run on."""
        w = args.split()
        rw = self.rw if self.rw is not None and self.rw["on"] else None
        if rw is not None:
            self.regwatch_collect(0)                # a hit that came in since the last slice
        if w[:1] == ["bp"] and len(w) > 1:
            if w[1] == "clear":
                self.probe("break clear")
                if rw is not None:
                    rw["on"] = False                # its break went with the others
            else:                                   # F9 on a line: there or not there
                at = self.main + int(w[1][2:], 16) if w[1].upper().startswith("M+") else int(w[1], 16)
                if rw is not None and at == rw["at"]:
                    raise RuntimeError("the instruction watch is on this line: Stop it first")
                have = [l.split()[0] for l in self.probe("break list")[1:]]
                there = "M+%X" % (at - self.main) in have or "%X" % at in have
                self.probe("break %s %X" % ("remove" if there else "add", at))
        elif w[:1] == ["runto"] and len(w) > 1:
            have = [l.split()[0] for l in self.probe("break list")[1:]]
            if w[1] not in have:
                self.probe("break add " + w[1])
                self.run_to = w[1]
            if self.probe("held")[0].startswith("+OK held"):
                self.probe("cont")
        elif w[:1] == ["reg"] and len(w) >= 3:
            name = {"fp": "x29", "lr": "x30"}.get(w[1], w[1])
            self.probe("setreg %s %s" % (name, " ".join(w[2:])))
        elif w[:1] == ["stop"]:
            if self.probe("held")[0].startswith("+OK held"):
                self.probe("cont")
        elif w:
            self.probe(w[0])                        # step, over, cont
            if w[0] in ("step", "over"):            # the answer is the state after it
                for _ in range(100):
                    if self.probe("held")[0].startswith("+OK held"):
                        break
                    time.sleep(0.02)
        r = self.probe("held")
        stopped = r[0].startswith("+OK held")
        if stopped and self.run_to:
            self.probe("break remove " + self.run_to)
            self.run_to = None
        st = {"gen2": True, "attached": True, "stopped": stopped, "break_word": "D4284840", "bps": [], "stack": None}
        for l in self.probe("break list")[1:]:
            p = l.split()
            kv = dict(x.split("=", 1) for x in p[1:] if "=" in x)
            at = self.main + int(p[0][2:], 16) if p[0].startswith("M+") else int(p[0], 16)
            self.bp_words[at - self.main] = int(kv.get("original", "0"), 16)
            if rw is None or at != rw["at"]:        # the instruction watch's own break is not the user's
                st["bps"].append({"at": "%X" % at, "word": kv.get("original", "0")})
        self.break_word = 0xD4284840
        if stopped and len(r) > 1:
            kv = dict(x.split("=", 1) for x in r[1].split())
            st["x"] = [kv.get("x%d" % i, "0") for i in range(31)]
            st["sp"], st["pc"], st["pstate"] = kv.get("sp", "0"), kv.get("pc", "0"), kv.get("pstate", "0")
            st["stack"] = self.block(int(st["sp"], 16))
            if vectors:
                r = self.probe("held v")
                if len(r) > 3:
                    kv = dict(x.split("=", 1) for x in r[3].split())
                    st["v"] = [kv.get("v%d" % i, "0:0").split(":") for i in range(32)]
                    st["fpcr"], st["fpsr"] = kv.get("fpcr", "?"), kv.get("fpsr", "?")
        return st

    def operand(self, line):
        """The memory an instruction uses: ("static", address), ("reg", base, index, shift, disp,
        text) for one that goes through registers, or None when it uses none."""
        if line.get("addr") is not None:
            return ("static", line["addr"])
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        for ins in md.disasm(struct.pack("<I", line["word"]), self.main + line["rva"]):
            for op in ins.operands:
                if op.type == A.ARM64_OP_MEM and op.mem.base != 0:
                    base = ins.reg_name(op.mem.base)
                    index = ins.reg_name(op.mem.index) if op.mem.index != 0 else None
                    shift = op.shift.value if index and op.shift.type != 0 else 0
                    text = "%s%s%s" % (base, "+%s%s" % (index, "<<%d" % shift if shift else "") if index else "",
                                       "%+#x" % op.mem.disp if op.mem.disp else "")
                    return ("reg", base, index, shift, op.mem.disp, text)
        return None

    def catch(self, rva):
        """The registers the next time the instruction at rva runs (the Lichii fork): a breakpoint
        there for a moment, taken off again, and the game runs on. None when nothing ran it."""
        where = "M+%X" % rva
        if self.emu_regwatch:
            return self.emu_catch(rva)
        if self.probe("held")[0].startswith("+OK held"):
            return None
        had = where in [l.split()[0] for l in self.probe("break list")[1:]]
        if not had:
            self.probe("break add " + where)
        regs = None
        try:
            for _ in range(150):
                r = self.probe("held")
                if r[0].startswith("+OK held") and len(r) > 1:
                    kv = dict(x.split("=", 1) for x in r[1].split())
                    if int(kv.get("pc", "0"), 16) == self.main + rva:
                        regs = {k: int(v, 16) for k, v in kv.items()}
                    break
                time.sleep(0.02)
        finally:
            if not had:
                self.probe("break remove " + where)
            if self.probe("held")[0].startswith("+OK held"):
                self.probe("cont")
        return regs

    def emu_catch(self, rva):
        """catch() on emuhost: its instruction watch for one run, the registers of that run."""
        if self.rw is not None and self.rw["on"]:
            raise RuntimeError("the instruction watch is on: stop it first")
        self.probe("regwatch start %X - - 0 0" % (self.main + rva))
        regs = None
        try:
            for _ in range(150):
                r = self.probe("regwatch rows")
                if "total=0" not in r[0]:
                    r = self.probe("regwatch last")
                    if len(r) > 1:
                        regs = {k: int(v, 16) for k, v in (x.split("=", 1) for x in r[1].split())}
                    break
                time.sleep(0.02)
        finally:
            self.probe("regwatch stop")
        return regs

    def pause(self, want=None):
        """Stops or lets go the whole game (None: only asks). Returns True when it is stopped."""
        if want is not None:
            r = self.b.cmd("freeze" if want else "resume")
            if not r.startswith("+OK"):
                raise RuntimeError(r)
        try:
            st = self.b.json("state")
        except Exception:  # noqa: BLE001
            return bool(want)
        return bool(st["paused"]) if "paused" in st else bool(want)   # a Switch does not say

    def set_vector(self, n, low, high):
        """Writes all 128 bits of v<n> and checks they took: beta125.00 sets the low half only."""
        st = self.debug("reg v%d %X %X" % (n, low, high), vectors=True)
        got = st.get("v", [])
        if n < len(got) and (int(got[n][0], 16), int(got[n][1], 16)) != (low, high):
            raise RuntimeError("only the low half of v%d was written: this needs a newer Breeze on the Switch" % n)
        return st

    def callers(self, rva):
        hits = self.b.xref_call(self.main + rva)
        return [(h, self.where(h)) for h in hits]

    def code_watch(self):
        """The last code watch's result: [(order, rva, caller rva or None, name, new)]."""
        data = self.b.get_file(self.dir + "code_watch.txt").decode("utf-8", "replace")
        rows, head = [], []
        for line in data.splitlines():
            if line.startswith("#"):
                head.append(line[1:].strip())
                continue
            p = [x.strip() for x in line.split("|")]
            if len(p) < 4 or not p[1].startswith("M+"):
                continue
            new = p[0].endswith("*")
            caller = int(p[2][2:], 16) if p[2].startswith("M+") else None
            rows.append((int(p[0].rstrip("*")), int(p[1][2:], 16), caller, p[3], new))
        return head, rows


    # ------------------------------------------------------------ gen2's watches (a Switch)
    def gen2(self, args=""):
        """`gen2 <args>`: what gen2 holds, as its JSON."""
        r = self.b.cmd(("gen2 " + args).strip())
        if not r.startswith("+OK"):
            raise RuntimeError(r[5:] if r.startswith("-ERR ") else r)
        return json.loads(r[4:]) if r[4:5] == "{" else {}

    def gen2_rows(self, mine, offset=None):
        """`gen2 rows`. `mine` is the instruction watch this window started ({"at", "offset", "size"}):
        when gen2 still holds it, each row gets the address the instruction used (the register's value
        plus the offset, or plus `offset` when given) and, for the first rows, the 8 bytes there now."""
        st = self.gen2("rows")
        ours = mine is not None and int(st.get("address", "0"), 16) == mine["at"]
        st["ours"] = ours
        off = mine["offset"] if ours and mine["kind"] == "reg" else 0
        if ours and offset is not None:
            off = offset
        for i, x in enumerate(st.get("list", [])):
            if "pc" in x:
                continue
            x["address"] = (int(x["value"], 16) + off) & 0xFFFFFFFFFFFFFFFF
            if i < GEN2_PEEK:
                try:
                    x["data"] = self.live(x["address"], 8)
                except Exception:  # noqa: BLE001 - not an address
                    x["data"] = b""
        return st


    # ------------------------------------------------------------ the same on the Lichii fork's probe
    # The probe has no instruction watch of its own. A breakpoint on the instruction holds the thread
    # that reaches it; its registers are read, the address worked out, and it is let go at once.
    def held(self):
        """(seq, registers) of the thread held at a breakpoint, or None."""
        r = self.probe("held")
        if not r[0].startswith("+OK held") or len(r) < 2:
            return None
        head = dict(x.split("=", 1) for x in r[0].split() if "=" in x)
        return int(head.get("seq", "0")), {k: int(v, 16) for k, v in (x.split("=", 1) for x in r[1].split())}

    def regwatch_start(self, mine):
        self.regwatch_stop()
        if self.emu_regwatch:
            index = mine["index"] or "-"
            r = self.probe("regwatch start %X %s %s %d %X" % (mine["at"], mine["base"], index, mine["shift"],
                                                           mine["disp"] & 0xFFFFFFFFFFFFFFFF))
            self.rw = dict(mine, counts={}, total=0, on=True, hold=None, matched=None)
            return r
        if self.held() is not None:
            raise RuntimeError("a thread is held at a breakpoint: Continue first")
        have = [l.split()[0] for l in self.probe("break list")[1:] if l.split()]
        if "M+%X" % mine["rva"] in have or "%X" % mine["at"] in have:
            raise RuntimeError("a breakpoint is on that instruction: take it off first (F9)")
        self.probe("break add %X" % mine["at"])
        self.rw = dict(mine, counts={}, total=0, on=True, hold=None, matched=None)

    def regwatch_stop(self):
        rw = self.rw
        if rw is None or not rw["on"]:
            return
        rw["on"] = False
        if self.emu_regwatch:
            self.probe("regwatch stop")
            return
        try:
            self.probe("break remove %X" % rw["at"])
        except RuntimeError:
            pass                                    # gone already
        h = self.held()
        if h is not None and h[1].get("pc") == rw["at"]:
            self.probe("cont")

    def regwatch_hold(self, address):
        """From now the thread stays held when the instruction uses this address (None: never)."""
        if self.rw is not None:
            self.rw["hold"] = address
            if self.emu_regwatch:
                self.probe("regwatch hold %s" % ("off" if address is None else "%X" % address))

    def regwatch_collect(self, ms):
        """Takes every hit for `ms` milliseconds (0: the one waiting, if any)."""
        rw = self.rw
        if rw is None or not rw["on"]:
            return
        if self.emu_regwatch:                       # emuhost takes the hits itself: only read them
            r = self.probe("regwatch rows")
            head = dict(x.split("=", 1) for x in r[0].split() if "=" in x)
            rw["counts"] = {int(a, 16): int(n) for a, n in (l.split() for l in r[1:] if len(l.split()) == 2)}
            rw["total"] = int(head.get("total", "0"))
            rw["on"] = head.get("on") == "1"
            if not rw["on"]:
                self.probe("regwatch stop")         # it came off by itself (its hit limit)
            if ms:
                time.sleep(min(ms, 150) / 1000.0)
            return
        end = time.time() + ms / 1000.0

        def reg(regs, name):
            if name is None:
                return 0
            if name.startswith("w"):
                return regs.get("x" + name[1:], 0) & 0xFFFFFFFF
            return regs.get({"fp": "x29", "lr": "x30"}.get(name, name), 0)

        while True:
            h = self.held()
            if h is not None:
                seq, regs = h
                if regs.get("pc") != rw["at"] or rw["matched"] == seq:
                    return                          # the debugger's stop, or the one kept for the user
                a = (reg(regs, rw["base"]) + (reg(regs, rw["index"]) << rw["shift"]) + rw["disp"]) & 0xFFFFFFFFFFFFFFFF
                rw["counts"][a] = rw["counts"].get(a, 0) + 1
                rw["total"] += 1
                if rw["hold"] is not None and a == rw["hold"]:
                    rw["matched"] = seq
                    return
                self.probe("cont")
                continue
            if time.time() >= end:
                return
            time.sleep(0.001)

    def regwatch_rows(self, offset=None):
        """What the instruction watch has, in the shape `gen2 rows` answers. With `offset` the
        addresses shown are the registers plus that offset instead of the watch's own; "value" stays
        the address the instruction used (what a hold matches)."""
        rw = self.rw
        st = {"gen2": "probe", "breeze_expects": "probe", "ours": True, "read": False, "write": False, "type": "probe",
              "attached": False, "address": "0", "rows": 0, "trig": 0, "list": []}
        if rw is None:
            return st
        self.regwatch_collect(0)
        st.update(attached=rw["on"], address="%X" % rw["at"], rows=len(rw["counts"]), trig=rw["total"])
        delta = 0 if offset is None else offset - rw["disp"]
        for i, (a, n) in enumerate(list(rw["counts"].items())):
            shown = (a + delta) & 0xFFFFFFFFFFFFFFFF
            x = {"value": "%X" % a, "address": shown, "count": n, "data": b""}
            if i < GEN2_PEEK:
                try:
                    x["data"] = self.live(shown, 8)
                except Exception:  # noqa: BLE001 - not an address
                    pass
            st["list"].append(x)
        return st


def access_size(mnem, ops):
    """(bytes, kind) an instruction reads or writes at its memory operand; kind is "i", "f" or "d"."""
    m = re.match(r"(?:ld|st)u?rs?([bhw]?)$", mnem.lower())
    if m and m.group(1):
        return {"b": 1, "h": 2, "w": 4}[m.group(1)], "i"
    r = ops.split(",")[0].strip().lower()[:1]
    return {"w": (4, "i"), "x": (8, "i"), "s": (4, "f"), "d": (8, "d"), "b": (1, "i"), "h": (2, "i")}.get(r, (8, "i"))


# The instruction watch's "show as": (bytes, kind); kind "i" unsigned, "s" signed, "f" float, "d" double.
SHOW_AS = {"auto": None, "u8": (1, "i"), "u16": (2, "i"), "u32": (4, "i"), "u64": (8, "i"),
           "s8": (1, "s"), "s16": (2, "s"), "s32": (4, "s"), "s64": (8, "s"), "f32": (4, "f"), "f64": (8, "d")}


def value_as(data, show, size, kind):
    """(hex, as a number) of the first bytes of `data` read as `show` (a SHOW_AS key); "auto" is the
    instruction's own size and kind, with no number for a plain 8-byte value (most are pointers)."""
    pick = SHOW_AS.get(show)
    if pick is None:
        return value_text(data[:size], kind)
    n, k = pick
    data = data[:n]
    if len(data) < n:
        return "", ""
    v = int.from_bytes(data, "little")
    hexa = "%0*X" % (n * 2, v)
    if k == "s":
        return hexa, str(v - (1 << (8 * n)) if v >> (8 * n - 1) else v)
    if k == "f":
        return hexa, "%.7g" % struct.unpack("<f", data)[0]
    if k == "d":
        return hexa, "%.15g" % struct.unpack("<d", data)[0]
    return hexa, str(v)


def value_text(data, kind):
    """(hex, as a number) of what a watched address holds."""
    if not data:
        return "", ""
    v = int.from_bytes(data, "little")
    if kind == "f" and len(data) == 4:
        return "%0*X" % (len(data) * 2, v), "%.7g" % struct.unpack("<f", data)[0]
    if kind == "d" and len(data) == 8:
        return "%0*X" % (len(data) * 2, v), "%.15g" % struct.unpack("<d", data)[0]
    return "%0*X" % (len(data) * 2, v), str(v) if len(data) < 8 else ""


class Worker(threading.Thread):
    """Owns the connection. Jobs are fn(game) -> result; the window collects (done, result, error)."""

    def __init__(self, host, code):
        super().__init__(daemon=True)
        self.host, self.code = host, code
        self.jobs, self.out = queue.Queue(), queue.Queue()
        self.game = None
        self.stop = False

    def run(self):
        b = None
        while not self.stop:
            fn, done = self.jobs.get()
            if fn is None:
                break
            try:
                if b is None:
                    b = Breeze(self.host, self.code, timeout=30)
                if self.game is None:
                    self.game = Game(b)
                self.out.put((done, fn(self.game), None))
            except Exception as e:  # noqa: BLE001 - shown in the status line
                self.out.put((done, None, e))
                if isinstance(e, (OSError, ConnectionError)):
                    if b is not None:
                        b.close()
                    b, self.game = None, None
        if b is not None:
            b.close()


class Disassembler:
    def __init__(self, root, host, code, cfg=None, save_cfg=None, game_dir=None):
        self.cfg = cfg if cfg is not None else {}
        self.save_cfg = save_cfg or (lambda: None)
        self.game_dir = game_dir
        self.win = tk.Toplevel(root)
        self.win.title("Breeze disassembler")
        self.win.geometry(self.cfg.get("asm_geometry", "1400x820"))
        self.win.configure(bg=BG_PANEL)
        self.game = None             # the worker's Game, read-only here
        self.lines, self.start, self.end = [], 0, 0
        self.row_of = {}             # rva -> text line
        self.cur = None
        self.history, self.hpos = [], -1
        self.items = []              # what the left list shows: (rva, caller or None)
        self.watch = None            # (head, rows) of the last code watch
        self.caller_rows = []
        self.dbg = {}                # the debugger's state as last read
        self.regs_before = None      # the registers at the stop before this one
        self.reg_rows = {}           # text line -> register name
        self.data_at = None          # the address the data panel shows, None = the stack
        self.shown_block = None      # what the data panel holds
        self.v_before = None         # the vector registers at the stop before this one
        self.poll_out = False
        self.busy = 0
        self.g2 = None               # the gen2 watch this window started: kind, at, rva, reg, offset, size, fmt, text
        self.g2_shown = []           # the rows the gen2 list shows
        self.g2_on = False           # gen2 is attached with a watch
        self.g2_out = False          # a refresh of the list is on its way
        self.g2_probe = False        # the host is the Lichii fork: the watch is run from here on its probe
        self.g2_cout = False         # a slice of that watch is on its way
        self.g2_read = 0.0           # when the list was last read
        size = int(self.cfg.get("asm_font", 11))
        self.font = ("Consolas", size)

        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        tk.Label(bar, text=" Go:").pack(side="left")
        self.go_var = tk.StringVar()
        self.go = tk.Entry(bar, width=30, textvariable=self.go_var)
        self.go.pack(side="left")
        self.go.bind("<Return>", lambda e: self.on_go())
        # Moving about first (Back / Forward, the function before / after), then what to look at;
        # what is used now and then is under More.
        for text, cmd, tip in (("◀", lambda: self.step(-1), "Back"), ("▶", lambda: self.step(1), "Forward")):
            tk.Button(bar, text=text, command=cmd, takefocus=0, width=2).pack(side="left", padx=(4 if tip == "Back" else 0, 0))
        tk.Label(bar, text=" Function").pack(side="left", padx=(6, 0))
        tk.Button(bar, text="▲", command=lambda: self.neighbour(-1), takefocus=0, width=2).pack(side="left")
        tk.Button(bar, text="▼", command=lambda: self.neighbour(1), takefocus=0, width=2).pack(side="left")
        tk.Button(bar, text="Callers", command=self.on_callers, takefocus=0).pack(side="left", padx=(6, 0))
        tk.Button(bar, text="Decompile F6", command=self.toggle_c, takefocus=0).pack(side="left")
        # Two buttons, not one that flips: another tab (Search, Cheats) may have paused the game.
        tk.Button(bar, text="Run", bg="#5cb85c", fg="white", width=6, takefocus=0,
                  command=lambda: self.set_pause(False)).pack(side="right", padx=(2, 4))
        tk.Button(bar, text="Pause", bg="#d9534f", fg="white", width=6, takefocus=0,
                  command=lambda: self.set_pause(True)).pack(side="right")
        tk.Label(bar, text="  Find:").pack(side="left")
        self.find_var = tk.StringVar()
        self.find = tk.Entry(bar, width=18, textvariable=self.find_var)
        self.find.pack(side="left")
        self.find.bind("<Return>", lambda e: self.find_next(1))
        self.find.bind("<Shift-Return>", lambda e: self.find_next(-1))
        self.font_var = tk.StringVar(value=str(size))
        self.bytes_var = tk.BooleanVar(value=bool(self.cfg.get("asm_bytes", True)))
        more = tk.Menubutton(bar, text="More ▾", relief="raised", takefocus=0)
        more.pack(side="left", padx=(8, 0))
        mm = tk.Menu(more, tearoff=0)
        mm.add_command(label="Reload", command=self.on_reload)
        mm.add_command(label="Memory used by this instruction", command=self.on_operand_memory)
        mm.add_separator()
        mm.add_command(label="Copy", command=self.copy)
        mm.add_command(label="Save...", command=self.save)
        mm.add_separator()
        mm.add_checkbutton(label="Show the instruction words", variable=self.bytes_var, command=self.render)
        fonts = tk.Menu(mm, tearoff=0)
        for n in (8, 9, 10, 11, 12, 13, 14, 16, 18, 20, 24):
            fonts.add_radiobutton(label=str(n), value=str(n), variable=self.font_var, command=self.set_font)
        mm.add_cascade(label="Font size", menu=fonts)
        more["menu"] = mm

        dbar = self.dbar = tk.Frame(self.win)
        dbar.pack(fill="x")
        tk.Label(dbar, text=" Debug:").pack(side="left")
        for text, cmd in (("Break F9", self.on_break), ("Run to F4", self.on_runto), ("Step F11", lambda: self.debug("step")),
                          ("Over F10", lambda: self.debug("over")), ("Continue F5", lambda: self.debug("cont")),
                          ("Stop", self.on_stop), ("Show PC", self.show_pc)):
            tk.Button(dbar, text=text, command=cmd, takefocus=0).pack(side="left")
        self.dbg_label = tk.Label(dbar, text="", anchor="w", fg="#555")
        self.dbg_label.pack(side="left", fill="x", expand=True, padx=8)

        self.status = tk.Label(self.win, text="connecting...", anchor="w", fg="#555")
        self.status.pack(fill="x", side="bottom")

        panes = self.panes = tk.PanedWindow(self.win, orient="horizontal", sashwidth=6, bg="#0f121b", bd=0)
        panes.pack(fill="both", expand=True)
        self.cpane, self.c_open = None, False

        left = tk.Frame(panes, bg=BG_PANEL)
        top = tk.Frame(left, bg=BG_PANEL)
        top.pack(fill="x")
        self.mode = tk.StringVar(value="functions")
        for text, value in (("Functions", "functions"), ("Code watch", "watch"), ("new only", "new")):
            tk.Radiobutton(top, text=text, value=value, variable=self.mode, command=self.fill_list, takefocus=0,
                           bg=BG_PANEL, fg=FG, selectcolor=BG, activebackground=BG_PANEL).pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter = tk.Entry(left, textvariable=self.filter_var)
        self.filter.pack(fill="x")
        self.filter_var.trace_add("write", lambda *a: self.fill_list())
        self.list_info = tk.Label(left, text="", anchor="w", bg=BG_PANEL, fg=FG_DIM)
        self.list_info.pack(fill="x")
        lf = tk.Frame(left)
        lf.pack(fill="both", expand=True)
        lbar = tk.Scrollbar(lf)
        lbar.pack(side="right", fill="y")
        self.list = tk.Listbox(lf, bg=BG, fg=FG, font=self.font, activestyle="none", bd=0, highlightthickness=0,
                               selectbackground=BG_CUR, yscrollcommand=lbar.set, exportselection=False)
        self.list.pack(side="left", fill="both", expand=True)
        lbar.config(command=self.list.yview)
        self.list.bind("<<ListboxSelect>>", self.on_pick)
        self.list.bind("<Double-Button-1>", lambda e: self.on_pick(e, caller=True))
        panes.add(left, minsize=160, width=380)

        mid = self.mid = tk.Frame(panes, bg=BG_PANEL)
        self.title = tk.Label(mid, text="", anchor="w", bg=BG_PANEL, fg="white", font=("Segoe UI", max(size, 9), "bold"))
        self.title.pack(fill="x")
        # The listing over the watch pane, with a divider to drag (the watch pane is added on a host that has one).
        self.vpanes = tk.PanedWindow(mid, orient="vertical", sashwidth=6, bg=BG_PANEL, bd=0, sashrelief="raised")
        self.vpanes.pack(fill="both", expand=True)
        tf = self.tf = tk.Frame(self.vpanes)
        self.vpanes.add(tf, stretch="always", minsize=80)
        tbar = tk.Scrollbar(tf)
        tbar.pack(side="right", fill="y")
        self.text = tk.Text(tf, wrap="none", bg=BG, fg=FG, font=self.font, insertwidth=0, bd=0, highlightthickness=0,
                            selectbackground="#4c6fb0", yscrollcommand=tbar.set, cursor="arrow")
        self.text.pack(side="left", fill="both", expand=True)
        tbar.config(command=self.text.yview)
        for tag, colour in (("addr", FG_ADDR), ("word", FG_DIM), ("call", FG_CALL), ("jump", FG_JUMP), ("ret", FG_RET),
                            ("note", FG_NOTE), ("str", FG_STR), ("label", FG_JUMP)):
            self.text.tag_configure(tag, foreground=colour)
        self.text.tag_configure("cur", background=BG_CUR)
        self.text.tag_configure("pc", background=BG_PC)
        self.text.tag_configure("bp", background=BG_BP, foreground="white")
        self.text.tag_configure("hit", background=BG_HIT)
        self.text.tag_raise("sel")
        self.text.config(state="disabled")
        self.text.bind("<ButtonRelease-1>", self.on_click)
        self.text.bind("<Double-Button-1>", self.on_follow)
        self.text.bind("<Return>", self.on_follow)
        menu = tk.Menu(self.text, tearoff=0)
        menu.add_command(label="Memory this instruction uses", command=self.on_operand_memory)
        menu.add_command(label="Go where it points (call, jump, address)", command=lambda: self.on_follow_cur())
        menu.add_separator()
        menu.add_command(label="Breakpoint here (F9)", command=self.on_break)
        menu.add_command(label="Run to here (F4)", command=self.on_runto)
        menu.add_separator()
        menu.add_command(label="Watch: the addresses this instruction uses (F8)", command=self.on_g2_watch)
        menu.add_command(label="Watch: who touches the address it uses (when it is a fixed one)", command=self.on_g2_static)
        menu.add_separator()
        menu.add_command(label="Patch this instruction: make a cheat, or add to one...", command=self.on_patch)
        menu.add_command(label="Hook here: make an ASM cheat...", command=self.on_hook)
        menu.add_separator()
        menu.add_command(label="Copy address", command=lambda: (self.win.clipboard_clear(),
                                                                self.win.clipboard_append("M+%X" % (self.cur or 0))))

        def popup(e):
            line = self.line_at(e)
            if line is not None:
                self.set_cur(line["rva"])
                menu.tk_popup(e.x_root, e.y_root)
        self.text.bind("<Button-3>", popup)
        self.build_gen2(mid)
        panes.add(mid, minsize=300, stretch="always")

        right = tk.PanedWindow(panes, orient="vertical", sashwidth=6, bg="#0f121b", bd=0)
        rf = tk.Frame(right, bg=BG_PANEL)
        rh = tk.Frame(rf, bg=BG_PANEL)
        rh.pack(fill="x")
        self.reg_mode = tk.StringVar(value="x")
        for text, value in (("General", "x"), ("Float", "v")):
            tk.Radiobutton(rh, text=text, value=value, variable=self.reg_mode, command=self.on_reg_mode, takefocus=0,
                           bg=BG_PANEL, fg=FG, selectcolor=BG, activebackground=BG_PANEL).pack(side="left")
        self.vview_var = tk.StringVar(value=self.cfg.get("asm_vector_view", VECTOR_VIEWS[0]))
        vview = tk.OptionMenu(rh, self.vview_var, *VECTOR_VIEWS, command=lambda _v: self.on_vector_view())
        vview.config(takefocus=0, bd=0, highlightthickness=0, bg=BG_PANEL, fg=FG, activebackground=BG_PANEL)
        vview.pack(side="left")
        self.regs_title = tk.Label(rh, text="(the game is running)", anchor="w", bg=BG_PANEL, fg="white")
        self.regs_title.pack(side="left", fill="x", expand=True)
        self.regs = tk.Text(rf, wrap="none", bg=BG, fg=FG, font=self.font, insertwidth=0, bd=0, highlightthickness=0,
                            width=46, height=18, cursor="arrow")
        self.regs.pack(fill="both", expand=True)
        self.regs.tag_configure("changed", foreground=FG_CHANGED)
        self.regs.tag_configure("name", foreground=FG_ADDR)
        self.regs.tag_configure("note", foreground=FG_NOTE)
        self.regs.tag_configure("cur", background=BG_CUR)
        self.regs.config(state="disabled")
        self.regs.bind("<ButtonRelease-1>", self.on_reg_click)
        self.regs.bind("<Double-Button-1>", self.on_reg_edit)
        right.add(rf, minsize=80)
        df = tk.Frame(right, bg=BG_PANEL)
        dh = tk.Frame(df, bg=BG_PANEL)
        dh.pack(fill="x")
        tk.Label(dh, text="Memory at", bg=BG_PANEL, fg="white").pack(side="left")
        self.mem_var = tk.StringVar(value="sp")
        self.mem = tk.Entry(dh, width=18, textvariable=self.mem_var)
        self.mem.pack(side="left")
        self.mem.bind("<Return>", lambda e: self.on_mem())
        tk.Button(dh, text="<", command=lambda: self.mem_page(-1), takefocus=0, bd=0, bg=BG_PANEL, fg=FG).pack(side="left")
        tk.Button(dh, text=">", command=lambda: self.mem_page(1), takefocus=0, bd=0, bg=BG_PANEL, fg=FG).pack(side="left")
        self.fmt_var = tk.StringVar(value=self.cfg.get("asm_format", FORMATS[0]))
        fmt = tk.OptionMenu(dh, self.fmt_var, *FORMATS, command=lambda _v: self.on_format())
        fmt.config(takefocus=0, bd=0, highlightthickness=0, bg=BG_PANEL, fg=FG, activebackground=BG_PANEL)
        fmt.pack(side="left")
        self.data_title = tk.Label(df, text="", anchor="w", bg=BG_PANEL, fg=FG_DIM)
        self.data_title.pack(fill="x")
        self.data = tk.Text(df, wrap="none", bg=BG, fg=FG, font=self.font, insertwidth=0, bd=0, highlightthickness=0,
                            width=46, height=12, cursor="arrow")
        self.data.pack(fill="both", expand=True)
        self.data.tag_configure("name", foreground=FG_ADDR)
        self.data.tag_configure("note", foreground=FG_NOTE)
        self.data.config(state="disabled")
        self.data.bind("<Double-Button-1>", self.on_data_follow)
        right.add(df, minsize=60)
        cf = tk.Frame(right, bg=BG_PANEL)
        self.callers_title = tk.Label(cf, text="Callers", anchor="w", bg=BG_PANEL, fg="white")
        self.callers_title.pack(fill="x")
        self.callers = tk.Listbox(cf, bg=BG, fg=FG, font=self.font, activestyle="none", bd=0, highlightthickness=0,
                                  selectbackground=BG_CUR, exportselection=False, height=5)
        self.callers.pack(fill="both", expand=True)
        self.callers.bind("<<ListboxSelect>>", self.on_caller)
        right.add(cf, minsize=40)
        panes.add(right, minsize=160, width=430)

        self.win.bind("<Alt-Left>", lambda e: self.step(-1))
        self.win.bind("<Alt-Right>", lambda e: self.step(1))
        # The mouse's back / forward buttons: 4 and 5 in Tk 8.6 on Windows (where the wheel is <MouseWheel>),
        # 8 and 9 on X11 and from Tk 8.7.
        side = {8: -1, 9: 1}
        if sys.platform == "win32" and tk.TkVersion < 8.7:
            side.update({4: -1, 5: 1})
        self.win.bind("<ButtonRelease>", lambda e: self.step(side[e.num]) if e.num in side else None)
        self.win.bind("<Control-f>", lambda e: (self.find.focus_set(), self.find.select_range(0, "end")))
        self.win.bind("<Control-g>", lambda e: (self.go.focus_set(), self.go.select_range(0, "end")))
        self.win.bind("<F3>", lambda e: self.find_next(1))
        self.win.bind("<F9>", lambda e: self.on_break())
        self.win.bind("<F4>", lambda e: self.on_runto())
        self.win.bind("<F11>", lambda e: self.debug("step"))
        self.win.bind("<F10>", lambda e: (self.debug("over"), "break")[1])
        self.win.bind("<F5>", lambda e: self.debug("cont"))
        self.win.bind("<F6>", lambda e: self.toggle_c())
        self.win.bind("<F8>", lambda e: self.on_g2_watch())
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        self.worker = Worker(host, code)
        self.worker.start()
        self.job(lambda g: g, self.on_game, "reading the game's function list...")
        self.win.after(40, self.pump)
        self.win.after(600, self.poll)
        self.win.after(1500, self.g2_tick)
        self.win.after(1500, self.g2_slices)

    # ------------------------------------------------------------ plumbing
    def alive(self):
        return self.win.winfo_exists()

    def close(self):
        self.cfg["asm_geometry"] = self.win.geometry()
        self.cfg["asm_bytes"] = bool(self.bytes_var.get())
        self.cfg["asm_c_open"] = self.c_open
        if self.c_open:
            self.cfg["asm_c_width"] = self.cpane.frame.winfo_width()
        if str(self.g2_frame) in [str(w) for w in self.vpanes.panes()] and self.g2_frame.winfo_height() > 1:
            self.cfg["asm_watch_height"] = self.g2_frame.winfo_height()
        self.save_cfg()
        if self.g2_probe and self.g2_on:     # its break must come off: a thread held with nobody to let it go
            self.worker.jobs.put((lambda game: game.regwatch_stop(), None))
        else:
            self.worker.stop = True
        self.worker.jobs.put((None, None))
        self.win.destroy()

    def job(self, fn, done, note=""):
        self.busy += 1
        if note:
            self.status.config(text=note)
        self.worker.jobs.put((fn, done))

    def pump(self):
        if not self.alive():
            return
        try:
            while True:
                done, result, error = self.worker.out.get_nowait()
                self.busy -= 1
                if done == self.on_poll:
                    self.poll_out = False
                    if error is not None:
                        continue      # a poll that failed says nothing new
                if done == self.on_g2_rows:
                    self.g2_out = False
                if done == self.on_g2_slice:
                    self.g2_cout = False
                if error is not None:
                    self.status.config(text="%s: %s" % (type(error).__name__, error))
                else:
                    done(result)
        except queue.Empty:
            pass
        if self.cpane is not None:
            self.cpane.pump()
        self.win.after(40, self.pump)

    def on_game(self, game):
        self.game = game
        self.win.title("Breeze disassembler - %s" % game.caption)
        self.status.config(text="%s %s  main %X  code %X bytes  |  %d functions: %s" % (
            game.tid, game.bid, game.main, game.text_size, len(game.starts), game.source))
        self.fill_list()
        if not (game.console or game.probe_debugger or "debug" in game.b.caps()):
            self.dbar.pack_forget()      # no debugger on this host: its buttons would only say so
        self.g2_probe = bool(game.probe_debugger or game.emu_regwatch) and not game.console
        if game.console or self.g2_probe:
            if self.g2_probe:                # who touches an address is the Watch tab's there
                self.g2_label.config(text=" probe:")
                self.g2_who.pack_forget()
            if str(self.g2_frame) not in [str(w) for w in self.vpanes.panes()]:
                self.vpanes.add(self.g2_frame, stretch="never", minsize=90, height=self.cfg.get("asm_watch_height", 230))
            self.g2_refresh(quiet=True)
        last = self.cfg.get("asm_last", {}).get(game.bid)
        self.goto(last if last is not None and 0 <= last < game.text_size else (game.starts[0] if game.starts else 0))
        asked, self.asked = getattr(self, "asked", None), None
        if asked is not None:
            self.goto_address(asked)
        if self.cfg.get("asm_c_open") and not self.c_open:
            self.toggle_c()

    def set_font(self):
        try:
            size = int(self.font_var.get())
        except ValueError:
            return
        self.cfg["asm_font"] = size
        self.save_cfg()
        self.font = ("Consolas", size)
        for w in (self.text, self.list, self.callers, self.regs, self.data):
            w.config(font=self.font)
        if self.cpane is not None:
            self.cpane.text.config(font=self.font)

    # ------------------------------------------------------------ the function list
    def fill_list(self):
        g = self.game
        if g is None:
            return
        mode = self.mode.get()
        words = self.filter_var.get().lower().split()
        self.list.delete(0, "end")
        self.items = []
        if mode == "functions":
            total = 0
            rows = []
            for rva, name, low in g.listed:
                if words and not all(w in low or w in "%x" % rva for w in words):
                    continue
                total += 1
                if len(rows) < LIST_MAX:
                    self.items.append((rva, None))
                    rows.append("%7X  %s" % (rva, short(name)))
            self.list.insert("end", *rows)
            self.list_info.config(text="%d of %d functions%s" % (total, len(g.listed),
                                                                 ", first %d shown" % LIST_MAX if total > LIST_MAX else ""))
            return
        if self.watch is None:
            self.list_info.config(text="reading code_watch.txt...")
            self.job(lambda game: game.code_watch(), self.on_watch, "reading the last code watch...")
            return
        head, rows = self.watch
        shown = [r for r in rows if (r[4] or mode == "watch")]
        shown.sort(key=lambda r: (not r[4], r[0]))
        for order, rva, caller, name, new in shown:
            low = name.lower()
            if words and not all(w in low or w in "%x" % rva for w in words):
                continue
            if len(self.items) >= LIST_MAX:
                break
            self.items.append((rva, caller))
            self.list.insert("end", "%5d%s %7X  %s" % (order, "*" if new else " ", rva, short(name)))
        self.list_info.config(text="%d shown of %d called, %d after the mark (*); double-click = the caller" % (
            len(self.items), len(rows), sum(1 for r in rows if r[4])))

    def on_watch(self, result):
        self.watch = result
        self.status.config(text="code watch: " + "  |  ".join(result[0][:2]))
        self.fill_list()

    def on_pick(self, _e, caller=False):
        sel = self.list.curselection()
        if not sel or sel[0] >= len(self.items):
            return
        rva, call = self.items[sel[0]]
        self.goto(call if caller and call is not None else rva)

    # ------------------------------------------------------------ navigation
    def parse(self, text):
        """An address typed into Go: an offset from main, or None when it is not one. Another module's
        code (sdk+5B1E78, or its absolute address) is an offset below 0 or past main's end."""
        g = self.game
        other = code_modules.parse(g.mods, text)
        if other is not None:
            return other - g.main
        t = text.strip().replace("main+", "").replace("M+", "").replace("m+", "")
        if t.lower().startswith("0x"):
            t = t[2:]
        if not re.fullmatch(r"[0-9A-Fa-f]+", t):
            return None
        v = int(t, 16)
        if g.main <= v < g.main + g.main_size:
            return v - g.main
        if v < g.main_size:
            return v
        return v - g.main if code_modules.module_of(g.mods, v) is not None else None

    def on_go(self):
        g = self.game
        if g is None:
            return
        text = self.go_var.get().strip()
        rva = self.parse(text)
        if rva is None:
            words = text.lower().split()
            for start, _name, low in g.listed:      # the whole name first: "X::Update", not "X::UpdateModules"
                if low == text.lower():
                    rva = start
                    break
        if rva is None:
            for start, _name, low in g.listed:
                if words and all(w in low for w in words):
                    rva = start
                    break
        if rva is None:
            self.status.config(text="nothing called \"%s\", and it is not an address in main" % text)
            return
        self.goto(rva)
        self.text.focus_set()

    def goto(self, rva, record=True):
        g = self.game
        if g is None:
            return
        if not g.is_code(rva):
            # Data: nothing to disassemble; say what is there.
            self.job(lambda game: game.describe(game.main + rva), lambda r: self.status.config(
                text="M+%X is data: %s" % (rva, r[1])))
            return
        if record:
            if self.cur is not None and self.hpos >= 0:
                self.history[self.hpos] = self.cur     # leave from the line the cursor was on
            self.history = self.history[:self.hpos + 1] + [rva]
            self.hpos = len(self.history) - 1
        if self.lines and self.start <= rva < self.end and rva in self.row_of:
            self.set_cur(rva)
            return
        self.job(lambda game: game.view(rva), lambda r: self.show(r, rva), "reading %s..." % g.label(rva))

    def step(self, d):
        if 0 <= self.hpos + d < len(self.history):
            if self.cur is not None:
                self.history[self.hpos] = self.cur
            self.hpos += d
            self.goto(self.history[self.hpos], record=False)
        return "break"

    def neighbour(self, d):
        g = self.game
        if g is None or not g.starts:
            return
        i = bisect.bisect_right(g.starts, self.cur if self.cur is not None else 0) - 1 + d
        self.goto(g.starts[max(0, min(len(g.starts) - 1, i))])

    def on_reload(self):
        if self.game is None:
            return
        at = self.cur if self.cur is not None else self.start
        self.lines = []

        def reload(game):
            game.pages.clear()
            return game.view(at)

        self.job(reload, lambda r: self.show(r, at), "reading the code again...")

    # ------------------------------------------------------------ the listing
    def show(self, result, rva):
        self.start, self.end, title, self.lines = result
        self.title.config(text=title)
        self.render()
        self.set_cur(rva)
        self.cfg.setdefault("asm_last", {})[self.game.bid] = rva
        self.status.config(text="%d instructions" % len(self.lines))
        self.callers.delete(0, "end")
        self.caller_rows = []
        self.callers_title.config(text="Callers (press Callers)")
        self.request_c()

    # ------------------------------------------------------------ the C pane
    def toggle_c(self):
        if self.c_open:
            self.cfg["asm_c_width"] = self.cpane.frame.winfo_width()
            self.panes.forget(self.cpane.frame)
            self.c_open = False
        else:
            if self.cpane is None:
                self.cpane = CPane(self.panes, self)
            self.panes.add(self.cpane.frame, after=self.mid, minsize=200, width=int(self.cfg.get("asm_c_width", 560)),
                           stretch="always")
            self.c_open = True
            self.request_c()
        return "break"

    def request_c(self):
        """Decompiles the function the listing shows into the C pane, when it is open."""
        if not self.c_open or self.game is None or not self.lines:
            return
        at = self.cur if self.cur is not None and self.start <= self.cur < self.end else self.start
        self.job(lambda g: g.decomp_input(at), self.cpane.submit)

    def line_text(self, line):
        """One line as plain text, and the column ranges of its parts."""
        rva = line["rva"]
        where = "M+%-7X" % rva if 0 <= rva < self.game.main_size else "%-9s" % self.game.label(rva)
        parts = [("%s %s" % (">" if line["label"] else " ", where), "label" if line["label"] else "addr")]
        if self.bytes_var.get():
            parts.append((" %08X" % line["word"], "word"))
        parts.append(("  %-7s %-34s" % (line["mnem"], line["ops"]), line["kind"] if line["kind"] in ("call", "jump", "ret") else ""))
        if line["note"]:
            parts.append(("  ; " + line["note"], "str" if line["kind"] == "str" else "note"))
        return parts

    def render(self):
        t = self.text
        top = t.yview()[0]
        t.config(state="normal")
        t.delete("1.0", "end")
        self.row_of = {}
        for n, line in enumerate(self.lines, 1):
            if n > 1:
                t.insert("end", "\n")
            self.row_of[line["rva"]] = n
            for text, tag in self.line_text(line):
                t.insert("end", text, (tag,) if tag else ())
        t.config(state="disabled")
        t.yview_moveto(top)
        if self.cur is not None:
            self.set_cur(self.cur)
        self.mark_debug()

    def set_cur(self, rva):
        row = self.row_of.get(rva & ~3)
        if row is None:
            return
        self.cur = rva & ~3
        t = self.text
        t.tag_remove("cur", "1.0", "end")
        t.tag_add("cur", "%d.0" % row, "%d.0" % (row + 1))
        t.see("%d.0" % max(row - 6, 1))
        t.see("%d.0" % min(row + 6, len(self.lines)))
        t.see("%d.0" % row)
        self.go_var.set(self.game.label(self.cur))
        if self.c_open:
            self.cpane.highlight(self.cur)

    def line_at(self, e):
        row = int(self.text.index("@%d,%d" % (e.x, e.y)).split(".")[0])
        return self.lines[row - 1] if 1 <= row <= len(self.lines) else None

    def on_click(self, e):
        self.text.focus_set()
        if self.text.tag_ranges("sel"):
            return
        line = self.line_at(e)
        if line is not None:
            self.set_cur(line["rva"])

    def on_follow(self, e):
        """Double-click or Enter: go where the line's call, branch or address points."""
        line = self.line_at(e) if e.type == tk.EventType.ButtonPress else self.lines[self.row_of[self.cur] - 1] if self.cur in self.row_of else None
        if line is not None and line["target"] is not None:
            self.goto(line["target"])
        return "break"

    def on_follow_cur(self):
        line = self.lines[self.row_of[self.cur] - 1] if self.cur in self.row_of else None
        if line is not None and line["target"] is not None:
            self.goto(line["target"])
        else:
            self.status.config(text="this line points nowhere in the game's code")

    def goto_address(self, address):
        """The listing at an address of the game's code. (Other tabs call this.)"""
        if self.game is None:
            self.asked = address
            return
        rva = address - self.game.main
        if self.game.is_code(rva):
            self.goto(rva)
        else:
            self.status.config(text="%X is not in the game's code" % address)

    def set_pause(self, want):
        """Pause: the whole game stops. Run: it goes on, and a thread held at a breakpoint is let go."""
        if self.game is None:
            return

        if not want and self.dbg.get("stopped"):
            # Held at a breakpoint: only the debugger may let it go. A plain resume under a
            # Switch's debugger (before beta129.00's fix) killed the game.
            self.debug("cont")
            return

        def done(paused):
            self.status.config(text="the game is paused" if paused else "the game runs")
        self.job(lambda game: game.pause(want), done, "pausing..." if want else "resuming...")

    def show_memory(self, address, how):
        """Opens the address in Studio's Memory tab; run alone, in this window's own memory pane."""
        studio = getattr(self.win, "studio", None)
        if studio is not None and not studio.send("Memory", "goto", address):
            return
        self.data_at = address
        self.mem_var.set("%X" % address)
        self.show_data()
        self.status.config(text="%s = %X" % (how, address))

    def on_operand_memory(self):
        """The memory the current line's instruction reads or writes."""
        g = self.game
        line = self.lines[self.row_of[self.cur] - 1] if g is not None and self.cur in self.row_of else None
        if line is None:
            return
        op = g.operand(line)
        if op is None:
            self.status.config(text="M+%X uses no memory" % line["rva"])
            return
        if op[0] == "static":
            self.show_memory(op[1], "M+%X" % line["rva"])
            return
        _kind, base, index, shift, disp, text = op

        def value(regs, name):
            name = {"x29": "fp", "x30": "lr"}.get(name, name) if "fp" in regs else name
            v = regs.get(name)
            if v is None and name.startswith("w"):
                v = regs.get("x" + name[1:])
                v = v & 0xFFFFFFFF if v is not None else None
            return v

        def use(regs, note=""):
            b = value(regs, base)
            i = value(regs, index) if index else 0
            if b is None or i is None:
                self.status.config(text="%s: no value for its registers" % text)
                return
            self.show_memory((b + (i << shift) + disp) & 0xFFFFFFFFFFFFFFFF, text + note)

        st = self.dbg
        if st.get("stopped"):
            regs = dict(zip(REG_NAMES, [int(v, 16) for v in st["x"] + [st["sp"], st["pc"], st["pstate"]]]))
            at_pc = self.pc_rva() == line["rva"]
            use(regs, "" if at_pc else "  (with the registers at the PC, which is not this line)")
            return
        if not (g.probe_debugger or g.emu_regwatch):
            self.status.config(text="%s needs the registers: stop the game on this line first (Run to F4)" % text)
            return

        def done(regs):
            if regs is None:
                self.status.config(text="nothing ran M+%X in 3 seconds: %s is not known" % (line["rva"], text))
            else:
                use(regs, "  (caught as it ran)")
        self.job(lambda game: game.catch(line["rva"]), done, "waiting for M+%X to run..." % line["rva"])

    def on_patch(self):
        """A code-patch cheat on the current instruction, keeping the game's instruction in the
        cheat (studio/patch_maker.py)."""
        if self.game is None or self.cur is None:
            return
        studio = os.path.join(os.path.dirname(os.path.abspath(__file__)), "studio")
        if studio not in sys.path:
            sys.path.insert(0, studio)
        import patch_maker
        start = self.game.func_of(self.cur) if 0 <= self.cur < self.game.text_size else None
        title = self.game.name_of(start[0]).rpartition(".")[2] if start else "M+%X" % self.cur
        patch_maker.PatchMaker(self.win, self.job, self.cur, title)

    def on_hook(self):
        """An ASM cheat hooked on the current instruction (studio/hook_maker.py). A named function's
        first instruction is a real entry; a start from the unwind table alone may be a split-off
        piece that is jumped into, where x9-x17 are not free."""
        if self.game is None or self.cur is None:
            return
        studio = os.path.join(os.path.dirname(os.path.abspath(__file__)), "studio")
        if studio not in sys.path:
            sys.path.insert(0, studio)
        import hook_maker
        start = self.game.func_of(self.cur)
        title = self.game.name_of(start[0]) if start else ""
        if start and self.cur != start[0]:
            title += "+%X" % (self.cur - start[0])
        hook_maker.HookMaker(self.win, self.job, self.cur, title, entry=self.cur in self.game.names)

    def on_callers(self):
        g = self.game
        if g is None or self.cur is None:
            return
        f = g.func_of(self.cur)
        start = f[0] if f else self.cur
        self.callers_title.config(text="Callers of %s: searching..." % short(g.name_of(start)))

        def done(rows):
            self.caller_rows = rows
            self.callers.delete(0, "end")
            for rva, where in rows:
                self.callers.insert("end", "%7X  %s" % (rva, short(where)))
            self.callers_title.config(text="%d callers of %s" % (len(rows), short(g.name_of(start))))
            self.status.config(text="%d b / bl to M+%X" % (len(rows), start))

        self.job(lambda game: game.callers(start), done, "looking for calls to M+%X..." % start)

    def on_caller(self, _e):
        sel = self.callers.curselection()
        if sel and sel[0] < len(self.caller_rows):
            self.goto(self.caller_rows[sel[0]][0])

    # ------------------------------------------------------------ gen2's watches (a Switch)
    def build_gen2(self, mid):
        """The gen2 menu's work, under the listing: which addresses an instruction uses, who touches
        an address, a break for one of them. Shown on a Switch."""
        f = self.g2_frame = tk.Frame(mid, bg=BG_PANEL)
        lab = dict(bg=BG_PANEL, fg=FG)
        bar = tk.Frame(f, bg=BG_PANEL)
        bar.pack(fill="x")
        self.g2_label = tk.Label(bar, text=" gen2:", bg=BG_PANEL, fg="white")
        self.g2_label.pack(side="left")
        tk.Button(bar, text="Watch instruction F8", command=self.on_g2_watch, takefocus=0).pack(side="left")
        tk.Label(bar, text=" register", **lab).pack(side="left")
        self.g2_reg = ttk.Combobox(bar, width=5, state="readonly", height=12, values=["auto"] + ["x%d" % i for i in range(31)])
        self.g2_reg.set("auto")
        self.g2_reg.pack(side="left")
        tk.Label(bar, text=" offset", **lab).pack(side="left")
        self.g2_off = tk.Entry(bar, width=7)
        self.g2_off.pack(side="left")
        self.g2_off.bind("<Return>", lambda e: self.g2_refresh())
        tk.Label(bar, text="(hex; empty: the instruction's)", bg=BG_PANEL, fg=FG_DIM).pack(side="left")
        tk.Button(bar, text="Stop", command=self.on_g2_stop, takefocus=0).pack(side="left", padx=(8, 0))
        tk.Button(bar, text="Refresh", command=self.g2_refresh, takefocus=0).pack(side="left")
        self.g2_follow = tk.BooleanVar(value=True)
        self.g2_bycount = tk.BooleanVar(value=False)
        for text, var, cmd in (("follow", self.g2_follow, None), ("most hits first", self.g2_bycount, self.g2_fill)):
            tk.Checkbutton(bar, text=text, variable=var, command=cmd, takefocus=0, bg=BG_PANEL, fg=FG, selectcolor=BG,
                           activebackground=BG_PANEL).pack(side="left")
        bar2 = tk.Frame(f, bg=BG_PANEL)
        bar2.pack(fill="x")
        tk.Label(bar2, text=" show as", **lab).pack(side="left")
        self.g2_as = ttk.Combobox(bar2, width=5, state="readonly", height=14, values=list(SHOW_AS))
        self.g2_as.set("auto")
        self.g2_as.pack(side="left")
        self.g2_as.bind("<<ComboboxSelected>>", lambda e: self.g2_fill())
        bar = self.g2_who = tk.Frame(bar2, bg=BG_PANEL)
        bar.pack(side="left")
        tk.Label(bar, text=" who touches", bg=BG_PANEL, fg="white").pack(side="left")
        self.g2_addr = tk.Entry(bar, width=14)
        self.g2_addr.pack(side="left")
        self.g2_addr.bind("<Return>", lambda e: self.on_g2_memory())
        self.g2_mode = ttk.Combobox(bar, width=3, state="readonly", values=["w", "r", "rw"])
        self.g2_mode.set("w")
        self.g2_mode.pack(side="left", padx=2)
        tk.Label(bar, text="bytes", **lab).pack(side="left")
        self.g2_size = ttk.Combobox(bar, width=2, state="readonly", values=["1", "2", "4", "8"])
        self.g2_size.set("4")
        self.g2_size.pack(side="left", padx=2)
        tk.Label(bar, text="stack", **lab).pack(side="left")
        self.g2_stack = ttk.Combobox(bar, width=2, state="readonly", values=["0", "1", "2", "3", "4", "5"])
        self.g2_stack.set("2")
        self.g2_stack.pack(side="left", padx=2)
        tk.Button(bar, text="Watch address", command=self.on_g2_memory, takefocus=0).pack(side="left")
        self.g2_info = tk.Label(bar2, text="", anchor="w", bg=BG_PANEL, fg=FG_NOTE)
        self.g2_info.pack(side="left", fill="x", expand=True, padx=8)
        box = tk.Frame(f)
        box.pack(fill="both", expand=True)
        cols = ("n", "a", "count", "b", "c", "d")
        self.g2_tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse", height=4)
        for c, w in zip(cols, (50, 150, 70, 260, 150, 260)):
            self.g2_tree.column(c, width=w, anchor="e" if c in ("n", "count") else "w", stretch=c != "n")
        sb = ttk.Scrollbar(box, command=self.g2_tree.yview)
        self.g2_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.g2_tree.pack(fill="both", expand=True)
        self.g2_tree.bind("<Double-1>", lambda e: self.on_g2_open())
        menu = self.g2_menu = tk.Menu(self.g2_tree, tearoff=0)
        menu.add_command(label="Open (the address in Memory, the instruction in the listing)", command=self.on_g2_open)
        menu.add_command(label="Go to the caller", command=lambda: self.on_g2_open(caller=True))
        menu.add_separator()
        menu.add_command(label="Who touches this address", command=self.on_g2_row_memory)
        menu.add_command(label="Break at the instruction for this value only", command=self.on_g2_break)
        menu.add_separator()
        menu.add_command(label="Copy", command=lambda: self.g2_copy(False))
        menu.add_command(label="Copy every row", command=lambda: self.g2_copy(True))

        def popup(e):
            row = self.g2_tree.identify_row(e.y)
            if row:
                self.g2_tree.selection_set(row)
                menu.tk_popup(e.x_root, e.y_root)
        self.g2_tree.bind("<Button-3>", popup)
        self.g2_heads(False)

    def g2_heads(self, memory):
        heads = ("#", "instruction", "hits", "in", "called from", "in") if memory else \
            ("#", "address", "hits", "holds now", "as a number", "")
        for c, h in zip(("n", "a", "count", "b", "c", "d"), heads):
            self.g2_tree.heading(c, text=h)

    def g2_clear_to_start(self):
        """Starting a watch detaches gen2 first. Whether the debugger's breakpoints are taken out of
        the code by that is not measured, and one left in crashes the game: they go first."""
        if self.dbg.get("stopped") or self.dbg.get("bps"):
            self.status.config(text="the debugger is in use: Stop in the Debug row first (a watch detaches gen2)")
            return False
        return True

    def cur_line(self):
        return self.lines[self.row_of[self.cur] - 1] if self.game is not None and self.cur in self.row_of else None

    def on_g2_watch(self):
        """An instruction watch on the current line. With register "auto" the register and the offset
        are read off the instruction, as the gen2 menu does: the rows are the addresses it uses."""
        g, line = self.game, self.cur_line()
        if line is None or not (g.console or self.g2_probe):
            return "break"
        choice, off_text = self.g2_reg.get(), self.g2_off.get().strip()
        op = g.operand(line)
        size, fmt = access_size(line["mnem"], line["ops"]) if op is not None else (8, "i")
        if self.g2_probe:
            return self.g2_probe_watch(line, op, choice, off_text, size, fmt)
        if choice == "auto":
            if op is None or op[0] != "reg":
                self.status.config(text="M+%X reaches no memory through a register: pick the register to record" % line["rva"])
                return "break"
            _kind, base, index, _shift, disp, text = op
            if index:
                self.status.config(text="%s: two registers. PC connect records one: pick it, and add the other by hand" % text)
                return "break"
            if not re.match(r"x\d+$", base):
                self.status.config(text="%s: gen2 records x0 to x30, not %s" % (text, base))
                return "break"
            reg, off = int(base[1:]), disp
        else:
            reg, off, size, fmt = int(choice[1:]), 0, 8, "i"
        if off_text:
            try:
                off = int(off_text, 16)
            except ValueError:
                self.status.config(text="offset: hex")
                return "break"
        if not self.g2_clear_to_start():
            return "break"
        at = g.main + line["rva"]
        mine = {"kind": "reg", "at": at, "rva": line["rva"], "reg": reg, "offset": off, "size": size, "fmt": fmt,
                "text": "x%d%s at M+%X" % (reg, "%+#x" % off if off else "", line["rva"])}

        def done(_st):
            self.g2 = mine
            self.status.config(text="gen2 records %s: hide Breeze so the game runs" % mine["text"])
            self.g2_refresh(quiet=True)
        self.job(lambda game: game.gen2("watch %X x%d" % (at, reg)), done, "gen2: watching %s..." % mine["text"])
        return "break"

    def g2_probe_watch(self, line, op, choice, off_text, size, fmt):
        """The same on the Lichii fork: every register is there at each hit, so the address is worked
        out whole (sp, two registers)."""
        g = self.game
        if choice == "auto":
            if op is None or op[0] != "reg":
                self.status.config(text="M+%X reaches no memory through a register: pick the register to record" % line["rva"])
                return "break"
            _kind, base, index, shift, disp, text = op
        else:
            base, index, shift, disp, size, fmt, text = choice, None, 0, 0, 8, "i", choice
        if off_text:
            try:
                disp = int(off_text, 16)
            except ValueError:
                self.status.config(text="offset: hex")
                return "break"
            text = "%s%s%s" % (base, "+" + index if index else "", "%+#x" % disp if disp else "")
        mine = {"kind": "reg", "at": g.main + line["rva"], "rva": line["rva"], "base": base, "index": index, "shift": shift,
                "disp": disp, "size": size, "fmt": fmt, "text": "%s at M+%X" % (text, line["rva"])}

        def done(_r):
            self.g2 = mine
            self.g2_on = True
            self.status.config(text=("emuhost records %s: each run stops the game for a moment" if g.emu_regwatch else
                                     "the probe records %s: each run holds its thread for a moment") % mine["text"])
            self.g2_refresh(quiet=True)
        self.job(lambda game: game.regwatch_start(mine), done, "probe: watching %s..." % mine["text"])
        return "break"

    def on_g2_slice(self, _r):
        self.g2_cout = False
        if time.time() - self.g2_read > 1.0 and self.g2_follow.get():
            self.g2_refresh(quiet=True)

    def g2_slices(self):
        """On the Lichii fork the watch is run from here: slice after slice, the worker takes the hits."""
        if not self.alive():
            return
        if self.g2_probe and self.g2_on and not self.g2_cout and self.game is not None:
            self.g2_cout = True
            self.busy += 1
            self.worker.jobs.put((lambda game: game.regwatch_collect(150), self.on_g2_slice))
        self.win.after(20, self.g2_slices)

    def others_busy(self):
        """Jobs on their way, the watch's own slice aside."""
        return self.busy - (1 if self.g2_cout else 0)

    def g2_to_watch_tab(self, address, size):
        studio = getattr(self.win, "studio", None)
        note = studio.send("Watch", "watch_address", address, size) if studio is not None else \
            "who touches an address is Breeze Studio's Watch tab on this host"
        if note:
            self.status.config(text=note)

    def g2_memory(self, address, size, mode):
        if self.g2_probe:
            self.g2_to_watch_tab(address, size)
            return
        if not self.g2_clear_to_start():
            return
        stack = int(self.g2_stack.get())
        mine = {"kind": "mem", "at": address, "text": "%s of %d byte(s) at %X" % (mode, size, address)}

        def done(_st):
            self.g2 = mine
            self.status.config(text="gen2 records the %s: hide Breeze so the game runs" % mine["text"])
            self.g2_refresh(quiet=True)
        self.job(lambda game: game.gen2("watch %X %s %d stack=%d" % (address, mode, size, stack)), done,
                 "gen2: watching %X..." % address)

    def on_g2_memory(self):
        """Who touches an address: every instruction that reads or writes it, with its caller."""
        g = self.game
        if g is None or not g.console:
            return
        t = self.g2_addr.get().strip()
        try:
            address = g.main + int(t[2:], 16) if t.upper().startswith("M+") else int(t, 16)
        except ValueError:
            self.status.config(text="who touches: a hex address or M+offset")
            return
        self.g2_memory(address, int(self.g2_size.get()), self.g2_mode.get())

    def on_g2_static(self):
        g, line = self.game, self.cur_line()
        if line is None or not (g.console or self.g2_probe):
            return
        op = g.operand(line)
        if op is None or op[0] != "static":
            self.status.config(text="M+%X has no fixed address: F8 lists the addresses it uses" % line["rva"])
            return
        size = access_size(line["mnem"], line["ops"])[0]
        self.g2_addr.delete(0, "end")
        self.g2_addr.insert(0, "%X" % op[1])
        self.g2_size.set(str(size))
        self.g2_memory(op[1], size, "rw")

    def on_g2_stop(self):
        if self.game is None:
            return
        if self.g2_probe:
            self.job(lambda game: game.regwatch_stop(), lambda _r: self.g2_refresh(), "probe: stopping...")
            return
        self.job(lambda game: game.gen2("stop"), lambda _st: self.g2_refresh(), "gen2: stopping...")

    def g2_tick(self):
        """While a watch is on, the list follows it."""
        if not self.alive():
            return
        if (self.game is not None and self.game.console and self.g2_on and self.g2_follow.get()
                and not self.g2_out and self.busy == 0 and self.win.winfo_viewable()):   # the probe's follows its slices
            self.g2_refresh(quiet=True)
        self.win.after(1500, self.g2_tick)

    def g2_refresh(self, quiet=False):
        if self.game is None or not (self.game.console or self.g2_probe) or self.g2_out:
            return
        self.g2_out = True
        self.g2_read = time.time()
        mine = self.g2
        off = self.g2_view_offset()
        if self.g2_probe:
            self.job(lambda game: game.regwatch_rows(off), self.on_g2_rows, "" if quiet else "probe: reading the rows...")
            return
        self.job(lambda game: game.gen2_rows(mine, off), self.on_g2_rows, "" if quiet else "gen2: reading the rows...")

    def g2_view_offset(self):
        """The offset box, once a register watch runs: the rows show register + this offset (None:
        empty or not hex, the watch's own). Changing it needs no new watch."""
        mine = self.g2
        if mine is None or mine["kind"] != "reg":
            return None
        try:
            off = int(self.g2_off.get().strip(), 16)
        except ValueError:
            return None
        return off if off != mine.get("disp", mine.get("offset", 0)) else None

    def on_g2_rows(self, st):
        self.g2_out = False
        self.g2_st = st
        memory = bool(st.get("read") or st.get("write"))
        self.g2_on = bool(st.get("attached")) and int(st.get("address", "0"), 16) != 0
        mine = self.g2 if st.get("ours") else None
        what = mine["text"] if mine else "%s at %s" % (st.get("type", "?"), st.get("address", "?"))
        if st.get("gen2") != st.get("breeze_expects"):
            text = "gen2 %s, Breeze wants %s: Settings > Install gen2 fork" % (st.get("gen2"), st.get("breeze_expects"))
        elif int(st.get("address", "0"), 16) == 0:
            text = "no watch yet: F8 on an instruction, or an address to the left"
        else:
            off = self.g2_view_offset() if mine else None
            shown = len(st.get("list", []))
            text = "%s:  %s rows%s,  %s hits%s%s%s" % (
                what, st.get("rows", 0), "" if shown == int(st.get("rows", 0) or 0) else " (%d listed)" % shown,
                st.get("trig", 0), "  (shown at %+#x)" % off if off is not None else "",
                "" if st.get("attached") else "  (stopped)",
                                              "  (%d could not be set)" % st["failed"] if st.get("failed") else "")
        self.g2_info.config(text=text)
        self.g2_list = [dict(x, memory="pc" in x) for x in st.get("list", [])]
        self.g2_heads(memory)
        self.g2_fill()

    def g2_fill(self):
        rows = list(getattr(self, "g2_list", []))
        if self.g2_bycount.get():
            rows.sort(key=lambda x: -int(x.get("count", 0)))
        st = getattr(self, "g2_st", {})
        reg = st.get("ours") and self.g2 and self.g2["kind"] == "reg"
        fmt = self.g2["fmt"] if reg else "i"
        size = self.g2["size"] if reg and self.g2.get("size") in (1, 2, 4, 8) else 8
        show = self.g2_as.get()
        values, keys = [], []
        for n, x in enumerate(rows, 1):
            if x["memory"]:
                values.append((n, x.get("pc", ""), x.get("count", ""), x.get("pc_name", ""), x.get("call_site", ""),
                               x.get("call_site_name", "")))
                keys.append(x.get("pc", "") + x.get("call_site", ""))
            else:
                hexa, number = value_as(x.get("data", b""), show, size, fmt)
                values.append((n, "%X" % x["address"], x.get("count", ""), hexa, number, x.get("call_site", "")))
                keys.append("%X" % x["address"] + x.get("call_site", ""))
        t = self.g2_tree
        kids = t.get_children()
        if keys == [r["key"] for r in self.g2_shown] and len(kids) == len(rows):
            for iid, v in zip(kids, values):      # only the numbers moved: the selection and the scroll stay
                t.item(iid, values=v)
        else:
            t.delete(*kids)
            for v in values:
                t.insert("", "end", values=v)
        self.g2_shown = [dict(x, key=k) for x, k in zip(rows, keys)]

    def g2_row(self):
        sel = self.g2_tree.selection()
        i = self.g2_tree.index(sel[0]) if sel else -1
        return self.g2_shown[i] if 0 <= i < len(self.g2_shown) else None

    def g2_code(self, text):
        """The listing at a code address as gen2 names it (M+offset)."""
        if text.upper().startswith("M+"):
            self.goto(int(text[2:].split("+")[0].split()[0], 16))
        else:
            self.status.config(text="%s is not in main's code" % (text or "that"))

    def on_g2_open(self, caller=False):
        x = self.g2_row()
        if x is None:
            return
        if caller:
            self.g2_code(x.get("call_site", ""))
        elif x["memory"]:
            self.g2_code(x.get("pc", ""))
        else:
            self.show_memory(x["address"], self.g2["text"] if self.g2 else "gen2")

    def on_g2_row_memory(self):
        x = self.g2_row()
        if x is None or x["memory"]:
            self.status.config(text="that row is an instruction, not an address")
            return
        size = self.g2["size"] if self.g2 and self.g2["kind"] == "reg" and self.g2["size"] in (1, 2, 4, 8) else 4
        if (x["address"] & 7) + size > 8:
            size = 1 if x["address"] & 1 else 2 if x["address"] & 2 else 4
        self.g2_addr.delete(0, "end")
        self.g2_addr.insert(0, "%X" % x["address"])
        self.g2_size.set(str(size))
        self.g2_memory(x["address"], size, self.g2_mode.get())

    def on_g2_break(self):
        """A break at the watched instruction that stops the game only for the picked row's value."""
        x, mine = self.g2_row(), self.g2
        st = getattr(self, "g2_st", {})
        if x is None or x["memory"] or not st.get("ours") or mine is None or mine["kind"] != "reg":
            self.status.config(text="pick a row of an instruction watch started here (F8)")
            return
        if self.g2_probe:
            if not self.g2_on:
                self.status.config(text="the watch is stopped: F8 starts it again")
                return
            a = int(x["value"], 16)                 # the address the instruction used, not the one shown
            self.job(lambda game: game.regwatch_hold(a), lambda _r: self.status.config(
                text="the thread stays held at M+%X when it uses %X. Continue F5 runs on to the next; Stop ends it" % (
                    mine["rva"], a)))
            return
        line = "break %X x%d=%s" % (mine["at"], mine["reg"], x["value"].lstrip("0") or "0")

        def done(_st):
            self.status.config(text="gen2 stops the game at M+%X when x%d = %s. Continue F5 runs on" % (
                mine["rva"], mine["reg"], x["value"]))
            self.g2_refresh(quiet=True)
        self.job(lambda game: game.gen2(line), done, "gen2: " + line)

    def g2_copy(self, every):
        t = self.g2_tree
        ids = t.get_children() if every else t.selection()
        text = "\n".join("\t".join(str(v) for v in t.item(i, "values")).rstrip() for i in ids)
        self.win.clipboard_clear()
        self.win.clipboard_append(text)

    # ------------------------------------------------------------ the debugger
    def poll(self):
        """Asks where the game stands, a few times a second, one question at a time."""
        if not self.alive():
            return
        if self.game is not None and not self.poll_out and self.others_busy() == 0:
            self.poll_out = True
            self.busy += 1
            vectors = self.reg_mode.get() == "v"
            self.worker.jobs.put((lambda game: game.debug("", vectors), self.on_poll))
        self.win.after(400, self.poll)

    def on_poll(self, st):
        self.poll_out = False
        self.on_debug(st, quiet=True)

    def debug(self, args):
        """One debugger command; the reply is the new state."""
        if self.game is None:
            return "break"
        vectors = self.reg_mode.get() == "v"
        self.job(lambda game: game.debug(args, vectors), self.on_debug, "dbg %s..." % args)
        return "break"

    def pc_rva(self, st=None):
        st = st or self.dbg
        if not st.get("stopped") or "pc" not in st:
            return None
        pc = int(st["pc"], 16) - self.game.main
        return pc if 0 <= pc < self.game.main_size else None

    def on_debug(self, st, quiet=False):
        g = self.game
        was = self.dbg
        self.dbg = st
        if st.get("no_debugger"):
            self.dbg_label.config(text="no debugger on this host (an emulator): the listing, Go, Callers and Reload work")
            return
        if not st.get("gen2"):
            self.dbg_label.config(text="no gen2 fork that this Breeze can talk to")
            return
        bps = st.get("bps", [])
        pc = self.pc_rva()
        if st.get("stopped"):
            where = ("M+%X  %s" % (pc, short(g.where(pc)))) if pc is not None else st["pc"]
            text = "STOPPED at " + where
        else:
            text = "running" if st.get("attached") else "running (gen2 not attached: a breakpoint attaches it)"
        if bps:
            text += "   |   %d breakpoint%s" % (len(bps), "" if len(bps) == 1 else "s")
        if st.get("watch", "0") != "0":
            text += "   |   Break and Trace watch at %s" % st["watch"]
        self.dbg_label.config(text=text, fg="#b00000" if st.get("stopped") else "#555")
        moved = st.get("stopped") and (not was.get("stopped") or was.get("pc") != st.get("pc"))
        if moved:
            if was.get("stopped"):
                self.regs_before = was.get("x", []) + [was.get("sp"), was.get("pc"), was.get("pstate")]
                self.v_before = was.get("v")
            if pc is not None and pc < g.text_size:
                self.goto(pc, record=not (self.lines and self.start <= pc < self.end))
        if st.get("stopped") != was.get("stopped") or moved or not quiet:
            self.show_registers()
            self.show_data()
        self.mark_debug()
        if not quiet:
            self.status.config(text=text)

    def mark_debug(self):
        """The line the game is stopped on and the lines with a breakpoint."""
        if self.game is None:
            return
        t = self.text
        t.tag_remove("pc", "1.0", "end")
        t.tag_remove("bp", "1.0", "end")
        for bp in self.dbg.get("bps", []):
            row = self.row_of.get(int(bp["at"], 16) - self.game.main)
            if row:
                t.tag_add("bp", "%d.0" % row, "%d.11" % row)
        pc = self.pc_rva()
        row = self.row_of.get(pc) if pc is not None else None
        if row:
            t.tag_add("pc", "%d.0" % row, "%d.0" % (row + 1))

    def show_pc(self):
        pc = self.pc_rva()
        if pc is None:
            self.status.config(text="the game is not stopped in its own code")
            return
        self.goto(pc)

    def on_break(self):
        if self.cur is not None:
            self.debug("bp " + self.game.debug_where(self.cur))
        return "break"

    def on_runto(self):
        if self.cur is not None:
            self.debug("runto " + self.game.debug_where(self.cur))
        return "break"

    def on_stop(self):
        self.debug("stop")
        self.debug("bp clear")

    def on_vector_view(self):
        self.cfg["asm_vector_view"] = self.vview_var.get()
        if self.reg_mode.get() != "v":
            self.reg_mode.set("v")       # picking a vector layout means wanting the vectors
            self.on_reg_mode()
        else:
            self.show_registers()

    def on_reg_mode(self):
        self.show_registers()
        if self.reg_mode.get() == "v" and self.dbg.get("stopped") and "v" not in self.dbg:
            self.debug("")       # fetch them

    def show_registers(self):
        st, g = self.dbg, self.game
        t = self.regs
        t.config(state="normal")
        t.delete("1.0", "end")
        self.reg_rows = {}
        if not st.get("stopped"):
            self.regs_title.config(text="(the game is running)")
            t.config(state="disabled")
            return
        if self.reg_mode.get() == "v":
            self.regs_title.config(text="double-click a value = change that lane")
            before = self.v_before or []
            for n, (lo, hi) in enumerate(st.get("v", [])):
                lo_i, hi_i = int(lo, 16), int(hi, 16)
                changed = n < len(before) and before[n] != [lo, hi]
                raw = struct.pack("<QQ", lo_i, hi_i)
                view = self.vview_var.get()
                if view == VECTOR_VIEWS[1]:
                    text = " ".join("%-14.8g" % x for x in struct.unpack("<4f", raw))
                elif view == VECTOR_VIEWS[2]:
                    text = " ".join("%-23.15g" % x for x in struct.unpack("<2d", raw))
                else:
                    text = "d %-22.15g  s %-14.8g" % (struct.unpack_from("<d", raw)[0], struct.unpack_from("<f", raw)[0])
                if n:
                    t.insert("end", "\n")
                t.insert("end", "%-5s" % ("v%d" % n), ("name",))
                t.insert("end", text, ("changed",) if changed else ())
                if view == VECTOR_VIEWS[0]:
                    t.insert("end", "  %016X %016X" % (hi_i, lo_i), ("note",))
                self.reg_rows[n + 1] = "v%d" % n
            if "v" in st:
                t.insert("end", "\nfpcr %s   fpsr %s" % (st.get("fpcr", "?"), st.get("fpsr", "?")), ("name",))
            else:
                t.insert("end", "reading...")
            t.config(state="disabled")
            return
        self.regs_title.config(text="click = memory there, double-click = change")
        values = st["x"] + [st["sp"], st["pc"], st["pstate"]]
        before = self.regs_before or []
        for n, (name, value) in enumerate(zip(REG_NAMES, values), 1):
            v = int(value, 16)
            changed = n - 1 < len(before) and before[n - 1] is not None and before[n - 1] != value
            note = ""
            if name == "pstate":
                note = "".join(c if v >> b & 1 else "-" for c, b in (("N", 31), ("Z", 30), ("C", 29), ("V", 28)))
            elif g.in_main(v):
                rva = v - g.main
                note = "M+%X %s" % (rva, short(g.where(rva)) if rva < g.text_size else "")
            elif g.heap <= v < g.heap + g.heap_size:
                note = "heap+%X" % (v - g.heap)
            if n > 1:
                t.insert("end", "\n")
            t.insert("end", "%-6s" % name, ("name",))
            t.insert("end", "%016X" % v, ("changed",) if changed else ())
            if note:
                t.insert("end", "  " + note, ("note",))
            self.reg_rows[n] = name
        t.config(state="disabled")

    def reg_value(self, name):
        """A general register of the stopped game, or None."""
        st = self.dbg
        if not st.get("stopped") or name not in REG_NAMES:
            return None
        return int((st["x"] + [st["sp"], st["pc"], st["pstate"]])[REG_NAMES.index(name)], 16)

    def mem_address(self, text):
        """What is typed into the memory box: terms joined by + or -, each hex, M+off, heap+off or a register."""
        g = self.game
        t = text.strip().lower().replace(" ", "").replace("main+", "m+")
        t = t.replace("m+", "%x+" % g.main).replace("heap+", "%x+" % g.heap).replace("-", "+-")
        total = 0
        for term in [x for x in t.split("+") if x]:
            sign = -1 if term.startswith("-") else 1
            term = term.lstrip("-")
            v = self.reg_value(term)
            if v is None:
                try:
                    v = int(term[2:] if term.startswith("0x") else term, 16)
                except ValueError:
                    return None
            total += sign * v
        return total if total > 0 else None

    def on_mem(self):
        text = self.mem_var.get().strip().lower()
        if text in ("", "sp"):
            self.data_at = None
        else:
            at = self.mem_address(text)
            if at is None:
                self.status.config(text="\"%s\" is not an address: hex, M+offset, heap+offset, a register, or a sum" % text)
                return "break"
            self.data_at = at
        self.show_data()
        return "break"

    def mem_page(self, d):
        base = self.data_at if self.data_at is not None else (self.reg_value("sp") or 0)
        if base:
            self.data_at = max(base + d * BLOCK, 0)
            self.mem_var.set("%X" % self.data_at)
            self.show_data()

    def on_format(self):
        self.cfg["asm_format"] = self.fmt_var.get()
        self.render_data()

    def show_data(self, block=None):
        """The stack, or the memory at the address in the box; read again at every stop."""
        if block is None:
            if self.data_at is not None:
                at = self.data_at
                self.job(lambda game: game.block(at), self.show_data)
                return
            block = self.dbg.get("stack") if self.dbg.get("stopped") else None
        self.shown_block = block
        self.render_data()

    def render_data(self):
        block = self.shown_block
        t = self.data
        t.config(state="normal")
        t.delete("1.0", "end")
        if block is None:
            self.data_title.config(text="the stack shows when the game is stopped; an address shows any time")
            t.config(state="disabled")
            return
        addr, data, notes = block["addr"], block["data"], block["notes"]
        g = self.game
        where = "M+%X" % (addr - g.main) if g.in_main(addr) else "heap+%X" % (addr - g.heap) if g.heap <= addr < g.heap + g.heap_size else ""
        self.data_title.config(text="%X  %s%s" % (addr, where, "" if data else "   cannot be read (%s)" % block.get("error", "not mapped")))
        fmt = self.fmt_var.get()
        size, per, pack, show = {
            FORMATS[0]: (8, 1, "<Q", lambda v: "%016X" % v),
            FORMATS[1]: (4, 4, "<I", lambda v: "%08X" % v),
            FORMATS[2]: (4, 4, "<i", lambda v: "%11d" % v),
            FORMATS[3]: (4, 4, "<f", lambda v: "%13.6g" % v),
            FORMATS[4]: (8, 2, "<d", lambda v: "%22.14g" % v),
            FORMATS[5]: (2, 8, "<H", lambda v: "%04X" % v),
            FORMATS[6]: (1, 16, "<B", lambda v: "%02X" % v),
        }.get(fmt, (8, 1, "<Q", lambda v: "%016X" % v))
        line = size * per
        for n, off in enumerate(range(0, len(data) - line + 1, line)):
            if n:
                t.insert("end", "\n")
            t.insert("end", "+%03X  " % off, ("name",))
            t.insert("end", " ".join(show(struct.unpack_from(pack, data, off + i * size)[0]) for i in range(per)))
            if fmt == FORMATS[0] and off in notes:
                t.insert("end", "  " + notes[off], ("note",))
            elif fmt == FORMATS[6]:
                t.insert("end", "  " + "".join(chr(c) if 32 <= c < 127 else "." for c in data[off:off + line]), ("note",))
        t.config(state="disabled")

    def reg_at(self, e):
        row = int(self.regs.index("@%d,%d" % (e.x, e.y)).split(".")[0])
        return row, self.reg_rows.get(row)

    def on_reg_click(self, e):
        row, name = self.reg_at(e)
        if name is None or name == "pstate" or name.startswith("v"):
            return
        self.regs.tag_remove("cur", "1.0", "end")
        self.regs.tag_add("cur", "%d.0" % row, "%d.0" % (row + 1))
        self.mem_var.set(name)
        self.on_mem()

    def vector_lane(self, col):
        """Which part of a vector register a column of the Float view is: (format, lane), or None."""
        view = self.vview_var.get()
        col -= 5                                    # past the name
        if col < 0:
            return None
        if view == VECTOR_VIEWS[1]:
            return ("f", col // 15) if col // 15 < 4 else None
        if view == VECTOR_VIEWS[2]:
            return ("d", col // 24) if col // 24 < 2 else None
        if col < 26:
            return ("d", 0)
        return ("f", 0) if col < 43 else None

    def on_vector_edit(self, name, col):
        """Changes the one float or double of a vector register that was double-clicked."""
        from tkinter import simpledialog
        n = int(name[1:])
        lane = self.vector_lane(col)
        vectors = self.dbg.get("v", [])
        if lane is None or n >= len(vectors):
            self.status.config(text="double-click the value to change, not the name or the hex")
            return
        fmt, index = lane
        size = 4 if fmt == "f" else 8
        raw = bytearray(struct.pack("<QQ", int(vectors[n][0], 16), int(vectors[n][1], 16)))
        old = struct.unpack_from("<" + fmt, raw, index * size)[0]
        kind = "float" if fmt == "f" else "double"
        value = simpledialog.askstring("Register", "v%d, %s %d of 0 to %d (now %.9g).\nA number, or 0x and its bits:" % (
            n, kind, index, 16 // size - 1, old), parent=self.win)
        if not value:
            return
        value = value.strip()
        try:
            if value.lower().startswith("0x"):
                bits = int(value, 16)
                if bits >> (size * 8):
                    raise ValueError
                raw[index * size:(index + 1) * size] = bits.to_bytes(size, "little")
            else:
                struct.pack_into("<" + fmt, raw, index * size, float(value))
        except (ValueError, struct.error, OverflowError):
            self.status.config(text="\"%s\" is not a %s" % (value, kind))
            return
        low, high = struct.unpack("<QQ", raw)
        self.job(lambda game: game.set_vector(n, low, high), self.on_debug, "setting v%d..." % n)

    def on_reg_edit(self, e):
        _row, name = self.reg_at(e)
        if name is None or not self.dbg.get("stopped"):
            return "break"
        if name.startswith("v"):
            self.on_vector_edit(name, int(self.regs.index("@%d,%d" % (e.x, e.y)).split(".")[1]))
            return "break"
        from tkinter import simpledialog
        vector = False
        value = simpledialog.askstring("Register", "New value for %s (hex%s):" % (
            name, "; or a number: 1.5 = double, 1.5f = float" if vector else ""), parent=self.win)
        if not value:
            return "break"
        value = value.strip()
        try:
            if vector and (value.lower().endswith("f") and "." in value):
                word = struct.unpack("<I", struct.pack("<f", float(value[:-1])))[0]
            elif vector and "." in value:
                word = struct.unpack("<Q", struct.pack("<d", float(value)))[0]
            else:
                word = int(value, 16)
        except (ValueError, struct.error):
            self.status.config(text="\"%s\" is not a value for %s" % (value, name))
            return "break"
        self.debug("reg %s %X" % (name, word))
        return "break"

    def on_data_follow(self, e):
        block = self.shown_block
        if block is None or self.fmt_var.get() != FORMATS[0]:
            return "break"
        off = (int(self.data.index("@%d,%d" % (e.x, e.y)).split(".")[0]) - 1) * 8
        if off + 8 <= len(block["data"]):
            v = struct.unpack_from("<Q", block["data"], off)[0]
            if self.game.in_main(v) and v - self.game.main < self.game.text_size:
                self.goto(v - self.game.main)
            elif v > 0x10000:
                self.mem_var.set("%X" % v)      # a pointer to data: follow it in this panel
                self.on_mem()
        return "break"

    # ------------------------------------------------------------ find, copy, save
    def find_next(self, step):
        needle = self.find_var.get()
        t = self.text
        t.tag_remove("hit", "1.0", "end")
        if not needle:
            return "break"
        row = self.row_of.get(self.cur, 1)
        if step > 0:
            pos = t.search(needle, "%d.end" % row, nocase=True) or t.search(needle, "1.0", nocase=True)
        else:
            pos = t.search(needle, "%d.0" % row, backwards=True, nocase=True)
        if not pos:
            self.status.config(text="\"%s\" is not in this function" % needle)
            return "break"
        t.tag_add("hit", pos, "%s+%dc" % (pos, len(needle)))
        n = int(pos.split(".")[0])
        self.set_cur(self.lines[n - 1]["rva"])
        return "break"

    def plain(self):
        head = "; " + self.title.cget("text")
        return head + "\n" + "\n".join("".join(p for p, _ in self.line_text(l)).rstrip() for l in self.lines) + "\n"

    def copy(self):
        try:
            text = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            text = self.plain()
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self.status.config(text="copied %d lines" % (text.count("\n") + 1))

    def save(self):
        if not self.lines:
            return
        folder = None
        if self.game_dir is not None:
            try:
                folder = self.game_dir("asm")
            except OSError:
                folder = None
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", self.game.name_of(self.start))[:80]
        path = filedialog.asksaveasfilename(parent=self.win, initialdir=folder, defaultextension=".txt",
                                            initialfile="%s_M%X.txt" % (name, self.start),
                                            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.plain())
        except OSError as e:
            messagebox.showerror("Save", str(e), parent=self.win)
            return
        self.status.config(text="saved to " + path)


def main():
    cfg = {}
    try:
        with open(CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    host = sys.argv[1] if len(sys.argv) > 1 else cfg.get("host")
    code = sys.argv[2] if len(sys.argv) > 2 else cfg.get("code")
    if not host or not code:
        sys.exit("usage: pcconnect_asm.py <ip> <code>")
    root = tk.Tk()
    root.withdraw()
    d = Disassembler(root, host, code, cfg)
    d.win.protocol("WM_DELETE_WINDOW", lambda: (d.close(), root.destroy()))
    root.mainloop()
    pcconnect_decomp.exit_process()


if __name__ == "__main__":
    main()
