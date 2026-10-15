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
from tkinter import filedialog, messagebox

import capstone
from capstone import arm64_const as A

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcconnect import Breeze  # noqa: E402
import pcconnect_decomp  # noqa: E402
from pcconnect_decomp import CPane  # noqa: E402

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
        self.heap, self.heap_size = int(g["heap"], 16), int(g["heap_size"], 16)
        self.pages = {}
        self.bp_words = {}           # main offset -> the instruction a breakpoint replaced, every one seen
        self.text_size = self.find_text()
        self.dir = ""
        self.title = ""
        self.starts, self.names, self.source = [], {}, "no function list"
        self.load_functions()

    def find_text(self):
        """The size of the code region main starts with."""
        for line in self.b.cmd("maps").split("\n")[1:]:
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
        f = self.func_of(rva) if rva < self.text_size else None
        if f is None:
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
            start, end = max(rva - 0x40, 0), rva + 0x400
            title = "M+%X (no function here)" % rva
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
            if start <= at < end - 3 and struct.unpack_from("<I", code, at - start)[0] == BREAK_WORD:
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
                line["ops"] = line["ops"].replace("#0x%x" % ops[-1].imm, "M+%X" % target)
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
            if rva <= at < rva + len(data) - 3 and struct.unpack_from("<I", data, at - rva)[0] == BREAK_WORD:
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
        when asked) when the game is stopped."""
        reply = self.b.cmd(("dbg " + args).strip())
        if not reply.startswith("+OK"):
            raise RuntimeError(reply[5:] if reply.startswith("-ERR ") else reply)
        st = json.loads(reply[4:])
        if "status" in st:
            st = st["status"]
        for bp in st.get("bps", []):
            at = int(bp["at"], 16) - self.main
            word = int(bp["word"], 16)
            if word != BREAK_WORD and word != 0:
                self.bp_words[at] = word
        st["stack"] = self.block(int(st["sp"], 16)) if st.get("stopped") else None
        if st.get("stopped") and vectors:
            reply = self.b.cmd("dbg v")
            if reply.startswith("+OK"):
                st.update(json.loads(reply[4:]))
        return st

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
        size = int(self.cfg.get("asm_font", 11))
        self.font = ("Consolas", size)

        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        tk.Label(bar, text=" Go:").pack(side="left")
        self.go_var = tk.StringVar()
        self.go = tk.Entry(bar, width=30, textvariable=self.go_var)
        self.go.pack(side="left")
        self.go.bind("<Return>", lambda e: self.on_go())
        for text, cmd in (("Back", lambda: self.step(-1)), ("Forward", lambda: self.step(1)),
                          ("Func up", lambda: self.neighbour(-1)), ("Func down", lambda: self.neighbour(1)),
                          ("Callers", self.on_callers), ("Reload", self.on_reload), ("Decompile F6", self.toggle_c)):
            tk.Button(bar, text=text, command=cmd, takefocus=0).pack(side="left")
        tk.Label(bar, text="  Find:").pack(side="left")
        self.find_var = tk.StringVar()
        self.find = tk.Entry(bar, width=18, textvariable=self.find_var)
        self.find.pack(side="left")
        self.find.bind("<Return>", lambda e: self.find_next(1))
        self.find.bind("<Shift-Return>", lambda e: self.find_next(-1))
        tk.Button(bar, text="Copy", command=self.copy, takefocus=0).pack(side="left", padx=(8, 0))
        tk.Button(bar, text="Save...", command=self.save, takefocus=0).pack(side="left")
        tk.Label(bar, text="  Font:").pack(side="left")
        self.font_var = tk.StringVar(value=str(size))
        tk.Spinbox(bar, from_=6, to=40, width=3, textvariable=self.font_var, command=self.set_font).pack(side="left")
        self.bytes_var = tk.BooleanVar(value=bool(self.cfg.get("asm_bytes", True)))
        tk.Checkbutton(bar, text="Words", variable=self.bytes_var, command=self.render, takefocus=0).pack(side="left")

        dbar = tk.Frame(self.win)
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
        tf = tk.Frame(mid)
        tf.pack(fill="both", expand=True)
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
        self.win.bind("<Control-f>", lambda e: (self.find.focus_set(), self.find.select_range(0, "end")))
        self.win.bind("<Control-g>", lambda e: (self.go.focus_set(), self.go.select_range(0, "end")))
        self.win.bind("<F3>", lambda e: self.find_next(1))
        self.win.bind("<F9>", lambda e: self.on_break())
        self.win.bind("<F4>", lambda e: self.on_runto())
        self.win.bind("<F11>", lambda e: self.debug("step"))
        self.win.bind("<F10>", lambda e: (self.debug("over"), "break")[1])
        self.win.bind("<F5>", lambda e: self.debug("cont"))
        self.win.bind("<F6>", lambda e: self.toggle_c())
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        self.worker = Worker(host, code)
        self.worker.start()
        self.job(lambda g: g, self.on_game, "reading the game's function list...")
        self.win.after(40, self.pump)
        self.win.after(600, self.poll)

    # ------------------------------------------------------------ plumbing
    def alive(self):
        return self.win.winfo_exists()

    def close(self):
        self.cfg["asm_geometry"] = self.win.geometry()
        self.cfg["asm_bytes"] = bool(self.bytes_var.get())
        self.cfg["asm_c_open"] = self.c_open
        if self.c_open:
            self.cfg["asm_c_width"] = self.cpane.frame.winfo_width()
        self.save_cfg()
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
        self.win.title("Breeze disassembler - %s" % (game.title or game.tid))
        self.status.config(text="%s %s  main %X  code %X bytes  |  %d functions: %s" % (
            game.tid, game.bid, game.main, game.text_size, len(game.starts), game.source))
        self.fill_list()
        last = self.cfg.get("asm_last", {}).get(game.bid)
        self.goto(last if last is not None and last < game.text_size else (game.starts[0] if game.starts else 0))
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
        """An address typed into Go: a main offset, or None when it is not one."""
        g = self.game
        t = text.strip().replace("main+", "").replace("M+", "").replace("m+", "")
        if t.lower().startswith("0x"):
            t = t[2:]
        if not re.fullmatch(r"[0-9A-Fa-f]+", t):
            return None
        v = int(t, 16)
        if g.main <= v < g.main + g.main_size:
            return v - g.main
        return v if v < g.main_size else None

    def on_go(self):
        g = self.game
        if g is None:
            return
        text = self.go_var.get().strip()
        rva = self.parse(text)
        if rva is None:
            words = text.lower().split()
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
        if rva >= g.text_size:
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
        self.job(lambda game: game.view(rva), lambda r: self.show(r, rva), "reading M+%X..." % rva)

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
        parts = [("%s M+%-7X" % (">" if line["label"] else " ", line["rva"]), "label" if line["label"] else "addr")]
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
        self.go_var.set("M+%X" % self.cur)
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

    # ------------------------------------------------------------ the debugger
    def poll(self):
        """Asks where the game stands, a few times a second, one question at a time."""
        if not self.alive():
            return
        if self.game is not None and not self.poll_out and self.busy == 0:
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
            self.debug("bp M+%X" % self.cur)
        return "break"

    def on_runto(self):
        if self.cur is not None:
            self.debug("runto M+%X" % self.cur)
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
