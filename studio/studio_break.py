"""Breeze Studio: Break and trace, a panel of the Watch tab (studio_watch.py builds it).

  Break     a breakpoint on an instruction: the thread that reaches it is held there, with its
            registers and stack. The other threads run on.
  Step      one instruction; Step over runs a call (bl, blr) to its return; Step out runs on until
            the function it is in returns (or, from the call chain, any frame above it).
  Call chain  the held thread's callers, innermost first (lr, then the x29 frames).
  Trace     runs N instructions from the held one and lists each with the registers it changed.

Served by the Lichii fork's probe (probe break / held / step / over / cont / trace / setreg). On a
Switch the same is Breeze's own Gen2 Action menu; a stock emulator has neither.
Python 3 with tkinter only (capstone is used for the instructions when installed).
"""
import struct
import time
import tkinter as tk

import code_modules
import studio_link
from tkinter import ttk

try:
    import capstone
    CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
except Exception:  # noqa: BLE001
    CS = None

REGS = ["x%d" % i for i in range(31)] + ["sp"]


def supported(back):
    """True when the host answers `probe held`."""
    try:
        return back.probe("held")[0].startswith("+OK")
    except Exception:  # noqa: BLE001
        return False


class BreakPanel:
    def __init__(self, app):
        self.app = app
        self.key = None            # (held, seq) of what is shown
        self.held = False
        self.busy = False          # a poll is on its way
        self.breaks = []           # (where, hits, original)
        self.breaks_read = 0.0     # when `break list` was last read
        self.regs, self.last_regs = {}, {}
        self.rows = []             # the trace: one dict of registers (and "pc") per instruction
        self.code_at = []          # the address of each line of the code pane
        self.build()
        app.root.after(500, self.poll)

    # ------------------------------------------------------------------ window
    def build(self):
        a = self.app
        f = self.frame = ttk.Frame(a.nb)
        a.nb.add(f, text="Break and trace")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=3)
        ttk.Label(bar, text="address (hex or M+)").pack(side="left")
        self.entry = ttk.Entry(bar, width=16)
        self.entry.pack(side="left", padx=3)
        self.entry.bind("<Return>", lambda e: self.add_typed())
        ttk.Button(bar, text="Break", command=self.add_typed).pack(side="left")
        ttk.Button(bar, text="Clear all", command=lambda: self.do("break clear")).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        self.when_held = [ttk.Button(bar, text="Continue", command=lambda: self.do("cont")),
                          ttk.Button(bar, text="Step", command=lambda: self.do("step")),
                          ttk.Button(bar, text="Step over", command=lambda: self.do("over")),
                          ttk.Button(bar, text="Step out", command=self.step_out)]
        for b in self.when_held:
            b.pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Label(bar, text="trace").pack(side="left")
        self.count = ttk.Entry(bar, width=6)
        self.count.insert(0, "200")
        self.count.pack(side="left", padx=3)
        ttk.Label(bar, text="instructions").pack(side="left")
        self.over = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="over calls", variable=self.over).pack(side="left", padx=4)
        b = ttk.Button(bar, text="Trace", command=self.trace)
        b.pack(side="left")
        self.when_held.append(b)
        ttk.Button(bar, text="Stop trace", command=lambda: self.do("trace stop")).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        self.reg = ttk.Entry(bar, width=14)
        self.reg.insert(0, "x0=0")
        self.reg.pack(side="left")
        self.reg.bind("<Return>", lambda e: self.set_register())
        b = ttk.Button(bar, text="Set register", command=self.set_register)
        b.pack(side="left", padx=3)
        self.when_held.append(b)
        self.info = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.info, foreground="#245").pack(fill="x", padx=4)

        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.PanedWindow(body, orient="vertical")
        body.add(left, weight=3)
        top = ttk.Frame(left)
        self.break_tree = self.tree(top, ("at", "fn", "hits"), ("breakpoint", "in", "hits"), (110, 380, 60), 5)
        left.add(top, weight=1)
        mid = ttk.Frame(left)
        self.chain_tree = self.tree(mid, ("k", "at", "fn"), ("frame", "returns to", "in"), (50, 130, 400), 6)
        left.add(mid, weight=1)
        self.chain = []            # the held thread's call chain, innermost first
        low = ttk.Frame(left)
        self.trace_tree = self.tree(low, ("n", "at", "fn", "ins", "chg"),
                                    ("#", "address", "in", "instruction", "changed"), (50, 100, 230, 230, 300), 14)
        left.add(low, weight=4)
        self.code = tk.Text(body, width=62, font=("Consolas", 9), wrap="none")
        self.code.tag_configure("here", background="#fe9")
        self.code.tag_configure("brk", foreground="#c00")
        self.code.tag_configure("ret", foreground="#05a")
        self.code.tag_configure("chg", foreground="#c00")
        body.add(self.code, weight=2)

        self.break_tree.bind("<<TreeviewSelect>>", lambda e: self.show_picked(self.break_tree, 0))
        self.trace_tree.bind("<<TreeviewSelect>>", lambda e: self.show_trace_row())
        m = tk.Menu(self.break_tree, tearoff=0)
        m.add_command(label="Remove this breakpoint", command=lambda: self.remove(self.picked(self.break_tree, 0)))
        m.add_command(label="Copy address", command=lambda: self.copy(self.picked(self.break_tree, 0)))
        self.break_tree.bind("<Button-3>", lambda e: a.popup(e, self.break_tree, m))
        m2 = tk.Menu(self.trace_tree, tearoff=0)
        m2.add_command(label="Break here", command=lambda: self.add(self.picked(self.trace_tree, 1)))
        m2.add_command(label="Copy address", command=lambda: self.copy(self.picked(self.trace_tree, 1)))
        self.trace_tree.bind("<Button-3>", lambda e: a.popup(e, self.trace_tree, m2))
        m3 = tk.Menu(self.chain_tree, tearoff=0)
        m3.add_command(label="Step out to here (run until this frame is returned to)", command=self.out_picked)
        m3.add_command(label="Go to (Code)", command=lambda: self.goto(self.picked(self.chain_tree, 1)))
        m3.add_command(label="Break here", command=lambda: self.add(self.picked(self.chain_tree, 1)))
        m3.add_command(label="Copy address", command=lambda: self.copy(self.picked(self.chain_tree, 1)))
        self.chain_tree.bind("<Button-3>", lambda e: a.popup(e, self.chain_tree, m3))
        self.chain_tree.bind("<Double-1>", lambda e: self.goto(self.picked(self.chain_tree, 1)))
        self.code_menu = tk.Menu(self.code, tearoff=0)
        self.code_menu.add_command(label="Break here", command=lambda: self.add(self.code_pick))
        self.code_menu.add_command(label="Remove the breakpoint here", command=lambda: self.remove(self.code_pick))
        self.code_menu.add_command(label="Copy address", command=lambda: self.copy(self.code_pick))
        self.code.bind("<Button-3>", self.code_popup)
        self.code_pick = ""
        self.enable()

    def tree(self, holder, cols, heads, widths, height):
        t = ttk.Treeview(holder, columns=cols, show="headings", selectmode="browse", height=height)
        for c, h, w in zip(cols, heads, widths):
            t.heading(c, text=h)
            t.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(holder, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True)
        return t

    def enable(self):
        for b in self.when_held:
            b.state(["!disabled"] if self.held else ["disabled"])

    def picked(self, tree, column):
        sel = tree.selection()
        return tree.item(sel[0], "values")[column] if sel else ""

    def copy(self, text):
        if text:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(text)

    def code_popup(self, e):
        line = int(self.code.index("@%d,%d" % (e.x, e.y)).split(".")[0]) - 1
        if 0 <= line < len(self.code_at) and self.code_at[line]:
            self.code_pick = self.rel(self.code_at[line])
            self.code_menu.tk_popup(e.x_root, e.y_root)

    # ------------------------------------------------------------------ addresses and code
    def rel(self, a):
        m = self.app.main
        return code_modules.label(getattr(self.app, "mods", []), a) or (
            "M+%X" % (a - m) if m and m <= a < m + 0x40000000 else "%X" % a)

    def name(self, a):
        m = self.app.main
        mod = code_modules.module_of(getattr(self.app, "mods", []), a)
        if mod is not None and mod[0] != "M":
            return ""          # the function map names main only
        return self.app.names.label(a - m) if m and m <= a < m + 0x40000000 else ""

    def goto(self, where):
        """The Code tab at an address of the chain or a list."""
        if not where:
            return
        try:
            a = self.app.addr(where)
        except ValueError:
            return
        self.app.said(studio_link.send(self.app.root, "Code", "goto_address", a) or "Code: %s" % where)

    def out_picked(self):
        sel = self.chain_tree.selection()
        if not sel or not self.held:
            self.app.said("Step out: a thread must be held, and a frame picked")
            return
        self.do("out %d" % self.chain_tree.index(sel[0]))

    def text_of(self, word, at):
        if CS is not None:
            for ins in CS.disasm(struct.pack("<I", word), at):
                return "%-8s %s%s" % (ins.mnemonic, ins.op_str, self.app.target_note(ins))
        return "%08X" % word

    def window(self, a, originals, before=8, after=20):
        """(address, text, tag) for the instructions around a, the one at a marked. A breakpoint's
        line shows the instruction it stands on."""
        data = self.app.client.peek(a - before * 4, (before + after + 1) * 4)
        out = []
        for k in range(0, len(data) - 3, 4):
            at = a - before * 4 + k
            word = originals.get(at, struct.unpack_from("<I", data, k)[0])
            mark = "*" if at in originals else " "
            out.append((at, "%s%-12s %s" % (mark, self.rel(at), self.text_of(word, at)),
                        "here" if at == a else "brk" if at in originals else ""))
        return out

    # ------------------------------------------------------------------ reading the host (worker thread)
    def read(self, force=False):
        probe = self.app.back.probe
        r = probe("held")
        if not r[0].startswith("+OK"):
            return None
        w = r[0].split()
        kv = dict(x.split("=", 1) for x in w[2:] if "=" in x)
        st = {"held": w[1] == "held", "kv": kv, "breaks": [], "fresh": False}
        # The list changes when a breakpoint is set or hit: read it then, and every 5 s besides
        # (each poll reading it filled every client's Activity log).
        seq = (st["held"], kv.get("seq"))
        if force or seq != self.key or time.time() - self.breaks_read > 5:
            self.breaks_read = time.time()
            for l in probe("break list")[1:]:
                p = l.split()
                k = dict(x.split("=", 1) for x in p[1:] if "=" in x)
                st["breaks"].append((p[0], k.get("hits", ""), int(k.get("original", "0"), 16)))
        else:
            st["breaks"] = list(self.breaks)
        st["originals"] = {self.app.addr(x[0]): x[2] for x in st["breaks"]}
        if (st["held"], kv.get("seq")) != self.key or force:
            st["fresh"] = True
            if st["held"] and len(r) >= 3:
                st["regs"] = dict(x.split("=", 1) for x in r[1].split())
                st["stack"] = r[2].split()
                st["code"] = self.window(int(st["regs"]["pc"], 16), st["originals"])
                if kv.get("reason") == "trace":
                    st["trace"] = self.read_trace(st["originals"])
        return st

    def read_trace(self, originals):
        rows, cur = [], {}
        for l in self.app.back.probe("trace list")[1:]:
            p = l.split()
            for x in p[1:]:
                k, v = x.split("=", 1)
                cur[k] = self.app.addr(v) if k == "pc" else int(v, 16)
            rows.append(dict(cur))
        words = {}
        for r in rows:
            pc = r["pc"]
            if pc not in words:
                d = self.app.client.peek(pc, 4)
                words[pc] = originals.get(pc, struct.unpack("<I", d)[0] if len(d) == 4 else 0)
            r["text"] = self.text_of(words[pc], pc)
        return rows

    # ------------------------------------------------------------------ following the host
    def shown(self):
        a = self.app
        return bool(a.nb.tabs()) and a.nb.nametowidget(a.nb.select()) is self.frame and a.root.winfo_viewable()

    def poll(self):
        a = self.app
        if a.closed:
            return
        if a.back and not self.busy and a.work.empty() and self.shown():
            self.refresh()
        a.root.after(500, self.poll)

    def refresh(self, force=False):
        self.busy = True

        def done(st):
            self.busy = False
            if st is not None:
                self.show(st)
        self.app.work.put((lambda: self.guarded(force), done))

    def guarded(self, force):
        try:
            return self.read(force)
        except Exception:  # noqa: BLE001 - the next poll tries again
            self.busy = False
            raise

    def show(self, st):
        kv = st["kv"]
        self.held = st["held"]
        self.enable()
        if st["breaks"] != self.breaks:
            self.breaks = st["breaks"]
            self.break_tree.delete(*self.break_tree.get_children())
            for where, hits, _o in self.breaks:
                self.break_tree.insert("", "end", values=(where, self.name(self.app.addr(where)), hits))
        if self.held:
            self.info.set("HELD at %s  %s   thread %s (%s). The other threads run on; Continue lets this one go."
                          % (kv.get("pc", ""), self.name(self.app.addr(kv.get("pc", "0"))), kv.get("thread", ""),
                             kv.get("reason", "")))
        elif kv.get("tracing") == "1":
            self.info.set("tracing: %s instructions so far" % kv.get("rows", "?"))
        else:
            self.info.set("the game runs%s" % (": %d breakpoint(s) set" % len(self.breaks) if self.breaks else
                                               ". Set a breakpoint: type an address, or right-click a row in the "
                                               "other lists"))
        if not st["fresh"]:
            return
        self.key = (st["held"], kv.get("seq"))
        if not self.held:
            return
        self.last_regs, self.regs = self.regs, st["regs"]
        self.draw(st["code"], self.regs, self.last_regs, st["stack"])
        self.fill_chain(kv.get("bt", "-"), kv.get("pc", ""))
        if "trace" in st:
            self.fill_trace(st["trace"])

    def draw(self, code, regs, before, stack):
        self.code.delete("1.0", "end")
        self.code_at = []
        for at, text, tag in code:
            self.code.insert("end", text + "\n", tag)
            self.code_at.append(at)
        self.code.insert("end", "\n")
        names = [n for n in REGS + ["pc", "pstate"] if n in regs]
        for i in range(0, len(names), 3):
            for n in names[i:i + 3]:
                v = regs[n] if isinstance(regs[n], str) else "%X" % regs[n]
                old = before.get(n)
                old = old if old is None or isinstance(old, str) else "%X" % old
                self.code.insert("end", "%-22s" % ("%s=%s" % (n, v)), "chg" if old is not None and old != v else "")
            self.code.insert("end", "\n")
        self.code.insert("end", "\n")
        for x in stack:
            where = x.split("=", 1)[1]
            fn = self.name(self.app.addr(where)) if where.startswith("M+") else ""
            self.code.insert("end", x + ("   " + fn if fn else "") + "\n", "ret" if "=M+" in x else "")

    def same_function(self, a, pc):
        """True when a return address lies in the function the thread is in: lr left over from a
        call that function already made (it is not a caller), or the place a step out landed."""
        if a is None or pc is None:
            return False
        if a == pc:
            return True
        here, there = self.name(pc).split("+")[0], self.name(a).split("+")[0]
        return bool(here) and here == there

    def fill_chain(self, bt, pc_text=""):
        t = self.chain_tree
        t.delete(*t.get_children())
        self.chain = [] if bt in ("", "-") else bt.split(",")
        try:
            pc = self.app.addr(pc_text) if pc_text else None
        except ValueError:
            pc = None
        self.out_frame = 0
        for k, where in enumerate(self.chain):
            try:
                a = self.app.addr(where)
            except ValueError:
                a = None
            shown = self.rel(a) if a is not None else where
            name = self.name(a) if a is not None else ""
            if k == self.out_frame and self.same_function(a, pc) and k + 1 < len(self.chain):
                self.out_frame = k + 1
                name = "(this function: the return of a call it already made - not a caller)  " + name
            t.insert("", "end", values=(k, shown, name))

    def step_out(self):
        """Runs until the function the thread is in returns: the first frame of the chain that is
        not in this function (lr may still hold the return of a call this function made)."""
        self.do("out %d" % getattr(self, "out_frame", 0))

    def fill_trace(self, rows):
        self.rows = rows
        t = self.trace_tree
        t.delete(*t.get_children())
        for i, r in enumerate(rows):
            chg = ""
            if i + 1 < len(rows):
                nxt = rows[i + 1]
                chg = "  ".join("%s=%X" % (n, nxt[n]) for n in REGS if n in nxt and nxt[n] != r.get(n))
            t.insert("", "end", values=(i, self.rel(r["pc"]), self.name(r["pc"]), r["text"], chg))
        self.app.said("trace: %d instructions. Each row shows what its instruction changed." % len(rows))

    def show_trace_row(self):
        sel = self.trace_tree.selection()
        if not sel:
            return
        i = self.trace_tree.index(sel[0])
        if i >= len(self.rows):
            return
        row, before = self.rows[i], self.rows[i - 1] if i else {}
        originals = {self.app.addr(x[0]): x[2] for x in self.breaks}
        self.app.run(lambda: self.window(row["pc"], originals),
                     lambda code: self.draw(code, {n: row[n] for n in REGS if n in row},
                                            {n: before[n] for n in REGS if n in before}, []))

    def show_picked(self, tree, column):
        where = self.picked(tree, column)
        if not where or self.held:
            return
        originals = {self.app.addr(x[0]): x[2] for x in self.breaks}
        self.app.run(lambda: self.window(self.app.addr(where), originals), lambda code: self.draw(code, {}, {}, []))

    # ------------------------------------------------------------------ commands
    def do(self, command, force=False):
        if not self.app.back:
            return

        def done(r):
            self.app.said(r)
            self.refresh(force)
        self.app.run(lambda: self.app.back.probe(command)[0], done)

    def add(self, where):
        """A breakpoint at an address ("M+958DA4" or hex). (The other lists call this.)"""
        try:
            self.app.addr(where.split()[0])
        except (ValueError, IndexError, AttributeError):
            self.app.said("not an address: %r" % (where,))
            return
        self.app.nb.select(self.frame)
        self.do("break add " + where.split()[0], force=True)

    def add_typed(self):
        self.add(self.entry.get().strip())

    def remove(self, where):
        if where:
            self.do("break remove " + where, force=True)

    def trace(self):
        try:
            n = int(self.count.get().strip())
        except ValueError:
            self.app.said("trace: how many instructions?")
            return
        self.do("trace %d%s" % (n, " over" if self.over.get() else ""))

    def set_register(self):
        t = self.reg.get().replace(" ", "")
        if "=" not in t:
            self.app.said("write it as x0=1F (x0..x30, sp or pc; the value in hex)")
            return
        name, value = t.split("=", 1)
        self.do("setreg %s %s" % (name.lower(), value), force=True)
