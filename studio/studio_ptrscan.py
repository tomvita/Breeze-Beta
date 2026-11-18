"""Breeze Studio: pointer chains from main to an address (the host's `ptrscan`), from the Memory tab.

Right-click a row of the Memory tab > Find pointer chains to here. The window:
  * Scan: the host searches backwards from the address, one pass over the game's writable memory
    per level, and lists every chain from main it finds, shortest first ("main+71BAD0 0 E8 +20":
    read [main+71BAD0], then [that + 0], then [that + E8], then add 20).
  * Each chain's row shows where it lands now and the value there (read again every 2 seconds
    while the list has 100 chains or fewer).
  * The chains are kept per game (views/<title id>.ptrscan.txt). After the game is restarted (the
    object moves) find the value again, then Keep only chains to here: the chains that do not land
    on the new address are dropped. Two or three restarts leave the chains the game really uses.
  * through: with an object_names.txt in the game folder (studio_names.py), the class of every
    object the chain passes and the field it ends on ("? > ? > sPlayer+20 coins").
  * Make cheat: the chain as cheat lines that write a value of the chosen type, to copy or to add
    to the game's cheats (on hosts that take cheats).
`ptrscan` is served by the emulator hosts (the core's PC connect server); a console's Breeze
answers it with an unknown-command error.
"""
import os
import re
import struct
import tkinter as tk
from tkinter import ttk

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE_MAX = 100            # chains whose values are read again every 2 seconds
TYPES = {"u8": (1, "<B"), "u16": (2, "<H"), "u32": (4, "<I"), "s32": (4, "<i"), "u64": (8, "<Q"),
         "f32": (4, "<f"), "f64": (8, "<d")}


def parse_chain(text):
    """'main+71BAD0 0 E8 +20' -> (0x71BAD0, [0, 0xE8], 0x20); None when it is not a chain from main."""
    words = text.split()
    m = re.fullmatch(r"(?:main|M)\+([0-9A-Fa-f]+)", words[0]) if words else None
    if not m:
        return None
    reads, last = [], 0
    for w in words[1:]:
        if w.startswith("+"):
            last = int(w[1:], 16)
            break
        reads.append(int(w, 16))
    return int(m.group(1), 16), reads, last


def cheat_lines(name, chain, type_, value):
    """Breeze cheat text for a write of `value` (text) as `type_` through the chain."""
    base, reads, last = parse_chain(chain)
    size, fmt = TYPES[type_]
    v = float(value) if type_.startswith("f") else int(value, 0)
    raw = struct.pack(fmt, v).ljust(8, b"\0")
    word = struct.unpack("<Q", raw)[0]
    out = ["[%s]" % name, "580F00%02X %08X" % (base >> 32, base & 0xFFFFFFFF)]
    for off in reads:
        out.append("580F10%02X %08X" % (off >> 32, off & 0xFFFFFFFF))
    if last:
        out.append("780F0000 %08X" % (last & 0xFFFFFFFF))
    out.append("6%d0F0000 %08X %08X" % (size, word >> 32, word & 0xFFFFFFFF))
    return "\n".join(out) + "\n"


class Window:
    """One pointer-chain window over the Memory tab's connection (its job queue)."""

    def __init__(self, app, address):
        self.app, self.address = app, address
        self.tid = (app.meta.get("title_id") or "game").upper()
        self.path = os.path.join(HERE, "views", "%s.ptrscan.txt" % self.tid)
        self.chains = []                       # chain texts, in order
        self.closed = False
        w = self.win = tk.Toplevel(app.root)
        w.title("Pointer chains")
        w.geometry("900x560")

        bar = ttk.Frame(w, padding=4)
        bar.pack(fill="x")
        ttk.Label(bar, text="Address").pack(side="left")
        self.at = ttk.Entry(bar, width=14)
        self.at.insert(0, "%X" % address)
        self.at.pack(side="left", padx=(2, 8))
        self.opts = {}
        for label, default, width in (("depth", "4", 3), ("max offset", "800", 6), ("chains", "500", 5)):
            ttk.Label(bar, text=label).pack(side="left")
            e = ttk.Entry(bar, width=width)
            e.insert(0, default)
            e.pack(side="left", padx=(2, 8))
            self.opts[label] = e
        ttk.Button(bar, text="Scan", command=self.scan).pack(side="left")
        ttk.Button(bar, text="Keep only chains to here", command=self.keep).pack(side="left", padx=4)
        ttk.Button(bar, text="Make cheat", command=self.make_cheat).pack(side="left")

        self.status = tk.StringVar()
        ttk.Label(w, textvariable=self.status, foreground="#555", padding=(6, 0)).pack(fill="x")

        tf = ttk.Frame(w)
        tf.pack(fill="both", expand=True, padx=4, pady=4)
        cols = ("chain", "lands at", "u32", "f32", "through")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="extended")
        for c, width in zip(cols, (300, 110, 90, 100, 360)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=width, anchor="w")
        sb = ttk.Scrollbar(tf, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-Button-1>", lambda e: self.go())
        m = self.menu = tk.Menu(w, tearoff=0)
        m.add_command(label="Go to where it lands (Memory)", command=self.go)
        m.add_command(label="Make cheat...", command=self.make_cheat)
        m.add_command(label="Copy chain", command=self.copy)
        m.add_command(label="Remove from the list", command=self.remove)
        self.tree.bind("<Button-3>", self.on_menu)
        w.protocol("WM_DELETE_WINDOW", self.close)

        self.load()
        if self.chains:
            self.status.set("%d chains kept from before for %s (%s). Scan for new ones, or find the value "
                            "again and Keep only chains to here." % (len(self.chains), self.tid, self.path))
        else:
            self.status.set("Scan finds the chains from main to %X." % address)
        self.show()
        w.after(500, self.refresh)

    # ------------------------------------------------------------ the list, kept per game
    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                self.chains = [l.strip() for l in f if parse_chain(l.strip())]
        except OSError:
            self.chains = []

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("".join(c + "\n" for c in self.chains))

    def show(self):
        self.tree.delete(*self.tree.get_children())
        for i, c in enumerate(self.chains):
            self.tree.insert("", "end", iid=str(i), values=(c, "", "", "", ""))

    def target(self):
        try:
            return self.app.parse(self.at.get())
        except ValueError:
            self.status.set("Address: hex, M+offset or main+offset")
            return None

    # ------------------------------------------------------------ host calls
    def scan(self):
        at = self.target()
        if at is None:
            return
        try:
            depth, maxoff, count = (int(self.opts["depth"].get()), int(self.opts["max offset"].get(), 16),
                                    int(self.opts["chains"].get()))
        except ValueError:
            self.status.set("depth and chains are numbers, max offset is hex")
            return
        self.status.set("scanning for chains to %X (depth %d, offsets up to %X)..." % (at, depth, maxoff))
        line = "ptrscan %X %d %X %d 300" % (at, depth, maxoff, count)

        def done(reply):
            if self.closed:
                return
            lines = reply.splitlines()
            if not reply.startswith("+OK"):
                self.status.set("ptrscan: %s" % (reply[:200] if "unknown" not in reply else
                                "this host has no ptrscan (it is served by the emulator hosts)"))
                return
            self.chains = [l for l in lines[1:] if parse_chain(l)]
            self.save()
            self.show()
            self.status.set("%s  ->  %d chains, kept in %s" % (lines[0][4:], len(self.chains), self.path))
            self.refresh(once=True)
        self.app.job(lambda: self.app.b.cmd(line), done)

    def lands(self):
        """Where every chain lands now: [(address or None, 8 bytes or None, names)]. names is
        the class of every object a hop reaches and what the end is ("sHud > sPlayer+20 coins"),
        when the game folder has an object_names.txt (studio_names.py)."""
        out, names, b = [], self.app.names, self.app.b
        for c in self.chains:
            reply = b.cmd("chain " + c)
            m = re.search(r"^end ([0-9A-Fa-f]+) \S+: ([0-9A-Fa-f]{16})", reply, re.M)
            if not m:
                out.append((None, None, ""))
                continue
            end, text = int(m.group(1), 16), ""
            if names.rules is not None:
                hops = [int(v, 16) for v in re.findall(r"^\[[^]]*\] = ([0-9A-Fa-f]+)", reply, re.M)]
                seen = [names.class_of(b, v) or "?" for v in hops[:-1]]
                last = names.class_of(b, hops[-1]) if hops else None
                o = (hops[-1], last) if last else names.owner(b, end)
                seen.append(names.describe(o[1], end - o[0]) if o else "?")
                text = " > ".join(seen)
            out.append((end, bytes.fromhex(m.group(2)), text))
        return out

    def refresh(self, once=False):
        if self.closed:
            return
        # every chain is a round trip: a long list is read after a scan or a keep, not every 2 s
        if self.chains and self.app.jobs.empty() and (once or len(self.chains) <= LIVE_MAX):
            chains = list(self.chains)

            def done(result):
                if self.closed or chains != self.chains:
                    return
                for i, (at, raw, through) in enumerate(result):
                    if at is None:
                        vals = (chains[i], "broken", "", "", "")
                    else:
                        f = struct.unpack_from("<f", raw)[0]
                        vals = (chains[i], "%X" % at, str(struct.unpack_from("<I", raw)[0]),
                                "%.6g" % f if f == f else "", through)
                    if self.tree.exists(str(i)):
                        self.tree.item(str(i), values=vals)
            self.app.job(self.lands, done)
        if not once:
            self.win.after(2000, self.refresh)

    def keep(self):
        at = self.target()
        if at is None or not self.chains:
            return
        before = len(self.chains)

        def done(result):
            if self.closed:
                return
            self.chains = [c for c, (where, _raw, _names) in zip(self.chains, result) if where == at]
            self.save()
            self.show()
            self.status.set("kept %d of %d chains: the ones that land on %X now" % (len(self.chains), before, at))
            self.refresh(once=True)
        self.app.job(self.lands, done)

    # ------------------------------------------------------------ a row
    def picked(self):
        return [self.chains[int(i)] for i in self.tree.selection() if int(i) < len(self.chains)]

    def on_menu(self, e):
        row = self.tree.identify_row(e.y)
        if row:
            if row not in self.tree.selection():
                self.tree.selection_set(row)
            self.menu.tk_popup(e.x_root, e.y_root)

    def go(self):
        sel = self.tree.selection()
        if sel:
            at = self.tree.item(sel[0], "values")[1]
            if re.fullmatch(r"[0-9A-Fa-f]+", at or ""):
                self.app.goto(int(at, 16))

    def copy(self):
        text = "\n".join(self.picked())
        if text:
            self.win.clipboard_clear()
            self.win.clipboard_append(text)
            self.status.set("copied")

    def remove(self):
        drop = set(self.picked())
        self.chains = [c for c in self.chains if c not in drop]
        self.save()
        self.show()

    def make_cheat(self):
        chains = self.picked()
        if not chains:
            self.status.set("pick one or more chains first")
            return
        d = tk.Toplevel(self.win)
        d.title("Make cheat")
        f = ttk.Frame(d, padding=6)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Name").grid(row=0, column=0, sticky="w")
        name = ttk.Entry(f, width=40)
        name.insert(0, "New cheat")
        name.grid(row=0, column=1, columnspan=3, sticky="we")
        ttk.Label(f, text="Type").grid(row=1, column=0, sticky="w")
        type_ = ttk.Combobox(f, values=list(TYPES), width=5, state="readonly")
        type_.set("u32")
        type_.grid(row=1, column=1, sticky="w")
        ttk.Label(f, text="Value").grid(row=1, column=2, sticky="e")
        value = ttk.Entry(f, width=16)
        value.insert(0, "0")
        value.grid(row=1, column=3, sticky="w")
        text = tk.Text(f, width=60, height=12, font=("Consolas", 10))
        text.grid(row=2, column=0, columnspan=4, pady=6, sticky="nsew")
        note = tk.StringVar()

        def build(*_a):
            try:
                many = len(chains) > 1
                body = "".join(cheat_lines("%s (%d)" % (name.get(), i + 1) if many else name.get(), c,
                                           type_.get(), value.get()) + "\n" for i, c in enumerate(chains))
            except (ValueError, struct.error) as e:
                note.set("value: %s" % e)
                return None
            note.set("")
            text.delete("1.0", "end")
            text.insert("1.0", body)
            return body

        def copy():
            body = build()
            if body:
                d.clipboard_clear()
                d.clipboard_append(body)
                note.set("copied")

        def add():
            body = build()
            if not body:
                return
            flat = " ".join(body.split())
            self.app.job(lambda: self.app.b.cmd("cheats add " + flat),
                         lambda reply: note.set("cheats add: %s" % reply[:120]))
        for wdg in (name, value):
            wdg.bind("<KeyRelease>", build)
        type_.bind("<<ComboboxSelected>>", build)
        row = ttk.Frame(f)
        row.grid(row=3, column=0, columnspan=4, sticky="w")
        ttk.Button(row, text="Copy", command=copy).pack(side="left")
        ttk.Button(row, text="Add to the game's cheats (off)", command=add).pack(side="left", padx=6)
        ttk.Label(row, textvariable=note, foreground="#555").pack(side="left")
        build()

    def close(self):
        self.closed = True
        self.win.destroy()
