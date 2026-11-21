"""Breeze Studio: the game's memory at an address, as Breeze's Memory Explorer shows it.

    python studio_memory.py [host[:port]] [code] [address]

  * Address: hex, M+offset or main+offset. Go; Back returns to where you were.
  * Each row is one value of the chosen size (1, 2, 4 or 8 bytes): its bytes as a number in
    hex, as a signed integer, as a float (4 and 8 bytes), and - on an 8-aligned address - as a
    pointer, when the 8 bytes there point into the game's memory.
  * Double-click a row to follow its pointer, or to change the value when it is not one.
  * Right-click: Follow pointer, Edit value, Hold / Unhold, Copy address, Who points here,
    Find pointer chains to here (studio_ptrscan.py: chains from main, kept per game, Make cheat),
    Label this field (field_annotations.txt in the game's folder).
  * A game whose engine Studio does not know can name its objects: object_names.txt in the game's
    folder (studio_names.py). Then the where column says "sPlayer+20 coins" and a pointer to an
    object shows its class.
    Watch this address (the Watch tab), Add to bookmarks, Field view (the Objects tab on the
    object that holds the address).
  * live values reads the page again every second.

Python 3 with tkinter only.
"""
import bisect
import os
import queue
import re
import struct
import sys
import threading
import tkinter as tk
from tkinter import simpledialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from pcconnect import Breeze, game_caption  # noqa: E402
import studio_link  # noqa: E402
import studio_names  # noqa: E402

PAGE = 0x400              # bytes shown
INT = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
UINT = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}
BOOKMARK = {1: "u8", 2: "u16", 4: "s32", 8: "u64"}


def parse_value(text, size):
    """A typed value as `size` bytes: 0x.. hex, a number with a point as a float, else an integer."""
    t = text.strip()
    if size in (4, 8) and re.fullmatch(r"-?(\d+\.\d*|\.\d+|\d+(\.\d*)?[eE]-?\d+)", t):
        return struct.pack("<f" if size == 4 else "<d", float(t))
    v = int(t, 0)
    return struct.pack(INT[size] if v < 0 else UINT[size], v)


class App:
    def __init__(self, root, address, code, start=None):
        self.root, self.address, self.code = root, address, code
        self.b, self.meta = None, {}
        self.main = self.main_size = 0
        self.regions, self.region_starts = [], []
        self.start, self.data, self.history = 0, b"", []
        self.want = None           # the address to pick once the page is shown
        self.names = studio_names.GameNames()
        self.page_ptrs, self.page_heads = {}, []   # this page's named pointers and objects
        self.jobs, self.out = queue.Queue(), queue.Queue()
        self.stop = self.reading = False
        root.title("Memory")
        root.geometry("1100x800")

        bar = ttk.Frame(root, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Back", command=self.back).pack(side="left")
        ttk.Label(bar, text="Address").pack(side="left", padx=(10, 2))
        self.at = ttk.Entry(bar, width=18)
        self.at.pack(side="left")
        self.at.bind("<Return>", lambda e: self.go_typed())
        ttk.Button(bar, text="Go", command=self.go_typed).pack(side="left", padx=4)
        ttk.Button(bar, text="< Page", command=lambda: self.show(self.start - PAGE)).pack(side="left")
        ttk.Button(bar, text="Page >", command=lambda: self.show(self.start + PAGE)).pack(side="left", padx=(2, 10))
        ttk.Label(bar, text="value size").pack(side="left")
        self.size = ttk.Combobox(bar, values=["1", "2", "4", "8"], width=3, state="readonly")
        self.size.set("4")
        self.size.pack(side="left", padx=2)
        self.size.bind("<<ComboboxSelected>>", lambda e: self.fill())
        self.live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="live values", variable=self.live).pack(side="left", padx=10)
        self.status = tk.StringVar(value="connecting...")
        ttk.Label(bar, textvariable=self.status, foreground="#555").pack(side="left", padx=8)

        tf = ttk.Frame(root)
        tf.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        cols = ("address", "where", "hex", "integer", "float", "pointer", "text")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (120, 130, 150, 170, 150, 220, 90)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(tf, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-Button-1>", self.on_double)
        self.tree.bind("<Button-3>", self.on_menu)

        m = self.menu = tk.Menu(root, tearoff=0)
        m.add_command(label="Follow pointer", command=self.follow)
        m.add_command(label="Edit value...", command=self.edit)
        m.add_command(label="Hold at its value", command=lambda: self.hold(True))
        m.add_command(label="Unhold", command=lambda: self.hold(False))
        m.add_command(label="Who points here", command=self.who)
        m.add_command(label="Find pointer chains to here...", command=self.ptrscan)
        m.add_command(label="Label this field...", command=self.label_field)
        m.add_command(label="Add to bookmarks", command=self.bookmark)
        m.add_command(label="Field view of what it points at", command=lambda: self.link("Objects", "field_view", self.pointer_at(self.picked())))
        # The places every tab can take an address (studio_link.address_menu).
        studio_link.address_menu(self.root, m, self.picked, self.status.set, size=lambda: int(self.size.get()),
                                 skip=("Memory",))

        threading.Thread(target=self.worker, daemon=True).start()
        self.job(lambda: None, lambda _r: self.connected())
        if start is not None:
            self.goto(start)
        root.after(50, self.pump)
        root.after(1000, self.tick)
        root.protocol("WM_DELETE_WINDOW", self.close)

    # ------------------------------------------------------------ plumbing
    def worker(self):
        while not self.stop:
            fn, done = self.jobs.get()
            if fn is None:
                break
            try:
                if self.b is None:
                    self.open()
                self.out.put((done, fn(), None))
            except Exception as e:  # noqa: BLE001 - shown in the status line
                self.out.put((done, None, e))
                if isinstance(e, (OSError, ConnectionError)) and self.b is not None:
                    self.b.close()
                    self.b = None
        if self.b is not None:
            self.b.close()

    def open(self):
        self.b = Breeze(self.address, self.code, timeout=30, connect_timeout=5)
        self.meta = self.b.json("meta")
        self.main, self.main_size = int(self.meta["main"], 16), int(self.meta["main_size"], 16)
        regions = []
        for line in self.b.cmd("maps").splitlines():
            m = re.match(r"([0-9A-Fa-f]+) ([0-9A-Fa-f]+) ", line)
            if m:
                regions.append((int(m.group(1), 16), int(m.group(2), 16)))
        regions.sort()
        self.regions, self.region_starts = regions, [r[0] for r in regions]
        self.names.mapped = self.mapped
        self.names.load(self.b)

    def job(self, fn, done):
        self.jobs.put((fn, done))

    def pump(self):
        if self.stop:
            return
        try:
            while True:
                done, result, error = self.out.get_nowait()
                if error is not None:
                    self.reading = False
                    self.status.set("%s: %s" % (type(error).__name__, str(error)[:160]))
                elif done is not None:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(50, self.pump)

    def tick(self):
        if self.stop:
            return
        if self.live.get() and self.data and self.jobs.empty() and not self.reading and self.root.winfo_viewable():
            self.read(self.start, quiet=True)
        self.root.after(1000, self.tick)

    def close(self):
        self.stop = True
        self.jobs.put((None, None))
        self.root.destroy()

    def connected(self):
        if not self.data:
            self.status.set(studio_link.joined(studio_link.caption(self.root, self.meta),
                                               "type an address: hex, M+offset", self.names.note))
            if self.want is None:
                self.goto(self.main)

    # ------------------------------------------------------------ the page
    def parse(self, text):
        t = text.strip().replace(" ", "")
        m = re.fullmatch(r"(?:M|main)\+(?:0x)?([0-9A-Fa-f]+)", t, re.I)
        if m:
            return self.main + int(m.group(1), 16)
        return int(t, 16)

    def go_typed(self):
        try:
            self.goto(self.parse(self.at.get()))
        except ValueError:
            self.status.set("Address: hex, M+offset or main+offset")

    def goto(self, address):
        """Shows the page that holds the address, with its row picked. (Other tabs call this.)"""
        if self.data:
            self.history.append((self.start, self.picked()))
        self.want = address
        self.show((address & ~0xF) - 0x40, keep=True)

    def back(self):
        if self.history:
            start, picked = self.history.pop()
            self.want = picked
            self.show(start, keep=True)

    def show(self, start, keep=False):
        if not keep:
            self.want = None
        self.read(max(start, 0))

    def read(self, start, quiet=False):
        self.reading = True

        def fn():
            data = self.b.peek(start, PAGE)
            return start, data, self.names.page(self.b, start, data)

        def done(r):
            self.reading = False
            if quiet and r[0] != self.start:
                return
            fresh = r[0] != self.start or not self.data
            self.start, self.data = r[0], r[1]
            self.page_ptrs, self.page_heads = r[2]
            if fresh:
                self.fill()
            else:
                self.update()
        self.job(fn, done)

    def where(self, address):
        if self.main <= address < self.main + self.main_size:
            return "main+%X" % (address - self.main)
        o = self.object_at(address)
        return self.names.describe(o[1], address - o[0]) if o else ""

    def objects_at(self, address):
        """Every (object, class) this page's names put the address in, nearest first."""
        if not self.names.rules or address is None:
            return []
        back = self.names.rules["back"]
        return [h for h in reversed(self.page_heads) if h[0] <= address and address - h[0] <= back]

    def object_at(self, address):
        """The (object, class) that describes the address best, or None."""
        return self.names.best(self.objects_at(address), address)

    def mapped(self, address):
        i = bisect.bisect_right(self.region_starts, address) - 1
        return i >= 0 and address < self.regions[i][0] + self.regions[i][1]

    def values(self, off, size):
        raw = self.data[off:off + size]
        at = self.start + off
        if len(raw) < size:
            return None
        u = struct.unpack(UINT[size], raw)[0]
        number = struct.unpack(INT[size], raw)[0]
        fl = ""
        if size in (4, 8):
            f = struct.unpack("<f" if size == 4 else "<d", raw)[0]
            fl = "%.7g" % f if f == f and (f == 0 or 1e-6 < abs(f) < 1e12) else ""
        ptr = ""
        if not at & 7 and off + 8 <= len(self.data):
            p = struct.unpack_from("<Q", self.data, off)[0]
            if p >= 0x10000 and not p & 3 and self.mapped(p):
                ptr = "-> %X  %s" % (p, self.where(p) if self.where(p).startswith("main") else "")
                if p in self.page_ptrs:
                    ptr += self.page_ptrs[p]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in self.data[off:off + max(size, 4)])
        return ("%X" % at, self.where(at), "%0*X" % (size * 2, u), str(number), fl, ptr, text)

    def fill(self):
        size = int(self.size.get())
        picked = self.want if self.want is not None else self.picked()
        self.tree.delete(*self.tree.get_children())
        for off in range(0, len(self.data) - size + 1, size):
            v = self.values(off, size)
            if v:
                self.tree.insert("", "end", iid=str(off), values=v)
        if picked is not None and self.start <= picked < self.start + len(self.data):
            iid = str((picked - self.start) // size * size)
            if self.tree.exists(iid):
                self.tree.selection_set(iid)
                self.tree.see(iid)
        if self.want is not None:
            self.at.delete(0, "end")
            self.at.insert(0, "%X" % self.want)
        self.want = None
        self.status.set(studio_link.joined(studio_link.caption(self.root, self.meta), "%X .. %X  %s" % (
            self.start, self.start + len(self.data) - 1, self.where(self.start))))

    def update(self):
        size = int(self.size.get())
        for off in range(0, len(self.data) - size + 1, size):
            if self.tree.exists(str(off)):
                v = self.values(off, size)
                if v and tuple(self.tree.item(str(off), "values")) != v:
                    self.tree.item(str(off), values=v)

    # ------------------------------------------------------------ a row
    def picked(self):
        sel = self.tree.selection()
        return self.start + int(sel[0]) if sel else None

    def pointer_at(self, address):
        if address is None:
            return None
        off = (address & ~7) - self.start
        if 0 <= off <= len(self.data) - 8:
            p = struct.unpack_from("<Q", self.data, off)[0]
            return p if self.mapped(p) else None
        return None

    def on_double(self, e):
        if not self.tree.identify_row(e.y):
            return
        if self.pointer_at(self.picked()) is not None and not self.picked() & 7:
            self.follow()
        else:
            self.edit()

    def on_menu(self, e):
        row = self.tree.identify_row(e.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(e.x_root, e.y_root)

    def follow(self):
        p = self.pointer_at(self.picked())
        if p is None:
            self.status.set("the 8 bytes here do not point into the game's memory")
        else:
            self.goto(p)

    def edit(self):
        at, size = self.picked(), int(self.size.get())
        if at is None:
            return
        now = self.tree.item(self.tree.selection()[0], "values")
        text = simpledialog.askstring("Edit", "%d bytes at %X (0x.. for hex, a point for a float):" % (size, at),
                                      initialvalue=now[4] if now[4] and "." in now[4] else now[3], parent=self.root)
        if text is None:
            return
        try:
            data = parse_value(text, size)
        except (ValueError, struct.error):
            self.status.set("not a value of %d bytes: %s" % (size, text))
            return
        self.job(lambda: self.b.cmd("poke %X %s" % (at, data.hex())),
                 lambda reply: (self.status.set("poke %X: %s" % (at, reply)), self.read(self.start, quiet=True)))

    def hold(self, on):
        at = self.picked()
        if at is not None:
            line = "hold %X %d" % (at, int(self.size.get())) if on else "unhold %X" % at
            self.job(lambda: self.b.cmd(line), lambda reply: self.status.set("%s: %s" % (line, reply)))

    def copy(self):
        at = self.picked()
        if at is not None:
            self.root.clipboard_clear()
            self.root.clipboard_append("%X" % at)
            self.status.set("copied %X" % at)

    def link(self, tab, method, *args):
        if args and args[0] is None:
            self.status.set("nothing to open: pick a row (for the pointer: one that points into the game)")
            return
        note = studio_link.send(self.root, tab, method, *args)
        if note:
            self.status.set(note)

    def watch(self):
        at = self.picked()
        if at is not None:
            self.link("Watch", "watch_address", at, int(self.size.get()))

    def bookmark(self):
        at, size = self.picked(), int(self.size.get())
        tid = (self.meta.get("title_id") or "").upper()
        if at is None or not tid:
            return
        name = simpledialog.askstring("Bookmark", "Name:", parent=self.root)
        if not name:
            return
        type_ = "f32" if size == 4 and self.tree.item(self.tree.selection()[0], "values")[4] else BOOKMARK[size]
        path = studio_link.add_bookmarks(tid, [(name, self.where(at) or "%X" % at, type_)])
        self.status.set("bookmarked %s as %s in %s%s" % (name, type_, path,
                        "" if self.where(at) else "  (a plain address: it holds for this run of the game only)"))

    def who(self):
        """Every place that points at the picked address, in a list; double-click goes there."""
        at = self.picked()
        if at is None:
            return
        self.status.set("looking for who points at %X..." % at)

        def done(reply):
            lines = reply.splitlines()
            if not reply.startswith("+OK"):
                self.status.set("refs: %s" % reply[:160])
                return
            self.status.set(lines[0][4:])
            win = tk.Toplevel(self.root)
            win.title("Who points at %X" % at)
            box = tk.Listbox(win, width=70, height=min(max(len(lines) - 1, 4), 30), font=("Consolas", 10))
            box.pack(fill="both", expand=True)
            for line in lines[1:]:
                box.insert("end", line)
            if len(lines) == 1:
                box.insert("end", "nothing in writable memory points at it")

            def go(_e):
                sel = box.curselection()
                m = re.match(r"([0-9A-Fa-f]+) ", box.get(sel[0])) if sel else None
                if m:
                    self.goto(int(m.group(1), 16))
            box.bind("<Double-Button-1>", go)
        self.job(lambda: self.b.cmd("refs %X 0 200 30" % at), done)

    def label_field(self):
        """Names the picked field of a named object, in field_annotations.txt (Breeze reads it too)."""
        at, size = self.picked(), int(self.size.get())
        objs = self.objects_at(at)
        if not objs:
            self.status.set("no named object here: the game folder needs an object_names.txt that "
                            "names this object (see studio_names.py)")
            return
        floaty = size == 4 and self.tree.item(self.tree.selection()[0], "values")[4]
        hint = "f32" if floaty else {1: "u8", 2: "u16", 4: "u32", 8: "u64"}[size]
        d = tk.Toplevel(self.root)
        d.title("Label this field")
        f = ttk.Frame(d, padding=8)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Field of").grid(row=0, column=0, sticky="w")
        # an object can hold others inline: the field can be named in any of them
        choices = ["%s+%X" % (cls, at - obj) for obj, cls in objs]
        best = self.names.best(objs, at)
        which = ttk.Combobox(f, values=choices, width=34, state="readonly")
        which.current(objs.index(best))
        which.grid(row=0, column=1, sticky="w")
        ttk.Label(f, text="Label").grid(row=1, column=0, sticky="w")
        name = ttk.Entry(f, width=36)
        name.grid(row=1, column=1, sticky="w")
        ttk.Label(f, text="Type").grid(row=2, column=0, sticky="w")
        type_ = ttk.Combobox(f, values=["u8", "u16", "u32", "s32", "u64", "f32", "f64", "ptr"], width=6)
        type_.set(hint)
        type_.grid(row=2, column=1, sticky="w")
        ttk.Label(f, text="An empty label removes it. Breeze's field views read the same file.",
                  foreground="#555").grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

        def pick(_e=None):
            obj, cls = objs[which.current()]
            name.delete(0, "end")
            name.insert(0, self.names.label(cls, at - obj))
        which.bind("<<ComboboxSelected>>", pick)
        pick()

        def save():
            obj, cls = objs[which.current()]
            off, label, h = at - obj, name.get().strip(), type_.get().strip() or hint
            d.destroy()
            self.job(lambda: self.names.save_label(self.b, cls, off, label, h),
                     lambda _r: (self.status.set("%s+%X %s in %sfield_annotations.txt" % (
                         cls, off, ("= " + label) if label else "label removed", self.names.dir)), self.fill()))
        ttk.Button(f, text="Save", command=save).grid(row=4, column=1, sticky="e", pady=(6, 0))
        name.bind("<Return>", lambda _e: save())
        name.focus_set()

    def ptrscan(self):
        """The pointer chains from main to the picked address, in a window of their own."""
        at = self.picked()
        if at is not None:
            import studio_ptrscan
            studio_ptrscan.Window(self, at)

    def ptrscan_address(self, address):
        """The pointer chains to an address another tab hands over (studio_link.address_menu)."""
        self.goto(address)
        import studio_ptrscan
        studio_ptrscan.Window(self, address)


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "1234"
    start = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    root = tk.Tk()
    App(root, address, code, start)
    root.mainloop()


if __name__ == "__main__":
    main()
