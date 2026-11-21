"""Breeze Studio: the Workbench, one address followed from the value to the code that changes it.

    python studio_workbench.py [host] [code] [port] [address]

The steps of making a cheat in one window, for one address:

  top     the value at the address, live: Edit, Hold, Bookmark, and the other tabs
  left    who reads or writes it: the host's data watch (gen2 on a Switch, the probe on the
          Lichii fork and emuhost), the same list the Watch tab shows
  right   the instruction picked on the left with the code around it: Open in Code,
          Patch this instruction..., Hook here...
  bottom  the cheats that write the address, or the picked instruction

Every tab's right-click menu has "Work on this address" (studio_link.address_menu), which opens
it here. Python 3 with tkinter; capstone for the instructions.
"""
import json
import os
import queue
import struct
import sys
import threading
import tkinter as tk
from tkinter import simpledialog, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import cheat_disasm  # noqa: E402
import code_modules  # noqa: E402
import code_patch  # noqa: E402
import studio_link  # noqa: E402
import studio_watch  # noqa: E402
from pcconnect import Breeze  # noqa: E402

AROUND = 8      # instructions shown before and after the picked one


def split_address(address):
    name, sep, tail = address.rpartition(":")
    if sep and tail.isdigit() and ":" not in name:
        return name, int(tail)
    return address, 6801


class Game:
    """What the cheat makers (patch_maker, hook_maker) take as the game."""

    def __init__(self, b, main, text_size):
        self.b, self.main, self.text_size = b, main, text_size


class App:
    def __init__(self, root, address, code):
        self.root, self.address, self.code = root, address, code
        self.host, self.port = split_address(address)
        self.b = self.back = self.game = None
        self.meta, self.main, self.mods = {}, 0, []
        self.at, self.size = None, 4
        self.rows, self.ins_at, self.exec_ranges = [], None, []
        self.work, self.ui = queue.Queue(), queue.Queue()
        self.busy = False
        self.closed = False
        self.asked = None
        root.title("Workbench")
        root.geometry("1280x860")

        # ---- top: the address and its value
        top = ttk.Frame(root, padding=(6, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Address (hex or M+)").pack(side="left")
        self.addr_var = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.addr_var, width=20)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda _e: self.on_go())
        self.size_var = tk.StringVar(value="4")
        ttk.Combobox(top, textvariable=self.size_var, values=("1", "2", "4", "8"), width=3, state="readonly").pack(side="left")
        ttk.Button(top, text="Go", command=self.on_go).pack(side="left", padx=4)
        self.value_var = tk.StringVar(value="")
        tk.Label(top, textvariable=self.value_var, font=("Consolas", 11, "bold"), fg="#05a").pack(side="left", padx=10)
        for text, fn in (("Edit...", self.on_edit), ("Hold", lambda: self.on_hold(True)), ("Unhold", lambda: self.on_hold(False)),
                         ("Bookmark...", self.on_bookmark), ("Memory", lambda: self.link("Memory", "goto")),
                         ("Field view", lambda: self.link("Objects", "field_view")),
                         ("Pointer chains...", lambda: self.link("Memory", "ptrscan_address"))):
            ttk.Button(top, text=text, command=fn).pack(side="left", padx=1)
        self.status = tk.StringVar(value="connecting...")

        vpane = ttk.PanedWindow(root, orient="vertical")
        vpane.pack(fill="both", expand=True, padx=6)
        hpane = ttk.PanedWindow(vpane, orient="horizontal")
        vpane.add(hpane, weight=3)

        # ---- left: who reads or writes it
        left = ttk.Frame(hpane)
        hpane.add(left, weight=1)
        bar = ttk.Frame(left)
        bar.pack(fill="x")
        ttk.Label(bar, text="Who reads or writes it").pack(side="left")
        self.mode_var = tk.StringVar(value="w")
        self.mode_box = ttk.Combobox(bar, textvariable=self.mode_var, values=("w", "r", "rw"), width=4, state="readonly")
        self.mode_box.pack(side="left", padx=4)
        ttk.Button(bar, text="Watch", command=self.on_watch).pack(side="left")
        ttk.Button(bar, text="Stop", command=lambda: self.watch_do("stop")).pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=lambda: self.watch_do("clear")).pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_watch).pack(side="left", padx=2)
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="follow", variable=self.follow_var).pack(side="left")
        self.watch_note = tk.StringVar(value="")
        ttk.Label(left, textvariable=self.watch_note, foreground="#666").pack(fill="x")
        cols = ("rw", "pc", "fn", "caller", "count")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, text, w in zip(cols, ("", "instruction", "function", "called from", "hits"), (30, 110, 200, 260, 50)):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=w, stretch=(c in ("fn", "caller")))
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.on_pick_row())

        # ---- right: the instruction and the code around it
        right = ttk.Frame(hpane)
        hpane.add(right, weight=1)
        bar = ttk.Frame(right)
        bar.pack(fill="x")
        self.ins_title = tk.StringVar(value="The instruction (pick a row on the left)")
        ttk.Label(bar, textvariable=self.ins_title).pack(side="left")
        ttk.Button(bar, text="Hook here...", command=self.on_hook).pack(side="right")
        ttk.Button(bar, text="Patch this instruction...", command=self.on_patch).pack(side="right", padx=2)
        ttk.Button(bar, text="Open in Code", command=lambda: self.link_code()).pack(side="right")
        self.listing = tk.Text(right, font=("Consolas", 10), wrap="none", state="disabled", height=20)
        self.listing.tag_configure("here", background="#fe9")
        self.listing.pack(fill="both", expand=True)

        # ---- bottom: the cheats that touch it
        bottom = ttk.Frame(vpane)
        vpane.add(bottom, weight=1)
        bar = ttk.Frame(bottom)
        bar.pack(fill="x")
        ttk.Label(bar, text="Cheats that write this address or the picked instruction").pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_cheats).pack(side="left", padx=4)
        cols = ("id", "on", "name", "what")
        self.cheats = ttk.Treeview(bottom, columns=cols, show="headings", height=6)
        for c, text, w in zip(cols, ("#", "on", "cheat", "the line that touches it"), (40, 40, 300, 600)):
            self.cheats.heading(c, text=text)
            self.cheats.column(c, width=w, stretch=(c == "what"))
        self.cheats.pack(fill="both", expand=True)

        ttk.Label(root, textvariable=self.status, anchor="w").pack(fill="x", padx=6, pady=2)
        threading.Thread(target=self.worker, daemon=True).start()
        self.job(self.connect, self.connected)
        root.after(100, self.tick)
        root.after(500, self.live)
        root.after(1500, self.follow)

    # ------------------------------------------------------------------ plumbing
    def worker(self):
        while True:
            fn, done = self.work.get()
            try:
                r, ex = fn(), None
            except Exception as e:  # noqa: BLE001 - shown in the status line
                r, ex = None, e
            self.ui.put((done, r, ex))

    def job(self, fn, done=None):
        self.busy = True
        self.work.put((fn, done))

    def tick(self):
        if self.closed:
            return
        while not self.ui.empty():
            done, r, ex = self.ui.get()
            self.busy = not self.work.empty()
            if ex is not None:
                self.status.set("error: %s" % ex)
            elif done:
                done(r)
        self.root.after(100, self.tick)

    def close(self):
        self.closed = True
        for c in (self.b, getattr(self.back, "c", None)):
            if c is not None:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass

    def connect(self):
        b = Breeze(self.host, self.code, port=self.port, timeout=60)
        meta = json.loads(b.cmd("meta")[4:] or "{}")
        main = int(meta.get("main", "0"), 16)
        text_size, mods = 0, []
        maps = b.cmd("maps").split("\n")[1:]
        self.exec_ranges = []
        for line in maps:
            f = line.split()
            if len(f) >= 3 and "x" in f[2]:
                self.exec_ranges.append((int(f[0], 16), int(f[0], 16) + int(f[1], 16)))
                if int(f[0], 16) == main:
                    text_size = int(f[1], 16)
        try:
            mods = code_modules.code_modules(maps, main)
        except Exception:  # noqa: BLE001 - names for other modules are a help
            pass
        # The data watch, as the Watch tab makes it (a connection of its own: it may block).
        back, note = None, ""
        try:
            c = studio_watch.Client(self.host, self.port, self.code, "studio_workbench")
            names = studio_watch.Names()
            if "ui" in c.cmd("caps").split():
                back = studio_watch.ConsoleBack(c, main, names)
            else:
                st = c.cmd("probe status", multi=True)
                if st[0].startswith("+OK"):
                    try:
                        names.load(self.address, self.code, meta)
                    except Exception:  # noqa: BLE001
                        pass
                    back = studio_watch.ProbeBack(c, main, names, json.loads(st[0][4:]))
                    back.mods = mods
                else:
                    c.close()
                    note = "this host has no data watch"
        except Exception as e:  # noqa: BLE001
            note = "no data watch: %s" % e
        return b, meta, main, text_size, mods, back, note

    def connected(self, r):
        self.b, self.meta, self.main, text_size, self.mods, self.back, note = r
        self.game = Game(self.b, self.main, text_size)
        if self.back is not None:
            self.mode_box.configure(values=list(m for m in self.back.modes if not m.startswith("x")))
            note = self.back.note
        self.watch_note.set(note)
        self.status.set("connected: %s  main %X" % (self.meta.get("title_name", ""), self.main))
        if self.asked:
            asked, self.asked = self.asked, None
            self.open_address(*asked)

    # ------------------------------------------------------------------ the address
    def open_address(self, address, size=4):
        """Works on an address another tab hands over (studio_link.address_menu)."""
        if self.b is None:
            self.asked = (address, size)
            return
        self.at, self.size = address, size if size in (1, 2, 4, 8) else 4
        self.size_var.set(str(self.size))
        self.addr_var.set(self.where(address))
        self.rows, self.ins_at = [], None
        self.tree.delete(*self.tree.get_children())
        self.show_code(None)
        self.status.set("working on %s (%d bytes)" % (self.where(address), self.size))
        self.refresh_cheats()
        self.refresh_watch(quiet=True)

    def on_go(self):
        t = self.addr_var.get().strip()
        try:
            a = self.main + int(t[2:], 16) if t.upper().startswith("M+") else int(t, 16)
        except ValueError:
            self.status.set("not an address: %s" % t)
            return
        self.open_address(a, int(self.size_var.get()))

    def where(self, a):
        if self.main and self.main <= a < self.main + 0x10000000:
            return "M+%X" % (a - self.main)
        return "%X" % a

    def live(self):
        """The value, twice a second."""
        if self.closed:
            return
        if self.at is not None and self.b is not None and not self.busy and self.root.winfo_viewable():
            at, n = self.at, self.size
            self.job(lambda: self.b.peek(at, n), lambda d, at=at, n=n: self.show_value(at, n, d))
        self.root.after(500, self.live)

    def show_value(self, at, n, data):
        if at != self.at or len(data or b"") != n:
            return
        v = int.from_bytes(data, "little")
        signed = v - (1 << (8 * n)) if v >> (8 * n - 1) else v
        text = "%0*X   %d" % (2 * n, v, signed)
        if n == 4:
            text += "   %g" % struct.unpack("<f", data)[0]
        elif n == 8:
            text += "   %g" % struct.unpack("<d", data)[0]
        self.value_var.set(text)

    def on_edit(self):
        if self.at is None:
            return
        text = simpledialog.askstring("Edit", "%d bytes at %s (0x.. for hex, a point for a float):" % (self.size, self.where(self.at)),
                                      parent=self.root)
        if not text:
            return
        try:
            if "." in text:
                data = struct.pack("<f" if self.size == 4 else "<d", float(text))
            else:
                v = int(text, 0)
                data = (v & ((1 << (8 * self.size)) - 1)).to_bytes(self.size, "little")
        except (ValueError, struct.error):
            self.status.set("not a value of %d bytes: %s" % (self.size, text))
            return
        at = self.at
        self.job(lambda: self.b.cmd("poke %X %s" % (at, data.hex())), self.status.set)

    def on_hold(self, on):
        if self.at is not None:
            line = "hold %X %d" % (self.at, self.size) if on else "unhold %X" % self.at
            self.job(lambda: self.b.cmd(line), self.status.set)

    def on_bookmark(self):
        tid = (self.meta.get("title_id") or "").upper()
        if self.at is None or not tid:
            return
        name = simpledialog.askstring("Bookmark", "Name:", parent=self.root)
        if not name:
            return
        type_ = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}[self.size]
        where = ("main+%X" % (self.at - self.main)) if self.main <= self.at < self.main + 0x10000000 else "%X" % self.at
        path = studio_link.add_bookmarks(tid, [(name.replace(" ", "_"), where, type_)])
        self.status.set("bookmark %s added to %s" % (name, path))

    def link(self, tab, method):
        if self.at is None:
            self.status.set("give an address first")
            return
        note = studio_link.send(self.root, tab, method, self.at)
        if note:
            self.status.set(note)

    # ------------------------------------------------------------------ who touches it
    def on_watch(self):
        if self.at is None or self.back is None:
            self.status.set("give an address first" if self.at is None else self.watch_note.get())
            return
        at, n, mode = self.at, self.size, self.mode_var.get()
        self.job(lambda: self.back.data_add(at, n, mode, 2), lambda r: (self.status.set(r), self.refresh_watch(quiet=True)))

    def watch_do(self, what):
        if self.back is None:
            return
        fn = self.back.data_stop if what == "stop" else self.back.data_clear
        self.job(fn, lambda r: (self.status.set(r), self.refresh_watch(quiet=True)))

    def refresh_watch(self, quiet=False):
        if self.back is None:
            return
        self.job(self.back.data_rows, lambda r: self.show_rows(r, quiet))

    def follow(self):
        if self.closed:
            return
        if self.back is not None and self.follow_var.get() and not self.busy and self.root.winfo_viewable():
            self.refresh_watch(quiet=True)
        self.root.after(1500, self.follow)

    def show_rows(self, r, quiet):
        text, rows, on = r
        self.watch_note.set("%s%s" % (text, "" if on else "  (press Watch to start one on this address)"))
        picked = self.tree.selection()
        key = self.rows[int(picked[0])]["key"] if picked and int(picked[0]) < len(self.rows) else None
        self.rows = rows
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(rows):
            self.tree.insert("", "end", iid=str(i), values=(row.get("rw", ""), row.get("pc", ""), row.get("fn", ""),
                                                             ("%s  %s" % (row.get("caller", ""), row.get("caller_fn", ""))).strip(),
                                                             row.get("count", "")))
            if row.get("key") == key:
                self.tree.selection_set(str(i))
        if not quiet:
            self.status.set("%d instruction(s) touch it" % len(rows))

    def code_address(self, text):
        t = (text or "").strip()
        if t.upper().startswith("M+"):
            try:
                return self.main + int(t[2:].split("+")[0], 16)
            except ValueError:
                return None
        other = code_modules.parse(self.mods, t)
        if other is not None:
            return other
        try:
            return int(t, 16)
        except ValueError:
            return None

    def on_pick_row(self):
        sel = self.tree.selection()
        if not sel or int(sel[0]) >= len(self.rows):
            return
        at = self.code_address(self.rows[int(sel[0])].get("pc"))
        if at is None or at == self.ins_at:
            return
        self.ins_at = at
        self.ins_title.set("%s   %s" % (self.where(at), self.rows[int(sel[0])].get("fn", "")))
        start = at - 4 * AROUND
        self.job(lambda: self.b.peek(start, 4 * (2 * AROUND + 1)), lambda d: self.show_code((start, d)))
        self.refresh_cheats()

    def show_code(self, got):
        t = self.listing
        t.configure(state="normal")
        t.delete("1.0", "end")
        if got:
            start, data = got
            for k in range(len(data) // 4):
                a = start + 4 * k
                w = struct.unpack_from("<I", data, 4 * k)[0]
                text = cheat_disasm.branch_named(cheat_disasm.asm(w, a), self.where) or ".word 0x%08X" % w
                t.insert("end", "%-14s %08X  %s\n" % (self.where(a), w, text), "here" if a == self.ins_at else "")
        t.configure(state="disabled")

    def link_code(self):
        if self.ins_at is None:
            self.status.set("pick an instruction on the left first")
            return
        note = studio_link.send(self.root, "Code", "goto_address", self.ins_at)
        if note:
            self.status.set(note)

    def maker_job(self, fn, done):
        """The makers' job(fn(game), done)."""
        self.job(lambda: fn(self.game), done)

    def on_patch(self):
        if self.ins_at is None or self.game is None:
            self.status.set("pick an instruction on the left first")
            return
        import patch_maker
        rva = self.ins_at - self.main
        title = self.tree.set(self.tree.selection()[0], "fn") if self.tree.selection() else ""
        patch_maker.PatchMaker(self.root, self.maker_job, rva, (title or "M+%X" % rva).rpartition(".")[2])

    def on_hook(self):
        if self.ins_at is None or self.game is None:
            self.status.set("pick an instruction on the left first")
            return
        import hook_maker
        rva = self.ins_at - self.main
        title = self.tree.set(self.tree.selection()[0], "fn") if self.tree.selection() else ""
        hook_maker.HookMaker(self.root, self.maker_job, rva, title or "M+%X" % rva)

    # ------------------------------------------------------------------ the cheats that touch it
    def refresh_cheats(self):
        if self.b is None or (self.at is None and self.ins_at is None):
            return
        at, n, ins = self.at, self.size, self.ins_at
        main = self.main

        def fn():
            game = {"main": main}
            for k in ("heap", "alias", "aslr"):
                if k in self.meta:
                    game[k] = int(self.meta[k], 16)
            found = []
            for cid, on, text in self.b.cheats_get():
                name, words = code_patch.split_cheat(text)
                if not words or cid == 0:
                    continue
                lines = cheat_disasm.explain(words, game, self.b.peek,
                                             lambda a: any(lo <= a < hi for lo, hi in self.exec_ranges),
                                             lambda w, i: code_patch.opcode_words(w, i))
                for e in lines:
                    t = e["target"]
                    if t is None:
                        continue
                    hits_value = at is not None and t < at + n and at < t + 8
                    hits_code = ins is not None and t <= ins < t + 8
                    if hits_value or hits_code:
                        found.append((cid, on, name, e["raw"] + "   " + e["text"]))
                        break
            return found

        def done(found):
            self.cheats.delete(*self.cheats.get_children())
            for cid, on, name, what in found:
                self.cheats.insert("", "end", values=(cid, "ON" if on else "", name, what))
        self.job(fn, done)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "1234"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 6801
    root = tk.Tk()
    app = App(root, "%s:%d" % (host, port), code)
    if len(sys.argv) > 4:
        app.open_address(int(sys.argv[4], 16))
    root.protocol("WM_DELETE_WINDOW", lambda: (app.close(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
