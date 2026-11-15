"""Breeze Studio: search the game's memory the way Breeze's search manager does.

    python studio_search.py [host] [code] [port] [--f9]

Each search target (one unit's HP, another's HP, gold...) is a candidate file on the host
(PC connect `search`), so any number of them run side by side:

  * New target: name, type, mode, value(s). "New" starts it at once; "Queue" + "Start queued"
    starts several with one pass over memory. Every Breeze mode is there: == != > < >= <=,
    [A..B] (..), <A..B>, &B=A, ==*A, ==**A, [A..B]f.0, PTR, ~PTR, [A,B], [A,,B], [A.B.C],
    STRING, and none (value not known yet: a dump).
  * Each target row has its own next mode and value(s): ++ -- DIFF SAME ++Val --Val, [A bflip B],
    the compares again, and the B-file modes SAMEB DIFFB B++ B-- NotAB (A = the B target's name).
    "Step" steps that one, "Step all" steps every row whose mode is set, in one command.
  * A long search shows its progress, elapsed time and an ETA (PC connect `search progress`).
  * The selected target's candidates: pages, live values, shown as any type (Retype makes the
    file that type for the next step), hex. On the selected rows: Set, Inc, Revert, Hold, Unhold,
    Copy, Bookmark (views/<title id>.txt, read by bookmarks.py). On a run of rows from the first
    selected one (Breeze's Set1000 / Inc1000 / Revert1000 / Freeze100): the batch buttons.
    Export writes every candidate to a CSV file.

Python 3 with tkinter only.
"""
import csv
import ctypes
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, simpledialog, ttk

from game_title import window_title

HERE = os.path.dirname(os.path.abspath(__file__))
HOTKEY_VK = 0x78  # F9
HOTKEY = "--f9" in sys.argv  # off by default: cheat_menu.py listens for F9
TYPES = ["u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "f32", "f64"]
SIZES = dict(u8=1, s8=1, u16=2, s16=2, u32=4, s32=4, u64=8, s64=8, f32=4, f64=8)

# mode -> (number of values, what it does). Names are PC connect's; Breeze's are in the hint.
MODES = {
    "==": (1, "==A  equal to A"),
    "!=": (1, "!=A  not equal to A"),
    ">": (1, ">A  greater than A"),
    "<": (1, "<A  less than A"),
    ">=": (1, ">=A"),
    "<=": (1, "<=A"),
    "..": (2, "[A..B]  from A to B, both included"),
    "<..>": (2, "<A..B>  strictly between A and B"),
    "&b=a": (2, "&B=A  the bits of mask B equal A"),
    "==*": (1, "==*A  A as u32, f32 or f64: the type is not known"),
    "==**": (1, "==**A  u32 equal to A, or a float within 1 of A"),
    "f.0": (2, "[A..B]f.0  a float from A to B with no fraction"),
    "ptr": (0, "PTR  points into heap or main (u64)"),
    "~ptr": (0, "~PTR  does not point into heap or main (u64)"),
    "[a,b]": (2, "[A,B]  A with B right after it"),
    "[a,,b]": (2, "[A,,B]  A with B within 3 values of it"),
    "[a.b.c]": (3, "[A.B.C]  A with B and C within 3 values of it"),
    "string": (1, "STRING  the text in A (bytes or UTF-16)"),
    "none": (0, "unknown value: dump memory, then compare with ++ -- DIFF SAME"),
    "++": (0, "++  increased since the last step"),
    "--": (0, "--  decreased since the last step"),
    "diff": (0, "DIFF  changed since the last step"),
    "same": (0, "SAME  unchanged since the last step"),
    "++val": (1, "++Val  increased by A"),
    "--val": (1, "--Val  decreased by A"),
    "bflip": (2, "[A bflip B]  the bits that differ between A and B flipped"),
    "sameb": (1, "SAMEB  equal to the B target's value (A = B target's name)"),
    "diffb": (1, "DIFFB  not equal to the B target's value (A = B target's name)"),
    "b++": (1, "B++  greater than the B target's value (A = B target's name)"),
    "b--": (1, "B--  less than the B target's value (A = B target's name)"),
    "notab": (1, "NotAB  neither its last value nor the B target's (A = B target's name)"),
}
COMPARE = ["==", "!=", ">", "<", ">=", "<=", "..", "<..>", "&b=a", "==*", "==**", "f.0", "ptr", "~ptr"]
FIRST_MODES = COMPARE + ["[a,b]", "[a,,b]", "[a.b.c]", "string", "none"]
NEXT_MODES = [""] + COMPARE + ["++", "--", "diff", "same", "++val", "--val", "bflip",
                               "sameb", "diffb", "b++", "b--", "notab"]


def fmt_ms(ms):
    s = int(ms / 1000)
    return "%d:%02d" % (s // 60, s % 60) if s >= 60 else "%d s" % s


def encode(text, typ):
    """A typed value as little-endian bytes."""
    if typ in ("f32", "f64"):
        return struct.pack("<f" if typ == "f32" else "<d", float(text))
    w = SIZES[typ]
    return (int(text, 0) & ((1 << (8 * w)) - 1)).to_bytes(w, "little")


def as_hex(text, typ):
    if typ in ("f32", "f64"):
        return text
    try:
        v = int(text, 0)
    except ValueError:
        return text
    return "0x%X" % (v & ((1 << (8 * SIZES[typ])) - 1))


class Client:
    def __init__(self, host, port, code, name="breeze_studio"):
        self.host, self.port, self.code = host, port, code
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(1800)  # a first search over every region, or a dump compare
        self.buf = b""
        self.lock = threading.Lock()
        self.banner = self._line()
        r = self.cmd("auth " + code)
        if not r.startswith("+OK"):
            raise RuntimeError(r)
        self.cmd("hello " + name)

    def _line(self):
        while b"\n" not in self.buf:
            d = self.sock.recv(65536)
            if not d:
                raise ConnectionError("PC connect closed the connection")
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def cmd(self, line, multi=False):
        with self.lock:
            self.sock.sendall((line + "\n").encode())
            first = self._line()
            if not multi:
                return first
            out = [first]
            if not first.startswith("+OK"):
                return out
            while True:
                l = self._line()
                if l == ".":
                    return out
                out.append(l)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TargetRow:
    """One candidate file: its numbers and its own next step."""

    def __init__(self, app, parent, name):
        self.app, self.name = app, name
        self.type = "u32"
        self.kind = "rows"
        self.count = 0
        self.frame = ttk.Frame(parent)
        self.label = ttk.Label(self.frame, text=name, width=14)
        self.info = ttk.Label(self.frame, text="", width=40)
        self.mode = ttk.Combobox(self.frame, values=NEXT_MODES, width=7, state="readonly")
        self.mode.bind("<<ComboboxSelected>>", lambda e: app.hint.set(MODES.get(self.mode.get(), (0, ""))[1]))
        self.a = ttk.Entry(self.frame, width=10)
        self.b = ttk.Entry(self.frame, width=10)
        self.label.pack(side="left")
        self.info.pack(side="left", padx=4)
        self.mode.pack(side="left")
        self.a.pack(side="left", padx=2)
        self.b.pack(side="left")
        ttk.Button(self.frame, text="Step", width=5, command=lambda: app.step([self])).pack(side="left", padx=2)
        ttk.Button(self.frame, text="Undo", width=5, command=lambda: app.undo(self)).pack(side="left")
        ttk.Button(self.frame, text="Show", width=5, command=lambda: app.select(self)).pack(side="left", padx=2)
        ttk.Button(self.frame, text="✕", width=2, command=lambda: app.delete(self)).pack(side="left")
        self.frame.pack(fill="x", pady=1)

    def update(self, type_, kind, count, step, last):
        self.type, self.kind = type_, kind
        try:
            self.count = int(count)
        except ValueError:
            self.count = 0
        what = "dump (unknown value)" if kind == "dump" else "%s candidates" % count
        self.info.configure(text="%s  %s  step %s  [%s]" % (type_, what, step, last))

    def step_text(self):
        m = self.mode.get()
        if not m:
            return None
        n = MODES[m][0]
        vals = [self.a.get().strip(), self.b.get().strip()][:n]
        if any(not v for v in vals):
            raise ValueError("%s: %s needs %d value(s)" % (self.name, m, n))
        return " ".join([self.name, m] + vals)


class App:
    def __init__(self, root, host, code, port):
        self.root = root
        self.client = None
        self.poller = None  # a second connection: search progress while a search runs
        self.jobs = queue.Queue()
        self.ui = queue.Queue()
        self.paused = False
        self.hotkey_down = False
        self.rows = {}
        self.queued = []
        self.selected = None
        self.busy = False
        self.busy_label = ""
        self.busy_since = 0.0
        self.meta = {}
        self.page = 0
        self.list_count = 0
        root.title("Search")
        root.geometry("1060x860")

        top = ttk.Frame(root, padding=6)
        top.pack(fill="x")
        self.host = tk.StringVar(value=host)
        self.port = tk.StringVar(value=str(port))
        self.code = tk.StringVar(value=code)
        for label, var, w in (("Host", self.host, 14), ("Port", self.port, 6), ("Code", self.code, 8)):
            ttk.Label(top, text=label).pack(side="left")
            ttk.Entry(top, textvariable=var, width=w).pack(side="left", padx=(2, 8))
        ttk.Button(top, text="Connect", command=self.connect).pack(side="left")
        self.game = tk.StringVar(value="not connected")
        ttk.Label(top, textvariable=self.game).pack(side="left", padx=10)

        self.pause_btn = tk.Button(root, text="Pause", font=("Segoe UI", 14, "bold"),
                                   bg="#d9534f", fg="white", command=self.toggle_pause)
        self.pause_btn.pack(fill="x", padx=6)

        new = ttk.LabelFrame(root, text="New target", padding=6)
        new.pack(fill="x", padx=6, pady=4)
        self.n_name = ttk.Entry(new, width=14)
        self.n_type = ttk.Combobox(new, values=TYPES, width=5, state="readonly")
        self.n_type.set("u32")
        self.n_mode = ttk.Combobox(new, values=FIRST_MODES, width=7, state="readonly")
        self.n_mode.set("==")
        self.n_mode.bind("<<ComboboxSelected>>", lambda e: self.hint.set(MODES[self.n_mode.get()][1]))
        self.n_a = ttk.Entry(new, width=12)
        self.n_b = ttk.Entry(new, width=10)
        self.n_c = ttk.Entry(new, width=10)
        for text, w in (("Name", self.n_name), ("Type", self.n_type), ("Mode", self.n_mode),
                        ("A", self.n_a), ("B", self.n_b), ("C", self.n_c)):
            ttk.Label(new, text=text).pack(side="left")
            w.pack(side="left", padx=(2, 8))
        ttk.Button(new, text="New", command=self.new_now).pack(side="left")
        ttk.Button(new, text="Queue", command=self.queue_new).pack(side="left", padx=2)
        self.start_btn = ttk.Button(new, text="Start queued (0)", command=self.start_queued)
        self.start_btn.pack(side="left")
        self.hint = tk.StringVar(value=MODES["=="][1])
        ttk.Label(root, textvariable=self.hint, foreground="#555").pack(fill="x", padx=12)

        tg = ttk.LabelFrame(root, text="Targets   (set each row's mode and value, then Step all)", padding=6)
        tg.pack(fill="x", padx=6)
        self.targets = ttk.Frame(tg)
        self.targets.pack(fill="x")
        bar = ttk.Frame(tg)
        bar.pack(fill="x", pady=(4, 0))
        ttk.Button(bar, text="Step all", command=lambda: self.step(list(self.rows.values()))).pack(side="left")
        ttk.Button(bar, text="Reload list", command=self.load_files).pack(side="left", padx=4)
        self.status = tk.StringVar()
        ttk.Label(bar, textvariable=self.status).pack(side="left", padx=8)

        pg = ttk.Frame(root, padding=(6, 2))
        pg.pack(fill="x")
        self.bar = ttk.Progressbar(pg, mode="determinate", maximum=100)
        self.bar.pack(side="left", fill="x", expand=True)
        self.prog = tk.StringVar(value="idle")
        ttk.Label(pg, textvariable=self.prog, width=58).pack(side="left", padx=6)

        res = ttk.LabelFrame(root, text="Candidates", padding=6)
        res.pack(fill="both", expand=True, padx=6, pady=4)
        head = ttk.Frame(res)
        head.pack(fill="x")
        self.res_title = tk.StringVar(value="(Show a target)")
        ttk.Label(head, textvariable=self.res_title).pack(side="left")
        nav = ttk.Frame(res)
        nav.pack(fill="x", pady=2)
        ttk.Button(nav, text="◀", width=3, command=lambda: self.go_page(-1)).pack(side="left")
        ttk.Button(nav, text="▶", width=3, command=lambda: self.go_page(1)).pack(side="left", padx=2)
        ttk.Label(nav, text="page size").pack(side="left", padx=(8, 2))
        self.page_size = ttk.Combobox(nav, values=["100", "500", "1000", "5000"], width=5, state="readonly")
        self.page_size.set("500")
        self.page_size.bind("<<ComboboxSelected>>", lambda e: self.go_row(0))
        self.page_size.pack(side="left")
        ttk.Label(nav, text="go to row").pack(side="left", padx=(8, 2))
        self.goto = ttk.Entry(nav, width=9)
        self.goto.bind("<Return>", lambda e: self.go_row(int(self.goto.get() or 0)))
        self.goto.pack(side="left")
        ttk.Label(nav, text="show as").pack(side="left", padx=(12, 2))
        self.show_as = ttk.Combobox(nav, values=["file"] + TYPES, width=5, state="readonly")
        self.show_as.set("file")
        self.show_as.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.show_as.pack(side="left")
        ttk.Button(nav, text="Retype file", command=self.retype).pack(side="left", padx=2)
        self.hex = tk.BooleanVar(value=False)
        ttk.Checkbutton(nav, text="hex", variable=self.hex, command=self.refresh).pack(side="left", padx=6)
        self.auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(nav, text="live values", variable=self.auto).pack(side="left")
        ttk.Button(nav, text="Export CSV", command=self.export).pack(side="right")

        inner = ttk.Frame(res)
        inner.pack(fill="both", expand=True)
        cols = ("row", "address", "now", "last", "where")
        self.tree = ttk.Treeview(inner, columns=cols, show="headings", selectmode="extended")
        for c, w in zip(cols, (70, 140, 130, 130, 300)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        act = ttk.Frame(res)
        act.pack(fill="x", pady=(4, 0))
        ttk.Label(act, text="selected:").pack(side="left")
        self.setval = ttk.Entry(act, width=10)
        self.setval.pack(side="left", padx=2)
        ttk.Button(act, text="Set", command=lambda: self.write_selected("set")).pack(side="left")
        ttk.Button(act, text="Inc by", command=lambda: self.write_selected("inc")).pack(side="left", padx=2)
        ttk.Button(act, text="Revert", command=lambda: self.write_selected("revert")).pack(side="left")
        ttk.Button(act, text="Hold", command=lambda: self.hold_selected(True)).pack(side="left", padx=2)
        ttk.Button(act, text="Unhold", command=lambda: self.hold_selected(False)).pack(side="left")
        ttk.Button(act, text="Copy address", command=self.copy_selected).pack(side="left", padx=2)
        ttk.Button(act, text="Bookmark", command=self.bookmark_selected).pack(side="left")
        bat = ttk.Frame(res)
        bat.pack(fill="x", pady=(4, 0))
        ttk.Label(bat, text="batch from the first selected row:  rows").pack(side="left")
        self.batch_n = ttk.Entry(bat, width=6)
        self.batch_n.insert(0, "1000")
        self.batch_n.pack(side="left", padx=2)
        ttk.Label(bat, text="value").pack(side="left", padx=(6, 2))
        self.batch_v = ttk.Entry(bat, width=10)
        self.batch_v.pack(side="left")
        for text, op in (("Set N", "set"), ("Inc N", "inc"), ("Revert N", "revert"),
                         ("Hold N", "hold"), ("Unhold N", "unhold")):
            ttk.Button(bat, text=text, command=lambda op=op: self.batch(op)).pack(side="left", padx=2)

        threading.Thread(target=self.worker, daemon=True).start()
        root.after(50, self.pump)
        root.after(50, self.poll_hotkey)
        root.after(1000, self.tick)
        root.after(500, self.poll_progress)
        if code:
            self.connect()

    # ---- one PC connect command at a time, off the UI thread; results run on the Tk thread
    def worker(self):
        while True:
            fn, done = self.jobs.get()
            try:
                self.ui.put((done, fn(), None))
            except Exception as ex:  # noqa: BLE001 - shown to the user
                self.ui.put((done, None, ex))

    def pump(self):
        while not self.ui.empty():
            done, r, ex = self.ui.get()
            done(r, ex)
        self.root.after(50, self.pump)

    def run(self, fn, done=None, label=None):
        if self.client is None:
            self.status.set("connect first")
            return
        if label:
            self.busy = True
            self.busy_label = label
            self.busy_since = time.time()
            self.status.set(label + "...")

        def finish(r, ex):
            if label:
                self.busy = False
            if ex:
                self.status.set(str(ex))
            elif done:
                done(r)
        self.jobs.put((fn, finish))

    def connect(self):
        for c in (self.client, self.poller):
            if c:
                c.close()
        self.client = self.poller = None

        def fn():
            host, port, code = self.host.get(), int(self.port.get()), self.code.get()
            c = Client(host, port, code, "search_gui")
            p = Client(host, port, code, "search_gui_progress")
            meta = c.cmd("meta")
            return c, p, meta

        def done(r, ex):
            if ex:
                self.game.set("connect failed: %s" % ex)
                return
            self.client, self.poller, meta = r
            try:
                self.meta = json.loads(meta[4:])
            except ValueError:
                self.meta = {}
            self.update_state()
            self.load_files()
        self.jobs.put((fn, done))

    def update_state(self):
        def done(r):
            if not r.startswith("+OK"):
                return
            st = json.loads(r[4:])
            g = st.get("game") or {}
            self.paused = bool(st.get("paused"))
            self.root.title(window_title("Search", g))
            self.game.set("%s  build %s  %s" % (g.get("title_id", "?"), g.get("build_id", "?"),
                                                "PAUSED" if self.paused else "running"))
            self.pause_btn.configure(text="Resume" if self.paused else "Pause",
                                     bg="#5cb85c" if self.paused else "#d9534f")
        self.run(lambda: self.client.cmd("state"), done)

    def toggle_pause(self):
        want = "resume" if self.paused else "freeze"
        self.run(lambda: self.client.cmd(want), lambda r: self.update_state())

    def poll_hotkey(self):
        if not HOTKEY:
            return  # the cheat menu has F9; two windows on one key would pause and resume at once
        try:
            down = bool(ctypes.windll.user32.GetAsyncKeyState(HOTKEY_VK) & 0x8000)
        except AttributeError:
            down = False
        if down and not self.hotkey_down and self.client:
            self.toggle_pause()
        self.hotkey_down = down
        self.root.after(50, self.poll_hotkey)

    def tick(self):
        if self.client and self.selected and self.auto.get() and not self.busy and self.jobs.empty():
            self.refresh()
        self.root.after(1000, self.tick)

    # ---- progress of a long search, over the second connection
    def poll_progress(self):
        if self.busy and self.poller:
            def fn():
                try:
                    r = self.poller.cmd("search progress")
                except Exception:  # noqa: BLE001
                    return
                self.ui.put((lambda r, ex: self.show_progress(r), r, None))
            threading.Thread(target=fn, daemon=True).start()
        elif not self.busy:
            self.bar["value"] = 0
            self.prog.set("idle")
        self.root.after(500, self.poll_progress)

    def show_progress(self, r):
        if not self.busy:
            return
        if not r.startswith("+OK running=1"):
            self.prog.set("%s  %s" % (self.busy_label, fmt_ms((time.time() - self.busy_since) * 1000)))
            return
        kv = dict(x.split("=", 1) for x in r[4:].split(" what=")[0].split() if "=" in x)
        pct = float(kv.get("pct", 0))
        eta = int(kv.get("eta_ms", -1))
        done_mb = int(kv.get("done", 0)) / 1048576
        total_mb = int(kv.get("total", 0)) / 1048576
        self.bar["value"] = pct
        self.prog.set("%.1f%%  %.0f / %.0f MB  elapsed %s  ETA %s" % (
            pct, done_mb, total_mb, fmt_ms(int(kv.get("ms", 0))), fmt_ms(eta) if eta >= 0 else "?"))

    # ---- targets
    def load_files(self):
        def done(r):
            if not r[0].startswith("+OK"):
                self.status.set(r[0])
                return
            seen = set()
            for line in r[1:]:
                f = line.split(" ", 6)
                if len(f) < 6:
                    continue
                name, type_, kind, count, step = f[:5]
                last = f[6] if len(f) > 6 else ""
                seen.add(name)
                row = self.rows.get(name) or TargetRow(self, self.targets, name)
                self.rows[name] = row
                row.update(type_, kind, count, step, last)
            for name in list(self.rows):
                if name not in seen:
                    self.rows.pop(name).frame.destroy()
                    if self.selected and self.selected.name == name:
                        self.selected = None
        self.run(lambda: self.client.cmd("search files", multi=True), done)

    def new_text(self):
        name = self.n_name.get().strip()
        mode = self.n_mode.get()
        n = MODES[mode][0]
        if mode == "string":
            text = self.n_a.get().strip()
            if not name or not text or ";" in text:
                raise ValueError("New target: a name, and the text in A (no ';')")
            return " ".join([name, "u8", mode, text])
        vals = [self.n_a.get().strip(), self.n_b.get().strip(), self.n_c.get().strip()][:n]
        if not name or any(not v for v in vals):
            raise ValueError("New target: a name, and %d value(s) for %s" % (n, mode))
        typ = self.n_type.get()
        if mode in ("ptr", "~ptr"):
            typ = "u64"
        return " ".join([name, typ, mode] + vals)

    def queue_new(self):
        try:
            self.queued.append(self.new_text())
        except ValueError as ex:
            self.status.set(str(ex))
            return
        self.start_btn.configure(text="Start queued (%d)" % len(self.queued))
        self.status.set("queued: " + " ; ".join(self.queued))

    def new_now(self):
        try:
            text = self.new_text()
        except ValueError as ex:
            self.status.set(str(ex))
            return
        self.start([text])

    def start_queued(self):
        if self.queued:
            self.start(self.queued)
            self.queued = []
            self.start_btn.configure(text="Start queued (0)")

    def start(self, groups):
        line = "search new " + " ; ".join(groups)
        self.run(lambda: self.client.cmd(line, multi=True), self.after_search,
                 "first search of every writable region, %d target(s)" % len(groups))

    def step(self, rows):
        try:
            groups = [t for t in (r.step_text() for r in rows) if t]
        except ValueError as ex:
            self.status.set(str(ex))
            return
        if not groups:
            self.status.set("set a mode on the rows to step")
            return
        line = "search next " + " ; ".join(groups)
        self.run(lambda: self.client.cmd(line, multi=True), self.after_search,
                 "stepping %d target(s)" % len(groups))

    def after_search(self, r):
        if not r[0].startswith("+OK"):
            self.status.set(r[0])
            return
        ms = int(r[0].split("ms=")[-1] or 0)
        self.status.set("%s:  " % fmt_ms(ms) + ",  ".join(r[1:]))
        self.load_files()
        if self.selected:
            self.go_row(0)

    def undo(self, row):
        self.run(lambda: self.client.cmd("search undo " + row.name),
                 lambda r: (self.status.set(r), self.load_files(), self.refresh()))

    def delete(self, row):
        self.run(lambda: self.client.cmd("search delete " + row.name),
                 lambda r: (self.status.set(r), self.load_files()))

    def select(self, row):
        self.selected = row
        self.list_count = 0
        self.go_row(0)

    # ---- candidates of the selected target
    def size_now(self):
        return int(self.page_size.get())

    def go_page(self, d):
        self.go_row(max(0, (self.page + d) * self.size_now()))

    def go_row(self, row):
        size = self.size_now()
        if self.list_count:
            row = min(row, max(0, self.list_count - 1))
        self.page = max(0, row) // size
        self.refresh()

    def shown_type(self):
        t = self.show_as.get()
        return self.selected.type if t == "file" or not self.selected else t

    def list_cmd(self, name, n, skip):
        t = self.show_as.get()
        return "search list %s %d %d%s" % (name, n, skip, "" if t == "file" else " as " + t)

    def refresh(self):
        row = self.selected
        if not row:
            return
        size = self.size_now()
        skip = self.page * size
        typ = self.shown_type()

        def done(r):
            if not r[0].startswith("+OK"):
                self.res_title.set(r[0])
                return
            head = dict(kv.split("=", 1) for kv in r[0][4:].split(" last=")[0].split() if "=" in kv)
            self.list_count = int(head.get("count", 0))
            shown = len(r) - 1
            self.res_title.set("%s: %s %s, %s candidates   rows %d-%d   page %d of %d" % (
                row.name, head.get("type"), head.get("kind"), head.get("count"), skip,
                skip + shown - 1 if shown else skip, self.page + 1, max(1, -(-self.list_count // size))))
            sel = set(self.tree.item(i, "values")[1] for i in self.tree.selection())
            self.tree.delete(*self.tree.get_children())
            for k, line in enumerate(r[1:]):
                f = (line.split(" ", 3) + [""])[:4]
                if self.hex.get():
                    f[1], f[2] = as_hex(f[1], typ), as_hex(f[2], typ)
                iid = self.tree.insert("", "end", values=[skip + k] + f)
                if f[0] in sel:
                    self.tree.selection_add(iid)
        self.run(lambda: self.client.cmd(self.list_cmd(row.name, size, skip), multi=True), done)

    def chosen(self):
        return [self.tree.item(i, "values") for i in self.tree.selection()]

    def write_selected(self, op):
        row = self.selected
        if not row:
            return
        typ = self.shown_type()
        rows = self.chosen()
        try:
            if op == "set":
                data = [(r[1], encode(self.setval.get().strip(), typ)) for r in rows]
            elif op == "revert":
                data = [(r[1], encode(r[3], typ)) for r in rows if r[3] != "?"]
            else:  # inc: the value now plus the delta
                d = self.setval.get().strip()
                if typ in ("f32", "f64"):
                    data = [(r[1], encode(str(float(r[2]) + float(d)), typ)) for r in rows if r[2] != "?"]
                else:
                    data = [(r[1], encode(str(int(r[2], 0) + int(d, 0)), typ)) for r in rows if r[2] != "?"]
        except ValueError:
            self.status.set("%s: a %s value in the box after 'selected:'" % (op, typ))
            return
        self.run(lambda: "; ".join(self.client.cmd("poke %s %s" % (a, b.hex())) for a, b in data),
                 lambda r: (self.status.set("%s %d: %s" % (op, len(data), r[:200])), self.refresh()))

    def hold_selected(self, on):
        if not self.selected:
            return
        w = SIZES[self.shown_type()]
        addrs = [r[1] for r in self.chosen()]
        self.run(lambda: "; ".join(self.client.cmd(("hold %s %d" % (a, w)) if on else ("unhold " + a))
                                   for a in addrs), self.status.set)

    def copy_selected(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(r[1] for r in self.chosen()))

    def bookmark_selected(self):
        rows = self.chosen()
        if not rows or not self.selected:
            self.status.set("select a candidate to bookmark")
            return
        tid = (self.meta.get("title_id") or "").upper()
        if not tid:
            self.status.set("no title id (connect again)")
            return
        name = simpledialog.askstring("Bookmark", "Name:", parent=self.root)
        if not name:
            return
        typ = self.shown_type()
        path = os.path.join(HERE, "views", "%s.txt" % tid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        text = open(path, encoding="utf-8").read() if os.path.exists(path) else "title %s\n" % tid
        if not re.search(r"^group Bookmarks\s*$", text, re.M):
            text = text.rstrip("\n") + "\n\ngroup Bookmarks\n"
        lines = text.split("\n")
        at = next(i for i, l in enumerate(lines) if re.match(r"group Bookmarks\s*$", l)) + 1
        while at < len(lines) and lines[at][:1] in (" ", "\t"):
            at += 1
        for k, r in enumerate(rows):
            where = r[4].strip() or r[1]
            label = name if len(rows) == 1 else "%s %d" % (name, k + 1)
            lines.insert(at + k, "    %s = %s %s" % (label, where, typ))
        open(path, "w", encoding="utf-8").write("\n".join(lines).rstrip("\n") + "\n")
        self.status.set("bookmarked %d in %s (bookmarks.py shows it)" % (len(rows), path))

    def batch(self, op):
        row = self.selected
        if not row:
            return
        sel = self.chosen()
        first = int(sel[0][0]) if sel else self.page * self.size_now()
        try:
            n = int(self.batch_n.get())
        except ValueError:
            self.status.set("batch: rows is a number")
            return
        value = self.batch_v.get().strip()
        if op in ("set", "inc") and not value:
            self.status.set("batch %s: a value" % op)
            return
        if row.type != self.shown_type():
            self.status.set("batch works in the file's type (%s): Retype file first, or show as file" % row.type)
            return
        line = "search %s %s %s%d %d" % (op, row.name, (value + " ") if op in ("set", "inc") else "", n, first)
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()),
                 "%s %d rows from row %d" % (op, n, first))

    def retype(self):
        row = self.selected
        t = self.show_as.get()
        if not row or t == "file":
            self.status.set("pick a type in 'show as', then Retype file")
            return
        self.run(lambda: self.client.cmd("search retype %s %s" % (row.name, t)),
                 lambda r: (self.status.set(r), self.show_as.set("file"), self.load_files(), self.refresh()))

    def export(self):
        row = self.selected
        if not row:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=row.name + ".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        total = row.count

        def fn():
            out, skip, step = [], 0, 50000
            while True:
                r = self.client.cmd(self.list_cmd(row.name, step, skip), multi=True)
                if not r[0].startswith("+OK"):
                    raise RuntimeError(r[0])
                out += [(line.split(" ", 3) + [""])[:4] for line in r[1:]]
                skip += step
                if len(r) - 1 < step:
                    break
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["address", "now", "last", "where"])
                w.writerows(out)
            return len(out)
        self.run(fn, lambda n: self.status.set("exported %d rows to %s" % (n, path)),
                 "exporting %d rows (reads each value live)" % total)


def main():
    args = [a for a in sys.argv[1:] if a != "--f9"]
    host = args[0] if len(args) > 0 else "127.0.0.1"
    code = args[1] if len(args) > 1 else ""
    port = int(args[2]) if len(args) > 2 else 6801
    root = tk.Tk()
    App(root, host, code, port)
    root.mainloop()


if __name__ == "__main__":
    main()
