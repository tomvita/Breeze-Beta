"""Breeze Studio: a cheat menu like Breeze's, for the running game.

    python studio_cheats.py [host] [code] [port]

  * The cheats, in file order, with Breeze's folders (a 20000000 entry opens one, 20000001
    closes it). Double-click or Space turns a cheat on or off; Turn off all / Restore as on Breeze.
  * Select a cheat to see its code, one opcode per line. Edit the name or the code and Apply
    keeps it in place with its on/off state; Add as new, Duplicate and Delete as you would expect.
  * The master code has its own editor.
  * Save to SD writes atmosphere/contents/<tid>/cheats/<bid>.txt + toggles.txt on the emulated
    SD card (what loads at the next start); Import / Export read and write a cheat .txt on the PC.
  * Pause / Resume (F9 works with the game focused).

Python 3 with tkinter only.
"""
import ctypes
import json
import queue
import re
import socket
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from game_title import window_title

HOTKEY_VK = 0x78  # F9


class Client:
    def __init__(self, host, port, code):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(60)
        self.buf = b""
        self.lock = threading.Lock()
        self.banner = self._line()
        r = self.cmd("auth " + code)
        if not r.startswith("+OK"):
            raise RuntimeError(r)

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


# ---------------------------------------------------------------- cheat text

def opcode_len(words, i):
    """How many words the dmnt opcode at words[i] takes (unknown forms: 1)."""
    w = words[i]
    t = w >> 28
    width = (w >> 24) & 0xF
    if t in (0x0, 0x1):
        return 2 + (2 if width == 8 else 1)
    if t == 0x3:
        return 2 if width == 0 else 1  # 300R0000 VVVVVVVV start, 310R0000 end
    if t in (0x4, 0x6):
        return 3
    if t in (0x5, 0x7):
        return 2
    if t == 0x9:
        return 1 if ((w >> 8) & 0xF) == 0 else (3 if width == 8 else 2)
    if t == 0xA:
        return 2 if ((w >> 8) & 0xF) in (2, 4, 5) else 1
    if t == 0xC:
        sub = (w >> 24) & 0xF
        if sub == 0:
            x = (w >> 8) & 0xF
            if x in (0, 2):
                return 2
            if x == 4:
                return 3 if ((w >> 20) & 0xF) == 8 else 2
            return 1
        if sub == 4:
            return 3
        return 1
    return 1


def code_lines(words):
    out, i = [], 0
    while i < len(words):
        n = max(1, min(opcode_len(words, i), len(words) - i))
        out.append(" ".join("%08X" % x for x in words[i:i + n]))
        i += n
    return out


def parse_entry(line):
    """'<id> on|off [name] w w w' -> (id, on, name, words)."""
    m = re.match(r"(\d+) (on|off) (\[(.*?)\]|\{(.*?)\})\s*(.*)$", line)
    if not m:
        return None
    name = m.group(4) if m.group(4) is not None else m.group(5)
    words = [int(x, 16) for x in m.group(6).split()] if m.group(6).strip() else []
    return int(m.group(1)), m.group(2) == "on", name, words


def parse_cheat_file(text):
    """A Breeze / Atmosphere cheat .txt -> [(name, words, is_master)]."""
    out, cur = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^(\[(.*)\]|\{(.*)\})$", line)
        if m:
            cur = [m.group(2) if m.group(2) is not None else m.group(3), [], m.group(3) is not None]
            out.append(cur)
            continue
        if cur is None:
            continue
        for tok in line.split():
            if re.fullmatch(r"[0-9A-Fa-f]{8}", tok):
                cur[1].append(int(tok, 16))
    return [(n, w, master) for n, w, master in out]


KEY_NAMES = ["A", "B", "X", "Y", "LS", "RS", "L", "R", "ZL", "ZR", "Plus", "Minus", "Left", "Up",
             "Right", "Down", "LS Left", "LS Up", "LS Right", "LS Down", "RS Left", "RS Up",
             "RS Right", "RS Down", "SL", "SR"]  # dmnt key bits 0..25


def key_names(mask):
    return "+".join(n for i, n in enumerate(KEY_NAMES) if mask >> i & 1)


def _is_key(w):
    return w & 0xF0000000 == 0x80000000


def condition_key(words):
    """The cheat's condition key mask (word 0, or word 3 in Breeze's ASM layout), or None."""
    if words and _is_key(words[0]):
        return words[0] & 0x0FFFFFFF
    if len(words) > 3 and _is_key(words[3]):
        return words[3] & 0x0FFFFFFF
    return None


def set_condition_key(words, mask):
    """Breeze's Add conditional key: (new words, None) or (None, reason)."""
    w = list(words)
    if not w:
        return None, "the cheat has no code"
    if all(x & ~1 == 0x20000000 for x in w):
        return None, "a folder line cannot have a key"
    if mask == 0 or mask & ~0x0FFFFFFF:
        return None, "no keys chosen"
    key = 0x80000000 | mask
    if _is_key(w[0]):
        w[0] = key
    elif len(w) > 3 and _is_key(w[3]):
        w[3] = key
    elif len(w) >= 4 and w[1] == w[4]:
        # Breeze's ASM layout: the first pair stays outside the key (turning off restores it).
        if len(w) + 5 > 0x100:
            return None, "no room for the key in this cheat"
        w = w[:3] + [key] + w + [0x20000000]
    else:
        if len(w) + 2 > 0x100:
            return None, "no room for the key in this cheat"
        w = [key] + w + [0x20000000]
    return w, None


def remove_condition_key(words):
    """Breeze's Remove conditional key: the words without it, or None when there is none."""
    w = list(words)
    if len(w) < 2 or w[-1] & 0xF0000000 != 0x20000000:
        return None
    if _is_key(w[0]):
        return w[1:-1]
    if len(w) >= 8 and _is_key(w[3]) and w[0:3] == w[4:7]:
        return w[4:-1]
    if len(w) > 3 and _is_key(w[3]):
        return w[:3] + w[4:-1]
    return None


def is_folder_open(words):
    return words == [0x20000000]


def is_folder_close(words):
    return words == [0x20000001]


# ---------------------------------------------------------------- the window

class App:
    def __init__(self, root, host, code, port):
        self.root = root
        self.client = None
        self.jobs = queue.Queue()
        self.cheats = {}      # id -> (on, name, words)
        self.order = []
        self.master = None    # (name, words) or None
        self.selected = None  # id, or 0 for the master
        self.paused = False
        self.hotkey_down = False
        root.title("Cheats")
        root.geometry("1040x700")

        top = ttk.Frame(root, padding=6)
        top.pack(fill="x")
        self.host = tk.StringVar(value=host)
        self.port = tk.StringVar(value=str(port))
        self.code = tk.StringVar(value=code)
        for label, var, w in (("Host", self.host, 14), ("Port", self.port, 6), ("Code", self.code, 8)):
            ttk.Label(top, text=label).pack(side="left")
            ttk.Entry(top, textvariable=var, width=w).pack(side="left", padx=(2, 8))
        ttk.Button(top, text="Connect", command=self.connect).pack(side="left")
        self.pause_btn = tk.Button(top, text="Pause (F9)", bg="#d9534f", fg="white", width=12,
                                   command=self.toggle_pause)
        self.pause_btn.pack(side="right")
        self.game = tk.StringVar(value="not connected")
        ttk.Label(top, textvariable=self.game).pack(side="left", padx=10)

        body = ttk.PanedWindow(root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=6)

        left = ttk.Frame(body)
        body.add(left, weight=3)
        self.tree = ttk.Treeview(left, columns=("state", "size"), show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Cheat")
        self.tree.heading("state", text="")
        self.tree.heading("size", text="opcodes")
        self.tree.column("#0", width=380)
        self.tree.column("state", width=50, anchor="center")
        self.tree.column("size", width=70, anchor="e")
        self.tree.tag_configure("on", foreground="#1a7f37")
        self.tree.tag_configure("folder", foreground="#6f42c1")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda e: self.toggle_selected())
        self.tree.bind("<space>", lambda e: (self.toggle_selected(), "break")[1])

        right = ttk.Frame(body, padding=(8, 0))
        body.add(right, weight=2)
        ttk.Label(right, text="Name").pack(anchor="w")
        self.name = ttk.Entry(right)
        self.name.pack(fill="x")
        ttk.Label(right, text="Code (one opcode per line; any spacing is fine)").pack(anchor="w", pady=(6, 0))
        self.text = tk.Text(right, height=20, font=("Consolas", 10), undo=True)
        self.text.pack(fill="both", expand=True)
        krow = ttk.Frame(right)
        krow.pack(fill="x", pady=(4, 0))
        self.key_var = tk.StringVar(value="Key: none")
        ttk.Label(krow, textvariable=self.key_var).pack(side="left")
        ttk.Button(krow, text="Remove key", command=self.remove_key).pack(side="right")
        ttk.Button(krow, text="Condition key...", command=self.choose_key).pack(side="right", padx=4)
        row = ttk.Frame(right)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Apply edit", command=self.apply_edit).pack(side="left")
        self.add_on = tk.BooleanVar(value=False)
        ttk.Button(row, text="Add as new", command=self.add_new).pack(side="left", padx=4)
        ttk.Checkbutton(row, text="on", variable=self.add_on).pack(side="left")
        ttk.Button(row, text="Duplicate", command=self.duplicate).pack(side="left", padx=4)
        ttk.Button(row, text="Delete", command=self.delete).pack(side="left")
        row2 = ttk.Frame(right)
        row2.pack(fill="x")
        ttk.Button(row2, text="Edit master code", command=self.select_master).pack(side="left")
        ttk.Button(row2, text="New cheat", command=self.new_blank).pack(side="left", padx=4)
        ttk.Button(row2, text="New folder", command=self.new_folder).pack(side="left")

        bar = ttk.Frame(root, padding=6)
        bar.pack(fill="x")
        for text, fn in (("On", lambda: self.set_selected(True)), ("Off", lambda: self.set_selected(False)),
                         ("Turn off all", lambda: self.simple("cheats off")),
                         ("Restore", lambda: self.simple("cheats restore")),
                         ("Refresh", self.refresh), ("Save to SD", lambda: self.simple("cheats save")),
                         ("Import .txt", self.import_file), ("Export .txt", self.export_file),
                         ("Add freeze game code", self.add_freeze_code)):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=2)
        self.status = tk.StringVar()
        ttk.Label(root, textvariable=self.status, padding=(6, 0, 6, 6)).pack(fill="x")

        threading.Thread(target=self.worker, daemon=True).start()
        root.after(50, self.poll_hotkey)
        if code:
            self.connect()

    # ---- PC connect off the UI thread
    def worker(self):
        while True:
            fn, done = self.jobs.get()
            try:
                r = fn()
                self.root.after(0, done, r, None)
            except Exception as ex:  # noqa: BLE001
                self.root.after(0, done, None, ex)

    def run(self, fn, done=None):
        if self.client is None:
            self.status.set("connect first")
            return

        def finish(r, ex):
            if ex:
                self.status.set(str(ex))
            elif done:
                done(r)
        self.jobs.put((fn, finish))

    def connect(self):
        if self.client:
            self.client.close()
            self.client = None

        def fn():
            return Client(self.host.get(), int(self.port.get()), self.code.get())

        def done(c, ex):
            if ex:
                self.game.set("connect failed: %s" % ex)
                return
            self.client = c
            self.update_state()
            self.refresh()
        self.jobs.put((fn, done))

    def update_state(self):
        def done(r):
            if not r.startswith("+OK"):
                return
            st = json.loads(r[4:])
            g = st.get("game") or {}
            self.paused = bool(st.get("paused"))
            self.root.title(window_title("Cheats", g))
            self.game.set("%s  build %s  %s" % (g.get("title_id", "?"), g.get("build_id", "?"),
                                                "PAUSED" if self.paused else ""))
            self.pause_btn.configure(text="Resume (F9)" if self.paused else "Pause (F9)",
                                     bg="#5cb85c" if self.paused else "#d9534f")
        self.run(lambda: self.client.cmd("state"), done)

    def toggle_pause(self):
        want = "resume" if self.paused else "freeze"
        self.run(lambda: self.client.cmd(want), lambda r: self.update_state())

    def poll_hotkey(self):
        try:
            down = bool(ctypes.windll.user32.GetAsyncKeyState(HOTKEY_VK) & 0x8000)
        except AttributeError:
            down = False
        if down and not self.hotkey_down and self.client:
            self.toggle_pause()
        self.hotkey_down = down
        self.root.after(50, self.poll_hotkey)

    # ---- list
    def refresh(self, keep=None):
        def fn():
            return self.client.cmd("cheats get", multi=True), self.client.cmd("cheats open")

        def done(r):
            lines, info = r
            if not lines[0].startswith("+OK"):
                self.status.set(lines[0])
                return
            self.cheats, self.order, self.master = {}, [], None
            for line in lines[1:]:
                e = parse_entry(line)
                if not e:
                    continue
                cid, on, name, words = e
                if cid == 0:
                    self.master = (name, words)
                    continue
                self.cheats[cid] = (on, name, words)
                self.order.append(cid)
            self.fill_tree()
            self.status.set(info[4:] if info.startswith("+OK ") else info)
            sel = keep if keep is not None else self.selected
            if sel and str(sel) in self.tree.get_children("") + tuple(self.all_items()):
                self.tree.selection_set(str(sel))
                self.tree.see(str(sel))
        self.run(fn, done)

    def all_items(self, parent=""):
        out = []
        for i in self.tree.get_children(parent):
            out.append(i)
            out += self.all_items(i)
        return out

    def fill_tree(self):
        opened = {i for i in self.all_items() if self.tree.item(i, "open")}
        self.tree.delete(*self.tree.get_children())
        stack = [""]
        for cid in self.order:
            on, name, words = self.cheats[cid]
            if is_folder_close(words):
                if len(stack) > 1:
                    stack.pop()
                continue
            if is_folder_open(words):
                self.tree.insert(stack[-1], "end", iid=str(cid), text="📁 " + name, values=("", ""),
                                 tags=("folder",), open=str(cid) in opened)
                stack.append(str(cid))
                continue
            self.tree.insert(stack[-1], "end", iid=str(cid), text=name,
                             values=("ON" if on else "", len(words)), tags=("on",) if on else ())

    def on_select(self, _e=None):
        sel = self.tree.selection()
        if len(sel) != 1:
            return
        cid = int(sel[0])
        on, name, words = self.cheats[cid]
        self.selected = cid
        self.show(name, words)

    def show(self, name, words):
        self.name.delete(0, "end")
        self.name.insert(0, name)
        self.text.delete("1.0", "end")
        self.text.insert("1.0", "\n".join(code_lines(words)))
        k = condition_key(words)
        self.key_var.set("Key: %s" % (key_names(k) if k is not None else "none"))

    def select_master(self):
        self.selected = 0
        self.tree.selection_remove(self.tree.selection())
        name, words = self.master if self.master else ("Master code", [])
        self.show(name, words)
        self.status.set("editing the master code: Apply edit sets it (empty code removes it)")

    def new_blank(self):
        self.selected = None
        self.tree.selection_remove(self.tree.selection())
        self.show("New cheat", [])
        self.status.set("type a name and code, then Add as new")

    def new_folder(self):
        name = self.name.get().strip() or "Folder"
        text = "cheats add [%s] 20000000 [%s end] 20000001" % (name, name)
        self.run(lambda: self.client.cmd(text), lambda r: (self.status.set(r), self.refresh()))

    # ---- editing
    def edited(self):
        name = self.name.get().strip()
        words = re.findall(r"\b[0-9A-Fa-f]{8}\b", self.text.get("1.0", "end"))
        bad = [t for t in self.text.get("1.0", "end").split() if not re.fullmatch(r"[0-9A-Fa-f]{8}", t)]
        if bad:
            raise ValueError("not a code word: %s" % bad[0])
        if not name or "]" in name:
            raise ValueError("a name, without ]")
        return name, [w.upper() for w in words]

    def apply_edit(self):
        try:
            name, words = self.edited()
        except ValueError as ex:
            self.status.set(str(ex))
            return
        cid = self.selected
        if cid == 0:
            line = "cheats master {%s} %s" % (name, " ".join(words)) if words else "cheats master"
            self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh(0)))
            return
        if cid is None or cid not in self.cheats:
            self.status.set("select a cheat to edit, or use Add as new")
            return
        if not words:
            self.status.set("no code: use Delete to remove a cheat")
            return
        self.replace_cheat(cid, name, words)

    def replace_cheat(self, cid, name, words, note=None):
        """cheats edit, or remove + add on an emulator without it. words: hex strings."""
        was_on = self.cheats[cid][0]

        def fn():
            r = self.client.cmd("cheats edit %d [%s] %s" % (cid, name, " ".join(words)))
            if r.startswith("+OK"):
                return (note or r), cid
            if "no such cheat" in r or "takes one" in r:
                return r, cid
            # An older emulator without cheats edit: remove and add (the id may change).
            self.client.cmd("cheats remove %d" % cid)
            r2 = self.client.cmd("cheats add %s[%s] %s" % ("on " if was_on else "", name, " ".join(words)))
            new = int(r2.split("ids=")[1]) if "ids=" in r2 else cid
            return (note or r2) + "  (no cheats edit in this emulator: removed and added)", new
        self.run(fn, lambda r: (self.status.set(r[0]), self.refresh(r[1])))

    # ---- condition keys and the freeze game code (Breeze's cheat menu)
    def selected_cheat(self):
        cid = self.selected
        if not cid or cid not in self.cheats:
            self.status.set("select a cheat first (not the master code)")
            return None
        return cid

    def choose_key(self):
        cid = self.selected_cheat()
        if cid is None:
            return
        on, name, words = self.cheats[cid]
        current = condition_key(words) or 0
        dlg = tk.Toplevel(self.root)
        dlg.title("Condition key")
        dlg.transient(self.root)
        ttk.Label(dlg, text="%s runs only while these buttons are held:" % name,
                  padding=6).grid(row=0, column=0, columnspan=4, sticky="w")
        boxes = []
        for i, n in enumerate(KEY_NAMES):
            v = tk.BooleanVar(value=bool(current >> i & 1))
            ttk.Checkbutton(dlg, text=n, variable=v).grid(row=1 + i // 4, column=i % 4, sticky="w",
                                                          padx=6, pady=1)
            boxes.append(v)

        def ok():
            mask = sum(1 << i for i, v in enumerate(boxes) if v.get())
            dlg.destroy()
            if mask == 0:
                self.remove_key()
                return
            new, err = set_condition_key(words, mask)
            if new is None:
                self.status.set("no key set: " + err)
                return
            self.replace_cheat(cid, name, ["%08X" % w for w in new],
                               "%s now runs while %s is held" % (name, key_names(mask)))
        bar = ttk.Frame(dlg, padding=6)
        bar.grid(row=9, column=0, columnspan=4, sticky="e")
        ttk.Button(bar, text="OK", command=ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Cancel", command=dlg.destroy).pack(side="left")
        dlg.grab_set()

    def remove_key(self):
        cid = self.selected_cheat()
        if cid is None:
            return
        on, name, words = self.cheats[cid]
        new = remove_condition_key(words)
        if new is None:
            self.status.set("%s has no condition key" % name)
            return
        self.replace_cheat(cid, name, ["%08X" % w for w in new], "%s runs without a key now" % name)

    def add_freeze_code(self):
        def fn():
            a = self.client.cmd("cheats add on [Freeze Game] 80000020 FF000000 20000000")
            b = self.client.cmd("cheats add on [Resume Game] 80000010 FF100000 20000000")
            if a.startswith("+OK") and b.startswith("+OK"):
                return "added Freeze Game (right stick pauses) and Resume Game (left stick resumes), on"
            return "%s / %s" % (a, b)
        self.run(fn, lambda r: (self.status.set(r), self.refresh()))

    def add_new(self):
        try:
            name, words = self.edited()
        except ValueError as ex:
            self.status.set(str(ex))
            return
        if not words:
            self.status.set("no code to add")
            return
        line = "cheats add %s[%s] %s" % ("on " if self.add_on.get() else "", name, " ".join(words))

        def done(r):
            self.status.set(r)
            if "ids=" in r:
                self.refresh(int(r.split("ids=")[1].split()[0]))
        self.run(lambda: self.client.cmd(line), done)

    def duplicate(self):
        if not self.selected or self.selected not in self.cheats:
            return
        _on, name, words = self.cheats[self.selected]
        line = "cheats add [%s (copy)] %s" % (name, " ".join("%08X" % w for w in words))
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))

    def delete(self):
        ids = [int(i) for i in self.tree.selection()]
        if not ids:
            return
        names = ", ".join(self.cheats[i][1] for i in ids if i in self.cheats)
        if not messagebox.askyesno("Delete", "Delete %s?" % names):
            return
        line = "cheats remove " + " ".join(map(str, ids))
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))

    def toggle_selected(self):
        sel = [int(i) for i in self.tree.selection() if int(i) in self.cheats]
        sel = [i for i in sel if not is_folder_open(self.cheats[i][2])]
        if not sel:
            return
        turn_on = not self.cheats[sel[0]][0]
        self.set_selected(turn_on, sel)

    def set_selected(self, on, ids=None):
        ids = ids or [int(i) for i in self.tree.selection() if int(i) in self.cheats]
        if not ids:
            return
        line = "cheats %s %s" % ("on" if on else "off", " ".join(map(str, ids)))
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))

    def simple(self, line):
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))

    # ---- files on the PC
    def import_file(self):
        path = filedialog.askopenfilename(filetypes=[("Cheat files", "*.txt"), ("All", "*.*")])
        if not path:
            return
        entries = parse_cheat_file(open(path, encoding="utf-8", errors="replace").read())

        def fn():
            added, out = 0, ""
            for name, words, master in entries:
                if not words:
                    continue
                if master:
                    out = self.client.cmd("cheats master {%s} %s" % (name, " ".join("%08X" % w for w in words)))
                    continue
                r = self.client.cmd("cheats add [%s] %s" % (name, " ".join("%08X" % w for w in words)))
                if not r.startswith("+OK"):
                    return "stopped at %s: %s (%d added)" % (name, r, added)
                added += 1
            return "imported %d cheat(s) (off)%s" % (added, "; " + out if out else "")
        self.run(fn, lambda r: (self.status.set(r), self.refresh()))

    def export_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Cheat files", "*.txt")])
        if not path:
            return
        parts = []
        if self.master:
            parts.append("{%s}\n%s\n" % (self.master[0], "\n".join(code_lines(self.master[1]))))
        for cid in self.order:
            _on, name, words = self.cheats[cid]
            parts.append("[%s]\n%s\n" % (name, "\n".join(code_lines(words))))
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(parts))
        self.status.set("exported %d cheat(s) to %s" % (len(self.order), path))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else ""
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 6801
    root = tk.Tk()
    App(root, host, code, port)
    root.mainloop()


if __name__ == "__main__":
    main()
