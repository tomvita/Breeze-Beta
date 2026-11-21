"""Breeze Studio: a cheat menu like Breeze's, for the running game.

    python studio_cheats.py [host] [code] [port]

  * The cheats, in file order, with Breeze's folders (a 20000000 entry opens one, 20000001
    closes it). Double-click or Space turns a cheat on or off; Turn off all / Restore as on Breeze.
  * Select a cheat to see its code, one opcode per line. Edit the name or the code and Apply
    keeps it in place with its on/off state; Add as new, Duplicate and Delete as you would expect.
  * The master code has its own editor.
  * Under the code, the cheat in words (cheat_disasm.py): each opcode, the address it reads or
    writes in the game now, and the instruction when it writes code. Jump to target opens that
    address in Memory, Jump to ASM opens the patched code in Code (Breeze's Edit Cheat keys).
  * Merge into... (Breeze's Merge into): the selected cheat's code patches go into another cheat,
    in the code-patch form of code_patch.py (the game's instructions in a block that never runs,
    which Breeze puts back when the cheat is turned off). Naming the cheat itself converts it.
  * Off and Turn off all put a code-patch cheat's original instructions back where its patch is
    still in the game (Breeze's second press, in one step); R1 patches need the master's R1.
  * Save to SD writes atmosphere/contents/<tid>/cheats/<bid>.txt + toggles.txt on the emulated
    SD card (what loads at the next start); Import / Export read and write a cheat .txt on the PC.
    Export adds a "<name> - restore" cheat after each code-patch cheat that has none, for players
    whose cheat tool does not put the originals back (as Breeze's Write Cheat to atm).
  * Pause / Resume (F9 works with the game focused).

Python 3 with tkinter only.
"""
import ctypes
import json
import queue
import re
import socket
import struct
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from game_title import window_title
import cheat_disasm
import code_patch
import studio_link

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
        self.tree = ttk.Treeview(left, columns=("state", "kind", "size"), show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="  #   Cheat")
        self.tree.heading("state", text="")
        self.tree.heading("kind", text="kind")
        self.tree.heading("size", text="opcodes")
        self.tree.column("#0", width=380)
        self.tree.column("state", width=50, anchor="center")
        self.tree.column("kind", width=90, anchor="w", stretch=False)
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
        self.text = tk.Text(right, height=10, font=("Consolas", 10), undo=True)
        self.text.pack(fill="both", expand=True)
        erow = ttk.Frame(right)
        erow.pack(fill="x", pady=(6, 0))
        ttk.Label(erow, text="What it does (pick a line)").pack(side="left")
        ttk.Button(erow, text="Jump to ASM", command=self.jump_asm).pack(side="right")
        ttk.Button(erow, text="Jump to target", command=self.jump_target).pack(side="right", padx=4)
        ttk.Button(erow, text="Read again", command=self.explain).pack(side="right")
        # What kind of cheat it is, when it is one Breeze treats specially (ASM hook, code patch).
        self.kind = tk.Label(right, text="", anchor="w", justify="left", fg="#05a", font=("Segoe UI", 9, "bold"))
        self.kind.pack(fill="x")
        self.what = tk.Text(right, height=10, font=("Consolas", 9), wrap="none", state="disabled", cursor="arrow")
        self.what.tag_configure("asm", foreground="#05a")
        self.what.tag_configure("pick", background="#fe9")
        self.what.pack(fill="both", expand=True)
        self.what.bind("<Button-1>", self.pick_line)
        self.what.bind("<Double-Button-1>", lambda e: (self.pick_line(e), self.jump_asm(quiet=True) or self.jump_target())[0])
        wmenu = tk.Menu(self.what, tearoff=0)
        wmenu.add_command(label="Jump to target (Memory)", command=self.jump_target)
        wmenu.add_command(label="Jump to ASM (Code)", command=self.jump_asm)

        # The places every tab can take an address (studio_link.address_menu): the picked line's
        # target, the address it reads or writes.
        def line_target():
            e = self.entry_with("target")
            return e["target"] if e is not None else None

        def line_size():
            e = self.entry_with("target")
            w = int(e["raw"].split()[0], 16) if e is not None else 0
            return (w >> 24) & 0xF if w >> 28 in (0, 1, 5, 6, 0xA) and (w >> 24) & 0xF in (1, 2, 4, 8) else 4
        studio_link.address_menu(self.root, wmenu, line_target, lambda text: self.status.set(text), size=line_size)
        self.what.bind("<Button-3>", lambda e: (self.pick_line(e), wmenu.tk_popup(e.x_root, e.y_root)))
        self.entries, self.picked_entry, self.exec_ranges, self.main_base = [], None, None, 0
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
        ttk.Button(row, text="Merge into...", command=self.merge_into).pack(side="left", padx=4)
        row2 = ttk.Frame(right)
        row2.pack(fill="x")
        ttk.Button(row2, text="Edit master code", command=self.select_master).pack(side="left")
        ttk.Button(row2, text="New cheat", command=self.new_blank).pack(side="left", padx=4)
        ttk.Button(row2, text="New folder", command=self.new_folder).pack(side="left")

        bar = ttk.Frame(root, padding=6)
        bar.pack(fill="x")
        for text, fn in (("On", lambda: self.set_selected(True)), ("Off", lambda: self.set_selected(False)),
                         ("Turn off all", self.turn_off_all),
                         ("Restore", lambda: self.simple("cheats restore")),
                         ("Refresh", self.refresh), ("Save to SD", lambda: self.simple("cheats save")),
                         ("Load from SD", self.load_from_sd),
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
            if "paused" in st:      # a Switch does not say: there the last Pause or Resume stands
                self.paused = bool(st["paused"])
            self.root.title(window_title("Cheats", g))
            ids = "" if studio_link.in_studio(self.root) else "%s  build %s  " % (g.get("title_id", "?"), g.get("build_id", "?"))
            self.game.set(ids + ("PAUSED" if self.paused else ""))
            self.pause_btn.configure(text="Resume (F9)" if self.paused else "Pause (F9)",
                                     bg="#5cb85c" if self.paused else "#d9534f")
        self.run(lambda: self.client.cmd("state"), done)

    def toggle_pause(self):
        want = "resume" if self.paused else "freeze"

        def done(r):
            if r.startswith("+OK"):
                self.paused = want == "freeze"
            self.update_state()
        self.run(lambda: self.client.cmd(want), done)

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
    def kind_of(self, words):
        """The list's kind column (cheat_disasm.kind)."""
        ranges = self.exec_ranges or []
        return cheat_disasm.kind(words, self.main_base, lambda a: any(lo <= a < hi for lo, hi in ranges))

    def load_ranges(self):
        """Worker: the game's code ranges and main, once (the kind column and What it does use them)."""
        if self.exec_ranges is None:
            ranges = []
            for l in self.client.cmd("maps", multi=True)[1:]:
                f = l.split()
                if len(f) >= 3 and "x" in f[2]:
                    ranges.append((int(f[0], 16), int(f[0], 16) + int(f[1], 16)))
            self.exec_ranges = ranges
        if not self.main_base:
            try:
                self.main_base = int((json.loads(self.client.cmd("state")[4:]).get("game") or {}).get("main", "0"), 16)
            except Exception:  # noqa: BLE001 - no game
                pass

    def refresh(self, keep=None):
        def fn():
            self.load_ranges()
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
                self.tree.insert(stack[-1], "end", iid=str(cid), text="%4d  📁 %s" % (cid, name), values=("", "", ""),
                                 tags=("folder",), open=str(cid) in opened)
                stack.append(str(cid))
                continue
            # The id goes first: it is the number PC connect (`cheats on 7`) and a helper use for it.
            self.tree.insert(stack[-1], "end", iid=str(cid), text="%4d  %s" % (cid, name),
                             values=("ON" if on else "", self.kind_of(words), len(words)), tags=("on",) if on else ())

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
        self.explain()

    # ---- the cheat in words, and where it points
    def explain(self):
        """Reads the code box as it stands and fills "What it does"."""
        try:
            words = [int(x, 16) for x in self.text.get("1.0", "end").split()]
        except ValueError:
            return
        if self.client is None:
            return
        c = self.client

        def fn():
            game = json.loads(c.cmd("state")[4:]).get("game") or {}
            bases = {k: int(game[k], 16) for k in ("main", "heap", "alias", "aslr") if k in game}
            if self.exec_ranges is None:
                ranges = []
                for l in c.cmd("maps", multi=True)[1:]:
                    f = l.split()
                    if len(f) >= 3 and "x" in f[2]:
                        ranges.append((int(f[0], 16), int(f[0], 16) + int(f[1], 16)))
                self.exec_ranges = ranges

            def read(address, n):
                r = c.cmd("peek %X %d" % (address, n))
                return bytes.fromhex(r.split()[-1]) if r.startswith("+OK") else b""
            return cheat_disasm.explain(words, bases, read, lambda a: any(lo <= a < hi for lo, hi in self.exec_ranges),
                                        opcode_len)

        def done(entries):
            self.kind.config(text=cheat_disasm.summary(words, opcode_len))
            self.entries, self.picked_entry = entries, None
            t = self.what
            t.configure(state="normal")
            t.delete("1.0", "end")
            for e in entries:
                t.insert("end", "%-30s %s\n" % (e["raw"], e["text"]), "asm" if e["asm"] is not None else "")
            t.configure(state="disabled")
        self.run(fn, done)

    def pick_line(self, e):
        row = int(self.what.index("@%d,%d" % (e.x, e.y)).split(".")[0]) - 1
        self.what.tag_remove("pick", "1.0", "end")
        self.picked_entry = row if 0 <= row < len(self.entries) else None
        if self.picked_entry is not None:
            self.what.tag_add("pick", "%d.0" % (row + 1), "%d.0" % (row + 2))
        return "break"

    def entry_with(self, key):
        """The picked line when it has the address asked for, else the first line that has."""
        if self.picked_entry is not None and self.entries[self.picked_entry][key] is not None:
            return self.entries[self.picked_entry]
        return next((e for e in self.entries if e[key] is not None), None)

    def jump_target(self):
        e = self.entry_with("target")
        if e is None:
            self.status.set("no line of this cheat has an address that can be worked out now")
            return
        self.status.set(studio_link.send(self.root, "Memory", "goto", e["target"]) or "%s  ->  %X" % (e["raw"], e["target"]))

    def jump_asm(self, quiet=False):
        e = self.entry_with("asm")
        if quiet and (self.picked_entry is None or self.entries[self.picked_entry]["asm"] is None):
            return False
        if e is None:
            self.status.set("this cheat writes no code")
            return False
        self.status.set(studio_link.send(self.root, "Code", "goto_address", e["asm"]) or "%s  ->  %X" % (e["raw"], e["asm"]))
        return True

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

    def merge_into(self):
        """Breeze's Merge into (code_patch.py): the selected cheat's code patches go into the cheat
        named in the dialog. A name that is no cheat yet renames this one in its form; its own name
        converts it in place. The merged-away cheat, and a "- restore" cheat the form makes
        unnecessary, are removed."""
        cid = self.selected_cheat()
        if cid is None:
            return
        src_name = self.cheats[cid][1]
        names = [n for i, (_on, n, w) in self.cheats.items() if i != cid and code_patch.parse(w)]
        self.ask_merge_target(src_name, names, lambda target: self.merge_cheat(cid, target))

    def merge_cheat(self, cid, target):
        """Merge into, once the target is named."""
        if cid not in self.cheats:
            self.status.set("cheat %d is gone; Refresh" % cid)
            return
        c = self.client
        cheats = [(i, on, "[%s] %s" % (n, " ".join("%08X" % x for x in w))) for i, (on, n, w) in self.cheats.items()]
        into = next((i for i, (_on, n, _w) in self.cheats.items()
                     if i != cid and code_patch.label_key(n) == code_patch.label_key(target)), None)

        def fn():
            game = json.loads(c.cmd("state")[4:]).get("game") or {}
            main, r1 = int(game["main"], 16), int(game.get("r1", "0"), 16)

            def read(p):
                at = p.address(main, r1)
                if at is None:
                    return None
                r = c.cmd("peek %X 4" % at)
                if not r.startswith("+OK"):
                    raise ValueError("cannot read %s: %s" % (p.label, r))
                return struct.unpack("<I", bytes.fromhex(r.split()[-1]))[0]
            key, frm, restore_id = code_patch.cheat_patches(cid, cheats, read)
            removes = [restore_id] if restore_id else []
            if into is not None:
                key2, have, restore2 = code_patch.cheat_patches(into, cheats, read)
                if key2 != key:
                    raise ValueError("the two cheats have different conditional keys: give them the same key (or none) first")
                merged = code_patch.merge(have, frm)
                if merged is None:
                    raise ValueError("both cheats patch an address and record different game instructions for it")
                removes += ([restore2] if restore2 else []) + [cid]
                edit_id, name = into, self.cheats[into][1]
            else:
                merged, edit_id, name = frm, cid, target
            ops = code_patch.build(merged, key)
            if len(ops) > 0x100:
                raise ValueError("%d patches need %d opcodes; a cheat holds 256" % (len(merged), len(ops)))
            if removes:
                r = c.cmd("cheats remove %s" % " ".join(map(str, removes)))
                if not r.startswith("+OK"):
                    raise ValueError("cheats remove: %s" % r)
            return edit_id, name, ["%08X" % w for w in ops], removes, len(merged)

        def done(r):
            edit_id, name, words, removes, count = r
            note = "%s: %d patch%s%s. Save to SD to keep it." % (
                name, count, "" if count == 1 else "es",
                "; removed cheat%s %s" % ("" if len(removes) == 1 else "s", ", ".join(map(str, removes))) if removes else "")
            self.replace_cheat(edit_id, name, words, note)
        self.run(fn, done)

    def ask_merge_target(self, src_name, names, then):
        """A small dialog for the name; then(name) runs on Merge. It does not wait in a nested
        loop (as the Condition key dialog), so Studio stays responsive behind it."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Merge into")
        dlg.transient(self.root)
        ttk.Label(dlg, text="Merge the code patches of %s into the cheat:\n"
                            "(its own name converts it; a new name renames it)" % src_name,
                  padding=6).pack(anchor="w")
        var = tk.StringVar(value=getattr(self, "last_merge_target", "") or src_name)
        box = ttk.Combobox(dlg, textvariable=var, values=names, width=50)
        box.pack(padx=6, fill="x")
        box.focus_set()

        def ok(_e=None):
            name = var.get().strip()
            dlg.destroy()
            if name:
                self.last_merge_target = name
                then(name)
        row = ttk.Frame(dlg, padding=6)
        row.pack(fill="x")
        ttk.Button(row, text="Merge", command=ok).pack(side="left")
        ttk.Button(row, text="Cancel", command=dlg.destroy).pack(side="left", padx=4)
        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.grab_set()

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
        if on:
            self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))
            return
        patches = self.code_patches(ids)
        self.run(lambda: self.off_and_restore(line, patches), lambda r: (self.status.set(r), self.refresh()))

    def turn_off_all(self):
        patches = self.code_patches([i for i, (on, _n, _w) in self.cheats.items() if on])
        self.run(lambda: self.off_and_restore("cheats off", patches), lambda r: (self.status.set(r), self.refresh()))

    def code_patches(self, ids):
        """[(name, Patch)] of the code-patch cheats among ids (code_patch.py's form), read here on
        the UI thread for the worker."""
        out = []
        for cid in ids:
            if cid in self.cheats:
                got = code_patch.parse(self.cheats[cid][2])
                if got:
                    out += [(self.cheats[cid][1], p) for p in got[1]]
        return out

    def off_and_restore(self, line, patches):
        """Worker: the cheats off, then the game's instructions back where a code-patch cheat's
        patch is still in the game (Breeze does this on its second press; dmnt never does). A
        word holding something else is left alone. R1 patches need the master cheat's R1."""
        c = self.client
        r = c.cmd(line)
        if not r.startswith("+OK") or not patches:
            return r
        meta = json.loads(c.cmd("meta")[4:] or "{}")
        main, r1 = int(meta.get("main", "0"), 16), int(meta.get("r1", "0"), 16)
        restored, skipped = 0, 0
        for _name, p in patches:
            at = p.address(main, r1)
            if at is None:
                skipped += 1
                continue
            if p.hack == p.original:
                continue
            got = c.cmd("peek %X 4" % at)
            if not got.startswith("+OK") or struct.unpack("<I", bytes.fromhex(got.split()[-1]))[0] != p.hack:
                continue
            if c.cmd("poke %X %s" % (at, struct.pack("<I", p.original).hex())).startswith("+OK"):
                restored += 1
        note = "; %d original instruction%s restored" % (restored, "" if restored == 1 else "s")
        if skipped:
            note += " (%d R1 patch%s skipped: no R1 known)" % (skipped, "" if skipped == 1 else "es")
        return r + note

    def simple(self, line):
        self.run(lambda: self.client.cmd(line), lambda r: (self.status.set(r), self.refresh()))

    def load_from_sd(self):
        """The game's cheat file on the SD (the one Save to SD writes) read again, replacing the
        list: edits not saved are lost."""
        if not messagebox.askyesno("Load from SD", "Read the game's cheat file on the SD again?\n\n"
                                   "It replaces the cheats loaded now; changes not saved to SD are lost.",
                                   parent=self.root):
            return

        def done(r):
            self.status.set(r)
            self.refresh()
            # Lichii takes the new list on the cheat engine's next pass: list it again then.
            self.root.after(700, self.refresh)
        self.run(lambda: self.client.cmd("cheats load"), done)

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
        # A file to share: each code-patch cheat gets a "<name> - restore" cheat for players
        # whose cheat tool does not put the originals back (as Breeze's atm file).
        listed = [(self.cheats[cid][1], self.cheats[cid][2]) for cid in self.order]
        cheats = code_patch.with_restore_cheats(listed)
        for name, words in cheats:
            parts.append("[%s]\n%s\n" % (name, "\n".join(code_lines(words))))
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(parts))
        added = len(cheats) - len(listed)
        self.status.set("exported %d cheat(s) to %s%s" % (
            len(cheats), path, " (%d - restore cheat%s added)" % (added, "" if added == 1 else "s") if added else ""))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else ""
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 6801
    root = tk.Tk()
    App(root, host, code, port)
    root.mainloop()


if __name__ == "__main__":
    main()
