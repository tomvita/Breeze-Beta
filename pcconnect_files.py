"""Two-panel file manager for the Breeze PC app: the Switch on the left, this PC
on the right. Opened from pcconnect_app.py's Files button.

It talks to Breeze over a PC connect connection of its own (the "fs" commands,
see pcconnect.md), so a long copy does not stall the screen in the main window.

Keys, in the panel that has the focus: Enter opens a folder, Backspace goes up,
Tab changes panel, F5 copies the selection to the other panel, F7 makes a
folder, F2 renames, F8 or Delete deletes, Ctrl+R reloads.

The Switch side's list of places belongs to the running game. It is read again
whenever the window gets the focus back, so after another game has been
started the list, and a panel that was showing the old game's folder, follow.

The PC side has a list too: the game's folder on this PC, named after the title
or after its title id, under a base folder picked with "Base folder...". The
folder is made when it does not exist. With a game running the PC side starts
in the title-name folder. The base folder is remembered in ~/.breeze_pc.json
("pc_game_base"); until one is picked it is "Breeze games" in the home folder.
"""
import ctypes
import os
import queue
import string
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from pcconnect import Breeze

PIECE = 1 << 20          # bytes per fsget / fsput
DRIVES = "<drives>"      # the PC panel's list of drive letters
# The PC side's list: the game's folder under the base folder, by name or by id.
PC_PLACES = ("Game directory (title name)", "Game directory (title id)")


def pc_folder_name(name):
    """A title name as a Windows folder name."""
    name = "".join("_" if c in '<>:"/\\|?*' or ord(c) < 32 else c for c in name)
    return name.rstrip(" .")


class _Guid(ctypes.Structure):
    _fields_ = [("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort), ("d3", ctypes.c_ushort), ("d4", ctypes.c_ubyte * 8)]


class _FormatEtc(ctypes.Structure):
    _fields_ = [("format", ctypes.c_ushort), ("device", ctypes.c_void_p), ("aspect", ctypes.c_ulong),
                ("index", ctypes.c_long), ("tymed", ctypes.c_ulong)]


class _StgMedium(ctypes.Structure):
    _fields_ = [("tymed", ctypes.c_ulong), ("handle", ctypes.c_void_p), ("release", ctypes.c_void_p)]


def _guid(text):
    g = _Guid()
    ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(text), ctypes.byref(g))
    return g


def _com_call(obj, index, restype, *argtypes):
    """Method `index` of a COM object's vtable, as a callable taking the arguments after `this`."""
    vtable = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    fn = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(vtable[index])
    return lambda *args: fn(obj, *args)


def _prefer_copy(data):
    """Tells a drop target that copying is what we would like ("Preferred DropEffect" = copy).
    Explorer would otherwise move files dropped on the same drive."""
    k, u = ctypes.windll.kernel32, ctypes.windll.user32
    k.GlobalAlloc.restype = k.GlobalLock.restype = ctypes.c_void_p
    k.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    k.GlobalLock.argtypes = k.GlobalUnlock.argtypes = k.GlobalFree.argtypes = [ctypes.c_void_p]
    mem = k.GlobalAlloc(2, 4)   # GMEM_MOVEABLE
    if not mem:
        return
    ctypes.cast(k.GlobalLock(mem), ctypes.POINTER(ctypes.c_ulong))[0] = 1   # DROPEFFECT_COPY
    k.GlobalUnlock(mem)
    fmt = _FormatEtc(u.RegisterClipboardFormatW(ctypes.c_wchar_p("Preferred DropEffect")), None, 1, -1, 1)
    medium = _StgMedium(1, mem, None)   # TYMED_HGLOBAL
    set_data = _com_call(data, 7, ctypes.c_long, ctypes.POINTER(_FormatEtc), ctypes.POINTER(_StgMedium), ctypes.c_int)
    if set_data(ctypes.byref(fmt), ctypes.byref(medium), 1) != 0:   # 1: the object frees the memory
        k.GlobalFree(mem)


def drag_files(hwnd, paths):
    """Starts a Windows drag of these files and folders, as Explorer would, and
    returns when the mouse button comes up: the effect of the drop (1 copy,
    2 move, 4 link), or 0 when nothing took them.

    The shell builds the data object and supplies the drop source, so no extra
    package is needed. Copy, move and link are all offered, as Explorer offers
    them: a web page's reply box refuses a drag that offers copy alone."""
    if sys.platform != "win32" or not paths:
        return 0
    shell32, ole32 = ctypes.windll.shell32, ctypes.windll.ole32
    ole32.OleInitialize(None)
    shell32.SHParseDisplayName.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    shell32.SHCreateShellItemArrayFromIDLists.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p),
                                                          ctypes.POINTER(ctypes.c_void_p)]
    shell32.SHDoDragDrop.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                     ctypes.POINTER(ctypes.c_ulong)]
    shell32.ILFree.argtypes = [ctypes.c_void_p]
    pidls = []
    array = ctypes.c_void_p()
    data = ctypes.c_void_p()
    try:
        for p in paths:
            pidl = ctypes.c_void_p()
            if shell32.SHParseDisplayName(os.path.abspath(p), None, ctypes.byref(pidl), 0, None) == 0 and pidl:
                pidls.append(pidl)
        if not pidls:
            return 0
        items = (ctypes.c_void_p * len(pidls))(*[p.value for p in pidls])
        if shell32.SHCreateShellItemArrayFromIDLists(len(pidls), items, ctypes.byref(array)) != 0:
            return 0
        # IShellItemArray::BindToHandler(NULL, BHID_DataObject, IID_IDataObject, &data)
        bind = _com_call(array, 3, ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(_Guid), ctypes.POINTER(_Guid),
                         ctypes.POINTER(ctypes.c_void_p))
        bhid = _guid("{B8C0BD9F-ED24-455C-83E6-D5390C4FE8C4}")
        iid = _guid("{0000010E-0000-0000-C000-000000000046}")
        if bind(None, ctypes.byref(bhid), ctypes.byref(iid), ctypes.byref(data)) != 0:
            return 0
        _prefer_copy(data)
        effect = ctypes.c_ulong(0)
        hr = shell32.SHDoDragDrop(hwnd, data, None, 1 | 2 | 4, ctypes.byref(effect))   # copy, move, link
        return effect.value if hr == 0x00040100 else 0                                  # DRAGDROP_S_DROP
    finally:
        for obj in (data, array):
            if obj:
                _com_call(obj, 2, ctypes.c_ulong)()   # IUnknown::Release
        for pidl in pidls:
            shell32.ILFree(pidl)


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def switch_join(folder, name):
    return folder + ("" if folder.endswith("/") else "/") + name


def switch_parent(path):
    """sdmc:/a/b/ -> sdmc:/a/ ; a device root has no parent."""
    p = path.rstrip("/")
    if p.endswith(":"):
        return None
    return p[:p.rfind("/") + 1]


class Worker(threading.Thread):
    """Runs jobs one at a time on its own Breeze connection. A job is
    fn(breeze, worker); what it returns, or the exception, goes to `out`."""

    def __init__(self, host, code, out):
        super().__init__(daemon=True)
        self.host, self.code, self.out = host, code, out
        self.jobs = queue.Queue()
        self.cancel = threading.Event()
        self.breeze = None
        self.closed = False

    def submit(self, fn, done):
        self.jobs.put((fn, done))

    def progress(self, text, fraction):
        self.out.put(("progress", text, fraction))

    def run(self):
        while not self.closed:
            fn, done = self.jobs.get()
            if fn is None:
                break
            self.cancel.clear()
            try:
                if self.breeze is None:
                    self.breeze = Breeze(self.host, self.code, timeout=30)
                self.out.put(("done", done, fn(self.breeze, self), None))
            except Exception as e:  # noqa: BLE001 - shown to the user
                if isinstance(e, (OSError, ConnectionError)):
                    self.breeze = None  # reconnect for the next job
                self.out.put(("done", done, None, e))
        if self.breeze is not None:
            self.breeze.close()

    def close(self):
        self.closed = True
        self.cancel.set()
        self.jobs.put((None, None))


class Cancelled(Exception):
    pass


class FileManager:
    def __init__(self, parent, host, code, cfg=None, save_cfg=None):
        self.cfg = cfg if cfg is not None else {}
        self.save_cfg = save_cfg or (lambda: None)
        self.pc_base = self.cfg.get("pc_game_base") or os.path.join(os.path.expanduser("~"), "Breeze games")
        self.title_name = ""
        self.pc_game_dir = None   # the game folder the PC side was sent to, to tell whether it is still there
        self.win = tk.Toplevel(parent)
        self.win.title("Breeze files - %s" % host)
        self.win.geometry("1100x600")
        self.out = queue.Queue()
        self.worker = Worker(host, code, self.out)
        self.worker.start()
        self.busy = False
        self.roots = []
        self.title_id = None      # the game the list of places is for
        self.roots_asked = 0.0    # when it was last asked for
        self.sw_path = "sdmc:/switch/Breeze/"
        self.sw_read_only = False
        self.sw_entries = []
        self.pc_path = os.path.expanduser("~")
        self.pc_entries = []
        self.active = "sw"

        panes = tk.Frame(self.win)
        panes.pack(fill="both", expand=True)
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=1)
        panes.rowconfigure(1, weight=1)

        top_l = tk.Frame(panes)
        top_l.grid(row=0, column=0, sticky="ew")
        self.root_box = ttk.Combobox(top_l, state="readonly", width=30)
        self.root_box.pack(side="left")
        self.root_box.bind("<<ComboboxSelected>>", self.on_root)
        self.sw_entry = tk.Entry(top_l)
        self.sw_entry.pack(side="left", fill="x", expand=True)
        self.sw_entry.bind("<Return>", lambda e: self.load_switch(self.sw_entry.get().strip()))

        top_r = tk.Frame(panes)
        top_r.grid(row=0, column=1, sticky="ew")
        self.pc_box = ttk.Combobox(top_r, state="disabled", width=27, values=PC_PLACES)
        self.pc_box.pack(side="left")
        self.pc_box.bind("<<ComboboxSelected>>", lambda e: self.go_pc_game())
        self.pc_entry = tk.Entry(top_r)
        self.pc_entry.pack(side="left", fill="x", expand=True)
        self.pc_entry.bind("<Return>", lambda e: self.load_pc(self.pc_entry.get().strip()))

        self.sw_tree = self.make_tree(panes, 0, "sw")
        self.pc_tree = self.make_tree(panes, 1, "pc")

        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        self.to_pc_btn = tk.Button(bar, text="Copy to PC  →", command=lambda: self.copy("sw"))
        self.to_pc_btn.pack(side="left")
        self.to_sw_btn = tk.Button(bar, text="←  Copy to Switch", command=lambda: self.copy("pc"))
        self.to_sw_btn.pack(side="left")
        tk.Button(bar, text="New folder (F7)", command=self.make_folder).pack(side="left")
        tk.Button(bar, text="Rename (F2)", command=self.rename).pack(side="left")
        tk.Button(bar, text="Delete (F8)", command=self.delete).pack(side="left")
        tk.Button(bar, text="Reload", command=self.reload).pack(side="left")
        tk.Button(bar, text="Base folder...", command=self.pick_pc_base).pack(side="left")
        self.cancel_btn = tk.Button(bar, text="Cancel", command=self.worker.cancel.set, state="disabled")
        self.cancel_btn.pack(side="right")
        # The progress bar fills the gap between the buttons and Cancel; a row of
        # its own was an empty band whenever nothing was being copied.
        self.bar = ttk.Progressbar(bar, maximum=1000)
        self.bar.pack(side="left", fill="x", expand=True, padx=6)
        self.status = tk.Label(self.win, text="", anchor="w")
        self.status.pack(fill="x")

        self.win.bind("<F5>", lambda e: self.copy(self.active))
        self.win.bind("<F7>", lambda e: self.make_folder())
        self.win.bind("<F2>", lambda e: self.rename())
        self.win.bind("<F8>", lambda e: self.delete())
        self.win.bind("<Control-r>", lambda e: self.reload())
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.win.bind("<FocusIn>", self.on_focus)

        self.load_pc(self.pc_path)
        self.ask_roots()
        self.win.after(50, self.pump)

    # ------------------------------------------------------------ widgets
    def make_tree(self, parent, column, side):
        frame = tk.Frame(parent)
        frame.grid(row=1, column=column, sticky="nsew")
        tree = ttk.Treeview(frame, columns=("size",), selectmode="extended")
        tree.heading("#0", text="Name", anchor="w")
        tree.heading("size", text="Size", anchor="e")
        tree.column("#0", width=380)
        tree.column("size", width=90, anchor="e", stretch=False)
        scroll = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        tree.bind("<Double-Button-1>", lambda e: self.open_selected(side))
        tree.bind("<Return>", lambda e: self.open_selected(side))
        tree.bind("<BackSpace>", lambda e: self.go_up(side))
        tree.bind("<Delete>", lambda e: self.delete())
        tree.bind("<FocusIn>", lambda e: self.set_active(side))
        tree.bind("<Tab>", lambda e: self.other_tree(side).focus_set() or "break")
        if side == "pc":
            # Files on this PC can be dragged out to Explorer or another program.
            tree.bind("<ButtonPress-1>", self.on_pc_press)
            tree.bind("<B1-Motion>", self.on_pc_motion)
        return tree

    def on_pc_press(self, e):
        # A press on a row that is already selected keeps the whole selection
        # for a drag; the list itself is about to reduce it to that one row.
        row = self.pc_tree.identify_row(e.y)
        keep = self.pc_tree.selection()
        self.pc_drag = (e.x, e.y, keep if row in keep else (row,)) if row and row != ".." else None

    def on_pc_motion(self, e):
        drag = getattr(self, "pc_drag", None)
        if drag is None or self.pc_path == DRIVES or abs(e.x - drag[0]) + abs(e.y - drag[1]) < 8:
            return "break" if drag else None
        self.pc_drag = None
        self.pc_tree.selection_set(*drag[2])
        paths = [os.path.join(self.pc_path, self.pc_entries[int(i)][0]) for i in drag[2]]
        drag_files(self.win.winfo_id(), paths)
        self.win.after(500, lambda: self.load_pc(self.pc_path))   # Explorer may have moved them (Shift held)
        return "break"

    def other_tree(self, side):
        return self.pc_tree if side == "sw" else self.sw_tree

    def tree(self, side):
        return self.sw_tree if side == "sw" else self.pc_tree

    def set_active(self, side):
        # One selection at a time: with both sides highlighted there is no telling
        # which one F5, rename or delete will act on.
        self.active = side
        other = self.other_tree(side)
        if other.selection():
            other.selection_remove(*other.selection())

    def fill(self, side, entries, has_parent):
        tree = self.tree(side)
        tree.delete(*tree.get_children())
        if has_parent:
            tree.insert("", "end", iid="..", text="[..]", values=("",))
        for i, (name, is_dir, size) in enumerate(entries):
            tree.insert("", "end", iid=str(i), text=("[%s]" % name) if is_dir else name,
                        values=("" if is_dir else human(size),))

    def selection(self, side):
        """[(name, is_dir, size)] of the selected rows, without [..]."""
        entries = self.sw_entries if side == "sw" else self.pc_entries
        return [entries[int(i)] for i in self.tree(side).selection() if i != ".."]

    # ------------------------------------------------------------ worker results
    def pump(self):
        try:
            while True:
                item = self.out.get_nowait()
                if item[0] == "progress":
                    self.status.config(text=item[1])
                    self.bar.config(value=int(item[2] * 1000))
                else:
                    _, done, result, error = item
                    done(result, error)
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(50, self.pump)

    def fail(self, error):
        if isinstance(error, Cancelled):
            self.status.config(text="cancelled")
            return
        text = str(error)
        self.status.config(text=text)
        if "-ERR denied" in text:
            # The game is not in the list of games Breeze may read yet.
            if messagebox.askokcancel(
                    "Game files", "Breeze is not allowed to read this game's files yet.\n\n"
                    "Allow it now? Breeze then has to be closed and opened again once, "
                    "by pressing HOME twice on the Switch.", parent=self.win):
                self.worker.submit(lambda b, w: b.cmd("romfsprobe enable"), self.after_enable)
            return
        messagebox.showerror("Files", text[5:] if text.startswith("-ERR ") else text, parent=self.win)

    def after_enable(self, reply, error):
        reply = reply or ""
        if error or not reply.startswith("+OK") or ('"enable":"added"' not in reply and '"enable":"listed"' not in reply):
            messagebox.showerror("Game files", "The game could not be added: %s" % (error or reply), parent=self.win)
            return
        if '"reopen":true' not in reply:
            self.load_switch(self.sw_path)
            return
        messagebox.showinfo(
            "Game files", "The game is allowed now. Breeze has to be reopened once:\n\n"
            "1. Press HOME twice on the Switch: the first press closes Breeze, the second opens it again.\n"
            "2. Pick the game's files here once more.\n\n"
            "Home toggle has been set to Fast restart for this. "
            "Breeze puts it back to what it was when it starts again.", parent=self.win)

    def set_busy(self, busy):
        self.busy = busy
        self.cancel_btn.config(state="normal" if busy else "disabled")
        if not busy:
            self.bar.config(value=0)

    # ------------------------------------------------------------ the Switch panel
    def ask_roots(self):
        self.roots_asked = time.time()
        self.worker.submit(lambda b, w: b.json("fs roots"), self.got_roots)

    def on_focus(self, _e):
        # Every widget in the window reports its own focus: ask once, not while
        # a copy is running, and not more than every few seconds.
        if not self.busy and time.time() - self.roots_asked > 3:
            self.ask_roots()

    def got_roots(self, reply, error):
        first = self.title_id is None
        if error:
            if first:
                self.fail(error)
            reply = {}
        roots = reply.get("roots") or [{"name": "SD card", "path": "sdmc:/"}]
        title = reply.get("title_id", "")
        if roots == self.roots and title == self.title_id:
            return
        old = self.roots[self.root_box.current()] if self.roots and self.root_box.current() >= 0 else None
        game_changed = title != self.title_id
        self.roots, self.title_id = roots, title
        self.set_pc_game(reply.get("title_name", ""), first or game_changed)
        self.root_box.config(values=[r["name"] for r in roots])
        paths = [r["path"] for r in roots]
        if not first and not game_changed and old and old["path"] in paths:
            # same game, the list only grew or shrank: stay where we are
            self.root_box.current(paths.index(old["path"]))
            return
        # Another game (or the first time): the place with the same name for
        # this game if there is one, else the first.
        names = [r["name"].lstrip("* ") for r in roots]
        want = old["name"].lstrip("* ") if old else None
        index = names.index(want) if want in names else 0
        self.root_box.current(index)
        self.load_switch(roots[index]["path"])

    def on_root(self, _e):
        self.load_switch(self.roots[self.root_box.current()]["path"])
        self.sw_tree.focus_set()

    def load_switch(self, path):
        if not path:
            return
        if not path.endswith("/"):
            path += "/"

        def done(entries, error):
            if error:
                self.fail(error)
                return
            self.sw_path, self.sw_entries = path, entries
            self.sw_read_only = path.startswith("game:/")
            self.sw_entry.delete(0, "end")
            self.sw_entry.insert(0, path)
            self.fill("sw", entries, switch_parent(path) is not None)
            self.to_sw_btn.config(state="disabled" if self.sw_read_only else "normal")
            self.status.config(text="%s: %d item(s)%s" % (path, len(entries), "  (read-only)" if self.sw_read_only else ""))
        self.worker.submit(lambda b, w: b.fs_ls(path), done)

    # ------------------------------------------------------------ the PC side's game folder
    def set_pc_game(self, title_name, changed):
        """Called with every fresh list of places. `changed`: first list, or another game."""
        if not title_name:
            # an older Breeze does not send the name: take it from its folder on the Switch
            for r in self.roots:
                if "(title name)" in r["name"]:
                    title_name = r["path"].rstrip("/").rsplit("/", 1)[-1]
        self.title_name = title_name
        if not self.title_id:
            self.pc_box.set("")
            self.pc_box.config(state="disabled")
            return
        self.pc_box.config(state="readonly")
        if not changed:
            return
        # Follow the game, unless the user has walked away from the game folder.
        if self.pc_game_dir is None or os.path.normcase(self.pc_path) == os.path.normcase(self.pc_game_dir):
            if self.pc_box.current() < 0:
                self.pc_box.current(0)
            self.go_pc_game()

    def go_pc_game(self):
        """Opens the game's folder under the base folder, making it first if needed."""
        if not self.title_id:
            return
        by_name = self.pc_box.current() == 0 and self.title_name
        if self.pc_box.current() == 0 and not by_name:
            self.pc_box.current(1)   # no name known: only the id can be offered
        folder = pc_folder_name(self.title_name) if by_name else self.title_id
        path = os.path.join(self.pc_base, folder)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Files", "The folder could not be made:\n%s" % e, parent=self.win)
            return
        self.pc_game_dir = path
        self.load_pc(path)

    def pick_pc_base(self):
        picked = filedialog.askdirectory(parent=self.win, initialdir=self.pc_base if os.path.isdir(self.pc_base) else None,
                                         title="Folder that holds one folder per game")
        if not picked:
            return
        self.pc_base = os.path.normpath(picked)
        self.cfg["pc_game_base"] = self.pc_base
        self.save_cfg()
        self.status.config(text="game folders on this PC are under " + self.pc_base)
        if self.title_id and self.pc_box.current() >= 0:
            self.go_pc_game()

    # ------------------------------------------------------------ the PC panel
    def load_pc(self, path):
        if not path:
            return
        try:
            if path == DRIVES:
                entries = [(d + ":\\", True, 0) for d in string.ascii_uppercase if os.path.exists(d + ":\\")]
            else:
                path = os.path.abspath(path)
                entries = []
                with os.scandir(path) as it:
                    for e in it:
                        try:
                            is_dir = e.is_dir()
                            entries.append((e.name, is_dir, 0 if is_dir else e.stat().st_size))
                        except OSError:
                            pass
                entries.sort(key=lambda x: (not x[1], x[0].lower()))
        except OSError as e:
            messagebox.showerror("Files", str(e), parent=self.win)
            return
        self.pc_path, self.pc_entries = path, entries
        self.pc_entry.delete(0, "end")
        self.pc_entry.insert(0, path)
        self.fill("pc", entries, path != DRIVES)

    def pc_parent(self):
        if self.pc_path == DRIVES:
            return None
        parent = os.path.dirname(self.pc_path.rstrip("\\/"))
        if os.name == "nt" and (not parent or parent == self.pc_path or len(self.pc_path.rstrip("\\/")) <= 2):
            return DRIVES
        return parent or None

    # ------------------------------------------------------------ navigation
    def open_selected(self, side):
        tree = self.tree(side)
        row = tree.focus() or (tree.selection() or [None])[0]
        if row is None:
            return
        if row == "..":
            self.go_up(side)
            return
        name, is_dir, _ = (self.sw_entries if side == "sw" else self.pc_entries)[int(row)]
        if not is_dir:
            return
        if side == "sw":
            self.load_switch(switch_join(self.sw_path, name))
        else:
            self.load_pc(name if self.pc_path == DRIVES else os.path.join(self.pc_path, name))

    def go_up(self, side):
        if side == "sw":
            parent = switch_parent(self.sw_path)
            if parent:
                self.load_switch(parent)
        else:
            parent = self.pc_parent()
            if parent:
                self.load_pc(parent)

    def reload(self):
        self.load_switch(self.sw_path)
        self.load_pc(self.pc_path)

    # ------------------------------------------------------------ copying
    def copy(self, source):
        if self.busy:
            return
        items = self.selection(source)
        if not items:
            return
        if source == "pc" and self.sw_read_only:
            messagebox.showinfo("Files", "The game's files are read-only.", parent=self.win)
            return
        if source == "sw" and self.pc_path == DRIVES or source == "pc" and self.pc_path == DRIVES:
            messagebox.showinfo("Files", "Open a folder on the PC side first.", parent=self.win)
            return
        there = {e[0].lower() for e in (self.pc_entries if source == "sw" else self.sw_entries)}
        clash = [n for n, _, _ in items if n.lower() in there]
        if clash and not messagebox.askokcancel(
                "Copy", "%d of these already exist(s) on the other side and will be overwritten:\n\n%s" % (
                    len(clash), "\n".join(clash[:12]) + ("\n..." if len(clash) > 12 else "")), parent=self.win):
            return
        sw_dir, pc_dir = self.sw_path, self.pc_path
        job = (lambda b, w: self.job_to_pc(b, w, sw_dir, pc_dir, items)) if source == "sw" else \
              (lambda b, w: self.job_to_switch(b, w, sw_dir, pc_dir, items))
        self.set_busy(True)

        def done(result, error):
            self.set_busy(False)
            if error:
                self.fail(error)
            else:
                self.status.config(text="copied %d file(s), %s" % result)
            (self.load_pc(self.pc_path) if source == "sw" else self.load_switch(self.sw_path))
        self.worker.submit(job, done)

    @staticmethod
    def job_to_pc(b, w, sw_dir, pc_dir, items):
        # (switch path, pc path, size), folders walked on the Switch
        files = []

        def walk(sw, pc, entries):
            for name, is_dir, size in entries:
                if w.cancel.is_set():
                    raise Cancelled()
                if is_dir:
                    os.makedirs(os.path.join(pc, name), exist_ok=True)
                    sub = switch_join(sw, name) + "/"
                    w.progress("reading " + sub, 0)
                    walk(sub, os.path.join(pc, name), b.fs_ls(sub))
                else:
                    files.append((switch_join(sw, name), os.path.join(pc, name), size))
        walk(sw_dir, pc_dir, items)
        total, moved = sum(f[2] for f in files) or 1, 0
        for sw, pc, size in files:
            part = pc + ".part"
            with open(part, "wb") as f:
                offset = 0
                while True:
                    if w.cancel.is_set():
                        f.close()
                        os.remove(part)
                        raise Cancelled()
                    data, whole = b.fs_get(sw, offset, PIECE)
                    f.write(data)
                    offset += len(data)
                    moved += len(data)
                    w.progress("%s  %s / %s" % (os.path.basename(pc), human(offset), human(whole)), moved / total)
                    if not data or offset >= whole:
                        break
            os.replace(part, pc)
        return len(files), human(moved)

    @staticmethod
    def job_to_switch(b, w, sw_dir, pc_dir, items):
        files = []

        def walk(sw, pc, entries):
            for name, is_dir, size in entries:
                if w.cancel.is_set():
                    raise Cancelled()
                if is_dir:
                    b.fs_do("mkdir " + switch_join(sw, name))
                    sub = os.path.join(pc, name)
                    inner = []
                    with os.scandir(sub) as it:
                        for e in it:
                            d = e.is_dir()
                            inner.append((e.name, d, 0 if d else e.stat().st_size))
                    walk(switch_join(sw, name) + "/", sub, inner)
                else:
                    files.append((os.path.join(pc, name), switch_join(sw, name), size))
        walk(sw_dir, pc_dir, items)
        total, moved = sum(f[2] for f in files) or 1, 0
        for pc, sw, size in files:
            with open(pc, "rb") as f:
                offset = 0
                while True:
                    if w.cancel.is_set():
                        raise Cancelled()
                    data = f.read(PIECE)
                    if not data and offset > 0:
                        break
                    b.fs_put(sw, offset, data)   # offset 0 creates the file, also an empty one
                    offset += len(data)
                    moved += len(data)
                    w.progress("%s  %s / %s" % (os.path.basename(pc), human(offset), human(size)), moved / total)
                    if len(data) < PIECE:
                        break
        return len(files), human(moved)

    # ------------------------------------------------------------ folder, rename, delete
    def make_folder(self):
        side = self.active
        if side == "sw" and self.sw_read_only:
            return
        name = simpledialog.askstring("New folder", "Name:", parent=self.win)
        if not name:
            return
        if side == "pc":
            try:
                os.makedirs(os.path.join(self.pc_path, name), exist_ok=True)
            except OSError as e:
                messagebox.showerror("Files", str(e), parent=self.win)
            self.load_pc(self.pc_path)
        else:
            path = switch_join(self.sw_path, name)
            self.worker.submit(lambda b, w: b.fs_do("mkdir " + path), self.after_switch_change)

    def rename(self):
        side = self.active
        items = self.selection(side)
        if len(items) != 1 or (side == "sw" and self.sw_read_only):
            return
        old = items[0][0]
        new = simpledialog.askstring("Rename", "New name:", initialvalue=old, parent=self.win)
        if not new or new == old:
            return
        if side == "pc":
            try:
                os.rename(os.path.join(self.pc_path, old), os.path.join(self.pc_path, new))
            except OSError as e:
                messagebox.showerror("Files", str(e), parent=self.win)
            self.load_pc(self.pc_path)
        else:
            line = "mv %s\t%s" % (switch_join(self.sw_path, old), switch_join(self.sw_path, new))
            self.worker.submit(lambda b, w: b.fs_do(line), self.after_switch_change)

    def delete(self):
        side = self.active
        items = self.selection(side)
        if not items or (side == "sw" and self.sw_read_only) or (side == "pc" and self.pc_path == DRIVES):
            return
        where = "the Switch" if side == "sw" else "this PC"
        names = "\n".join(n for n, _, _ in items[:12]) + ("\n..." if len(items) > 12 else "")
        if not messagebox.askokcancel("Delete", "Delete %d item(s) from %s? Folders go with everything in them.\n\n%s" % (
                len(items), where, names), icon="warning", parent=self.win):
            return
        if side == "pc":
            import shutil
            try:
                for name, is_dir, _ in items:
                    full = os.path.join(self.pc_path, name)
                    shutil.rmtree(full) if is_dir else os.remove(full)
            except OSError as e:
                messagebox.showerror("Files", str(e), parent=self.win)
            self.load_pc(self.pc_path)
        else:
            paths = [switch_join(self.sw_path, n) for n, _, _ in items]

            def job(b, w):
                for p in paths:
                    b.fs_do("rm " + p)
            self.worker.submit(job, self.after_switch_change)

    def after_switch_change(self, _result, error):
        if error:
            self.fail(error)
        self.load_switch(self.sw_path)

    def close(self):
        self.worker.close()
        self.win.destroy()
