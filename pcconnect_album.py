#!/usr/bin/env python3
"""The album of the Breeze PC app: the screenshots kept for a game on this PC.

Opened with the app's Album button. The pictures are the files in the
`album` folder inside the game's folder on the PC (see pcconnect_files.py for
where that is); the app's Screenshot button saves there.

- Thumbnails, newest first. Click to select, Ctrl+click and Shift+click for more.
- Double-click (or Enter) opens a picture in the program Windows uses for it.
- Drag the selection out of the window to copy it somewhere else: an Explorer
  folder, a chat, the reply box of a web page. Windows only.
- Delete removes the selection, after asking. Open folder shows it in Explorer.
"""
import os
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox

from PIL import Image, ImageTk

from pcconnect_files import drag_files

PICTURES = (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp")
THUMB_W, THUMB_H = 192, 108
CELL_W, CELL_H = THUMB_W + 16, THUMB_H + 34


def open_path(path):
    """Opens a file or a folder with whatever the system uses for it."""
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - a picture or folder the user picked
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path])


class Album:
    def __init__(self, parent, folder, title=""):
        self.folder = folder
        self.win = tk.Toplevel(parent)
        self.win.geometry("%dx%d" % (CELL_W * 4 + 30, CELL_H * 3 + 60))
        self.files = []        # names, newest first
        self.selected = set()
        self.anchor = None
        self.thumbs = {}       # name -> (mtime, PhotoImage)
        self.pending = []      # names still to load
        self.columns = 1
        self.press = None      # where the mouse went down, for telling a drag from a click

        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        tk.Button(bar, text="Open", command=self.open_selected).pack(side="left")
        tk.Button(bar, text="Delete", command=self.delete_selected).pack(side="left")
        tk.Button(bar, text="Open folder", command=lambda: open_path(self.folder)).pack(side="left")
        tk.Button(bar, text="Reload", command=self.reload).pack(side="left")
        self.info = tk.Label(bar, text="", anchor="w", fg="#555")
        self.info.pack(side="left", fill="x", expand=True)

        self.canvas = tk.Canvas(self.win, bg="#202020", highlightthickness=0)
        scroll = tk.Scrollbar(self.win, orient="vertical", command=self.canvas.yview)
        self.canvas.config(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.layout())
        self.canvas.bind("<ButtonPress-1>", self.on_press)
        self.canvas.bind("<B1-Motion>", self.on_motion)
        self.canvas.bind("<Double-Button-1>", lambda e: self.open_selected())
        self.canvas.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.win.bind("<Return>", lambda e: self.open_selected())
        self.win.bind("<Delete>", lambda e: self.delete_selected())
        self.win.bind("<F5>", lambda e: self.reload())
        self.set_folder(folder, title)

    def set_folder(self, folder, title=""):
        """Shows another game's album (the app calls this when the game changes)."""
        self.folder = folder
        self.win.title("Album - %s" % (title or os.path.basename(os.path.dirname(folder))))
        self.selected.clear()
        self.anchor = None
        self.reload()

    def reload(self):
        try:
            names = [n for n in os.listdir(self.folder) if n.lower().endswith(PICTURES)]
        except OSError:
            names = []

        def mtime(n):
            try:
                return os.path.getmtime(os.path.join(self.folder, n))
            except OSError:
                return 0
        self.files = sorted(names, key=mtime, reverse=True)
        self.selected &= set(self.files)
        for n in list(self.thumbs):
            if n not in self.files:
                del self.thumbs[n]
        self.pending = [n for n in self.files if n not in self.thumbs or self.thumbs[n][0] != mtime(n)]
        self.layout()
        if self.pending:
            self.win.after(1, self.load_some)

    def load_some(self):
        """A few thumbnails per turn of the event loop, so a big album does not freeze the window."""
        if not self.win.winfo_exists():
            return
        for _ in range(6):
            if not self.pending:
                break
            name = self.pending.pop(0)
            path = os.path.join(self.folder, name)
            try:
                img = Image.open(path)
                img.draft("RGB", (THUMB_W * 2, THUMB_H * 2))   # JPEG: decode small, much faster
                img.thumbnail((THUMB_W, THUMB_H))
                self.thumbs[name] = (os.path.getmtime(path), ImageTk.PhotoImage(img.convert("RGB")))
            except Exception:  # noqa: BLE001 - a file that is not a picture after all
                self.thumbs[name] = (0, None)
        self.draw()
        if self.pending:
            self.win.after(1, self.load_some)

    def layout(self):
        self.columns = max(1, self.canvas.winfo_width() // CELL_W)
        rows = (len(self.files) + self.columns - 1) // self.columns
        self.canvas.config(scrollregion=(0, 0, self.columns * CELL_W, max(rows * CELL_H, 1)))
        self.draw()

    def draw(self):
        c = self.canvas
        c.delete("all")
        for i, name in enumerate(self.files):
            x, y = (i % self.columns) * CELL_W, (i // self.columns) * CELL_H
            on = name in self.selected
            c.create_rectangle(x + 3, y + 3, x + CELL_W - 3, y + CELL_H - 3,
                               fill="#3465a4" if on else "#2c2c2c", outline="")
            photo = self.thumbs.get(name, (0, None))[1]
            if photo is not None:
                c.create_image(x + CELL_W // 2, y + 8 + THUMB_H // 2, image=photo)
            c.create_text(x + CELL_W // 2, y + THUMB_H + 20, text=name[:28], fill="white", font=("Segoe UI", 8))
        if not self.files:
            c.create_text(12, 12, anchor="nw", fill="#aaa",
                          text="No screenshots yet. The Screenshot button saves them here:\n%s" % self.folder)
        self.info.config(text="  %d picture(s), %d selected   %s" % (len(self.files), len(self.selected), self.folder))

    def index_at(self, e):
        x, y = self.canvas.canvasx(e.x), self.canvas.canvasy(e.y)
        col, row = int(x // CELL_W), int(y // CELL_H)
        i = row * self.columns + col
        return i if 0 <= col < self.columns and 0 <= i < len(self.files) else None

    def on_press(self, e):
        self.canvas.focus_set()
        i = self.index_at(e)
        self.press = (e.x, e.y) if i is not None else None
        if i is None:
            self.selected.clear()
        elif e.state & 0x1 and self.anchor is not None:          # Shift: a range
            a, b = sorted((self.anchor, i))
            self.selected = set(self.files[a:b + 1])
        elif e.state & 0x4:                                      # Ctrl: add or remove one
            self.selected ^= {self.files[i]}
            self.anchor = i
        elif self.files[i] not in self.selected:                 # a selected one keeps the group, for dragging
            self.selected = {self.files[i]}
            self.anchor = i
        self.draw()

    def on_motion(self, e):
        if self.press is None or abs(e.x - self.press[0]) + abs(e.y - self.press[1]) < 8:
            return
        self.press = None
        paths = [os.path.join(self.folder, n) for n in self.files if n in self.selected]
        if paths:
            effect = drag_files(self.win.winfo_id(), paths)
            self.info.config(text="  dropped" if effect else "  not dropped")
            self.win.after(500, self.reload)   # Explorer may have moved the files (Shift held)

    def open_selected(self):
        for n in [n for n in self.files if n in self.selected][:8]:
            try:
                open_path(os.path.join(self.folder, n))
            except OSError as e:
                messagebox.showerror("Album", str(e), parent=self.win)

    def delete_selected(self):
        names = [n for n in self.files if n in self.selected]
        if not names or not messagebox.askokcancel(
                "Delete", "Delete %d picture(s)?\n\n%s" % (len(names), "\n".join(names[:10])), parent=self.win):
            return
        for n in names:
            try:
                os.remove(os.path.join(self.folder, n))
            except OSError as e:
                messagebox.showerror("Album", str(e), parent=self.win)
        self.reload()
