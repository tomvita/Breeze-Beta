#!/usr/bin/env python3
"""Breeze PC text view: Breeze's screen as text, drawn on the PC.

Opened with "Text view" in pcconnect_app.py. It asks Breeze what its screen
holds (PC connect's `state`) instead of taking a picture of it, so it is quick,
the text can be selected and copied, and nothing is limited to what fits on
the Switch's screen:

- The list panel shows the rows around the cursor (400 of them, not 11), with
  Breeze's colours. Click a row to move Breeze's cursor there, double-click to
  press A on it. Drag to select text; Ctrl+C copies it.
- The action panel shows every action of the screen at once, whichever page
  or shift layer its button is on, with its key. A click runs it.
- The screens Breeze came through stay visible to the left of the current one,
  as they were left. Pin keeps a copy of a panel after Breeze has moved on, so
  two screens can be compared side by side.
- Find looks through every row of the list (Enter = next, Shift+Enter =
  previous) and moves Breeze's cursor to the match; Filter shows only the rows
  that match. Copy all and Save take the whole list.
- The font size of the lists and of the actions is set separately, the panels
  are resized by dragging the bars between them, and Detach actions puts the
  action panel in a window of its own.

Keys are the Switch's buttons as in the main window, apart from Ctrl+F (find),
Ctrl+C (copy), Ctrl+S (save) and F3 (next match).
"""
import json
import os
import re
import time
import tkinter as tk
from tkinter import filedialog, messagebox

ROWS = 400                 # rows asked for around the cursor
CHUNK = 2000               # rows per request when the whole list is wanted
CHANGED_MS = 1500          # how long a changed row stays marked
TAB_COLUMNS = 100          # a row's width in characters, for Breeze's {tNN} tab stops
TAB_GAP = [4]              # spaces between tab columns (the "Column gap" box)

BG, FG = "#1b2030", "#d8dce6"
BG_CUR, BG_HIT, FG_DIM = "#3a4a78", "#7a5a00", "#8a93a8"
BG_PANEL, BG_BTN, BG_BTN_OFF, BG_BTN_SEL = "#262c3f", "#39466a", "#2b3248", "#5c7fc4"
FG_CHANGED = "#ffb347"

# Switch button glyphs (private-use characters in Breeze's font) as text.
GLYPHS = {
    "": "A", "": "B", "": "X", "": "Y", "": "L", "": "R",
    "": "ZL", "": "ZR", "": "LS", "": "RS", "": "+", "": "-",
    "": "Left", "": "Up", "": "Right", "": "Down",
    "": "LS-left", "": "LS-up", "": "LS-right", "": "LS-down",
    "": "RS-left", "": "RS-up", "": "RS-right", "": "RS-down",
}
KEY_NAMES = {"PLUS": "Plus", "MINUS": "Minus", "UP": "Up", "DOWN": "Down", "LEFT": "Left", "RIGHT": "Right",
             "LSLEFT": "LS-left", "LSUP": "LS-up", "LSRIGHT": "LS-right",
             "LSDOWN": "LS-down", "RSLEFT": "RS-left", "RSUP": "RS-up", "RSRIGHT": "RS-right", "RSDOWN": "RS-down"}
CODE = re.compile(r"\{c([0-9A-Fa-f]{6})\}|\{r\}|\{t(\d{1,3})\}")
GLYPH = re.compile("[-]")


def glyphs(text):
    """Button glyphs as [A], [ZL]; consecutive ones as one chord [ZL+A]."""
    out, run = [], []
    for ch in text:
        if ch in GLYPHS:
            run.append(GLYPHS[ch])
            continue
        if run:
            out.append("[" + "+".join(run) + "]")
            run = []
        out.append(ch)
    if run:
        out.append("[" + "+".join(run) + "]")
    return GLYPH.sub("?", "".join(out))


def columns(text):
    """A row's tab-separated columns, as Breeze splits them (a run of tabs is one)."""
    parts = glyphs(text).split("\t")
    return [parts[0].rstrip()] + [p.strip() for p in parts[1:] if p.strip()]


def tab_stops(rows):
    """Where each column starts, in characters, so the columns line up down the whole list."""
    widths = []
    for raw in rows:
        cols = columns(raw)
        if len(cols) < 2:
            continue
        for i, c in enumerate(cols):
            n = len(CODE.sub("", c).rstrip())
            if i == len(widths):
                widths.append(n)
            elif n > widths[i]:
                widths[i] = n
    stops, at = [], 0
    for w in widths:
        stops.append(at)
        at += w + TAB_GAP[0]
    return tuple(stops)


def segments(text, stops=()):
    """A row as [(text, colour or None)]: colour codes applied, columns padded to their stops."""
    out, col = [], 0
    for i, part in enumerate(columns(text)):
        if i:
            pad = max((stops[i] if i < len(stops) else 0) - col, TAB_GAP[0])
            out.append((" " * pad, None))
            col += pad
        col = column_segments(part, col, out)
    return out


def column_segments(text, col, out):
    """One column's text into out; returns the character position after it."""
    colour, pos = None, 0
    for m in CODE.finditer(text):
        if m.start() > pos:
            part = text[pos:m.start()]
            out.append((part, colour))
            col += len(part)
        pos = m.end()
        if m.group(1):
            colour = "#" + m.group(1).lower()
        elif m.group(2):
            stop = int(m.group(2)) * TAB_COLUMNS // 100
            pad = max(stop - col, 1 if col else 0)
            out.append((" " * pad, None))
            col += pad
        else:
            colour = None
    if pos < len(text):
        out.append((text[pos:], colour))
        col += len(text) - pos
    return col


def plain(text, stops=()):
    return "".join(t for t, _ in segments(text, stops))


def norm_title(title):
    """A title with its numbers taken out: an address that follows the cursor is not a new screen."""
    return re.sub(r"0x[0-9A-Fa-f]+|\b[0-9A-Fa-f]{6,}\b|\d+", "#", title or "").strip()


def key_text(key):
    if not key or key == "-":
        return ""
    return "+".join(KEY_NAMES.get(k, k) for k in key.split("+"))


class Pane:
    """One list panel: a title, a status line, the rows, a help line."""

    def __init__(self, view, depth=None):
        self.view = view
        self.depth = depth          # 0 the screen in front, n a screen down the stack, None a kept copy
        self.pinned = False
        self.key = None             # (uid, title without numbers)
        self.uid = ""
        self.title = self.status = self.help = ""
        self.rows, self.first, self.index, self.count = [], 0, 0, 0
        self.show_index = True
        self.all_rows = None        # the whole list, once fetched
        self.shown = []             # what the Text holds: [(row index, raw text)]
        self.changed = {}           # row index -> time it changed
        self.stamp = None           # what the rows were fetched for (stack panes)
        self.tags = set()           # colour tags this Text has
        self.stops = ()             # where the tab columns of the rows on show start

        self.frame = tk.Frame(view.panes, bg=BG_PANEL)
        head = tk.Frame(self.frame, bg=BG_PANEL)
        head.pack(fill="x")
        self.title_label = tk.Label(head, text="", anchor="w", bg=BG_PANEL, fg="white", font=view.title_font)
        self.title_label.pack(side="left", fill="x", expand=True)
        if depth != 0:
            tk.Button(head, text="x", command=lambda: view.close_pane(self), takefocus=0, bd=0, bg=BG_PANEL,
                      fg=FG_DIM, activebackground=BG_BTN).pack(side="right")
        self.pin_btn = tk.Button(head, text="Pin", command=lambda: view.pin(self), takefocus=0, bd=0, bg=BG_PANEL,
                                 fg=FG_DIM, activebackground=BG_BTN)
        self.pin_btn.pack(side="right")
        self.status_label = tk.Label(self.frame, text="", anchor="w", justify="left", bg=BG_PANEL, fg=FG_DIM,
                                     font=view.small_font)
        self.status_label.pack(fill="x")
        body = tk.Frame(self.frame, bg=BG)
        body.pack(fill="both", expand=True)
        bar = tk.Scrollbar(body)
        bar.pack(side="right", fill="y")
        self.text = tk.Text(body, wrap="none", bg=BG, fg=FG, font=view.data_font, insertwidth=0, bd=0,
                            highlightthickness=1, highlightbackground=BG_PANEL, highlightcolor=BG_BTN_SEL,
                            selectbackground="#4c6fb0", yscrollcommand=bar.set, width=20, height=5, cursor="arrow")
        self.text.pack(side="left", fill="both", expand=True)
        bar.config(command=self.text.yview)
        self.text.tag_configure("cur", background=BG_CUR)
        self.text.tag_configure("num", foreground=FG_DIM)
        self.text.tag_configure("changed", foreground=FG_CHANGED)
        self.text.tag_configure("hit", background=BG_HIT)
        self.text.tag_raise("sel")
        self.text.config(state="disabled")
        self.help_label = tk.Label(self.frame, text="", anchor="w", justify="left", bg=BG_PANEL, fg=FG,
                                   font=view.small_font)
        self.help_label.pack(fill="x")
        self.text.bind("<ButtonRelease-1>", self.on_click)
        self.text.bind("<Double-Button-1>", self.on_double)
        self.text.bind("<FocusIn>", lambda e: view.set_active(self))
        # Keys are Switch buttons; the Text's own bindings would move its insert mark and scroll.
        self.text.bind("<KeyPress>", lambda e: view.on_key(e) or "break")
        self.frame.bind("<Configure>", self.on_width)

    # ------------------------------------------------------------ content
    def on_width(self, e):
        for label in (self.status_label, self.help_label):
            label.config(wraplength=max(e.width - 8, 80))

    def live(self):
        return self.depth == 0

    def kind_text(self):
        if self.depth == 0:
            return ""
        if self.depth is None:
            return "pinned: " if self.pinned else "before: "
        return "from: "

    def set_head(self):
        title = glyphs(self.title)
        if self.count and self.show_index:
            title += "  %d/%d" % (self.index + 1, self.count)
        self.title_label.config(text=self.kind_text() + title)
        self.status_label.config(text=plain(self.status))
        self.help_label.config(text=plain(self.help))
        self.pin_btn.config(text="Unpin" if self.pinned else "Pin")

    def row_list(self):
        """[(row index, raw text)] to show, the filter applied."""
        needle = self.view.needle() if self.view.filter_var.get() else ""
        if needle and self.all_rows is not None and len(self.all_rows) == self.count:
            rows = list(enumerate(self.all_rows))   # a filter is over the whole list
        else:
            rows = [(self.first + i, r) for i, r in enumerate(self.rows)]
        if needle:
            rows = [(i, r) for i, r in rows if needle in plain(r).lower()]
        return rows

    def insert_row(self, line, i, raw):
        """Writes one row at the start of text line `line` (no newline)."""
        t = self.text
        at = "%d.0" % line
        if self.view.numbers_var.get():
            t.insert(at, "%5d  " % (i + 1), ("num",))
            at = "%d.end" % line
        for part, colour in segments(raw, self.stops):
            tags = ()
            if colour:
                tag = "c" + colour
                if tag not in self.tags:
                    self.tags.add(tag)
                    t.tag_configure(tag, foreground=colour)
                    t.tag_lower(tag)
                tags = (tag,)
            t.insert("%d.end" % line, part, tags)

    def render(self, follow=False):
        new = self.row_list()
        t = self.text
        now = time.time()
        stops = tab_stops(r for _, r in new)
        same_shape = (len(new) == len(self.shown) and all(a[0] == b[0] for a, b in zip(new, self.shown)) and
                      stops == self.stops)
        self.stops = stops
        t.config(state="normal")
        if same_shape:
            # Only the lines that changed, so a selection elsewhere survives.
            for n, ((i, raw), (_, old)) in enumerate(zip(new, self.shown)):
                if raw != old:
                    t.delete("%d.0" % (n + 1), "%d.end" % (n + 1))
                    self.insert_row(n + 1, i, raw)
                    self.changed[i] = now
        else:
            top = t.yview()[0]
            t.delete("1.0", "end")
            for n, (i, raw) in enumerate(new):
                if n:
                    t.insert("end", "\n")
                self.insert_row(n + 1, i, raw)
            self.changed.clear()
            if not follow:
                t.yview_moveto(top)
        self.shown = new
        if not new and self.depth == 0 and not self.count:
            t.delete("1.0", "end")
            t.insert("1.0", self.view.empty_text())
        t.config(state="disabled")
        self.mark(follow or not same_shape)

    def line_of(self, row):
        for n, (i, _) in enumerate(self.shown):
            if i == row:
                return n + 1
        return None

    def mark(self, follow):
        """The cursor row, the rows that changed a moment ago, the find matches."""
        t = self.text
        for tag in ("cur", "changed", "hit"):
            t.tag_remove(tag, "1.0", "end")
        line = self.line_of(self.index)
        if line and self.count:
            t.tag_add("cur", "%d.0" % line, "%d.0" % (line + 1))
            if follow:
                t.see("%d.0" % line)
        now = time.time()
        for row, when in list(self.changed.items()):
            if now - when > CHANGED_MS / 1000.0:
                del self.changed[row]
                continue
            n = self.line_of(row)
            if n:
                t.tag_add("changed", "%d.0" % n, "%d.end" % n)
        needle = self.view.needle()
        if needle:
            pos = "1.0"
            while True:
                pos = t.search(needle, pos, "end", nocase=True)
                if not pos:
                    break
                end = "%s+%dc" % (pos, len(needle))
                t.tag_add("hit", pos, end)
                pos = end

    # ------------------------------------------------------------ mouse
    def row_at(self, e):
        line = int(self.text.index("@%d,%d" % (e.x, e.y)).split(".")[0])
        if 1 <= line <= len(self.shown):
            return self.shown[line - 1][0]
        return None

    def on_click(self, e):
        self.view.set_active(self)
        if self.text.tag_ranges("sel"):
            return  # a drag selected text: leave Breeze's cursor alone
        row = self.row_at(e)
        if row is None:
            return
        if self.live():
            self.view.send("select %d" % row)
        else:
            self.index = row
            self.set_head()
            self.mark(False)

    def on_double(self, e):
        row = self.row_at(e)
        if row is not None and self.live():
            self.view.send("select %d" % row)
            self.view.send("press A")
        return "break"

    def text_out(self, rows=None):
        """The panel as a text file."""
        lines = ["# " + glyphs(self.title) + ("  %d/%d" % (self.index + 1, self.count) if self.count else "")]
        for extra in (self.status, self.help):
            for part in plain(extra).splitlines():
                if part.strip():
                    lines.append("# " + part)
        rows = rows if rows is not None else self.row_list()
        stops = tab_stops(r for _, r in rows)
        for i, raw in rows:
            lines.append(("> " if i == self.index else "  ") + plain(raw, stops).rstrip())
        return "\n".join(lines) + "\n"


class TextView:
    def __init__(self, app):
        self.app = app
        cfg = app.cfg
        self.win = tk.Toplevel(app.root)
        self.win.title("Breeze text view")
        self.win.geometry(cfg.get("text_geometry", "1280x760"))
        self.win.configure(bg=BG_PANEL)
        self.state = {}
        self.prev_stack = set()
        self.ask_pending = 0.0
        self.jobs = {}               # "rows ..." command -> what to do with the reply
        self.last_cur_key = None
        self.last_sig = None
        self.action_sig = None
        self.action_buttons = []
        self.action_cols = 0
        self.actions_win = None

        size = int(cfg.get("text_font", 11))
        asize = int(cfg.get("text_action_font", 10))
        self.data_font = ("Consolas", size)
        self.title_font = ("Segoe UI", max(size, 9), "bold")
        self.small_font = ("Segoe UI", max(size - 1, 8))
        self.action_font = ("Segoe UI", asize)

        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        tk.Label(bar, text=" Find:").pack(side="left")
        self.find_var = tk.StringVar()
        self.find = tk.Entry(bar, width=22, textvariable=self.find_var)
        self.find.pack(side="left")
        self.find.bind("<Return>", lambda e: self.find_next(1))
        self.find.bind("<Shift-Return>", lambda e: self.find_next(-1))
        self.find.bind("<Escape>", self.find_done)
        self.find_var.trace_add("write", lambda *a: self.refind())
        tk.Button(bar, text="Next", command=lambda: self.find_next(1), takefocus=0).pack(side="left")
        tk.Button(bar, text="Prev", command=lambda: self.find_next(-1), takefocus=0).pack(side="left")
        self.filter_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="Filter", variable=self.filter_var, command=self.refind, takefocus=0).pack(side="left")
        tk.Button(bar, text="Copy row", command=self.copy_row, takefocus=0).pack(side="left", padx=(8, 0))
        tk.Button(bar, text="Copy all", command=self.copy_all, takefocus=0).pack(side="left")
        tk.Button(bar, text="Save...", command=self.save, takefocus=0).pack(side="left")
        tk.Label(bar, text="  Font:").pack(side="left")
        self.font_var = tk.StringVar(value=str(size))
        tk.Spinbox(bar, from_=6, to=40, width=3, textvariable=self.font_var, command=self.set_fonts).pack(side="left")
        tk.Label(bar, text=" Actions:").pack(side="left")
        self.afont_var = tk.StringVar(value=str(asize))
        tk.Spinbox(bar, from_=6, to=40, width=3, textvariable=self.afont_var, command=self.set_fonts).pack(side="left")
        tk.Label(bar, text=" Column gap:").pack(side="left")
        TAB_GAP[0] = int(cfg.get("text_gap", 4))
        self.gap_var = tk.StringVar(value=str(TAB_GAP[0]))
        tk.Spinbox(bar, from_=1, to=20, width=2, textvariable=self.gap_var, state="readonly",
                   command=self.on_options).pack(side="left")
        tk.Label(bar, text=" Earlier screens:").pack(side="left")
        self.sources_var = tk.StringVar(value=str(cfg.get("text_sources", 2)))
        tk.Spinbox(bar, from_=0, to=6, width=2, textvariable=self.sources_var, state="readonly",
                   command=self.on_options).pack(side="left")
        self.numbers_var = tk.BooleanVar(value=bool(cfg.get("text_numbers", True)))
        tk.Checkbutton(bar, text="Row numbers", variable=self.numbers_var, command=self.on_options,
                       takefocus=0).pack(side="left")
        self.picture_var = tk.BooleanVar(value=bool(cfg.get("text_picture", False)))
        tk.Checkbutton(bar, text="Picture too", variable=self.picture_var, command=self.on_options,
                       takefocus=0).pack(side="left")
        self.detach_var = tk.BooleanVar(value=bool(cfg.get("text_detach", False)))
        tk.Checkbutton(bar, text="Detach actions", variable=self.detach_var, command=self.place_actions,
                       takefocus=0).pack(side="left")

        self.crumbs = tk.Label(self.win, text="", anchor="w", bg=BG_PANEL, fg=FG_DIM, font=self.small_font)
        self.crumbs.pack(fill="x")

        self.panes = tk.PanedWindow(self.win, orient="horizontal", sashwidth=6, bg="#0f121b", bd=0)
        self.panes.pack(fill="both", expand=True)
        self.cur = Pane(self, 0)
        self.sources = []            # panes to the left: kept copies first, then the stack, oldest first
        self.active = self.cur
        self.actions = None
        self.panes.add(self.cur.frame, stretch="always", minsize=160)
        self.place_actions()

        # Breeze's keyboard, shown only while it is open.
        self.kbd = tk.Frame(self.win, bg="#203040")
        self.kbd_label = tk.Label(self.kbd, text="", anchor="w", bg="#203040", fg="white")
        self.kbd_label.pack(fill="x")
        self.kbd_entry = tk.Entry(self.kbd, font=("Consolas", 14))
        self.kbd_entry.pack(fill="x")
        self.kbd_entry.bind("<Return>", lambda e: self.send("text " + self.kbd_entry.get()))
        self.kbd_entry.bind("<KP_Enter>", lambda e: self.send("text " + self.kbd_entry.get()))
        self.kbd_entry.bind("<Escape>", lambda e: self.send("cancel"))
        self.kbd_open = False

        self.status = tk.Label(self.win, text="", anchor="w", fg="#555")
        self.status.pack(fill="x", side="bottom")

        self.win.bind("<KeyPress>", self.on_key)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.on_options()
        self.ask()
        self.win.after(300, self.tick)

    # ------------------------------------------------------------ plumbing
    def alive(self):
        return self.win.winfo_exists()

    def send(self, line):
        self.app.link.send(line)
        return "break"

    def ask(self):
        """Asks for the whole screen; the reply comes back through on_state."""
        if time.time() - self.ask_pending < 0.5:
            return
        self.ask_pending = time.time()
        self.send("state %d" % ROWS)

    def close(self):
        self.app.cfg["text_geometry"] = self.win.geometry()
        self.app.save_cfg()
        self.app.link.picture = True
        if self.actions_win is not None:
            self.actions_win.destroy()
        self.win.destroy()

    def on_options(self):
        cfg = self.app.cfg
        cfg["text_sources"] = int(self.sources_var.get())
        cfg["text_gap"] = TAB_GAP[0] = int(self.gap_var.get())
        cfg["text_numbers"] = bool(self.numbers_var.get())
        cfg["text_picture"] = bool(self.picture_var.get())
        self.app.save_cfg()
        # The pictures take most of the connection's time; without them the text is much quicker.
        self.app.link.picture = bool(self.picture_var.get())
        for p in self.all_panes():
            p.shown = []
            p.render()
        if self.state:
            self.sync_sources(self.state)

    def set_fonts(self):
        try:
            size, asize = int(self.font_var.get()), int(self.afont_var.get())
        except ValueError:
            return
        self.app.cfg["text_font"], self.app.cfg["text_action_font"] = size, asize
        self.app.save_cfg()
        self.data_font = ("Consolas", size)
        self.title_font = ("Segoe UI", max(size, 9), "bold")
        self.small_font = ("Segoe UI", max(size - 1, 8))
        self.action_font = ("Segoe UI", asize)
        for p in self.all_panes():
            p.text.config(font=self.data_font)
            p.title_label.config(font=self.title_font)
            p.status_label.config(font=self.small_font)
            p.help_label.config(font=self.small_font)
        self.crumbs.config(font=self.small_font)
        self.action_sig = None
        self.show_actions()

    def all_panes(self):
        return self.sources + [self.cur]

    def set_active(self, pane):
        self.active = pane

    def needle(self):
        return self.find_var.get().strip().lower()

    def empty_text(self):
        m = self.state.get("menu", {})
        if m.get("kind") == "alert":
            return "%s\n\n%s" % (glyphs(m.get("text", "")), glyphs(m.get("subtext", "")))
        if self.state.get("overlay") == "hidden":
            return "(Breeze is hidden behind the game)"
        return "(this screen has no list)"

    # ------------------------------------------------------------ state
    def on_state(self, s, source):
        """Every state the app receives. An event only says something changed: ask for all of it."""
        self.state = s
        self.show_keyboard(s.get("keyboard"))
        if source == "event":
            self.ask_pending = 0.0
            self.ask()
            return
        self.ask_pending = 0.0
        m = s.get("menu", {})
        title = m.get("left_title") or ("Message" if m.get("kind") == "alert" else "")
        key = (m.get("uid", ""), norm_title(title))
        if self.last_cur_key is not None and key != self.last_cur_key:
            self.screen_changed(self.last_cur_key, key, s)
        self.last_cur_key = key
        self.prev_stack = {e.get("uid") for e in s.get("stack", [])}

        c = self.cur
        moved = (c.key, c.index) != (key, m.get("index", 0))
        c.key, c.uid = key, m.get("uid", "")
        c.title, c.status, c.help = title, m.get("left_status", ""), m.get("left_help", "")
        c.show_index = m.get("show_index", True)
        c.rows, c.first = m.get("rows", []), m.get("rows_start", 0)
        c.index, c.count = m.get("index", 0), m.get("row_count", 0)
        if c.all_rows is not None:
            # The whole list was fetched: keep it current where the new rows overlap, drop it if the list changed.
            if len(c.all_rows) == c.count:
                c.all_rows[c.first:c.first + len(c.rows)] = c.rows
            else:
                c.all_rows = None
        c.set_head()
        c.render(follow=moved)
        self.sync_sources(s)
        self.show_actions()
        stack = [glyphs(e.get("title") or e.get("kind", "")) for e in reversed(s.get("stack", []))]
        self.crumbs.config(text="  " + "  >  ".join(stack + [glyphs(title)]) + "      [%s]" % {"shown": "overlay"}.get(s.get("overlay"), s.get("overlay", "?")))

    def snapshot(self, pane, pinned):
        """A kept copy of a panel as it is now."""
        p = Pane(self, None)
        p.pinned = pinned
        p.key, p.uid = pane.key, pane.uid
        p.title, p.status, p.help = pane.title, pane.status, pane.help
        p.rows, p.first, p.index, p.count = list(pane.rows), pane.first, pane.index, pane.count
        p.all_rows = list(pane.all_rows) if pane.all_rows is not None else None
        p.show_index = pane.show_index
        return p

    def screen_changed(self, old, new, s):
        """The screen in front is another one. Same menu object, other title: Breeze rebuilt the
        screen in place, so the one before is not on its stack; keep a copy of it."""
        self.cur.all_rows = None
        if new[0] in self.prev_stack:
            # Back to a screen further down: copies of the one just left have served.
            for p in [p for p in self.sources if p.depth is None and not p.pinned and p.uid == old[0]]:
                self.drop(p, relayout=False)
            self.layout()
            return
        # Going back to a screen there is a copy of: the copy has served.
        for p in list(self.sources):
            if p.depth is None and not p.pinned and p.key == new:
                i = self.sources.index(p)
                for q in [q for q in self.sources[i:] if q.depth is None and not q.pinned]:
                    self.drop(q)
                return
        if old[0] == new[0] and old[1] != new[1] and self.cur.rows and int(self.sources_var.get()) > 0:
            self.sources.append(self.snapshot(self.cur, False))
            self.layout()

    def sync_sources(self, s):
        """The stack's list screens as panels, nearest last; kept copies stay to their left."""
        want = int(self.sources_var.get())
        stack = [(d, e) for d, e in enumerate(s.get("stack", []), 1) if "row_count" in e]
        have = {p.depth: p for p in self.sources if p.depth}
        changed = False
        # Copies are the screens nearest the one in front; the stack fills what room is left, nearest first.
        copies = [p for p in self.sources if p.depth is None and not p.pinned]
        while len(copies) > want:
            self.drop(copies.pop(0), relayout=False)
            changed = True
        stack = stack[:max(want - len(copies), 0)]
        for d, p in have.items():
            if d not in [x[0] for x in stack]:
                self.drop(p, relayout=False)
                changed = True
        for d, e in stack:
            p = have.get(d)
            if p is None or p not in self.sources:
                p = Pane(self, d)
                self.sources.append(p)
                changed = True
            stamp = (e.get("uid"), e.get("title"), e.get("row_count"), e.get("index"), e.get("current_row"))
            p.uid, p.key = e.get("uid", ""), (e.get("uid", ""), norm_title(e.get("title", "")))
            p.title, p.status, p.help = e.get("title", ""), e.get("left_status", ""), e.get("left_help", "")
            p.index, p.count = e.get("index", 0), e.get("row_count", 0)
            p.set_head()
            if p.stamp != stamp:
                p.stamp = stamp
                p.all_rows = None
                start = max(p.index - ROWS // 2, 0)
                self.rows_job(p, start, ROWS, self.fill_source)
        if changed:
            self.layout()

    def rows_job(self, pane, start, count, done):
        line = "rows %d %d %d" % (start, count, pane.depth)
        self.jobs[line] = (pane, done)
        self.send(line)

    def on_rows(self, line, reply):
        job = self.jobs.pop(line, None)
        if job is None or not reply.startswith("+OK {"):
            return
        pane, done = job
        j = json.loads(reply[4:])
        if pane not in self.all_panes() or j.get("uid") != pane.uid:
            return  # Breeze has moved on since this was asked
        done(pane, j)

    def fill_source(self, pane, j):
        pane.rows, pane.first = j.get("rows", []), j.get("rows_start", 0)
        pane.index = j.get("index", pane.index)
        pane.set_head()
        pane.render(follow=True)

    def drop(self, pane, relayout=True):
        if pane in self.sources:
            self.sources.remove(pane)
        if self.active is pane:
            self.active = self.cur
        try:
            self.panes.forget(pane.frame)
        except tk.TclError:
            pass
        pane.frame.destroy()
        if relayout:
            self.layout()

    def close_pane(self, pane):
        if pane.depth:
            # A stack screen comes back with the next state; turn the count down to keep it away.
            self.status.config(text="that screen is on Breeze's stack: lower \"Earlier screens\" to hide it")
            return
        self.drop(pane)

    def pin(self, pane):
        """Keeps a copy of the panel until it is closed, whatever Breeze shows next."""
        if pane.depth is None:
            pane.pinned = not pane.pinned
            pane.set_head()
            return
        self.sources.insert(0, self.snapshot(pane, True))
        self.layout()

    def layout(self):
        """Left to right: pinned copies, earlier screens, the screen in front, the actions."""
        order = ([p for p in self.sources if p.depth is None and p.pinned] +
                 sorted([p for p in self.sources if p.depth], key=lambda p: -p.depth) +
                 [p for p in self.sources if p.depth is None and not p.pinned])
        self.sources = order
        frames = [p.frame for p in order] + [self.cur.frame]
        if self.actions is not None and self.actions_win is None:
            frames.append(self.actions)
        for f in self.panes.panes():
            self.panes.forget(f)
        for f in frames:
            self.panes.add(f, stretch="always", minsize=120)
        for p in order:
            p.set_head()
            if not p.shown and (p.rows or p.all_rows):
                p.render(follow=True)
        self.win.after_idle(self.place_sashes)

    def place_sashes(self):
        """Shares the width out when the set of panels changes: the screen in front gets the most."""
        if not self.alive():
            return
        frames = list(self.panes.panes())
        total = self.panes.winfo_width()
        if len(frames) < 2 or total < 100:
            return
        docked = self.actions is not None and self.actions_win is None
        weights = [2] * len(self.sources) + [4] + ([3] if docked else [])
        x = 0.0
        for i, w in enumerate(weights[:len(frames) - 1]):
            x += total * w / float(sum(weights))
            self.panes.sash_place(i, int(x), 0)

    # ------------------------------------------------------------ actions
    def place_actions(self):
        """The action panel: beside the lists, or in a window of its own."""
        self.app.cfg["text_detach"] = bool(self.detach_var.get())
        self.app.save_cfg()
        if self.actions is not None:
            try:
                self.panes.forget(self.actions)
            except tk.TclError:
                pass
            self.actions.destroy()
        if self.actions_win is not None:
            self.app.cfg["text_actions_geometry"] = self.actions_win.geometry()
            self.actions_win.destroy()
            self.actions_win = None
        if self.detach_var.get():
            self.actions_win = tk.Toplevel(self.win)
            self.actions_win.title("Breeze actions")
            self.actions_win.geometry(self.app.cfg.get("text_actions_geometry", "420x700"))
            self.actions_win.protocol("WM_DELETE_WINDOW", lambda: (self.detach_var.set(False), self.place_actions()))
            self.actions_win.bind("<KeyPress>", self.on_key)
            parent = self.actions_win
        else:
            parent = self.panes
        a = self.actions = tk.Frame(parent, bg=BG_PANEL)
        self.act_title = tk.Label(a, text="", anchor="w", bg=BG_PANEL, fg="white", font=self.title_font)
        self.act_title.pack(fill="x")
        self.act_status = tk.Label(a, text="", anchor="w", justify="left", bg=BG_PANEL, fg=FG, font=self.small_font)
        self.act_status.pack(fill="x")
        # The buttons scroll when there are more than the panel is tall.
        wrap = tk.Frame(a, bg=BG_PANEL)
        wrap.pack(fill="both", expand=True)
        bar = tk.Scrollbar(wrap)
        bar.pack(side="right", fill="y")
        self.act_canvas = tk.Canvas(wrap, bg=BG_PANEL, highlightthickness=0, yscrollcommand=bar.set, width=200, height=100)
        self.act_canvas.pack(side="left", fill="both", expand=True)
        bar.config(command=self.act_canvas.yview)
        self.act_grid = tk.Frame(self.act_canvas, bg=BG_PANEL)
        self.act_item = self.act_canvas.create_window(0, 0, anchor="nw", window=self.act_grid)
        self.act_grid.bind("<Configure>", lambda e: self.act_canvas.config(scrollregion=self.act_canvas.bbox("all")))
        self.act_canvas.bind("<Configure>", self.on_actions_width)
        self.act_canvas.bind("<MouseWheel>", self.on_actions_wheel)
        self.act_help = tk.Label(a, text="", anchor="w", justify="left", bg=BG_PANEL, fg=FG_DIM, font=self.small_font)
        self.act_help.pack(fill="x")
        if self.actions_win is not None:
            a.pack(fill="both", expand=True)
        self.action_sig = None
        self.layout()
        self.show_actions()

    def on_actions_wheel(self, e):
        if self.act_grid.winfo_height() > self.act_canvas.winfo_height():
            self.act_canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        return "break"

    def on_actions_width(self, e):
        self.act_canvas.itemconfigure(self.act_item, width=e.width)
        for label in (self.act_status, self.act_help):
            label.config(wraplength=max(e.width - 8, 80))
        if self.columns_for(e.width) != self.action_cols:
            self.action_sig = None
            self.show_actions()

    def columns_for(self, width):
        # A label longer than 26 characters wraps instead of costing every button its width.
        widest = min(max([len(b[0]) for b in self.action_list()] + [12]), 26)
        cell = int(widest * max(self.action_font[1] * 0.62, 5)) + 24
        return max(1, width // cell)

    def action_list(self):
        """[(text, command, enabled, on page, selected)]: every action, then the page's other buttons."""
        m = self.state.get("menu", {})
        out, seen = [], set()
        sel = m.get("selected_button")
        for a in m.get("actions", []):
            key = key_text(a.get("key", ""))
            text = glyphs(plain(a["label"])) + ("   " + key if key else "")
            out.append((text, "action %d" % a["id"], a["enabled"], a["on_page"], a["id"] == sel))
            seen.add(a["id"])
        for b in m.get("buttons", []):
            if b["id"] not in seen:
                out.append((plain(b["text"]), "button %d" % b["id"], b["enabled"], True, b["id"] == sel))
        return out

    def show_actions(self):
        if self.actions is None:
            return
        m = self.state.get("menu", {})
        self.act_title.config(text=glyphs(m.get("right_title", "")) or "Actions")
        self.act_status.config(text=plain(m.get("right_status", "")))
        self.act_help.config(text=plain(m.get("right_help", "")))
        items = self.action_list()
        width = self.act_canvas.winfo_width()
        cols = self.columns_for(width if width > 1 else 300)
        sig = (tuple(items), cols)
        if sig == self.action_sig:
            return
        self.action_sig, self.action_cols = sig, cols
        for w in self.act_grid.winfo_children():
            w.destroy()
        for c in range(max(cols, self.act_grid.grid_size()[0])):
            # columns left over from a wider layout would still take their share
            self.act_grid.columnconfigure(c, weight=1 if c < cols else 0, uniform="a" if c < cols else "")
        for n, (text, cmd, enabled, on_page, selected) in enumerate(items):
            b = tk.Button(self.act_grid, text=text, anchor="w", font=self.action_font, takefocus=0, bd=1,
                          justify="left", wraplength=max((width if width > 1 else 300) // cols - 16, 60),
                          relief="solid" if selected else "flat", fg="white", disabledforeground="#6b7285",
                          bg=BG_BTN_SEL if selected else BG_BTN if on_page else BG_BTN_OFF,
                          activebackground=BG_BTN_SEL, activeforeground="white",
                          state="normal" if enabled else "disabled", command=lambda c=cmd: self.send(c))
            b.grid(row=n // cols, column=n % cols, sticky="nsew", padx=1, pady=1)
            b.bind("<MouseWheel>", self.on_actions_wheel)
        self.act_canvas.yview_moveto(0)

    # ------------------------------------------------------------ keyboard
    def show_keyboard(self, kb):
        if kb and not self.kbd_open:
            self.kbd_open = True
            head = kb.get("header", "")
            if kb.get("subheader"):
                head += "  |  " + kb["subheader"]
            self.kbd_label.config(text="Breeze keyboard: " + head + "   (Enter sends, Esc cancels)")
            self.kbd_entry.delete(0, "end")
            self.kbd_entry.insert(0, kb.get("text", ""))
            self.kbd.pack(fill="x", side="bottom")
            self.kbd_entry.focus_set()
            self.kbd_entry.select_range(0, "end")
        elif not kb and self.kbd_open:
            self.kbd_open = False
            self.kbd.pack_forget()
            self.cur.text.focus_set()

    def on_key(self, e):
        if isinstance(e.widget, (tk.Entry, tk.Spinbox)):
            return None
        ctrl = bool(e.state & 0x4)
        key = e.keysym.lower()
        if ctrl and key == "f":
            self.find.focus_set()
            self.find.select_range(0, "end")
            return "break"
        if ctrl and key == "c":
            self.copy_selection()
            return "break"
        if ctrl and key == "s":
            self.save()
            return "break"
        if e.keysym == "F3":
            self.find_next(-1 if e.state & 0x1 else 1)
            return "break"
        if self.kbd_open or self.app.pad is not None:
            return None   # Game input holds keys down, and the key-up only reaches the main window
        return self.app.on_key(e)

    # ------------------------------------------------------------ find, copy, save
    def with_all_rows(self, pane, then):
        """Calls then(rows) with every row of the panel's list, fetching what is missing."""
        if pane.all_rows is not None and len(pane.all_rows) == pane.count:
            then(list(enumerate(pane.all_rows)))
            return
        have = [(pane.first + i, r) for i, r in enumerate(pane.rows)]
        if pane.depth is None or (pane.first == 0 and len(pane.rows) >= pane.count):
            then(have)
            return
        got = [None] * pane.count
        self.status.config(text="reading %d rows..." % pane.count)

        def piece(p, j):
            start = j.get("rows_start", 0)
            rows = j.get("rows", [])
            if j.get("row_count") != len(got):
                self.status.config(text="the list changed while it was being read; try again")
                return
            got[start:start + len(rows)] = rows
            nxt = start + len(rows)
            if rows and nxt < len(got):
                self.rows_job(p, nxt, CHUNK, piece)
                return
            p.all_rows = ["" if r is None else r for r in got]
            self.status.config(text="%d rows read" % len(got))
            then(list(enumerate(p.all_rows)))

        self.rows_job(pane, 0, CHUNK, piece)

    def refind(self):
        pane = self.active if self.active in self.all_panes() else self.cur
        if self.filter_var.get() and self.needle():
            # A filter is over the whole list, not the rows around the cursor.
            self.with_all_rows(pane, lambda rows: self.rerender())
        else:
            self.rerender()

    def rerender(self):
        for p in self.all_panes():
            p.render()

    def find_next(self, step):
        needle = self.needle()
        pane = self.active if self.active in self.all_panes() else self.cur
        if not needle:
            return "break"

        def go(rows):
            hits = [i for i, r in rows if needle in plain(r).lower()]
            if not hits:
                self.status.config(text="\"%s\" not found in %d rows" % (self.find_var.get(), len(rows)))
                return
            after = [i for i in hits if i > pane.index] if step > 0 else [i for i in reversed(hits) if i < pane.index]
            row = after[0] if after else (hits[0] if step > 0 else hits[-1])
            self.status.config(text="match %d of %d" % (hits.index(row) + 1, len(hits)))
            if pane.live():
                self.send("select %d" % row)
            else:
                if not pane.first <= row < pane.first + len(pane.rows):
                    # outside the rows on show: show the ones around the match
                    pane.first = max(row - ROWS // 2, 0)
                    pane.rows = [r for _, r in rows[pane.first:pane.first + ROWS]]
                pane.index = row
                pane.set_head()
                pane.render(follow=True)

        self.with_all_rows(pane, go)
        return "break"

    def find_done(self, _e):
        self.find_var.set("")
        self.cur.text.focus_set()
        return "break"

    def to_clipboard(self, text, what):
        self.win.clipboard_clear()
        self.win.clipboard_append(text)
        self.status.config(text="copied " + what)

    def copy_selection(self):
        pane = self.active if self.active in self.all_panes() else self.cur
        try:
            text = pane.text.get("sel.first", "sel.last")
        except tk.TclError:
            self.copy_row()
            return
        self.to_clipboard(text, "%d characters" % len(text))

    def copy_row(self):
        pane = self.active if self.active in self.all_panes() else self.cur
        for i, raw in pane.row_list():
            if i == pane.index:
                self.to_clipboard(plain(raw, pane.stops).rstrip(), "row %d" % (i + 1))
                return
        self.status.config(text="no row to copy")

    def copy_all(self):
        pane = self.active if self.active in self.all_panes() else self.cur
        def copy(rows):
            rows = self.filtered(rows)
            stops = tab_stops(r for _, r in rows)
            self.to_clipboard("\n".join(plain(r, stops).rstrip() for _, r in rows), "%d rows" % len(rows))

        self.with_all_rows(pane, copy)

    def filtered(self, rows):
        needle = self.needle() if self.filter_var.get() else ""
        return [(i, r) for i, r in rows if needle in plain(r).lower()] if needle else rows

    def save(self):
        pane = self.active if self.active in self.all_panes() else self.cur
        try:
            folder = self.app.game_dir("panels")
        except OSError as e:
            messagebox.showerror("Save", str(e), parent=self.win)
            return
        name = re.sub(r"[^A-Za-z0-9._ -]+", "_", glyphs(pane.title)).strip(" _")[:60] or "panel"
        path = filedialog.asksaveasfilename(parent=self.win, initialdir=folder, defaultextension=".txt",
                                            initialfile="%s_%s.txt" % (name, time.strftime("%Y%m%d_%H%M%S")),
                                            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return

        def write(rows):
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(pane.text_out(self.filtered(rows)))
            except OSError as e:
                messagebox.showerror("Save", str(e), parent=self.win)
                return
            self.status.config(text="saved %d rows to %s" % (len(self.filtered(rows)), path))

        self.with_all_rows(pane, write)

    # ------------------------------------------------------------ housekeeping
    def tick(self):
        if not self.alive():
            return
        for p in self.all_panes():
            if p.changed:
                p.mark(False)
        if self.app.last_reply:
            self.status.config(text=self.app.last_reply)
        self.win.after(300, self.tick)
