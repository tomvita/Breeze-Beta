"""Cheat source editor for the Breeze PC app: the running game's <TitleID>.ini
(cheat_source.md) edited on the PC, checked and built by Breeze on the Switch.
Opened from pcconnect_app.py's "Cheat source" button.

The file is read and written with fsget / fsput; what Breeze makes of it comes
from PC connect's `source` commands (pcsource.cpp), so the Switch stays the one
place code is filled and assembled:

  Reload        reads the file and Breeze's view of it (cheats, their state)
  Save (Ctrl+S) writes the file back
  Check (F7)    Check ASM on the cheat the cursor is in: a note per code line
  Listing (F8)  where each code line of that cheat is in its cave, and the
                word the game holds there
  Build (F9)    saves, then rebuilds that cheat on the Switch where it is
  Name address (Ctrl+N)
                the number on the code line at the cursor (a pointer cheat's
                base) becomes a name of the build section, as in the Cheat
                composer
  Make mod (Ctrl+M)
                the value on the code line at the cursor (a pointer cheat's
                write) gets a [mod] of values, one cheat each; then a rebuild
  Shelf         the cheats taken out of the list: Restore or Discard
  Install       Cheats > Install from source

Every operation opens a connection of its own and closes it, so the editor
does not hold one of PC connect's client slots while it sits open.
"""
import json
import queue
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from pcconnect import Breeze

PIECE = 1 << 20
CODE_KEYS = ("code", "codes")


def sections(text):
    """Every section of the file: (kind, title, header line index, end line index)."""
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines):
        t = line.strip()
        if line[:1] == "[" and t.endswith("]"):
            head = t[1:-1].strip()
            kind, _, title = head.partition(" ")
            if out:
                out[-1][3] = i
            out.append([kind.lower(), title.strip(), i, len(lines)])
    return [tuple(s) for s in out]


def code_text_lines(text, header):
    """The text line of every code line of the section starting at `header`,
    in the order Breeze reads them (the parser in asmsource.cpp): the rest of
    the `code =` line, then indented lines up to the next key or section."""
    lines = text.split("\n")
    out, inside = [], False
    for i in range(header + 1, len(lines)):
        line = lines[i].rstrip("\r")
        t = line.strip()
        indented = line[:1] in (" ", "\t")
        if not indented and t:
            if t[0] in ";#" or t.startswith("//"):
                continue
            if t[0] == "[" and t.endswith("]"):
                break
            key, eq, rest = t.partition("=")
            if inside:
                break
            if eq and key.strip().lower() in CODE_KEYS:
                inside = True
                if rest.strip():
                    out.append(i)
            continue
        if inside and t:
            out.append(i)
    return out


class SourceEditor:
    def __init__(self, root, host, code, cfg, save_cfg):
        self.host, self.code, self.cfg, self.save_cfg = host, code, cfg, save_cfg
        self.path = None
        self.info = {}
        self.jobs = queue.Queue()
        self.busy = False
        self.win = tk.Toplevel(root)
        self.win.title("Cheat source")
        self.win.geometry(cfg.get("source_geometry", "1200x760"))
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        bar = tk.Frame(self.win)
        bar.pack(side="top", fill="x")
        for text, fn in (("Reload", self.reload), ("Save", self.save), ("Check", self.check),
                         ("Listing", self.listing), ("Build", self.build), ("Name address", self.name_address),
                         ("Make mod", self.make_mod), ("Shelf", self.shelf), ("Install from source", self.install)):
            tk.Button(bar, text=text, command=fn).pack(side="left", padx=1)
        self.status = tk.Label(bar, text="", anchor="w")
        self.status.pack(side="left", fill="x", expand=True, padx=8)

        body = ttk.PanedWindow(self.win, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = tk.Frame(body)
        self.tree = ttk.Treeview(left, columns=("state",), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Section")
        self.tree.heading("state", text="In Breeze")
        self.tree.column("#0", width=260)
        self.tree.column("state", width=150)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_pick)
        body.add(left, weight=1)

        right = ttk.PanedWindow(body, orient="vertical")
        edit = tk.Frame(right)
        self.text = tk.Text(edit, wrap="none", undo=True, font=("Consolas", 10))
        ys = tk.Scrollbar(edit, command=self.text.yview)
        xs = tk.Scrollbar(edit, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        self.text.pack(fill="both", expand=True)
        right.add(edit, weight=4)
        self.out = tk.Text(right, height=10, wrap="none", font=("Consolas", 9), state="disabled")
        self.out.bind("<Double-Button-1>", self.on_out_click)
        right.add(self.out, weight=1)
        body.add(right, weight=4)

        self.text.tag_configure("head", foreground="#0050b0", font=("Consolas", 10, "bold"))
        self.text.tag_configure("key", foreground="#7a3e9d")
        self.text.tag_configure("name", foreground="#a05000")
        self.text.tag_configure("comment", foreground="#6a8a6a")
        self.text.tag_configure("note", background="#ffe0e0")
        self.text.tag_configure("cur", background="#e8f0ff")
        self.text.bind("<<Modified>>", self.on_modified)
        self.text.bind("<KeyRelease>", lambda _e: self.after_edit())
        for key, fn in (("<Control-s>", self.save), ("<F7>", self.check), ("<F8>", self.listing), ("<F9>", self.build), ("<F5>", self.reload),
                        ("<Control-n>", self.name_address), ("<Control-m>", self.make_mod)):
            self.text.bind(key, lambda _e, f=fn: (f(), "break")[1])
            self.win.bind(key, lambda _e, f=fn: (f(), "break")[1])
        self.out_lines = []   # text line of each output row (for double-click)
        self.win.after(100, self.poll)
        self.reload()

    # ------------------------------------------------------------ plumbing

    def alive(self):
        return self.win.winfo_exists()

    def close(self):
        try:
            self.cfg["source_geometry"] = self.win.geometry()
            self.save_cfg()
        except Exception:
            pass
        if self.text.edit_modified() and not messagebox.askyesno("Cheat source", "Close without saving?", parent=self.win):
            return
        self.win.destroy()

    def connect(self, timeout=15):
        return Breeze(self.host, self.code, timeout=timeout)

    def run(self, what, fn, done):
        """fn() on a worker thread, done(result) back on Tk's."""
        if self.busy:
            self.say("Busy: " + self.busy)
            return
        self.busy = what
        self.say(what + "...")

        def work():
            try:
                self.jobs.put((done, fn(), None))
            except Exception as e:  # shown, not raised: the window stays usable
                self.jobs.put((done, None, e))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        if not self.alive():
            return
        try:
            while True:
                done, result, err = self.jobs.get_nowait()
                self.busy = False
                if err is not None:
                    self.say("Error: %s" % err)
                else:
                    done(result)
        except queue.Empty:
            pass
        self.win.after(100, self.poll)

    def say(self, text):
        self.status.configure(text=text)

    def show_out(self, rows):
        """rows: (text line or None, text) pairs."""
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out_lines = []
        for line, row in rows:
            self.out.insert("end", row + "\n")
            self.out_lines.append(line)
        self.out.configure(state="disabled")

    def on_out_click(self, event):
        row = int(self.out.index("@%d,%d" % (event.x, event.y)).split(".")[0]) - 1
        if 0 <= row < len(self.out_lines) and self.out_lines[row] is not None:
            self.goto_line(self.out_lines[row])

    def goto_line(self, line):
        self.text.see("%d.0" % (line + 1))
        self.text.mark_set("insert", "%d.0" % (line + 1))
        self.text.tag_remove("cur", "1.0", "end")
        self.text.tag_add("cur", "%d.0" % (line + 1), "%d.0" % (line + 2))
        self.text.focus_set()

    # ------------------------------------------------------------ the file

    def reload(self, keep_cursor=False, then=None):
        cursor = self.text.index("insert")
        if self.text.edit_modified() and not messagebox.askyesno("Cheat source", "Reload and lose the changes?", parent=self.win):
            return

        def fn():
            b = self.connect()
            try:
                info = b.json("source")
                data = b""
                if info.get("exists"):
                    off = 0
                    while True:
                        piece, size = b.fs_get(info["path"], off, PIECE)
                        data += piece
                        off += len(piece)
                        if off >= size or not piece:
                            break
                return info, data.decode("utf-8", "replace")
            finally:
                b.close()

        def done(result):
            info, text = result
            self.info, self.path = info, info["path"]
            self.crlf = "\r\n" in text
            self.text.delete("1.0", "end")
            self.text.insert("1.0", text.replace("\r\n", "\n"))
            self.text.edit_reset()
            self.text.edit_modified(False)
            self.after_edit()
            if keep_cursor:
                self.text.mark_set("insert", cursor)
                self.text.see(cursor)
            if then is not None:
                then()
            self.win.title("Cheat source - %s (build %s)" % (self.path, info.get("build_id", "?")))
            self.say("%d cheats, %d mods%s" % (len(info.get("cheats", [])), len(info.get("mods", [])),
                                             "" if info.get("exists") else " - no file yet: Save makes one"))
        self.run("Reading", fn, done)

    def body_text(self):
        text = self.text.get("1.0", "end-1c")
        return text.replace("\n", "\r\n") if getattr(self, "crlf", False) else text

    def save(self, then=None):
        if self.path is None:
            return
        data = self.body_text().encode("utf-8")

        def fn():
            b = self.connect()
            try:
                if not data:
                    b.fs_put(self.path, 0, b"")
                for off in range(0, len(data), PIECE):
                    b.fs_put(self.path, off, data[off:off + PIECE])
                return True
            finally:
                b.close()

        def done(_ok):
            self.text.edit_modified(False)
            self.say("Saved %d bytes" % len(data))
            if then is not None:
                then()
        self.run("Saving", fn, done)

    def on_modified(self, _e=None):
        mark = "*" if self.text.edit_modified() else ""
        title = self.win.title().lstrip("*")
        self.win.title(mark + title)

    # ------------------------------------------------------------ sections

    def after_edit(self):
        self.highlight()
        self.fill_tree()

    def highlight(self):
        for tag in ("head", "key", "name", "comment"):
            self.text.tag_remove(tag, "1.0", "end")
        text = self.text.get("1.0", "end-1c")
        for n, line in enumerate(text.split("\n"), start=1):
            t = line.strip()
            if not t:
                continue
            if line[:1] == "[" and t.endswith("]"):
                self.text.tag_add("head", "%d.0" % n, "%d.end" % n)
                continue
            c = line.find("//")
            if c >= 0:
                self.text.tag_add("comment", "%d.%d" % (n, c), "%d.end" % n)
            if line[:1] not in (" ", "\t") and t[0] in ";#":
                self.text.tag_add("comment", "%d.0" % n, "%d.end" % n)
            if line[:1] not in (" ", "\t") and "=" in line:
                self.text.tag_add("key", "%d.0" % n, "%d.%d" % (n, line.index("=")))
            start = 0
            while True:
                a = line.find("{", start)
                if a < 0:
                    break
                b = line.find("}", a)
                if b < 0:
                    break
                self.text.tag_add("name", "%d.%d" % (n, a), "%d.%d" % (n, b + 1))
                start = b + 1

    def fill_tree(self):
        state = {c["label"]: c for c in self.info.get("cheats", [])}
        text = self.text.get("1.0", "end-1c")
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        groups = {}
        for kind, title, head, _end in sections(text):
            group = {"cheat": "Cheats", "routine": "Routines", "mod": "Mods", "build": "Builds"}.get(kind, "Other")
            if group not in groups:
                groups[group] = self.tree.insert("", "end", text=group, open=True)
            s = state.get(title)
            if kind != "cheat":
                desc = ""
            elif s is None:
                desc = "not in the file Breeze read"
            elif s.get("shelved"):
                desc = "shelved"
            elif s.get("template"):
                desc = "template (its mods)"
            elif not s.get("loaded"):
                desc = "not loaded"
            else:
                desc = ("on" if s.get("on") else "off") + (", split" if s.get("split") else "") + (", fixed" if s.get("fixed") else "")
            self.tree.insert(groups[group], "end", iid="L%d" % head, text=title or kind, values=(desc,))
        if keep and self.tree.exists(keep[0]):
            self.tree.selection_set(keep[0])

    def on_pick(self, _e=None):
        sel = self.tree.selection()
        if sel and sel[0].startswith("L"):
            self.goto_line(int(sel[0][1:]))

    def section_at_cursor(self):
        """The [cheat] section the cursor is in: (label, header line)."""
        line = int(self.text.index("insert").split(".")[0]) - 1
        for kind, title, head, end in sections(self.text.get("1.0", "end-1c")):
            if head <= line < end:
                if kind == "cheat":
                    return title, head
                if kind == "routine":
                    # A routine is checked as one of the cheats using it.
                    for c in self.info.get("cheats", []):
                        if c.get("source") == title:
                            return c["label"], head
                break
        self.say("Put the cursor in a [cheat] section (or a routine a cheat uses)")
        return None, None

    def lines_for(self, reply):
        """Text line of each code line Breeze returned, by the section it names."""
        kind, _, title = reply["section"].partition(" ")
        text = self.text.get("1.0", "end-1c")
        for k, t, head, _end in sections(text):
            if k == kind and t == title:
                found = code_text_lines(text, head)
                if len(found) == len(reply["lines"]):
                    return found
        return [None] * len(reply["lines"])

    # ------------------------------------------------------------ Breeze

    def ask(self, line, timeout=15):
        def fn():
            b = self.connect(timeout)
            try:
                return b.cmd(line)
            finally:
                b.close()
        return fn

    def ask_json(self, line):
        b = self.connect()
        try:
            return b.json(line)
        finally:
            b.close()

    def with_saved(self, then):
        if self.text.edit_modified():
            self.save(then=then)
        else:
            then()

    def check(self):
        label, _ = self.section_at_cursor()
        if label is None:
            return

        def go():
            def done(reply):
                if not reply.startswith("+OK"):
                    self.say(reply)
                    return
                r = json.loads(reply[4:])
                where = self.lines_for(r)
                self.text.tag_remove("note", "1.0", "end")
                rows, bad = [], 0
                for line, code, note in zip(where, r["lines"], r["notes"]):
                    if note:
                        bad += 1
                        rows.append((line, "%5s  %s   %s" % ("" if line is None else line + 1, note, code.strip())))
                        if line is not None:
                            self.text.tag_add("note", "%d.0" % (line + 1), "%d.end" % (line + 1))
                self.show_out(rows or [(None, "Check ASM: no notes for [%s]" % r["section"])])
                self.say("Check ASM on [%s]: %d note(s)" % (r["section"], bad))
            self.run("Checking " + label, self.ask("source check " + label), done)
        self.with_saved(go)

    def listing(self):
        label, _ = self.section_at_cursor()
        if label is None:
            return

        def go():
            def done(reply):
                if not reply.startswith("+OK"):
                    self.say(reply)
                    return
                r = json.loads(reply[4:])
                where = self.lines_for(r)
                rows = [(line, "%-34s %s" % (lst, code.strip())) for line, code, lst in zip(where, r["lines"], r["listing"])]
                if not any(lst for lst in r["listing"]):
                    rows.insert(0, (None, "Its cave is not in the game (not loaded as a hook and cave fill: Install from source)"))
                self.show_out(rows)
                self.say("Listing of [%s]" % r["section"])
            self.run("Listing " + label, self.ask("source listing " + label), done)
        self.with_saved(go)

    def build(self):
        label, _ = self.section_at_cursor()
        if label is None:
            return

        def go():
            def done(reply):
                self.show_out([(None, part) for part in reply.split("|")])
                self.say(reply.split("|")[0])
                self.refresh_info()
            self.run("Building " + label, self.ask("source build " + label, timeout=150), done)
        self.with_saved(go)

    def code_line_at_cursor(self, head):
        """Index of the cursor's line among the code lines of the section at
        `head` (as `source check` numbers them), or None."""
        line = int(self.text.index("insert").split(".")[0]) - 1
        found = code_text_lines(self.text.get("1.0", "end-1c"), head)
        return found.index(line) if line in found else None

    def cursor_target(self, what):
        """(label, line index) for Name address / Make mod; line 0 on a pointer cheat."""
        label, head = self.section_at_cursor()
        if label is None:
            return None, None
        c = next((c for c in self.info.get("cheats", []) if c["label"] == label), {})
        if c.get("chain"):
            return label, 0
        n = self.code_line_at_cursor(head)
        if n is None:
            self.say("%s: put the cursor on a code line of [%s]" % (what, label))
            return None, None
        return label, n

    def name_address(self):
        label, n = self.cursor_target("Name address")
        if label is None:
            return

        def go():
            def planned(reply):
                if not reply.startswith("+OK"):
                    self.say(reply)
                    return
                r = json.loads(reply[4:])
                if r["chain"]:
                    what = "The base of %s's chain, %s" % (label, r["value"])
                elif r["page"]:
                    what = "The adrp page %s%s: %s" % (r["text"], "" if r["lo_line"] < 0 else " and its low 12 bits", r["value"])
                else:
                    what = "%s (%s)" % (r["text"], r["value"])
                name = simpledialog.askstring("Name address", what + "\n\nName for the build section:",
                                              initialvalue=r["suggest"], parent=self.win)
                if not name:
                    return

                def applied(reply):
                    self.show_out([(None, reply)])
                    self.say(reply)
                    if reply.startswith("+OK"):
                        self.reload(keep_cursor=True)
                self.run("Naming", self.ask("source name %d %s|%s" % (n, label, name.strip())), applied)
            self.run("Name address", self.ask("source name %d %s" % (n, label)), planned)
        self.with_saved(go)

    def make_mod(self):
        label, n = self.cursor_target("Make mod")
        if label is None:
            return

        def go():
            def planned(reply):
                if not reply.startswith("+OK"):
                    self.say(reply)
                    return
                r = json.loads(reply[4:])
                name = r["have"]
                if not name:
                    name = simpledialog.askstring("Make mod", "Mod name (its cheats are named <name> = <value>,\n"
                                                  "or <name> <label> for a value written label = value):",
                                                  initialvalue=r["suggest"], parent=self.win)
                    if not name:
                        return
                ask = ("What %s can write, ; between (one cheat each, one on at a time):" % name if r["chain"] else
                       "What %s can be set to, ; between (%s; the first is the default, the one the code holds):" % (name, r["type"]))
                values = simpledialog.askstring("Make mod", ask, initialvalue=r["values"], parent=self.win)
                if not values:
                    return

                def applied(reply):
                    self.show_out([(None, part) for part in reply.split("|")])
                    self.say(reply.split("|")[0])
                    self.reload(keep_cursor=True)
                self.run("Making the mod", self.ask("source mod %d %s|%s|%s" % (n, label, name.strip(), values.strip()), timeout=150), applied)
            self.run("Make mod", self.ask("source mod %d %s" % (n, label)), planned)
        self.with_saved(go)

    def shelf(self):
        ShelfDialog(self)

    def install(self):
        def go():
            def done(reply):
                self.show_out([(None, part) for part in reply.split("|")])
                self.say(reply.split("|")[0])
                self.refresh_info()
            self.run("Installing", self.ask("source install", timeout=150), done)
        self.with_saved(go)

    def refresh_info(self):
        def fn():
            b = self.connect()
            try:
                return b.json("source")
            finally:
                b.close()

        def done(info):
            self.info = info
            self.fill_tree()
        self.run("Reading Breeze's state", fn, done)


class ShelfDialog:
    """The cheats taken out of the list (shelved in the file): Restore puts one
    back in the list where it was, Discard takes its section out of the file."""

    def __init__(self, editor):
        self.ed = editor
        self.win = tk.Toplevel(editor.win)
        self.win.title("Shelf")
        self.win.geometry("560x320")
        self.list = tk.Listbox(self.win, font=("Consolas", 10), activestyle="none")
        self.list.pack(fill="both", expand=True)
        bar = tk.Frame(self.win)
        bar.pack(fill="x")
        tk.Button(bar, text="Restore", command=self.restore).pack(side="left", padx=1)
        tk.Button(bar, text="Discard", command=self.discard).pack(side="left", padx=1)
        tk.Button(bar, text="Close", command=self.win.destroy).pack(side="right", padx=1)
        self.fill()

    def fill(self):
        self.cheats = [c for c in self.ed.info.get("cheats", []) if c.get("shelved")]
        self.list.delete(0, "end")
        for c in self.cheats:
            where = c.get("was_after") or ""
            where = (" (was after %s)" % where) if where else ""
            inside = (" in " + c["was_in"]) if c.get("was_in") else ""
            self.list.insert("end", c["label"] + where + inside)
        if not self.cheats:
            self.list.insert("end", "Nothing on the shelf: a source cheat deleted from the list goes here")

    def picked(self):
        sel = self.list.curselection()
        if not sel or sel[0] >= len(self.cheats):
            return None
        return self.cheats[sel[0]]["label"]

    def act(self, verb, label):
        def done(reply):
            self.ed.show_out([(None, part) for part in reply.split("|")])
            self.ed.say(reply.split("|")[0])

            def refreshed(info):
                self.ed.info = info
                self.ed.fill_tree()
                if self.win.winfo_exists():
                    self.fill()
            if verb == "discard":
                self.ed.reload(keep_cursor=True, then=lambda: self.win.winfo_exists() and self.fill())
            else:
                self.ed.run("Reading Breeze's state", lambda: self.ed.ask_json("source"), refreshed)
        self.ed.with_saved(lambda: self.ed.run(verb.capitalize() + " " + label, self.ed.ask("source %s %s" % (verb, label), timeout=150), done))

    def restore(self):
        label = self.picked()
        if label:
            self.act("restore", label)

    def discard(self):
        label = self.picked()
        if label and messagebox.askyesno("Shelf", "Take [cheat %s] out of the file for good?" % label, parent=self.win):
            self.act("discard", label)
