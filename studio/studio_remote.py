"""Breeze Studio remote: see and drive a running Studio from a script (or from Claude).

Studio listens on 127.0.0.1 only (port 6810; `studio_remote_port` in ~/.breeze_pc.json, 0 turns it
off; the BREEZE_STUDIO_REMOTE_PORT environment variable overrides both, for this client too - give a
second Studio its own port, or its commands go to whichever Studio took 6810 first). One command per line; the reply is lines that end with a line holding only ".".

  tabs                        the tabs: name, open (its tool made), detached
  tab <name>                  shows a tab (opens its tool)
  dump [<tab>] [all]          the widgets as text: each one's path, class, text, value, state; lists
                              with their rows, text panes with their lines, inner tabs. Hidden
                              (unmapped) widgets are left out unless `all`.
  click <w>                   presses a button (or toggles a check button)
  set <w> <text>|@<file>      types into an entry, combobox (also picks the value) or text pane
  select <w> <row>            picks a list row (index from 0, or the row's first value)
  dclick <w> <row> [column]   double-clicks a list row (column by heading or index)
  menu <w> <words>            runs the context-menu entry of w whose label has the words
  menus <w>                   lists w's context menus and their entries
  key <w> <sequence>          sends a key or event (<Return>, <F5>, <<ComboboxSelected>>) to w
  innertab <w> <text>         picks the tab named text in the notebook w
  shot [<tab>]                a PNG of the window (or of a detached tab): its path
  reload <module>...          reads an edited module again (for development)
  wait <ms>                   waits (lets the tools' timers and replies run)

<w> is a widget: its path from `dump` (".!frame.!button2"), or text=<label> for the first shown
widget with that text, as `tab:Watch text=Refresh` to look only in one tab.

    python studio/studio_remote.py dump Watch
    python studio/studio_remote.py "click text=Refresh" ";;" "dump Watch"

Python 3 only.
"""
import os
import queue
import re
import shlex
import socket
import sys
import tempfile
import threading
import time

PORT = int(os.environ.get("BREEZE_STUDIO_REMOTE_PORT") or 6810)   # the Studio started with the same variable
MAX_ROWS = 60
MAX_LINES = 80


# ---------------------------------------------------------------- the server (inside Studio)
class RemoteServer(threading.Thread):
    """Accepts local connections; each command runs on the Tk thread (Studio's pump calls pump())."""

    def __init__(self, studio, port=PORT):
        super().__init__(daemon=True)
        self.studio, self.port = studio, port
        self.todo = queue.Queue()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE if hasattr(socket, "SO_EXCLUSIVEADDRUSE")
                             else socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))      # raises when another Studio has the port
        self.sock.listen(4)

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        f = conn.makefile("rwb")
        try:
            f.write(b"+OK Breeze Studio remote\n")
            f.flush()
            for raw in f:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                if line.split()[0] == "wait":
                    try:
                        time.sleep(min(int(line.split()[1]), 60000) / 1000.0)
                        out = ["+OK"]
                    except (IndexError, ValueError):
                        out = ["-ERR wait <ms>"]
                else:
                    done = threading.Event()
                    box = []
                    self.todo.put((line, box, done))
                    if not done.wait(60):
                        out = ["-ERR Studio did not answer in 60 s (busy?)"]
                    else:
                        out = box[0]
                f.write(("\n".join(out) + "\n.\n").encode("utf-8"))
                f.flush()
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def pump(self):
        """Runs the waiting commands (Tk thread)."""
        try:
            while True:
                line, box, done = self.todo.get_nowait()
                try:
                    box.append(Commands(self.studio).run(line))
                except Exception as e:  # noqa: BLE001 - the client hears what went wrong
                    box.append(["-ERR %s: %s" % (type(e).__name__, e)])
                done.set()
        except queue.Empty:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def text_of(w):
    try:
        return str(w.cget("text"))
    except Exception:  # noqa: BLE001
        return ""


def short(s, n=120):
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + "..."


class Commands:
    def __init__(self, studio):
        self.s = studio
        self.root = studio.root

    def run(self, line):
        words = shlex.split(line, posix=True)
        verb, args = words[0].lower(), words[1:]
        fn = getattr(self, "c_" + verb, None)
        if fn is None:
            return ["-ERR unknown command %s (tabs, tab, dump, click, set, select, dclick, menu, menus, key, "
                    "innertab, shot, wait)" % verb]
        return fn(args)

    # ------------------------------------------------------------ finding widgets
    def scope(self, args):
        """(widget to search in, rest of args): a leading tab:<name> narrows to that tab."""
        if args and args[0].startswith("tab:"):
            holder = self.s.holders.get(args[0][4:])
            if holder is None:
                raise ValueError("no tab %s" % args[0][4:])
            return holder, args[1:]
        return self.root, args

    def widget(self, args):
        """(widget, rest of args) from a path or text=<label>."""
        within, args = self.scope(args)
        if not args:
            raise ValueError("which widget?")
        spec, rest = args[0], args[1:]
        if spec.startswith("."):
            return self.root.nametowidget(spec), rest
        if spec.startswith("text="):
            want = spec[5:]
            hidden = None
            for w in self.walk(within):
                if text_of(w) == want:
                    if w.winfo_ismapped():
                        return w, rest
                    hidden = hidden or w
            if hidden is not None:
                return hidden, rest
            raise ValueError("no widget with the text %r" % want)
        raise ValueError("a widget is a path (.!frame...) or text=<label>")

    def walk(self, w):
        yield w
        for c in w.winfo_children():
            yield from self.walk(c)

    # ------------------------------------------------------------ commands
    def c_tabs(self, args):
        out = ["+OK %d tabs" % len(self.s.holders)]
        shown = self.s.shown()
        for label in self.s.holders:
            p = self.s.panels.get(label)
            out.append("%s open=%d detached=%d shown=%d" % (
                label, int(p is not None and not p.dead), int(label in self.s.detached),
                int(shown is not None and shown.label == label)))
        return out

    def c_tab(self, args):
        if not args or args[0] not in self.s.holders:
            return ["-ERR tab <%s>" % "|".join(self.s.holders)]
        label = args[0]
        if label in self.s.detached:
            self.s.open_panel(label)
            self.s.raise_detached(label)
        else:
            self.s.tabs.select(self.s.holders[label])
            self.root.update_idletasks()
            self.s.on_tab()
        return ["+OK %s" % label]

    def c_dump(self, args):
        show_all = "all" in args
        args = [a for a in args if a != "all"]
        if args:
            holder = self.s.holders.get(args[0])
            if holder is None:
                return ["-ERR no tab %s" % args[0]]
            top = holder
        else:
            top = self.root
        self.root.update_idletasks()
        out = ["+OK %s" % (self.root.title())]
        self.dump(top, 0, out, show_all)
        return out

    def dump(self, w, depth, out, show_all):
        cls = w.winfo_class()
        mapped = w.winfo_ismapped()
        if not mapped and not show_all and depth > 0 and cls != "Menu":
            return
        if cls == "Menu":
            return            # context menus: `menus <w>`
        pad = "  " * depth
        line = "%s%s %s" % (pad, str(w), cls)
        t = "" if cls in ("TEntry", "Entry", "TCombobox", "TSpinbox", "Spinbox") else text_of(w)
        if t:
            line += " text=%r" % short(t)
        try:
            st = str(w.cget("state"))
            if st and st not in ("normal", "!disabled"):
                line += " state=%s" % st
        except Exception:  # noqa: BLE001
            pass
        try:
            if "disabled" in w.state():
                line += " disabled"
        except Exception:  # noqa: BLE001
            pass
        if not mapped:
            line += " hidden"
        if cls in ("TEntry", "Entry", "TCombobox", "TSpinbox", "Spinbox"):
            line += " value=%r" % short(w.get())
        if cls in ("TCheckbutton", "Checkbutton", "TRadiobutton", "Radiobutton"):
            try:
                var = w.cget("variable")
                line += " var=%s" % self.root.getvar(str(var)) if str(var) else ""
            except Exception:  # noqa: BLE001
                pass
        if cls == "TCombobox":
            line += " values=%s" % short(" | ".join(map(str, w.cget("values"))), 200)
        if cls == "TNotebook":
            tabs = []
            for t in w.tabs():
                name = w.tab(t, "text")
                tabs.append(("[%s]" % name) if str(t) == str(w.select()) else name)
            line += " tabs=" + " | ".join(tabs)
        out.append(line)
        if cls == "Treeview":
            self.dump_tree(w, pad + "    ", out)
            return
        if cls == "Text":
            n = int(w.index("end-1c").split(".")[0])
            for i in range(1, min(n, MAX_LINES) + 1):
                out.append(pad + "    | " + w.get("%d.0" % i, "%d.end" % i))
            if n > MAX_LINES:
                out.append(pad + "    | ... %d lines" % n)
            return
        if cls == "Listbox":
            n = w.size()
            sel = set(w.curselection())
            for i in range(min(n, MAX_ROWS)):
                out.append(pad + "    %s%d: %s" % ("*" if i in sel else " ", i, w.get(i)))
            if n > MAX_ROWS:
                out.append(pad + "    ... %d rows" % n)
            return
        for c in w.winfo_children():
            self.dump(c, depth + 1, out, show_all)

    def dump_tree(self, t, pad, out):
        cols = list(t.cget("displaycolumns"))
        if cols in (["#all"], ("#all",)) or not cols or cols[0] == "#all":
            cols = list(t.cget("columns"))
        heads = [t.heading(c, "text") or c for c in cols]
        out.append(pad + "columns: " + " | ".join(heads))
        kids = t.get_children()
        sel = set(t.selection())
        for i, iid in enumerate(kids[:MAX_ROWS]):
            vals = t.item(iid, "values")
            allcols = list(t.cget("columns"))
            shown = [str(vals[allcols.index(c)]) if c in allcols and allcols.index(c) < len(vals) else "" for c in cols]
            text = t.item(iid, "text")      # the tree column (#0), when the list shows it
            out.append(pad + "%s%d: %s" % ("*" if iid in sel else " ", i,
                                          " | ".join(([str(text)] if text != "" else []) + shown)))
        if len(kids) > MAX_ROWS:
            out.append(pad + "... %d rows" % len(kids))

    def c_click(self, args):
        w, _ = self.widget(args)
        if not hasattr(w, "invoke"):
            return ["-ERR %s has no invoke (use key or dclick)" % w]
        r = w.invoke()
        return ["+OK clicked %s %r%s" % (w, text_of(w), "" if r in (None, "") else " -> %s" % r)]

    def c_set(self, args):
        w, rest = self.widget(args)
        value = " ".join(rest)
        if value.startswith("@") and os.path.isfile(value[1:]):
            # set <w> @<file>: the file's text (a script for a Text widget has several lines)
            with open(value[1:], encoding="utf-8") as f:
                value = f.read()
        cls = w.winfo_class()
        if cls == "TCombobox":
            w.set(value)
            w.event_generate("<<ComboboxSelected>>")
        elif cls == "Text":
            w.delete("1.0", "end")
            w.insert("1.0", value)
        else:
            w.delete(0, "end")
            w.insert(0, value)
        return ["+OK %s = %r" % (w, value)]

    def row_of(self, t, spec):
        kids = t.get_children()
        if spec.isdigit() and int(spec) < len(kids):
            return kids[int(spec)]
        for iid in kids:
            vals = t.item(iid, "values")
            if vals and str(vals[0]) == spec:
                return iid
        raise ValueError("no row %s (%d rows)" % (spec, len(kids)))

    def c_select(self, args):
        w, rest = self.widget(args)
        if not rest:
            return ["-ERR select <w> <row>"]
        if w.winfo_class() == "Listbox":
            w.selection_clear(0, "end")
            w.selection_set(int(rest[0]))
            w.see(int(rest[0]))
            w.event_generate("<<ListboxSelect>>")
            return ["+OK row %s" % rest[0]]
        iid = self.row_of(w, rest[0])
        w.selection_set(iid)
        w.focus(iid)
        w.see(iid)
        return ["+OK row %d: %s" % (w.index(iid), " | ".join(map(str, w.item(iid, "values"))))]

    def c_dclick(self, args):
        w, rest = self.widget(args)
        if not rest:
            return ["-ERR dclick <w> <row> [column]"]
        iid = self.row_of(w, rest[0])
        w.selection_set(iid)
        w.see(iid)
        self.root.update_idletasks()
        column = "#1"
        if len(rest) > 1:
            cols = list(w.cget("displaycolumns"))
            if not cols or cols[0] == "#all":
                cols = list(w.cget("columns"))
            heads = [w.heading(c, "text") for c in cols]
            c = rest[1]
            k = int(c) if c.isdigit() else (heads.index(c) if c in heads else cols.index(c))
            column = "#%d" % (k + 1)
        box = w.bbox(iid, column)
        if not box:
            return ["-ERR the row is not on screen"]
        x, y = box[0] + box[2] // 2, box[1] + box[3] // 2
        w.event_generate("<Double-1>", x=x, y=y)
        return ["+OK double-clicked row %d at %s" % (w.index(iid), column)]

    def menus_of(self, w):
        found = [m for m in self.walk(w) if m.winfo_class() == "Menu"]
        return found

    def c_menus(self, args):
        w, _ = self.widget(args)
        out = ["+OK"]
        for m in self.menus_of(w):
            out.append(str(m))
            last = m.index("end")
            for i in range(0, (last if last is not None else -1) + 1):
                if m.type(i) in ("command", "checkbutton", "radiobutton", "cascade"):
                    out.append("    %d: %s" % (i, m.entrycget(i, "label")))
        return out

    def c_menu(self, args):
        w, rest = self.widget(args)
        want = " ".join(rest).lower().split()
        for m in self.menus_of(w):
            last = m.index("end")
            for i in range(0, (last if last is not None else -1) + 1):
                if m.type(i) != "command":
                    continue
                label = m.entrycget(i, "label")
                if want and all(x in label.lower() for x in want):
                    m.invoke(i)
                    return ["+OK ran %r" % label]
        return ["-ERR no menu entry of %s has %r" % (w, " ".join(rest))]

    def c_key(self, args):
        w, rest = self.widget(args)
        if not rest:
            return ["-ERR key <w> <sequence>"]
        seq = rest[0]
        if seq.startswith("<<"):
            w.event_generate(seq)       # a virtual event goes to the widget itself
            return ["+OK %s -> %s" % (seq, w)]
        # A generated key press goes to the window with the keyboard focus, which is not Studio
        # while someone works in another window: the handlers bound to the sequence are run
        # directly instead, in bindtags order (widget, class, window, all), as Tk would.
        ran = []
        for tag in w.bindtags():
            script = w.bind(seq) if tag == str(w) else w.bind_class(tag, seq)
            for cmd in re.findall(r'\[(\S+) %#', script or ""):
                # %# %b %f %h %k %s %t %w %x %y %A %E %K %N %W %T %X %Y %D, as tkinter reads them
                keysym = seq.strip("<>").split("-")[-1]
                fields = ["0", "1", "0", "0", "0", "0", "0", "0", "0", "0", "", "0", keysym, "0",
                          str(w), "2", "0", "0", "0"]
                r = w.tk.call(cmd, *fields)
                ran.append("%s:%s" % (tag, cmd))
                if str(r) == "break":
                    return ["+OK %s -> %s (%s, break)" % (seq, w, ", ".join(ran))]
        if not ran:
            return ["-ERR nothing is bound to %s on %s" % (seq, w)]
        return ["+OK %s -> %s (%s)" % (seq, w, ", ".join(ran))]

    def c_innertab(self, args):
        w, rest = self.widget(args)
        name = " ".join(rest)
        for t in w.tabs():
            if w.tab(t, "text") == name:
                w.select(t)
                return ["+OK %s" % name]
        return ["-ERR tabs are: %s" % " | ".join(w.tab(t, "text") for t in w.tabs())]

    def c_reload(self, args):
        """reload <module>...: a module edited since Studio started is read again (dialogs and
        helpers opened after this use the new code; a tab already open keeps its old objects)."""
        import importlib
        out = ["+OK"]
        for name in args:
            mod = sys.modules.get(name)
            if mod is None:
                out.append("%s: not loaded yet (it is read when first used)" % name)
                continue
            importlib.reload(mod)
            out.append("%s: reloaded" % name)
        return out

    def c_shot(self, args):
        from PIL import ImageGrab
        target = self.root
        if args and args[0] in self.s.detached:
            target = self.s.holders[args[0]]
        elif args:
            self.c_tab(args[:1])
        target.update()
        x, y = target.winfo_rootx(), target.winfo_rooty()
        w, h = target.winfo_width(), target.winfo_height()
        img = ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True)
        path = os.path.join(tempfile.gettempdir(), "breeze_studio_shot_%d.png" % int(time.time() * 1000))
        img.save(path)
        return ["+OK %s %dx%d" % (path, img.width, img.height)]


# ---------------------------------------------------------------- the client
def send(commands, port=PORT):
    """Runs the commands in order; returns the replies (lists of lines)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=90)
    f = s.makefile("rwb")
    f.readline()
    replies = []
    for c in commands:
        f.write((c + "\n").encode("utf-8"))
        f.flush()
        lines = []
        while True:
            l = f.readline().decode("utf-8", "replace").rstrip("\r\n")
            if l == ".":
                break
            lines.append(l)
        replies.append(lines)
    s.close()
    return replies


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return
    # Commands are separated by ";;"; a word with spaces keeps them (it is quoted for the server).
    commands, cur = [], []
    for a in argv + [";;"]:
        if a == ";;":
            if cur:
                commands.append(" ".join(cur))
            cur = []
        else:
            cur.append(a if a.startswith(("'", '"')) or " " not in a or len(argv) == 1 else '"%s"' % a)
    for c, r in zip(commands, send(commands)):
        print("> " + c)
        print("\n".join(r))


if __name__ == "__main__":
    main()
