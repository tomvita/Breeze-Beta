"""Breeze Studio: Watch. Two questions about a running game, on whatever answers them:

  Who touches this address?   every instruction that reads or writes it, with its caller
  What code ran?              the functions called, and the ones first called after a mark

  host                         who touches                      what code ran
  Breeze on a Switch           gen2 watch / gen2 rows           codewatch
  the Lichii fork              its probe (probe data)           its probe (probe code)
  emuhost (a stock emulator)   the stub's watchpoints           -

    python studio_watch.py [ip[:port]] [code]

The Lichii fork has one more, Break and trace (studio_break.py): breakpoints that hold the
thread that reaches them, step, step over, and a trace of the next N instructions.

A Switch has two more, gen2's field watch and method watch:

  Which fields are used?      every byte of an object watched; names from the field map
  Which methods run?          called or not, the first caller, the object it ran on

On a Switch the game runs only while Breeze is hidden (the button in Studio's header), and a
watch slows a busy address. On emuhost every hit stops the game for a moment, and the emulator
has four watchpoints. Emulator hosts also show every client's commands live (Activity).
Python 3 with tkinter only (capstone is used for the instructions when installed).
"""
import bisect
import json
import os
import queue
import socket
import struct
import sys
import threading
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from game_title import window_title  # noqa: E402
import studio_break  # noqa: E402

try:
    import capstone
    CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
except Exception:  # noqa: BLE001
    CS = None

CACHE = os.path.join(os.path.expanduser("~"), ".breeze_pc_cache")


class Client:
    """One connection. *EVENT lines that arrive between replies go to `events`."""

    def __init__(self, host, port, code, name="breeze_studio"):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(900)
        self.buf = b""
        self.lock = threading.Lock()
        self.events = queue.Queue()
        self.banner = self._line()
        r = self.cmd("auth " + code)
        if not r.startswith("+OK"):
            raise RuntimeError(r)
        self.cmd("hello " + name)

    def _raw_line(self):
        while b"\n" not in self.buf:
            d = self.sock.recv(65536)
            if not d:
                raise ConnectionError("PC connect closed the connection")
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def _line(self):
        while True:
            l = self._raw_line()
            if l.startswith("*EVENT "):
                self.events.put(l[7:])
                continue
            return l

    def cmd(self, line, multi=False):
        """The reply's first line; with multi, every line of a +OK reply up to its '.'."""
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

    def peek(self, addr, n):
        r = self.cmd("peek %X %d" % (addr, n))
        if not r.startswith("+OK"):
            return b""
        return bytes.fromhex(r.split()[-1]) if len(r.split()) > 1 else b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def split_address(address):
    host, _, port = address.partition(":")
    return host, int(port) if port else 6801


class Names:
    """Function names for a code address, from the game folder's function map. A name is given
    only for the function the unwind table says the address is in, when that table is there."""

    def __init__(self):
        self.starts, self.names, self.sure = [], {}, False

    def load(self, address, code, meta):
        import pcconnect_asm
        from pcconnect import Breeze
        b = Breeze(address, code, timeout=120, connect_timeout=5)
        try:
            files = b.files()
            have = {f["name"]: f["size"] for f in files.get("files", []) if "size" in f}
            bid = meta.get("build_id", "").upper()
            folder = os.path.join(CACHE, "%s_%s" % (meta.get("title_id", ""), bid))
            os.makedirs(folder, exist_ok=True)

            def cached(name):
                local = os.path.join(folder, name)
                if os.path.exists(local) and os.path.getsize(local) == have[name]:
                    with open(local, "rb") as f:
                        return f.read()
                return b.get_file(files.get("dir", "") + name, local)

            size = int(meta.get("main_size", "0"), 16)
            for name in pcconnect_asm.MAPS:
                if name in have:
                    self.names = pcconnect_asm.map_names(cached(name).decode("utf-8", "replace"), size)
                    break
            starts = set(self.names)
            eh = "ehframe_%s.bin" % bid[:16]
            if eh in have:
                data = cached(eh)
                if data[:8] == b"BZEHFR01":
                    count = struct.unpack_from("<I", data, 48)[0]
                    starts.update(struct.unpack_from("<%dI" % count, data, 56))
                    self.sure = True
            self.starts = sorted(starts)
        finally:
            b.close()

    def label(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i < 0:
            return ""
        start = self.starts[i]
        name = self.names.get(start)
        if not name or rva - start > 0x40000:
            return ""
        return (name if rva == start else "%s+%X" % (name, rva - start)) + ("" if self.sure else " ?")


class Back:
    """What a host answers. Rows are dicts; `key` is what the host knows a row by."""
    console = False
    has_code = True
    code_views = ()
    lengths = None       # the lengths a data watch may have (None: any)
    note = ""

    def __init__(self, client, main, names):
        self.c, self.main, self.names = client, main, names

    def rva(self, text):
        """'M+1234' -> 0x1234; anything else -> None."""
        t = (text or "").strip()
        if t.upper().startswith("M+"):
            try:
                return int(t[2:].split("+")[0], 16)
            except ValueError:
                return None
        return None

    def named(self, text):
        r = self.rva(text)
        return self.names.label(r) if r is not None else ""


class ProbeBack(Back):
    """The fork's probe, and emuhost's data watch: the same `probe` lines."""

    def __init__(self, client, main, names, status):
        Back.__init__(self, client, main, names)
        self.has_code = status.get("code") is not None
        self.code_views = ("new", "all", "hot")
        slots = status.get("data", {}).get("slots")
        if slots:
            self.note = ("a stock emulator: each hit stops the game for a moment, %d watches at most, and they come "
                         "off after %s hits" % (slots, status["data"].get("max", "?")))

    def probe(self, args):
        return self.c.cmd("probe " + args, multi=True)

    def data_add(self, address, length, mode, stack):
        return self.probe("data add %X %X %s" % (address, length, mode))[0]

    def data_stop(self):
        return self.probe("data stop")[0]

    def data_clear(self):
        return self.probe("data clear")[0]

    def data_rows(self):
        r = self.probe("data list")
        rows = []
        for l in r[1:]:
            p = l.split()
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            rows.append({"key": p[0], "rw": p[1], "pc": kv.get("pc", ""), "fn": self.named(kv.get("pc")),
                         "caller": kv.get("lr", ""), "caller_fn": self.named(kv.get("lr")), "count": kv.get("count", ""),
                         "before": kv.get("before", ""), "after": kv.get("after", ""), "last": kv.get("last", ""),
                         "thread": kv.get("thread", "")})
        st = self.probe("status")
        on = 0
        try:
            on = json.loads(st[0][4:])["data"]["watches"]
        except Exception:  # noqa: BLE001
            pass
        return r[0][4:] + (", %d watch(es) on" % on if on else ", no watch on"), rows, on > 0

    def data_detail(self, row):
        out = []
        for l in self.probe("data regs %s" % row["key"])[1:]:
            if l.startswith("sp+"):
                for x in l.split():
                    where = x.split("=", 1)[1]
                    out.append((x + ("   " + self.named(where) if where.startswith("M+") else ""), "ret" if "=M+" in x else ""))
            else:
                words = l.split()
                for i in range(0, len(words), 3):
                    out.append(("   ".join("%-20s" % w for w in words[i:i + 3]), ""))
                out.append(("", ""))
        return out

    def code_start(self, scope):
        return self.probe("code start main")[0]

    def code_mark(self):
        return self.probe("code mark")[0]

    def code_stop(self):
        return self.probe("code stop")[0]

    def code_clear(self):
        return self.probe("code clear")[0]

    def code_trace(self, addresses, cap):
        return self.probe("code add %s count %s" % (" ".join(addresses), cap))[0]

    def code_rows(self, view):
        r = self.probe("code list %s 2000" % view)
        rows = []
        for l in r[1:]:
            p = l.split()
            if len(p) < 3:
                continue
            kv = dict(x.split("=", 1) for x in p[2:] if "=" in x)
            rows.append({"order": p[0], "at": p[1], "name": self.named(p[1]), "caller": kv.get("caller", ""),
                         "caller_fn": self.named(kv.get("caller")), "hits": kv.get("hits", ""),
                         "more": l.split(" callers ", 1)[1] if " callers " in l else ""})
        return r[0][4:] if r[0].startswith("+OK") else r[0], rows, True


class ConsoleBack(Back):
    """Breeze on a Switch: the gen2 fork's watches."""
    console = True
    code_views = ("new", "all", "classes new", "classes")
    lengths = (1, 2, 4, 8)
    note = "a Switch: the game runs only while Breeze is hidden (the button in the header)"

    def one(self, line):
        r = self.c.cmd(line)
        return r

    def data_add(self, address, length, mode, stack):
        return self.short(self.one("gen2 watch %X %s %d stack=%d" % (address, mode, length, stack)))

    def short(self, r):
        if not r.startswith("+OK {"):
            return r
        try:
            j = json.loads(r[4:])
        except ValueError:
            return r[:200]
        if "state" in j:
            return "+OK code watch %s: %s functions, %s called, %s new" % (
                j.get("state"), j.get("functions", 0), j.get("called", 0), j.get("new", 0))
        return "+OK gen2 %s%s, %s rows, %s hits" % (
            "watching %s" % j.get("address") if j.get("attached") else "not attached",
            ", %d failed" % j["failed"] if j.get("failed") else "", j.get("rows", 0), j.get("trig", 0))

    def data_stop(self):
        return self.short(self.one("gen2 stop"))

    def data_clear(self):
        return "-ERR gen2 keeps its rows until the next watch starts"

    def data_rows(self):
        r = self.one("gen2 rows")
        if not r.startswith("+OK"):
            return r, [], False
        j = json.loads(r[4:])
        rows = []
        for i, x in enumerate(j.get("list", [])):
            if "pc" not in x:      # an instruction watch: the values a register held
                rows.append({"key": str(i), "rw": "", "pc": x.get("value", ""), "fn": "(register value)", "caller": "",
                             "caller_fn": "", "count": x.get("count", ""), "before": "", "after": "", "last": "", "thread": "",
                             "stack": []})
                continue
            rows.append({"key": str(i), "rw": ("R" if j.get("read") else "") + ("W" if j.get("write") else ""),
                         "pc": x.get("pc", ""), "fn": x.get("pc_name", ""), "caller": x.get("call_site", ""),
                         "caller_fn": x.get("call_site_name", ""), "count": x.get("count", ""), "before": "", "after": "",
                         "last": "", "thread": "", "stack": x.get("stack", [])})
        return self.short(r)[4:], rows, bool(j.get("attached"))

    def data_detail(self, row):
        out = [("%s   %s" % (row["pc"], row["fn"]), ""), ("called from %s   %s" % (row["caller"], row["caller_fn"]), ""), ("", "")]
        for off, where in row.get("stack", []):
            out.append(("sp+%X=%s" % (off, where), "ret"))
        if not row.get("stack"):
            out.append(("(start the watch with a stack depth to record return addresses)", ""))
        return out

    def code_start(self, scope):
        return self.short(self.one("codewatch start %s" % (scope or "own")))

    def code_mark(self):
        return self.short(self.one("codewatch mark"))

    def code_stop(self):
        return self.short(self.one("codewatch stop"))

    def code_clear(self):
        return self.short(self.one("codewatch clear"))

    def code_trace(self, addresses, cap):
        return "-ERR on a Switch use the Code tab's breakpoints for one function"

    def code_rows(self, view):
        st = self.one("codewatch")
        head = self.short(st)
        on = '"capturing"' in st
        r = self.one("codewatch " + ("classes" if view.startswith("classes") else "list") + (" new" if view.endswith("new") else ""))
        if not r.startswith("+OK"):
            return head[4:] + "   (" + r + ")", [], on
        rows = []
        for x in json.loads(r[4:]).get("list", []):
            if "class" in x:
                rows.append({"order": "", "at": "", "name": x["class"], "caller": "", "caller_fn": "",
                             "hits": "%s of %s called" % (x.get("called"), x.get("methods")), "more": "%s new" % x.get("new")})
            else:
                rows.append({"order": str(x.get("order", "")), "at": x.get("at", ""), "name": x.get("name", ""),
                             "caller": x.get("caller", ""), "caller_fn": "", "hits": "", "more": ""})
        return head[4:], rows, on


class App:
    def __init__(self, root, address, code):
        self.root, self.address, self.code = root, address, code
        self.host, self.port = split_address(address)
        self.client = self.events_client = self.back = None
        self.main = 0
        self.names = Names()
        self.work, self.ui = queue.Queue(), queue.Queue()
        self.data_on = self.code_on = self.field_on = self.method_on = False
        self.data_rows, self.code_rows, self.field_rows, self.method_rows = [], [], [], []
        self.objects = None        # studio_objects.Game: the field map, for the field watch's names
        self.jobs = {}
        self.closed = False
        self.asked = None          # a watch another tab asked for before this one was connected
        self.brk = None            # studio_break.BreakPanel, where the host has breakpoints
        root.title("Watch")
        root.geometry("1180x820")

        top = ttk.Frame(root)
        top.pack(fill="x", padx=6, pady=4)
        self.status = tk.StringVar(value="connecting...")
        ttk.Label(top, textvariable=self.status).pack(side="left")
        self.note = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.note, foreground="#666").pack(side="right")

        self.pane = ttk.PanedWindow(root, orient="vertical")
        self.pane.pack(fill="both", expand=True, padx=6)
        self.nb = ttk.Notebook(self.pane)
        self.pane.add(self.nb, weight=3)
        self.build_data()
        self.build_code()
        self.build_fields()
        self.build_methods()
        self.act = None
        self.nb.bind("<<NotebookTabChanged>>", self.on_inner_tab)

        threading.Thread(target=self.worker, daemon=True).start()
        self.run(self.connect, self.connected)
        root.after(100, self.tick)
        root.after(1500, self.live)

    # ------------------------------------------------------------------ plumbing
    def worker(self):
        while True:
            fn, done = self.work.get()
            try:
                r, ex = fn(), None
            except Exception as e:  # noqa: BLE001
                r, ex = None, e
            self.ui.put((done, r, ex))

    def run(self, fn, done=None, label=None):
        if label:
            self.status.set(label + "...")
        self.work.put((fn, done))

    def tick(self):
        if self.closed:
            return
        while not self.ui.empty():
            done, r, ex = self.ui.get()
            if ex is not None:
                self.status.set("error: %s" % ex)
            elif done:
                done(r)
        if self.events_client and self.act is not None:
            n = 0
            while not self.events_client.events.empty() and n < 400:
                self.event(self.events_client.events.get())
                n += 1
        self.root.after(100, self.tick)

    def close(self):
        self.closed = True
        for c in (self.client, self.events_client, self.objects.b if self.objects else None):
            if c:
                c.close()

    def connect(self):
        self.client = Client(self.host, self.port, self.code, "studio_watch")
        caps = self.client.cmd("caps").split()[1:]
        meta = {}
        try:
            meta = json.loads(self.client.cmd("meta")[4:])
            self.main = int(meta.get("main", "0"), 16)
        except Exception:  # noqa: BLE001
            pass
        history = []
        if "ui" in caps:
            back = ConsoleBack(self.client, self.main, self.names)
        else:
            st = self.client.cmd("probe status", multi=True)
            if not st[0].startswith("+OK"):
                raise RuntimeError("this host has no watch (%s)" % st[0])
            try:
                self.names.load(self.address, self.code, meta)
            except Exception:  # noqa: BLE001 - names are a help, not a need
                pass
            back = ProbeBack(self.client, self.main, self.names, json.loads(st[0][4:]))
            back.has_break = studio_break.supported(back)
            ev = Client(self.host, self.port, self.code, "studio_watch_events")
            ev.cmd("events on")
            self.events_client = ev
            history = self.client.cmd("activity 300", multi=True)[1:]
            threading.Thread(target=self.event_reader, daemon=True).start()
        return back, meta, history

    def connected(self, r):
        self.back, meta, history = r
        try:
            self.root.title(window_title("Watch", meta))
        except Exception:  # noqa: BLE001
            pass
        self.note.set(self.back.note)
        self.status.set("connected to %s  main %X%s" % (self.address, self.main,
                        "" if self.back.console or self.names.names else "  (no function map in the game's folder: addresses only)"))
        if self.back.lengths:
            self.d_len.configure(values=[str(x) for x in self.back.lengths], state="readonly")
            self.d_len.set("4")
            self.d_stack_label.pack(side="left")
            self.d_stack.pack(side="left", padx=3)
            self.d_clear.state(["disabled"])
            # gen2 records who, not the values or the thread
            self.data_tree.configure(displaycolumns=("rw", "pc", "fn", "caller", "caller_fn", "count"))
        if self.back.has_code:
            self.code_view.configure(values=list(self.back.code_views))
            self.code_view.set(self.back.code_views[0])
            if self.back.console:
                self.scope_label.pack(side="left", before=self.code_start_button)
                self.scope.pack(side="left", padx=3, before=self.code_start_button)
                self.trace_button.pack_forget()
                self.cap_label.pack_forget()
                self.cap.pack_forget()
        else:
            self.nb.forget(self.code_frame)
        if not self.back.console:
            self.nb.forget(self.field_frame)       # gen2's field and method watches: a Switch only
            self.nb.forget(self.method_frame)
            if getattr(self.back, "has_break", False) and self.brk is None:
                self.brk = studio_break.BreakPanel(self)
                for menu, tree, entries in (
                        (self.data_menu, self.data_tree, (("Break at this instruction", 1), ("Break at the caller", 3))),
                        (self.code_menu, self.code_tree, (("Break at this function", 1),))):
                    menu.add_separator()
                    for label, column in entries:
                        menu.add_command(label=label, command=lambda t=tree, c=column: self.break_picked(t, c))
            self.build_activity()
            for l in history:
                self.event(l)
        self.refresh_data()
        if self.back.has_code:
            self.refresh_code()
        if self.back.console:
            self.refresh_fields(quiet=True)
            self.refresh_methods(quiet=True)
        if self.asked:
            asked, self.asked = self.asked, None
            self.watch_address(*asked)

    def on_inner_tab(self, _e=None):
        """gen2 runs one watch at a time: the one started last ended the others, so a tab reads
        its state again when it is shown."""
        if not self.back or not self.back.console or not self.nb.tabs():
            return
        shown = self.nb.nametowidget(self.nb.select())
        for frame, refresh in ((self.data_frame, self.refresh_data), (self.code_frame, self.refresh_code),
                               (self.field_frame, self.refresh_fields), (self.method_frame, self.refresh_methods)):
            if shown is frame:
                refresh(quiet=True)

    def live(self):
        """While a watch is on, the lists follow it."""
        if self.closed:
            return
        if self.back and self.work.empty() and self.root.winfo_viewable():
            shown = self.nb.nametowidget(self.nb.select()) if self.nb.tabs() else None
            if shown is self.data_frame and self.data_on and self.d_live.get():
                self.refresh_data(quiet=True)
            elif shown is self.code_frame and self.code_on and self.c_live.get():
                self.refresh_code(quiet=True)
            elif shown is self.field_frame and self.field_on and self.f_live.get():
                self.refresh_fields(quiet=True)
            elif shown is self.method_frame and self.method_on and self.m_live.get():
                self.refresh_methods(quiet=True)
        self.root.after(1500, self.live)

    def addr(self, text):
        """M+offset or hex -> absolute."""
        t = text.strip()
        if t.upper().startswith("M+"):
            return self.main + int(t[2:], 16)
        return int(t, 16)

    def said(self, r):
        self.status.set(r if isinstance(r, str) else str(r))

    # ------------------------------------------------------------------ who touches an address
    def build_data(self):
        f = self.data_frame = ttk.Frame(self.nb)
        self.nb.add(f, text="Who touches an address")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=3)
        ttk.Label(bar, text="address (hex or M+)").pack(side="left")
        self.d_addr = ttk.Entry(bar, width=16)
        self.d_addr.pack(side="left", padx=3)
        self.d_addr.bind("<Return>", lambda e: self.data_add())
        ttk.Label(bar, text="bytes (hex)").pack(side="left")
        self.d_len = ttk.Combobox(bar, width=5, values=["1", "2", "4", "8", "10", "40", "100"])
        self.d_len.set("4")
        self.d_len.pack(side="left", padx=3)
        self.d_mode = ttk.Combobox(bar, values=["w", "r", "rw"], width=4, state="readonly")
        self.d_mode.set("w")
        self.d_mode.pack(side="left", padx=3)
        self.d_stack_label = ttk.Label(bar, text="stack")
        self.d_stack = ttk.Combobox(bar, values=["0", "1", "2", "3", "4", "5"], width=3, state="readonly")
        self.d_stack.set("2")
        self.d_watch = ttk.Button(bar, text="Watch", command=self.data_add)
        self.d_watch.pack(side="left")
        ttk.Button(bar, text="Stop", command=lambda: self.data_do("data_stop")).pack(side="left", padx=4)
        self.d_clear = ttk.Button(bar, text="Clear", command=lambda: self.data_do("data_clear"))
        self.d_clear.pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_data).pack(side="left", padx=4)
        self.d_live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="follow", variable=self.d_live).pack(side="left")
        self.d_info = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.d_info, foreground="#245").pack(side="right", padx=6)

        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True)
        cols = ("rw", "pc", "fn", "caller", "caller_fn", "count", "before", "after", "last", "thread")
        heads = ("", "instruction", "in", "called from", "in", "count", "before", "after", "last", "thread")
        left = ttk.Frame(body)
        self.data_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, heads, (30, 95, 230, 95, 200, 55, 85, 85, 85, 50)):
            self.data_tree.heading(c, text=h)
            self.data_tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(left, command=self.data_tree.yview)
        self.data_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.data_tree.pack(fill="both", expand=True)
        self.data_tree.bind("<<TreeviewSelect>>", lambda e: self.show_data_row())
        body.add(left, weight=3)
        self.detail = tk.Text(body, width=58, font=("Consolas", 9), wrap="none")
        self.detail.tag_configure("ret", foreground="#05a")
        self.detail.tag_configure("here", background="#fe9")
        body.add(self.detail, weight=2)
        menu = tk.Menu(self.data_tree, tearoff=0)
        menu.add_command(label="Copy instruction address", command=lambda: self.copy(self.data_tree, 1))
        menu.add_command(label="Copy caller address", command=lambda: self.copy(self.data_tree, 3))
        self.data_menu = menu
        self.data_tree.bind("<Button-3>", lambda e: self.popup(e, self.data_tree, menu))

    def popup(self, e, tree, menu):
        row = tree.identify_row(e.y)
        if row:
            tree.selection_set(row)
            menu.tk_popup(e.x_root, e.y_root)

    def copy(self, tree, column):
        sel = tree.selection()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(tree.item(sel[0], "values")[column])

    def break_picked(self, tree, column):
        sel = tree.selection()
        if sel and self.brk:
            self.brk.add(tree.item(sel[0], "values")[column])

    def break_address(self, address):
        """A breakpoint on the instruction at an address. (Other tabs call this.)"""
        if self.brk:
            self.brk.add("%X" % address)
        else:
            self.status.set("this host has no breakpoints (the Lichii fork has; on a Switch use Breeze's Gen2 Action)")

    def watch_address(self, address, size=4):
        """Starts "Who touches an address" on it. (Other tabs call this.) On a Switch gen2 runs
        one watch at a time: this one ends the watch that was running."""
        if not self.back:
            self.asked = (address, size)
            return
        size = size if size in (1, 2, 4, 8) else 4
        if self.back.lengths and size not in self.back.lengths:
            size = max([x for x in self.back.lengths if x <= size] or [min(self.back.lengths)])
        self.d_addr.delete(0, "end")
        self.d_addr.insert(0, "%X" % address)
        self.d_len.set("%X" % size)
        self.d_mode.set("rw")
        self.nb.select(self.data_frame)
        self.data_add()

    def data_add(self):
        if not self.back:
            return
        try:
            a = self.addr(self.d_addr.get())
            n = int(self.d_len.get().strip() or "4", 16)
        except ValueError:
            self.status.set("address: hex or M+offset; bytes: hex")
            return
        mode, stack = self.d_mode.get(), int(self.d_stack.get())

        def done(r):
            self.said(r)
            self.refresh_data(quiet=True)
        self.run(lambda: self.back.data_add(a, n, mode, stack), done, "watching %X" % a)

    def data_do(self, what):
        if not self.back:
            return

        def done(r):
            self.said(r)
            self.refresh_data(quiet=True)
        self.run(getattr(self.back, what), done)

    def refresh_data(self, quiet=False):
        if not self.back:
            return

        def done(r):
            summary, rows, on = r
            self.data_on = on
            self.d_info.set(summary)
            sel = self.data_tree.selection()
            keep = self.data_tree.index(sel[0]) if sel else None
            same = [x["key"] for x in rows] == [x["key"] for x in self.data_rows]
            self.data_rows = rows
            if same:        # only the numbers moved: the selection and the scroll stay
                for iid, x in zip(self.data_tree.get_children(), rows):
                    self.data_tree.item(iid, values=self.data_values(x))
                return
            self.data_tree.delete(*self.data_tree.get_children())
            for x in rows:
                self.data_tree.insert("", "end", values=self.data_values(x))
            kids = self.data_tree.get_children()
            if keep is not None and keep < len(kids):
                self.data_tree.selection_set(kids[keep])
        self.run(self.back.data_rows, done, None if quiet else "reading the rows")

    def data_values(self, x):
        return (x["rw"], x["pc"], x["fn"], x["caller"], x["caller_fn"], x["count"], x["before"], x["after"], x["last"], x["thread"])

    def show_data_row(self):
        sel = self.data_tree.selection()
        if not sel:
            return
        i = self.data_tree.index(sel[0])
        if i >= len(self.data_rows):
            return
        row = self.data_rows[i]

        def fn():
            return self.back.data_detail(row), self.code_around(row["pc"])

        def done(r):
            lines, code = r
            self.detail.delete("1.0", "end")
            for text, tag in code + [("", "")] + lines:
                self.detail.insert("end", text + "\n", tag)
        self.run(fn, done)

    def target_note(self, ins):
        """"  ; Class::Method" for a call or jump to a named function of main."""
        if ins.mnemonic not in ("bl", "b") or not ins.op_str.startswith("#"):
            return ""
        try:
            rva = int(ins.op_str[1:], 16) - self.main
        except ValueError:
            return ""
        name = self.names.label(rva) if rva >= 0 else ""
        return "  ; " + name if name else ""

    def code_around(self, where, before=6, after=6):
        """The instructions around a code address, the one at it marked."""
        try:
            a = self.addr(where.split()[0])
        except (ValueError, IndexError):
            return []
        data = self.client.peek(a - before * 4, (before + after + 1) * 4)
        out = []
        for k in range(0, len(data) - 3, 4):
            at = a - before * 4 + k
            word = struct.unpack_from("<I", data, k)[0]
            text = "%08X" % word
            if CS is not None:
                for ins in CS.disasm(data[k:k + 4], at):
                    text = "%-8s %s%s" % (ins.mnemonic, ins.op_str, self.target_note(ins))
            rel = "M+%X" % (at - self.main) if self.main and self.main <= at < self.main + 0x40000000 else "%X" % at
            out.append(("%-12s %s" % (rel, text), "here" if at == a else ""))
        if CS is None and out:
            out.append(("(pip install capstone to read these as instructions)", ""))
        return out

    # ------------------------------------------------------------------ what code ran
    def build_code(self):
        f = self.code_frame = ttk.Frame(self.nb)
        self.nb.add(f, text="What code ran")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=3)
        self.scope_label = ttk.Label(bar, text="functions")
        self.scope = ttk.Combobox(bar, width=14, values=["own", "all"])
        self.scope.set("own")
        self.code_start_button = ttk.Button(bar, text="Start", command=self.code_start)
        self.code_start_button.pack(side="left")
        ttk.Button(bar, text="Mark", command=lambda: self.code_do("code_mark")).pack(side="left", padx=4)
        ttk.Button(bar, text="Stop", command=lambda: self.code_do("code_stop")).pack(side="left")
        ttk.Button(bar, text="Clear", command=lambda: self.code_do("code_clear")).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Label(bar, text="show").pack(side="left")
        self.code_view = ttk.Combobox(bar, values=["new", "all"], width=11, state="readonly")
        self.code_view.set("new")
        self.code_view.bind("<<ComboboxSelected>>", lambda e: self.refresh_code())
        self.code_view.pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh", command=self.refresh_code).pack(side="left")
        self.c_live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="follow", variable=self.c_live).pack(side="left", padx=4)
        self.trace_button = ttk.Button(bar, text="Count calls of the selected", command=self.trace_selected)
        self.trace_button.pack(side="left", padx=4)
        self.cap_label = ttk.Label(bar, text="up to")
        self.cap_label.pack(side="left")
        self.cap = ttk.Entry(bar, width=6)
        self.cap.insert(0, "500")
        self.cap.pack(side="left", padx=3)
        self.c_info = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.c_info, foreground="#245").pack(side="right", padx=6)

        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True)
        cols = ("order", "at", "name", "caller", "caller_fn", "hits", "more")
        heads = ("order", "function", "name", "first caller", "in", "calls", "callers")
        left = ttk.Frame(body)
        self.code_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended")
        for c, h, w in zip(cols, heads, (50, 95, 300, 95, 200, 90, 220)):
            self.code_tree.heading(c, text=h)
            self.code_tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(left, command=self.code_tree.yview)
        self.code_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.code_tree.pack(fill="both", expand=True)
        self.code_tree.bind("<<TreeviewSelect>>", lambda e: self.show_code_row())
        body.add(left, weight=3)
        self.disasm = tk.Text(body, width=58, font=("Consolas", 9), wrap="none")
        self.disasm.tag_configure("here", background="#fe9")
        body.add(self.disasm, weight=2)
        menu = tk.Menu(self.code_tree, tearoff=0)
        menu.add_command(label="Copy function address", command=lambda: self.copy(self.code_tree, 1))
        menu.add_command(label="Copy name", command=lambda: self.copy(self.code_tree, 2))
        self.code_menu = menu
        self.code_tree.bind("<Button-3>", lambda e: self.popup(e, self.code_tree, menu))

    def code_start(self):
        if not self.back:
            return
        scope = self.scope.get().strip()

        def done(r):
            # A Switch arms tens of thousands of breaks: longer than its 3 s for one answer.
            self.said("starting: the list follows" if "busy" in r else r)
            self.code_on = True
            self.refresh_code(quiet=True)
        self.run(lambda: self.back.code_start(scope), done, "starting the code watch")

    def code_do(self, what):
        if not self.back:
            return

        def done(r):
            self.said("still at it: the list follows" if "busy" in r else r)
            self.refresh_code(quiet=True)
        self.run(getattr(self.back, what), done)

    def refresh_code(self, quiet=False):
        if not self.back or not self.back.has_code:
            return
        view = self.code_view.get() or "new"

        def done(r):
            summary, rows, on = r
            self.code_on = on
            self.c_info.set(summary)
            if [(x["at"], x["name"]) for x in rows] == [(x["at"], x["name"]) for x in self.code_rows]:
                self.code_rows = rows
                for iid, x in zip(self.code_tree.get_children(), rows):
                    self.code_tree.item(iid, values=self.code_values(x))
                return
            chosen = set(self.code_tree.item(i, "values")[1] for i in self.code_tree.selection())
            self.code_rows = rows
            self.code_tree.delete(*self.code_tree.get_children())
            for x in rows:
                iid = self.code_tree.insert("", "end", values=self.code_values(x))
                if x["at"] and x["at"] in chosen:
                    self.code_tree.selection_add(iid)
        self.run(lambda: self.back.code_rows(view), done, None if quiet else "reading the list")

    def code_values(self, x):
        return (x["order"], x["at"], x["name"], x["caller"], x["caller_fn"], x["hits"], x["more"])

    def trace_selected(self):
        at = [self.code_tree.item(i, "values")[1] for i in self.code_tree.selection()]
        at = [a for a in at if a]
        if not at:
            self.status.set("select functions in the list first")
            return
        cap = self.cap.get().strip() or "500"

        def done(r):
            self.said(r)
            if "hot" in self.back.code_views:
                self.code_view.set("hot")
            self.refresh_code(quiet=True)
        self.run(lambda: self.back.code_trace(at, cap), done)

    def show_code_row(self):
        sel = self.code_tree.selection()
        if not sel:
            return
        at = self.code_tree.item(sel[0], "values")[1]
        if not at:
            return

        def done(lines):
            self.disasm.delete("1.0", "end")
            for text, tag in lines:
                self.disasm.insert("end", text + "\n", tag)
        self.run(lambda: self.code_around(at, 0, 40), done)

    # ------------------------------------------------------------------ which fields are used (a Switch)
    def build_fields(self):
        f = self.field_frame = ttk.Frame(self.nb)
        self.nb.add(f, text="Which fields are used")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=3)
        ttk.Label(bar, text="object (hex)").pack(side="left")
        self.f_addr = ttk.Entry(bar, width=16)
        self.f_addr.pack(side="left", padx=3)
        self.f_addr.bind("<Return>", lambda e: self.field_start())
        ttk.Label(bar, text="bytes (hex; empty: from its class)").pack(side="left")
        self.f_size = ttk.Entry(bar, width=6)
        self.f_size.pack(side="left", padx=3)
        self.f_mode = ttk.Combobox(bar, values=["w", "r", "rw"], width=4, state="readonly")
        self.f_mode.set("rw")
        self.f_mode.pack(side="left", padx=3)
        ttk.Button(bar, text="Start", command=self.field_start).pack(side="left")
        for text, what in (("Sweep", "sweep"), ("Mark", "mark"), ("Stop", "stop"), ("Clear", "clear")):
            ttk.Button(bar, text=text, command=lambda w=what: self.field_do(w)).pack(side="left", padx=2)
        ttk.Button(bar, text="Refresh", command=self.refresh_fields).pack(side="left", padx=4)
        self.f_live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="follow", variable=self.f_live).pack(side="left")
        self.f_info = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.f_info, foreground="#245", anchor="w").pack(fill="x", padx=4)
        ttk.Label(f, foreground="#666", anchor="w", text="Every byte of the object is watched; the fields the game reads or "
                  "writes appear here. Sweep goes on with only the bytes not seen yet, at full game speed. "
                  "Mark, do one thing in the game: what it touches shows as new.").pack(fill="x", padx=4)
        cols = ("off", "name", "type", "value", "new", "of")
        heads = ("offset", "field", "type", "value", "", "declared in")
        box = ttk.Frame(f)
        box.pack(fill="both", expand=True)
        self.field_tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, heads, (60, 300, 300, 220, 50, 260)):
            self.field_tree.heading(c, text=h)
            self.field_tree.column(c, width=w, anchor="w")
        self.field_tree.tag_configure("new", background="#fe9")
        sb = ttk.Scrollbar(box, command=self.field_tree.yview)
        self.field_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.field_tree.pack(fill="both", expand=True)
        menu = tk.Menu(self.field_tree, tearoff=0)
        menu.add_command(label="Who touches this field", command=self.field_to_data)
        menu.add_command(label="Copy field address", command=self.field_copy)
        self.field_tree.bind("<Button-3>", lambda e: self.popup(e, self.field_tree, menu))
        self.field_tree.bind("<Double-1>", lambda e: self.field_to_data())

    def game_objects(self):
        """The field map (worker thread). None when the game has none."""
        if self.objects is None:
            try:
                import studio_objects
                self.objects = studio_objects.Game(self.address, self.code)
            except Exception:  # noqa: BLE001 - names are a help, not a need
                self.objects = False
        return self.objects or None

    def class_fields(self, base):
        """(class name, [(offset, size, field, declaring class)]) of the object at base."""
        g = self.game_objects()
        if g is None or not g.classes:
            return "", []
        g.fresh()
        k = g.class_of(base, "")
        if k is None:
            return "", []
        return k.name, [(f.offset, g.size_of(f.type), f, c) for c, f in g.instance_fields(k)]

    def field_start(self):
        if not self.back:
            return
        try:
            base = int(self.f_addr.get().strip(), 16)
            size = int(self.f_size.get().strip(), 16) if self.f_size.get().strip() else 0
        except ValueError:
            self.status.set("object: a hex address; bytes: hex")
            return
        mode = self.f_mode.get()

        def fn():
            n = size
            if n == 0:
                name, fields = self.class_fields(base)
                if not fields:
                    return "-ERR that object's class is not in the field map: give the bytes to watch"
                n = (max(off + sz for off, sz, _f, _c in fields) + 7) & ~7
            return self.short_field(self.client.cmd("fieldwatch start %X %X %s" % (base, n, mode)))

        def done(r):
            self.said(r)
            self.refresh_fields(quiet=True)
        self.run(fn, done, "watching the object at %X" % base)

    def short_field(self, r):
        if not r.startswith("+OK {"):
            return r
        j = json.loads(r[4:])
        if j.get("state") == "none":
            return "+OK no field watch"
        return "+OK field watch %s: %s +%X, %s hits" % (j.get("state"), j.get("base"), j.get("size", 0), j.get("trig", 0))

    def field_do(self, what):
        if not self.back:
            return

        def done(r):
            self.said(r)
            self.refresh_fields(quiet=True)
        self.run(lambda: self.short_field(self.client.cmd("fieldwatch " + what)), done)

    def read_fields(self):
        r = self.client.cmd("fieldwatch")
        if not r.startswith("+OK {"):
            return r, [], False
        j = json.loads(r[4:])
        if j.get("state") == "none":
            return "no field watch yet", [], False
        base, runs = int(j["base"], 16), j.get("bytes", [])
        fresh = set(x["off"] for x in j.get("fields", []) if x.get("new"))
        name, fields = self.class_fields(base)
        g = self.objects or None
        rows, covered = [], set()
        if fields:
            import studio_objects
            if any(a < 8 for a, _n in runs):
                rows.append({"off": 0, "name": "(the object's class pointer)", "type": "", "value": "",
                             "new": any(o in fresh for o in range(0, 8)), "of": "", "size": 8})
            covered.update(range(0, 16))
            for off, size, f, c in fields:
                if not any(a < off + size and a + n > off for a, n in runs):
                    continue
                row = studio_objects.Row(f.name, f.type, base + off, "")
                g.describe(row)
                rows.append({"off": off, "name": f.name, "type": f.type, "value": (row.value + "  " + row.note).strip(),
                             "new": any(o in fresh for o in range(off, off + size)), "of": c.name, "size": size})
                covered.update(range(off, off + size))
        for x in j.get("fields", []):      # what the map has no field for, as Breeze gives it
            if x["off"] not in covered:
                rows.append({"off": x["off"], "name": x.get("name", ""), "type": x.get("type", ""), "value": x.get("value", ""),
                             "new": bool(x.get("new")), "of": "", "size": 4})
        rows.sort(key=lambda x: x["off"])
        for x in rows:
            x["address"] = base + x["off"]
        seen = ", ".join("+%X..+%X" % (a, a + n - 1) for a, n in runs) or "nothing yet"
        summary = "%s  %X +%X (%s%s)%s  %s hits  bytes used: %s" % (
            j.get("state"), base, j.get("size", 0), "r" if j.get("read") else "", "w" if j.get("write") else "",
            "  " + name if name else "", j.get("trig", 0), seen)
        return summary, rows, j.get("state") in ("capturing", "sweeping")

    def refresh_fields(self, quiet=False):
        if not self.back or not self.back.console:
            return

        def done(r):
            summary, rows, on = r
            self.field_on = on
            self.f_info.set(summary)
            self.field_rows = rows
            kids = self.field_tree.get_children()
            if len(kids) == len(rows) and [self.field_tree.item(i, "values")[0] for i in kids] == ["+%X" % x["off"] for x in rows]:
                for iid, x in zip(kids, rows):
                    self.field_tree.item(iid, values=self.field_values(x), tags=("new",) if x["new"] else ())
                return
            self.field_tree.delete(*kids)
            for x in rows:
                self.field_tree.insert("", "end", values=self.field_values(x), tags=("new",) if x["new"] else ())
        self.run(self.read_fields, done, None if quiet else "reading the fields")

    def field_values(self, x):
        return ("+%X" % x["off"], x["name"], x["type"], x["value"], "new" if x["new"] else "", x["of"])

    def picked_field(self):
        sel = self.field_tree.selection()
        i = self.field_tree.index(sel[0]) if sel else -1
        return self.field_rows[i] if 0 <= i < len(self.field_rows) else None

    def field_copy(self):
        x = self.picked_field()
        if x:
            self.root.clipboard_clear()
            self.root.clipboard_append("%X" % x["address"])

    def field_to_data(self):
        """The field's address into "Who touches an address". gen2 runs one watch at a time: starting
        that one ends the field watch."""
        x = self.picked_field()
        if not x:
            return
        self.d_addr.delete(0, "end")
        self.d_addr.insert(0, "%X" % x["address"])
        self.d_len.set(str(x["size"] if x["size"] in (1, 2, 4, 8) else 4))
        self.d_mode.set("rw")
        self.nb.select(self.data_frame)
        self.status.set("Watch starts it (the field watch stops: gen2 runs one watch at a time)")

    # ------------------------------------------------------------------ which methods run (a Switch)
    def build_methods(self):
        f = self.method_frame = ttk.Frame(self.nb)
        self.nb.add(f, text="Which methods run")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=3)
        ttk.Label(bar, text="methods whose name contains").pack(side="left")
        self.m_text = ttk.Entry(bar, width=34)
        self.m_text.pack(side="left", padx=3)
        self.m_text.bind("<Return>", lambda e: self.method_start())
        ttk.Button(bar, text="Start", command=self.method_start).pack(side="left")
        ttk.Button(bar, text="Stop", command=lambda: self.method_do("stop")).pack(side="left", padx=4)
        ttk.Button(bar, text="Clear", command=lambda: self.method_do("clear")).pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh_methods).pack(side="left", padx=4)
        self.m_live = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="follow", variable=self.m_live).pack(side="left")
        self.m_called = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="called only", variable=self.m_called, command=self.show_methods).pack(side="left", padx=6)
        self.m_info = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.m_info, foreground="#245").pack(side="right", padx=6)
        ttk.Label(f, foreground="#666", anchor="w", text="A class (PlayerStats::), a namespace or a word (Damage): 3 letters or "
                  "more, 768 methods at most. Each method stops the game once, at its first call. Clear, do one thing in the "
                  "game: the list is what that ran. \"this\" is the object it ran on.").pack(fill="x", padx=4)
        body = ttk.PanedWindow(f, orient="horizontal")
        body.pack(fill="both", expand=True)
        cols = ("state", "at", "name", "caller", "caller_fn", "this")
        heads = ("", "method", "name", "first caller", "in", "this (the object)")
        left = ttk.Frame(body)
        self.method_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, heads, (80, 95, 330, 95, 250, 100)):
            self.method_tree.heading(c, text=h)
            self.method_tree.column(c, width=w, anchor="w")
        self.method_tree.tag_configure("called", background="#dfd")
        self.method_tree.tag_configure("overwritten", foreground="#b00")
        sb = ttk.Scrollbar(left, command=self.method_tree.yview)
        self.method_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.method_tree.pack(fill="both", expand=True)
        self.method_tree.bind("<<TreeviewSelect>>", lambda e: self.show_method_row())
        body.add(left, weight=3)
        self.m_disasm = tk.Text(body, width=58, font=("Consolas", 9), wrap="none")
        self.m_disasm.tag_configure("here", background="#fe9")
        body.add(self.m_disasm, weight=2)
        menu = tk.Menu(self.method_tree, tearoff=0)
        menu.add_command(label="Watch this object's fields", command=self.method_to_fields)
        menu.add_command(label="Copy method address", command=lambda: self.copy(self.method_tree, 1))
        menu.add_command(label="Copy name", command=lambda: self.copy(self.method_tree, 2))
        menu.add_command(label="Copy this (the object)", command=lambda: self.copy(self.method_tree, 5))
        self.method_tree.bind("<Button-3>", lambda e: self.popup(e, self.method_tree, menu))

    def short_method(self, r):
        if not r.startswith("+OK {"):
            return r
        j = json.loads(r[4:])
        if j.get("state") == "none":
            return "+OK no method watch"
        return "+OK method watch %s: %s methods, %s called" % (j.get("state"), j.get("methods", 0), j.get("called", 0))

    def method_start(self):
        text = self.m_text.get().strip()
        if not self.back or len(text) < 3:
            self.status.set("3 letters or more of the methods' names")
            return

        def done(r):
            # It reads the function map from the SD card first: longer than the 3 s for one answer.
            self.said("starting: the list follows" if "busy" in r else r)
            self.method_on = True
            self.refresh_methods(quiet=True)
        self.run(lambda: self.short_method(self.client.cmd("methodwatch start " + text)), done, "starting the method watch")

    def method_do(self, what):
        if not self.back:
            return

        def done(r):
            self.said("still at it: the list follows" if "busy" in r else r)
            self.refresh_methods(quiet=True)
        self.run(lambda: self.short_method(self.client.cmd("methodwatch " + what)), done)

    def read_methods(self):
        r = self.client.cmd("methodwatch")
        if not r.startswith("+OK {"):
            return r, None, self.method_on
        j = json.loads(r[4:])
        if j.get("state") == "none":
            return "no method watch yet", [], False
        summary = "%s  \"%s\"  %s methods, %s called%s%s" % (
            j.get("state"), j.get("title", ""), j.get("methods", 0), j.get("called", 0),
            ", %s overwritten" % j["overwritten"] if j.get("overwritten") else "",
            ", %s not set" % j["not_set"] if j.get("not_set") else "")
        return summary, j.get("list", []), j.get("state") == "capturing"

    def refresh_methods(self, quiet=False):
        if not self.back or not self.back.console:
            return

        def done(r):
            summary, rows, on = r
            self.method_on = on
            self.m_info.set(summary)
            if rows is not None:
                self.method_rows = rows
                self.show_methods()
        self.run(self.read_methods, done, None if quiet else "reading the methods")

    def show_methods(self):
        rows = [x for x in self.method_rows if not self.m_called.get() or x.get("state") == "called"]
        values = [(x.get("state", ""), x.get("at", ""), x.get("name", ""), x.get("caller", ""), x.get("caller_name", ""),
                   x.get("this", "")) for x in rows]
        kids = self.method_tree.get_children()
        if [self.method_tree.item(i, "values")[1] for i in kids] == [v[1] for v in values]:
            for iid, v in zip(kids, values):
                self.method_tree.item(iid, values=v, tags=(v[0],))
            return
        self.method_tree.delete(*kids)
        for v in values:
            self.method_tree.insert("", "end", values=v, tags=(v[0],))

    def show_method_row(self):
        sel = self.method_tree.selection()
        if not sel:
            return
        at = self.method_tree.item(sel[0], "values")[1]

        def done(lines):
            self.m_disasm.delete("1.0", "end")
            for text, tag in lines:
                self.m_disasm.insert("end", text + "\n", tag)
        self.run(lambda: self.code_around(at, 0, 40), done)

    def method_to_fields(self):
        sel = self.method_tree.selection()
        this = self.method_tree.item(sel[0], "values")[5] if sel else ""
        if not this:
            self.status.set("no object: the method was not called yet, or it is static")
            return
        self.f_addr.delete(0, "end")
        self.f_addr.insert(0, this)
        self.nb.select(self.field_frame)
        self.status.set("Start watches it (the method watch stops: gen2 runs one watch at a time)")

    # ------------------------------------------------------------------ activity (emulator hosts)
    def build_activity(self):
        act = ttk.LabelFrame(self.pane, text="Activity: every client's commands, live")
        self.pane.add(act, weight=1)
        self.running = tk.StringVar(value="running: nothing")
        ttk.Label(act, textvariable=self.running, foreground="#a40").pack(fill="x", padx=4)
        self.act = tk.Text(act, height=8, wrap="none", font=("Consolas", 9))
        sb = ttk.Scrollbar(act, command=self.act.yview)
        self.act.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.act.pack(fill="both", expand=True)
        for tag, colour in (("run", "#a40"), ("done", "#222"), ("probe", "#05a"), ("err", "#c00"), ("me", "#999")):
            self.act.tag_configure(tag, foreground=colour)

    def event_reader(self):
        ev = self.events_client
        while True:
            try:
                l = ev._raw_line()
            except Exception:  # noqa: BLE001
                if not self.closed:
                    ev.events.put("err activity connection lost")
                return
            ev.events.put(l[7:] if l.startswith("*EVENT ") else l)

    def event(self, line):
        tag = "done"
        if line.startswith("run "):
            tag = "run"
        elif line.startswith("probe "):
            tag = "probe"
        elif line.startswith("err"):
            tag = "err"
        if " studio_watch" in line:
            return          # this tab's own polling would bury everything else
        if "| -ERR" in line:
            tag = "err"
        self.act.insert("end", line + "\n", tag)
        if int(self.act.index("end-1c").split(".")[0]) > 3000:
            self.act.delete("1.0", "500.0")
        self.act.see("end")
        w = line.split(" ", 3)
        if len(w) < 4:
            return
        if w[0] == "run":
            self.jobs[(w[2], w[3])] = self.jobs.get((w[2], w[3]), 0) + 1
        elif w[0] == "done" and " | " in line:
            key = (w[2], line.split(" | ")[1])
            if self.jobs.get(key, 0) > 1:
                self.jobs[key] -= 1
            else:
                self.jobs.pop(key, None)
        else:
            return
        self.running.set("running: " + (" | ".join("%s %s" % k for k in self.jobs) if self.jobs else "nothing"))


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "1234"
    root = tk.Tk()
    App(root, address, code)
    root.mainloop()


if __name__ == "__main__":
    main()
