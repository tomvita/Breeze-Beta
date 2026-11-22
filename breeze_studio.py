#!/usr/bin/env python3
"""Breeze Studio: Breeze on the PC, for a Switch or an emulator.

    python breeze_studio.py [address] [code]

One window with a tab for each kind of work. The address is the Switch's IP (Breeze: Settings >
PC connect), 127.0.0.1 for an emulator on this PC, or ip:port when the host is not on 6801.
Which tabs there are depends on what the host can do (PC connect `caps`):

  Screen     Breeze's own screen, driven from the PC          a Switch
  Engine     what the game is built with (the engine scan)    every host
  Search     search targets, candidates, set / hold           a host with `search`
  Cheats     the cheat list, on / off, edit, add              a host with `cheats`
  Bookmarks  values by name from a game file, live            every host
  Workbench  one address: value, who writes it, code, cheats  every host
  Objects    classes, fields and objects, live                every host, a Unity or Unreal game
  Watch      who touches an address, what code ran            a Switch, the fork, emuhost (data only)
  Code       the disassembler (and the debugger on a Switch)  every host
  Files      the SD card (or the folder that stands for it)   every host

To see tabs side by side, double-click a tab (or right-click it, Detach): it becomes a window of
its own, with its connection and what it shows kept. Closing that window docks it back as a tab
(right-click any tab for Dock); each window's size is remembered.

A tab connects when it is first opened; on a Switch a tab other than Screen lets go of its
connection when another one is opened. For a Switch the header also says whether Breeze is in
front of the game (the game is stopped then) and has Show / Hide.
"""
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "studio"))
from pcconnect import Breeze, PORT, game_caption  # noqa: E402
import pcconnect_app  # noqa: E402

NAME = "Breeze Studio"
# The Breeze release this Studio comes with (pc_app.zip). Run from the Breeze repo, the version in
# source/appversion.cpp is shown instead, so a checkout never shows a stale one.
VERSION = "beta129.05"


def studio_version():
    try:
        with open(os.path.join(HERE, "source", "appversion.cpp")) as f:
            m = re.search(r'"(beta[0-9.]+[a-z]?)"', f.read())
        if m:
            return m.group(1)
    except OSError:
        pass
    return VERSION


TITLE = "%s %s" % (NAME, studio_version())


def style_tabs(root):
    """The tab shown stands out (blue, white text, a little taller). Windows' own theme draws every
    tab the same and ignores colours, so the tabs are drawn with the plain element, which takes
    them. It applies to every notebook in Studio (Watch's and Bookmarks' inner tabs too)."""
    s = ttk.Style(root)
    try:
        s.element_create("Studio.Notebook.tab", "from", "default")
    except tk.TclError:
        pass                     # made already (a second Studio window in this process)
    s.layout("TNotebook.Tab", [("Studio.Notebook.tab", {"sticky": "nswe", "children": [
        ("Notebook.padding", {"side": "top", "sticky": "nswe", "children": [
            ("Notebook.label", {"side": "top", "sticky": ""})]})]})])
    s.configure("TNotebook.Tab", padding=(10, 3), background="#e1e1e1", foreground="#333", borderwidth=1)
    s.map("TNotebook.Tab",
          background=[("selected", "#1f6feb"), ("active", "#cddcf3")],
          foreground=[("selected", "#ffffff")],
          font=[("selected", ("Segoe UI", 9, "bold"))],
          expand=[("selected", (1, 2, 1, 0))])


def split_address(address):
    """'ip' or 'ip:port' -> (ip, port)."""
    name, sep, tail = address.rpartition(":")
    if sep and tail.isdigit() and ":" not in name:
        return name, int(tail)
    return address, PORT


class Panel(tk.Frame):
    """A tab that stands in for the window a tool was written for: the tools call title, geometry,
    protocol and bind on what they take for their window."""

    def __init__(self, studio, label, holder):
        super().__init__(holder)
        self.studio, self.label = studio, label
        self.app = None
        self.close_fn = None
        self.caption = label
        self.size = ""
        self.dead = False
        self.keys = []      # (sequence, func) the tool bound on its window: made again on a detached window

    def title(self, text=None):
        if text is None:
            return self.caption
        self.caption = text
        self.studio.panel_caption(self)

    def geometry(self, text=None):
        if text is None:
            return self.size
        self.size = text

    def protocol(self, name, fn=None):
        if name == "WM_DELETE_WINDOW":
            self.close_fn = fn

    def bind(self, sequence=None, func=None, add=None):
        # A window's bindings reach every widget in it. Here that is the Studio window, so the
        # binding is made there and only acts while this tab is the one shown.
        if func is None:
            return super().bind(sequence, func, add)

        def guarded(e):
            if not self.dead and self.studio.shown() is self:
                return func(e)
            return None

        self.keys.append((sequence, func))
        holder = self.studio.holders.get(self.label)
        if holder is not None and self.label in self.studio.detached:
            self.studio.bind_detached(self, holder, sequence, func)
        return self.studio.root.bind(sequence, guarded, add="+")

    def lift(self, *a):
        self.studio.show(self)

    def close(self):
        """Ends the tool: its connections and its timers."""
        if self.dead:
            return
        self.dead = True
        app = self.app
        try:
            if self.close_fn is not None:
                self.close_fn()
            elif app is not None and hasattr(app, "close"):
                app.close()
        except Exception:  # noqa: BLE001 - a tool that fails to close must not keep the tab
            pass
        if app is not None:
            for name in ("link", "worker"):
                if hasattr(getattr(app, name, None), "stop"):
                    getattr(app, name).stop = True
            for name in ("client", "c", "p", "events_client"):
                c = getattr(app, name, None)
                if c is not None and hasattr(c, "close"):
                    try:
                        c.close()
                    except Exception:  # noqa: BLE001
                        pass
            if hasattr(app, "stop"):
                app.stop = True
        if self.winfo_exists():
            self.destroy()


class WindowShim:
    """tkinter for a module whose tool opens a window of its own: its first Toplevel is the tab."""

    def __init__(self, panel):
        self.panel = panel

    def Toplevel(self, *a, **k):
        if self.panel is not None:
            panel, self.panel = self.panel, None
            return panel
        return tk.Toplevel(*a, **k)

    def __getattr__(self, name):
        return getattr(tk, name)


def in_tab(module, panel, make):
    """Runs make() with module.tk replaced, so the tool builds itself in the panel."""
    real = module.tk
    module.tk = WindowShim(panel)
    try:
        return make()
    finally:
        module.tk = real


def hide_address_row(panel):
    """A tool written as a program of its own asks for Host, Port and Code: the Studio's header
    has them, so the tab keeps only the button, as Reconnect."""
    for row in panel.winfo_children():
        kids = row.winfo_children()
        labels = [w for w in kids if isinstance(w, ttk.Label) and str(w.cget("text")) in ("Host", "Port", "Code")]
        if len(labels) != 3:
            continue
        at = kids.index(labels[0])
        for w in kids[at:]:
            if w in labels or isinstance(w, ttk.Entry):
                w.pack_forget()
            elif isinstance(w, ttk.Button) and str(w.cget("text")) == "Connect":
                w.config(text="Reconnect")
        return


class Overlay(threading.Thread):
    """A Switch only: whether Breeze is in front of the game, and Show / Hide. While Breeze is
    shown the game is stopped, so a search for what changed finds nothing: the header says which
    it is. One connection of its own."""

    def __init__(self, address, code, out):
        super().__init__(daemon=True)
        self.address, self.code, self.out = address, code, out
        self.todo = queue.Queue()
        self.stop = False

    def run(self):
        b = None
        while not self.stop:
            try:
                if b is None:
                    b = Breeze(self.address, self.code, timeout=8, connect_timeout=4)
                try:
                    b.cmd(self.todo.get(timeout=2.0))
                except queue.Empty:
                    pass
                self.out.put(b.state(1).get("overlay", ""))
            except Exception:  # noqa: BLE001 - asleep, restarting: try again
                if b is not None:
                    b.close()
                b = None
                self.out.put("")
                for _ in range(20):
                    if self.stop:
                        break
                    threading.Event().wait(0.1)
        if b is not None:
            b.close()


class Studio:
    def __init__(self, root, cfg, address="", code=""):
        self.root, self.cfg = root, cfg
        self.address, self.code = address, code
        self.caps, self.banner, self.game = frozenset(), "", {}
        self.has_probe = False
        self.panels = {}             # label -> Panel, made when the tab is first opened
        self.holders = {}            # label -> the empty frame the notebook shows for it
        self.detached = set()        # labels whose holder is a window of its own (wm manage)
        self.results = queue.Queue()
        self.overlay, self.overlay_notes, self.overlay_state = None, queue.Queue(), ""
        root.title(TITLE)
        style_tabs(root)
        root.geometry(cfg.get("studio_geometry", "1280x900"))

        bar = tk.Frame(root)
        bar.pack(fill="x", padx=4, pady=3)
        tk.Label(bar, text="Address:").pack(side="left")
        recent = [r["host"] for r in cfg.get("recent", []) if isinstance(r, dict) and r.get("host")]
        self.address_var = tk.StringVar(value=address)
        self.address_box = ttk.Combobox(bar, width=22, textvariable=self.address_var, values=recent)
        self.address_box.pack(side="left", padx=(2, 8))
        self.address_box.bind("<<ComboboxSelected>>", self.on_pick_recent)
        tk.Label(bar, text="Code:").pack(side="left")
        self.code_var = tk.StringVar(value=code)
        code_box = tk.Entry(bar, width=7, textvariable=self.code_var)
        code_box.pack(side="left", padx=(2, 8))
        tk.Button(bar, text="Connect", command=self.connect).pack(side="left")
        self.overlay_btn = tk.Button(bar, text="", command=self.toggle_overlay)
        self.host_label = tk.Label(bar, text="not connected", anchor="w", fg="#555")
        self.host_label.pack(side="left", padx=10, fill="x", expand=True)
        for w in (self.address_box, code_box):
            w.bind("<Return>", lambda e: self.connect())

        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True)
        self.tabs.bind("<<NotebookTabChanged>>", self.on_tab)
        # A tab as a window of its own, to see two side by side: right-click it (or double-click).
        self.tab_menu = tk.Menu(root, tearoff=0)
        self.tabs.bind("<Button-3>", self.on_tab_menu)
        self.tabs.bind("<Double-1>", self.on_tab_double)
        self.hint = tk.Label(self.tabs, text="Type the address and the code, then Connect.\n\n"
                             "A Switch: its IP and code are in Breeze, Settings > PC connect.\n"
                             "The Lichii fork: Configure > Debug > Enable PC connect; 127.0.0.1 and its code.\n"
                             "Another emulator: start emuhost beside it; 127.0.0.1 and code 1234.\n"
                             "A host on another port: ip:port.", justify="left", fg="#555")
        self.tabs.add(self.hint, text="Start")

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = self.on_callback_error
        # A script (or Claude) sees and drives this window over 127.0.0.1 (studio/studio_remote.py).
        self.remote = None
        # BREEZE_STUDIO_REMOTE_PORT first: a second Studio (a helper's) beside someone's own needs
        # its own port, or the helper's commands land in the other window (Nov 21 2026).
        port = int(os.environ.get("BREEZE_STUDIO_REMOTE_PORT") or cfg.get("studio_remote_port", 6810) or 0)
        if port:
            try:
                import studio_remote
                self.remote = studio_remote.RemoteServer(self, port)
                self.remote.start()
            except OSError:
                self.remote = None       # another Studio has the port
        root.after(50, self.pump)
        if address and code:
            self.connect()

    # ------------------------------------------------------------ the connection
    def on_pick_recent(self, _e=None):
        for r in self.cfg.get("recent", []):
            if isinstance(r, dict) and r.get("host") == self.address_var.get():
                self.code_var.set(r.get("code", ""))

    def connect(self):
        address, code = self.address_var.get().strip(), self.code_var.get().strip()
        if not address or not code:
            self.host_label.config(text="an address and a code are needed", fg="#b00000")
            return
        self.host_label.config(text="connecting to %s..." % address, fg="#555")

        def ask():
            try:
                b = Breeze(address, code, timeout=15, connect_timeout=4)
                try:
                    caps = b.caps()
                    try:
                        game = b.json("meta")
                    except Exception:  # noqa: BLE001 - no game is running
                        game = {}
                    # The fork's probe has no name in caps: a console's `probe` is another command.
                    probe = "ui" not in caps and b.cmd("probe status").startswith("+OK")
                    return address, code, b.banner, caps, game, probe, None
                finally:
                    b.close()
            except Exception as e:  # noqa: BLE001 - shown in the header
                return address, code, "", frozenset(), {}, False, e

        threading.Thread(target=lambda: self.results.put(ask()), daemon=True).start()

    def connected(self, address, code, banner, caps, game, probe, error):
        if error is not None:
            self.host_label.config(text="%s: %s" % (address, error), fg="#b00000")
            return
        self.close_panels()
        self.stop_overlay()
        self.address, self.code = address, code
        self.caps, self.game, self.has_probe = caps, game, probe
        self.banner = banner[4:] if banner.startswith("+OK ") else banner
        self.banner = self.banner.split(" PC connect")[0].strip()
        pcconnect_app.remember_connection(self.cfg, address, code)
        self.cfg.update(host=address, code=code)
        self.save_cfg()
        self.address_box.config(values=[r["host"] for r in self.cfg.get("recent", [])])
        name = pcconnect_app.connection_name(self.cfg, address)
        where = "%s (%s)" % (name, address) if name else address
        self.host_label.config(text="%s  |  %s  |  %s" % (self.banner, game_caption(game), " ".join(sorted(caps))), fg="#222")
        self.root.title("%s - %s - %s" % (TITLE, where, game_caption(game)))
        for label in list(self.detached):
            self.dock(label, select=False)
        for tab in self.tabs.tabs():
            self.tabs.forget(tab)
        self.holders = {}
        for label, needs, _make in self.specs():
            if needs:
                holder = tk.Frame(self.tabs)
                self.holders[label] = holder
                self.tabs.add(holder, text=label)
        if not self.holders:
            self.tabs.add(self.hint, text="Start")
        if "ui" in caps:
            self.overlay_notes = queue.Queue()
            self.overlay = Overlay(address, code, self.overlay_notes)
            self.overlay.start()
            self.overlay_btn.pack(side="left", padx=(10, 0), before=self.host_label)

    def stop_overlay(self):
        if self.overlay is not None:
            self.overlay.stop = True
            self.overlay = None
        self.overlay_btn.pack_forget()
        self.overlay_state = ""

    def toggle_overlay(self):
        if self.overlay is not None and self.overlay_state:
            self.overlay.todo.put("hide" if self.overlay_state == "shown" else "show")

    def show_overlay(self, state):
        self.overlay_state = state
        if state == "shown":
            self.overlay_btn.config(text="Breeze is shown, the game is stopped: Hide", bg="#f3d9a4")
        elif state == "hidden":
            self.overlay_btn.config(text="Breeze is hidden, the game runs: Show", bg="#cfe8cf")
        else:
            self.overlay_btn.config(text="Breeze does not answer", bg="#e0e0e0")

    def specs(self):
        """(tab, whether this host has it, how to make it)."""
        c = self.caps
        return [("Screen", "ui" in c, self.make_screen),
                ("Engine", "read" in c, self.make_engine),
                ("Search", "search" in c, self.make_search),
                ("Cheats", "cheats" in c, self.make_cheats),
                ("Bookmarks", "read" in c, self.make_bookmarks),
                ("Memory", "read" in c, self.make_memory),
                ("Workbench", "read" in c, self.make_workbench),
                ("Objects", "read" in c, self.make_objects),
                ("Watch", self.has_probe or "debug" in c, self.make_watch),
                ("Code", "read" in c, self.make_code),
                ("Files", "read" in c, self.make_files)]

    # ------------------------------------------------------------ the tools
    def make_screen(self, panel):
        app = pcconnect_app.App(panel, self.address, self.code, self.cfg)
        # The Studio's header is where the host is chosen.
        for bar in panel.winfo_children():
            for w in bar.winfo_children():
                if isinstance(w, tk.Button) and w.cget("text") == "Connect...":
                    w.pack_forget()
        return app

    def make_search(self, panel):
        import studio_search
        host, port = split_address(self.address)
        app = studio_search.App(panel, host, self.code, port)
        hide_address_row(panel)
        return app

    def make_cheats(self, panel):
        import studio_cheats
        host, port = split_address(self.address)
        app = studio_cheats.App(panel, host, self.code, port)
        hide_address_row(panel)
        return app

    def make_bookmarks(self, panel):
        import studio_bookmarks
        host, port = split_address(self.address)
        client = studio_bookmarks.Client(host, port, self.code, "studio_bookmarks")
        return studio_bookmarks.App(panel, client, None)

    def make_memory(self, panel):
        import studio_memory
        return studio_memory.App(panel, self.address, self.code)

    def make_workbench(self, panel):
        import studio_workbench
        return studio_workbench.App(panel, self.address, self.code)

    def send(self, label, method, *args):
        """One tab hands an address to another: opens that tab and calls its method.
        Returns "" or why it could not."""
        holder = self.holders.get(label)
        if holder is None:
            return "this host has no %s tab" % label
        if label in self.detached:
            self.open_panel(label)
            self.raise_detached(label)
        else:
            self.tabs.select(holder)
            self.root.update_idletasks()
            self.on_tab()
        panel = self.panels.get(label)
        fn = getattr(getattr(panel, "app", None), method, None)
        if fn is None:
            return "the %s tab could not start" % label
        fn(*args)
        return ""

    def make_engine(self, panel):
        import studio_engine
        return studio_engine.App(panel, self.address, self.code)

    def make_objects(self, panel):
        import studio_objects
        return studio_objects.App(panel, self.address, self.code)

    def make_watch(self, panel):
        import studio_watch
        return studio_watch.App(panel, self.address, self.code)

    def make_code(self, panel):
        import pcconnect_asm
        return in_tab(pcconnect_asm, panel, lambda: pcconnect_asm.Disassembler(
            self.root, self.address, self.code, self.cfg, self.save_cfg))

    def make_files(self, panel):
        import pcconnect_files
        return in_tab(pcconnect_files, panel, lambda: pcconnect_files.FileManager(
            self.root, self.address, self.code, self.cfg, self.save_cfg))

    # ------------------------------------------------------------ tabs
    def shown(self):
        """The panel of the tab in front, or None."""
        try:
            label = self.tabs.tab(self.tabs.select(), "text")
        except tk.TclError:
            return None
        return self.panels.get(label)

    def show(self, panel):
        holder = self.holders.get(panel.label)
        if panel.label in self.detached:
            self.raise_detached(panel.label)
        elif holder is not None:
            self.tabs.select(holder)

    def panel_caption(self, panel):
        pass  # the header already names the host and the game

    def on_tab(self, _e=None):
        try:
            label = self.tabs.tab(self.tabs.select(), "text")
        except tk.TclError:
            return
        if label not in self.holders:
            return
        # A Switch serves few clients: Screen keeps its one, the others take turns (a detached
        # window keeps its own).
        if "ui" in self.caps:
            for other in list(self.panels):
                if other not in (label, "Screen") and other not in self.detached:
                    self.close_panel(other)
        self.open_panel(label)

    def open_panel(self, label):
        """The tab's tool, made when it is first shown."""
        panel = self.panels.get(label)
        if panel is not None and not panel.dead and panel.winfo_exists():
            return
        make = next(m for l, _n, m in self.specs() if l == label)
        holder = self.holders[label]
        for w in holder.winfo_children():
            w.destroy()
        panel = Panel(self, label, holder)
        panel.pack(fill="both", expand=True)
        self.panels[label] = panel
        try:
            try:
                panel.app = make(panel)
            except (OSError, RuntimeError):
                # A Switch frees a closed tab's connection a moment after it is closed.
                for w in panel.winfo_children():
                    w.destroy()
                self.root.update_idletasks()
                self.root.after(700)
                panel.app = make(panel)
        except Exception as e:  # noqa: BLE001 - the tab says what went wrong
            panel.close()
            del self.panels[label]
            for w in holder.winfo_children():
                w.destroy()
            tk.Label(holder, text="%s could not start:\n\n%s: %s" % (label, type(e).__name__, e), fg="#b00000",
                     justify="left").pack(padx=20, pady=20, anchor="nw")

    def close_panel(self, label):
        panel = self.panels.pop(label, None)
        if panel is not None:
            panel.close()
        holder = self.holders.get(label)
        if holder is not None and holder.winfo_exists():
            for w in holder.winfo_children():
                w.destroy()

    def close_panels(self):
        for label in list(self.panels):
            self.close_panel(label)

    # ------------------------------------------------------------ detached tabs
    def tab_at(self, e):
        """The label of the tab under the mouse, or None."""
        try:
            index = self.tabs.index("@%d,%d" % (e.x, e.y))
            label = self.tabs.tab(index, "text")
        except tk.TclError:
            return None
        return label if label in self.holders else None

    def on_tab_menu(self, e):
        label = self.tab_at(e)
        if label is None:
            return
        self.tab_menu.delete(0, "end")
        self.tab_menu.add_command(label="Detach %s (a window of its own)" % label, command=lambda: self.detach(label))
        if self.detached:
            self.tab_menu.add_separator()
            for other in sorted(self.detached):
                self.tab_menu.add_command(label="Dock %s back" % other, command=lambda o=other: self.dock(o))
        self.tab_menu.tk_popup(e.x_root, e.y_root)

    def on_tab_double(self, e):
        label = self.tab_at(e)
        if label is not None:
            self.detach(label)
            return "break"
        return None

    def bind_detached(self, panel, holder, sequence, func):
        """A key the tool bound on its window, on the detached window (the Studio window's
        bindings do not reach a window of its own)."""
        def guarded(e):
            if not panel.dead:
                return func(e)
            return None
        holder.bind(sequence, guarded, add="+")

    def detach(self, label):
        """The tab as a window of its own; closing that window docks it back."""
        holder = self.holders.get(label)
        if holder is None or label in self.detached:
            return
        self.open_panel(label)            # a tab that was never shown is made now
        self.tabs.forget(holder)
        self.detached.add(label)
        self.root.tk.call("wm", "manage", holder)
        self.root.tk.call("wm", "title", holder, "%s - %s" % (label, self.root.title()))
        self.root.tk.call("wm", "protocol", holder, "WM_DELETE_WINDOW", self.root.register(lambda: self.dock(label)))
        size = self.cfg.get("studio_detached", {}).get(label) or "%dx%d" % (
            max(self.tabs.winfo_width(), 600) // 2 + 200, max(self.tabs.winfo_height(), 500))
        self.root.tk.call("wm", "geometry", holder, size)
        panel = self.panels.get(label)
        if panel is not None:
            for sequence, func in panel.keys:
                self.bind_detached(panel, holder, sequence, func)
        if not self.tabs.tabs():
            self.tabs.add(self.hint, text="(every tab is a window: close one to dock it)")

    def raise_detached(self, label):
        holder = self.holders[label]
        self.root.tk.call("wm", "deiconify", holder)
        self.root.tk.call("raise", holder)

    def dock(self, label, select=True):
        """A detached window back as a tab, where it was."""
        holder = self.holders.get(label)
        if holder is None or label not in self.detached:
            return
        try:
            self.cfg.setdefault("studio_detached", {})[label] = self.root.tk.call("wm", "geometry", holder)
        except tk.TclError:
            pass
        self.root.tk.call("wm", "forget", holder)
        self.detached.discard(label)
        for sequence, _f in getattr(self.panels.get(label), "keys", []):
            holder.unbind(sequence)
        if self.hint in [self.tabs.nametowidget(t) for t in self.tabs.tabs()]:
            self.tabs.forget(self.hint)
        order = [l for l, _n, _m in self.specs() if l in self.holders]
        shown = [self.tabs.tab(t, "text") for t in self.tabs.tabs()]
        at = sum(1 for l in order[:order.index(label)] if l in shown)
        if at >= len(shown):
            self.tabs.add(holder, text=label)
        else:
            self.tabs.insert(at, holder, text=label)
        holder.pack_propagate(True)
        if select:
            self.tabs.select(holder)

    # ------------------------------------------------------------ housekeeping
    def pump(self):
        try:
            while True:
                self.connected(*self.results.get_nowait())
        except queue.Empty:
            pass
        try:
            while True:
                state = self.overlay_notes.get_nowait()
                if self.overlay is not None:
                    self.show_overlay(state)
        except queue.Empty:
            pass
        if self.remote is not None:
            self.remote.pump()
        self.root.after(50, self.pump)

    def on_callback_error(self, exc, val, tb):
        # A closed tab's timers still fire once: its widgets are gone, and that is all it means.
        if issubclass(exc, tk.TclError):
            return
        import traceback
        traceback.print_exception(exc, val, tb)

    def save_cfg(self):
        try:
            with open(pcconnect_app.CONFIG, "w") as f:
                json.dump(self.cfg, f)
        except OSError:
            pass

    def on_close(self):
        self.cfg["studio_geometry"] = self.root.geometry()
        for label in list(self.detached):
            try:
                self.cfg.setdefault("studio_detached", {})[label] = self.root.tk.call("wm", "geometry", self.holders[label])
            except tk.TclError:
                pass
        self.close_panels()
        self.stop_overlay()
        if self.remote is not None:
            self.remote.close()
        self.save_cfg()
        self.root.destroy()


def main():
    cfg = {}
    try:
        with open(pcconnect_app.CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    address = sys.argv[1] if len(sys.argv) > 1 else cfg.get("host", "")
    code = sys.argv[2] if len(sys.argv) > 2 else cfg.get("code", "")
    root = tk.Tk()
    Studio(root, cfg, address, code)
    root.mainloop()
    # The window is closed and the settings saved (on_close). A tool's worker thread that is not
    # a daemon (or one blocked on a socket) would keep the process alive with no window - found
    # Nov 20 2026: nine windowless Studios left over, still connected to Lichii.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
