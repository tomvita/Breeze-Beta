#!/usr/bin/env python3
"""Breeze PC: see and drive Breeze from the PC through PC connect.

    python pcconnect_app.py [ip] [code]

The last ip and code are remembered in ~/.breeze_pc.json.

- The window shows Breeze's screen (PC connect's capture), refreshed while the
  window has focus.
- When Breeze opens its keyboard, a text box opens at the bottom: type, Enter
  sends the text, Esc cancels.
- Otherwise keys are Switch buttons (see KEYS below; Ctrl adds ZL, Shift adds
  ZR, so Shift+Down is ZR+DOWN). The "Keys" box sends any chord, e.g. L+ZR.
- Click a button to press it; click a row to select it, double-click to select
  it and press A. Anywhere else, and on Breeze's keyboard, a click is a touch on
  the screen. The mouse wheel scrolls.
- Reset restarts Breeze from whatever screen it is on (PC connect's
  "restart now"), for when a menu is stuck. It asks first.
- Save redirect to SD / Save snapshot / Restore: Atmosphere can keep a game's
  save as plain files on the SD card, where it can be copied while the game
  runs. The check box turns that on for the running game (it starts the next
  time the game is started; the very first time the Switch has to be rebooted
  too). Save snapshot copies the save as the game last wrote it, with a picture
  of the game at that moment. Restore lists the snapshots and puts one back,
  which needs the game closed. The last game is remembered, so Restore works
  with no game running.
  Restore writes to wherever the game's save is: the SD card while the box is
  ticked, the save inside the console (NAND) while it is not. The first line
  of the list is the save in the other place, so a save can be carried over
  from the console to the SD card or back. With the box unticked a snapshot
  can only be taken while the game is closed.
- Stop game ends the running game at once, as if it had crashed: anything it
  has not saved is lost. Start game starts the last game again; Breeze closes
  to let it start and comes back the way it does after any exit (press HOME
  if it does not). Together with Restore: Stop game, Restore, Start game.
- Files... opens a two-panel file manager: the Switch on the left (the game's
  directory, the game's own files, its save on the SD card, the album, the SD
  card), this PC on the right, where a list offers a folder for the game by
  title name or title id under a base folder of your choice. See
  pcconnect_files.py.

One connection is used for everything but the file manager, which opens a
second one while its window is open. PC connect takes three clients, so a
script can still connect.
"""
import io
import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog

from PIL import Image, ImageTk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcconnect import Breeze  # noqa: E402
from pcconnect_files import FileManager  # noqa: E402

CONFIG = os.path.join(os.path.expanduser("~"), ".breeze_pc.json")
SCREEN_W, SCREEN_H = 1280, 720

# Tk keysym -> Switch button.
KEYS = {
    "Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT",
    "Return": "A", "KP_Enter": "A", "Escape": "B", "BackSpace": "B",
    "a": "A", "b": "B", "x": "X", "y": "Y",
    "l": "L", "r": "R", "q": "ZL", "e": "ZR",
    "plus": "PLUS", "equal": "PLUS", "KP_Add": "PLUS", "minus": "MINUS", "KP_Subtract": "MINUS",
    "i": "RSUP", "k": "RSDOWN", "j": "RSLEFT", "o": "RSRIGHT",
    "s": "LS", "t": "RS",
}
# Keys that move the list cursor (rows), like Breeze's own USB keyboard
# support: Page Up / Page Down jump 10 rows.
ROW_KEYS = {"Prior": -10, "Next": 10, "Home": -1000000, "End": 1000000}
# The first line of the Restore list: the save in the place the game is not using.
OTHER_SAVE = {"nand": "<the save inside the console (NAND)>", "sd": "<the save on the SD card>"}
PLACE = {"nand": "the save inside the console (NAND)", "sd": "the save on the SD card"}
HELP = ("Arrows=D-pad  Enter/A=A  Esc/B=B  X Y  L R  Q=ZL E=ZR  +/-=PLUS/MINUS  PgUp/PgDn=10 rows  "
        "Home/End  IJKO=right stick  S=LS T=RS  Ctrl=+ZL Shift=+ZR  click=select/press")


class Link(threading.Thread):
    """Owns the socket. Runs queued commands first, captures in between."""

    def __init__(self, host, code, out):
        super().__init__(daemon=True)
        self.host, self.code, self.out = host, code, out
        self.jobs = queue.Queue()
        self.capture_on = threading.Event()
        self.capture_on.set()
        self.fps = 6.0
        self.stop = False

    def send(self, line):
        self.jobs.put(line)

    def run(self):
        while not self.stop:
            try:
                b = Breeze(self.host, self.code, timeout=10)
                self.out.put(("status", "connected: " + b.banner))
                b.cmd("events on")
                self.loop(b)
            except Exception as e:  # noqa: BLE001 - shown, then retried
                self.out.put(("status", "disconnected: %s (retrying)" % e))
                time.sleep(3)

    def drain_events(self, b):
        for e in b.events:
            if e.startswith("*EVENT state "):
                try:
                    self.out.put(("state", json.loads(e[len("*EVENT state "):])))
                except ValueError:
                    pass
        b.events.clear()

    def loop(self, b):
        next_capture = 0.0
        while not self.stop:
            try:
                line = self.jobs.get(timeout=0.02)
            except queue.Empty:
                line = None
            if line is not None and line.startswith("#rows "):
                # Move the cursor by n rows from where it is now (read fresh,
                # so quick repeats do not start from an old position).
                reply = b.cmd("state 1")
                if reply.startswith("+OK "):
                    m = json.loads(reply[4:]).get("menu", {})
                    count = m.get("row_count", 0)
                    if count:
                        row = max(0, min(count - 1, m.get("index", 0) + int(line.split()[1])))
                        reply = b.cmd("select %d" % row)
                self.out.put(("reply", line, reply))
                self.drain_events(b)
                next_capture = 0.0
                continue
            if line is not None:
                reply = b.cmd(line)
                if isinstance(reply, tuple):
                    if line.startswith("saveshot "):
                        self.out.put(("shot", line.split()[1], reply[1]))
                    reply = reply[0]
                self.out.put(("reply", line, reply))
                if reply.startswith("+OK {") and line.startswith("state"):
                    self.out.put(("state", json.loads(reply[4:])))
                self.drain_events(b)
                next_capture = 0.0  # show the result of the press soon
                continue
            if self.capture_on.is_set() and time.time() >= next_capture:
                next_capture = time.time() + 1.0 / max(self.fps, 0.5)
                reply = b.cmd("capture")
                if isinstance(reply, tuple):
                    self.out.put(("frame", reply[1]))
                else:
                    self.out.put(("status", "capture: " + reply))
                    next_capture = time.time() + 2.0
            else:
                # Keep reading events while idle; ping is cheap and answers at once.
                if not self.capture_on.is_set():
                    b.cmd("ping")
                    time.sleep(0.25)
            self.drain_events(b)


class App:
    def __init__(self, root, host, code, cfg=None):
        self.root = root
        self.cfg = dict(cfg or {}, host=host, code=code)
        root.title("Breeze PC - %s" % host)
        self.state = {}
        self.photo = None
        self.view_w, self.view_h = 960, 540
        self.frames, self.fps_t0 = 0, time.time()
        self.last_reply = ""

        self.canvas = tk.Canvas(root, width=self.view_w, height=self.view_h, bg="black", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.image_id = self.canvas.create_image(0, 0, anchor="nw")

        bar = tk.Frame(root)
        bar.pack(fill="x")
        tk.Button(bar, text="Show", command=lambda: self.link.send("show")).pack(side="left")
        tk.Button(bar, text="Hide", command=lambda: self.link.send("hide")).pack(side="left")
        tk.Button(bar, text="Reset", command=self.reset).pack(side="left")
        tk.Label(bar, text=" Keys:").pack(side="left")
        self.chord = tk.Entry(bar, width=14)
        self.chord.pack(side="left")
        self.chord.bind("<Return>", self.send_chord)
        tk.Label(bar, text=" fps:").pack(side="left")
        self.fps_var = tk.StringVar(value="6")
        fps = tk.Spinbox(bar, from_=1, to=15, width=3, textvariable=self.fps_var, command=self.set_fps)
        fps.pack(side="left")
        self.info = tk.Label(bar, text="", anchor="w")
        self.info.pack(side="left", fill="x", expand=True)

        # Save redirect and snapshots (PC connect's "save" command).
        self.save = None                               # last status from Breeze
        self.after_snapshot = None                     # (snapshot name, command to send once it exists)
        self.save_tid = self.cfg.get("save_tid", "")   # the game it is about
        self.restore_win = None
        sbar = tk.Frame(root)
        sbar.pack(fill="x")
        self.redirect_var = tk.BooleanVar(value=False)
        self.redirect_box = tk.Checkbutton(sbar, text="Save redirect to SD", variable=self.redirect_var,
                                           command=self.on_redirect, state="disabled")
        self.redirect_box.pack(side="left")
        self.snap_btn = tk.Button(sbar, text="Save snapshot", command=self.on_snapshot, state="disabled")
        self.snap_btn.pack(side="left")
        self.restore_btn = tk.Button(sbar, text="Restore...", command=self.on_restore, state="disabled")
        self.restore_btn.pack(side="left")
        self.stop_btn = tk.Button(sbar, text="Stop game", command=self.on_stop_game, state="disabled")
        self.stop_btn.pack(side="left")
        self.start_btn = tk.Button(sbar, text="Start game", command=self.on_start_game, state="disabled")
        self.start_btn.pack(side="left")
        self.files = None
        tk.Button(sbar, text="Files...", command=self.on_files).pack(side="left")
        self.save_info = tk.Label(sbar, text="", anchor="w", fg="#555")
        self.save_info.pack(side="left", fill="x", expand=True)

        # Breeze's keyboard, shown only while it is open.
        self.kbd = tk.Frame(root, bg="#203040")
        self.kbd_label = tk.Label(self.kbd, text="", anchor="w", bg="#203040", fg="white")
        self.kbd_label.pack(fill="x")
        self.kbd_entry = tk.Entry(self.kbd, font=("Consolas", 14))
        self.kbd_entry.pack(fill="x")
        self.kbd_entry.bind("<Return>", self.kbd_send)
        self.kbd_entry.bind("<KP_Enter>", self.kbd_send)
        self.kbd_entry.bind("<Escape>", self.kbd_cancel)
        self.kbd_open = False

        self.status = tk.Label(root, text=HELP, anchor="w", fg="#555")
        self.status.pack(fill="x")

        root.bind("<KeyPress>", self.on_key)
        root.bind("<FocusIn>", lambda e: self.link.capture_on.set())
        root.bind("<FocusOut>", self.on_focus_out)
        self.canvas.bind("<Configure>", self.on_resize)
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Double-Button-1>", self.on_double)
        self.canvas.bind("<MouseWheel>", self.on_wheel)

        self.out = queue.Queue()
        self.link = Link(host, code, self.out)
        self.link.start()
        root.after(30, self.pump)
        root.after(1500, self.poll_save)

    # ------------------------------------------------------------ input
    def press(self, chord):
        self.link.send("press " + chord)

    def on_key(self, e):
        if self.kbd_open or e.widget in (self.chord, self.kbd_entry):
            return
        if e.keysym in ROW_KEYS:
            self.link.send("#rows %d" % ROW_KEYS[e.keysym])
            return "break"
        btn = KEYS.get(e.keysym) or KEYS.get(e.keysym.lower())
        if not btn:
            return
        mods = []
        if e.state & 0x4:
            mods.append("ZL")
        if e.state & 0x1 and e.keysym not in ("plus",):
            mods.append("ZR")
        self.press("+".join(mods + [btn]))
        return "break"

    def send_chord(self, _e):
        c = self.chord.get().strip().upper().replace(" ", "")
        if c:
            self.press(c)
        self.canvas.focus_set()
        return "break"

    def reset(self):
        # "restart now": works from any screen and while hidden, which is the
        # point - a menu that keeps reopening a message box cannot be left by
        # pressing buttons. The connection drops and Link reconnects.
        if messagebox.askyesno("Reset Breeze", "Restart Breeze now?\n\n"
                               "Whatever Breeze is doing is dropped. The game and its cheats are not touched."):
            self.link.send("restart now")
            self.status.config(text="restarting Breeze...")

    def set_fps(self):
        try:
            self.link.fps = float(self.fps_var.get())
        except ValueError:
            pass

    def on_focus_out(self, _e):
        # Capture only while the app is in front; Breeze's keyboard still
        # gets the text box when it opens.
        if self.root.focus_get() is None:
            self.link.capture_on.clear()

    def to_screen(self, x, y):
        return x * SCREEN_W / self.view_w, y * SCREEN_H / self.view_h

    def hit(self, x, y):
        m = self.state.get("menu", {})
        for b in m.get("buttons", []):
            r = b.get("rect")
            if r and b.get("enabled") and r[0] <= x < r[0] + r[2] and r[1] <= y < r[1] + r[3]:
                return ("button", b["id"])
        for i, rx, ry, rw, rh in m.get("row_rects", []):
            if rx <= x < rx + rw and ry <= y < ry + rh:
                return ("row", i)
        return None

    def on_click(self, e):
        self.canvas.focus_set()
        x, y = self.to_screen(e.x, e.y)
        # Breeze's keyboard covers the menu, so a click there is a touch on
        # the keyboard; so is a click on nothing the menu reports.
        h = None if self.state.get("keyboard") else self.hit(x, y)
        if h and h[0] == "button":
            self.link.send("button %d" % h[1])
        elif h:
            self.link.send("select %d" % h[1])
        else:
            self.link.send("tap %d %d" % (min(int(x), SCREEN_W - 1), min(int(y), SCREEN_H - 1)))

    def on_double(self, e):
        if self.state.get("keyboard"):
            self.on_click(e)  # each click is a key press on Breeze's keyboard
            return
        h = self.hit(*self.to_screen(e.x, e.y))
        if h and h[0] == "row":
            self.link.send("select %d" % h[1])
            self.press("A")

    def on_wheel(self, e):
        self.press("UP" if e.delta > 0 else "DOWN")

    def kbd_send(self, _e):
        self.link.send("text " + self.kbd_entry.get())
        return "break"

    def kbd_cancel(self, _e):
        self.link.send("cancel")
        return "break"

    # ------------------------------------------------------------ output
    def on_resize(self, e):
        self.view_w, self.view_h = max(e.width, 64), max(e.height, 36)

    def show_frame(self, data):
        img = Image.open(io.BytesIO(data))
        # Keep 16:9 inside the canvas.
        w, h = self.view_w, self.view_h
        if w * 9 > h * 16:
            w = h * 16 // 9
        else:
            h = w * 9 // 16
        self.view_w, self.view_h = w, h
        self.photo = ImageTk.PhotoImage(img.resize((w, h), Image.BILINEAR))
        self.canvas.itemconfigure(self.image_id, image=self.photo)
        self.frames += 1

    def apply_state(self, s):
        self.state = s
        kb = s.get("keyboard")
        if kb and not self.kbd_open:
            self.kbd_open = True
            head = kb.get("header", "")
            if kb.get("subheader"):
                head += "  |  " + kb["subheader"]
            self.kbd_label.config(text="Breeze keyboard: " + head + "   (Enter sends, Esc cancels)")
            self.kbd_entry.delete(0, "end")
            self.kbd_entry.insert(0, kb.get("text", ""))
            self.kbd.pack(fill="x", before=self.status)
            self.kbd_entry.focus_set()
            self.kbd_entry.select_range(0, "end")
        elif not kb and self.kbd_open:
            self.kbd_open = False
            self.kbd.pack_forget()
            self.canvas.focus_set()

    # ------------------------------------------------------------ saves
    def save_cmd(self, sub, tid=True):
        """Queues a "save" command about the remembered game."""
        self.link.send("save " + sub + (" tid=" + self.save_tid if tid and self.save_tid else ""))

    def poll_save(self):
        # The running game first; with none, on_save_reply asks about the last one.
        self.link.send("save")
        self.root.after(6000, self.poll_save)

    def on_save_reply(self, line, reply):
        words = line.split()
        action = words[1] if len(words) > 1 and not words[1].startswith("tid=") else "status"
        if not reply.startswith("+OK {"):
            if line == "save" and "no game attached" in reply:
                if self.save_tid:
                    self.save_cmd("status")
                else:
                    self.save = None
                    self.refresh_save()
            elif action != "status":
                self.after_snapshot = None
                messagebox.showerror("Save", reply[5:] if reply.startswith("-ERR ") else reply,
                                     parent=self.restore_win if self.restore_open() else self.root)
                self.save_cmd("status")
            return
        j = json.loads(reply[4:])
        self.save = j
        if j.get("title_id") and j["title_id"] != self.save_tid:
            self.save_tid = j["title_id"]
            self.cfg["save_tid"] = self.save_tid
            self.save_cfg()
        self.refresh_save()
        if action == "redirect" and words[2] == "on":
            steps = []
            if j.get("needs_reboot"):
                steps.append("Reboot the Switch (the setting is read when it starts).")
            steps.append("Start the game again: its save is copied to the SD card when it opens it.")
            steps.append("Let the game save once before you close it. Until it has, the copy on the SD "
                         "card is not complete, and closing the game would leave it with an empty save.")
            messagebox.showinfo("Save redirect is on for this game",
                                "\n\n".join("%d. %s" % (i + 1, t) for i, t in enumerate(steps)), parent=self.root)
        elif action == "redirect":
            messagebox.showinfo("Save redirect is off for this game",
                                "The next time the game starts it uses its save on the console again, as it was "
                                "before redirect was turned on. The files on the SD card are kept.", parent=self.root)
        elif action == "snapshot" and "taken" in j:
            t = j["taken"]
            self.save_info.config(text="snapshot %s: %d file(s), %d KB%s" % (
                t["name"], t["files"], t["bytes"] // 1024, "" if t["shot"] else ", no picture"))
            if self.after_snapshot and self.after_snapshot[0] == t["name"]:
                line, self.after_snapshot = self.after_snapshot[1], None
                self.link.send(line)
        elif action == "restore":
            to = j.get("restored", {}).get("to", "sd")
            messagebox.showinfo("Save", "%s is now %s. Start the game." % (words[2], PLACE[to]),
                                parent=self.restore_win if self.restore_open() else self.root)

    def refresh_save(self):
        j = self.save
        if not j:
            self.redirect_var.set(False)
            for w in (self.redirect_box, self.snap_btn, self.restore_btn, self.stop_btn, self.start_btn):
                w.config(state="disabled")
            self.save_info.config(text="no game")
            return
        on = self.redirect_on()
        self.redirect_var.set(on)
        self.redirect_box.config(state="normal")
        snaps = j.get("snapshots", [])
        # On the SD card the save can be copied while the game runs; inside the
        # console only while the game is closed.
        ready = j.get("committed") if on else (j.get("nand_users") and not j.get("game_running"))
        self.snap_btn.config(state="normal" if ready else "disabled")
        self.restore_btn.config(state="normal" if snaps or self.other_save() else "disabled")
        self.stop_btn.config(state="normal" if j.get("game_running") else "disabled")
        self.start_btn.config(state="disabled" if j.get("game_running") else "normal")
        if not on:
            text = "off: the save is inside the console%s" % (
                " (close the game to take a snapshot)" if j.get("game_running") else "")
        elif j.get("needs_reboot"):
            text = "on: reboot the Switch to start it"
        elif not j.get("users"):
            text = "on: restart the game to move its save to the SD card"
        elif not j.get("committed"):
            text = "on: waiting for the game to save (do not close the game before it has)"
        else:
            text = "on, %d snapshot(s)" % len(snaps)
        self.save_info.config(text="%s  %s%s" % (j.get("title_id", ""), text, "" if j.get("game_running") else "  (game not running)"))
        self.fill_restore_list()

    def on_files(self):
        if self.files is not None and self.files.win.winfo_exists():
            self.files.win.lift()
            return
        self.files = FileManager(self.root, self.cfg["host"], self.cfg["code"], self.cfg, self.save_cfg)

    def save_cfg(self):
        try:
            with open(CONFIG, "w") as f:
                json.dump(self.cfg, f)
        except OSError:
            pass

    def on_stop_game(self):
        if messagebox.askokcancel("Stop game", "Stop the game now?\n\nIt ends at once, as if it had crashed: "
                                  "anything it has not saved is lost.", parent=self.root):
            self.link.send("gamestop")

    def on_start_game(self):
        if self.save_tid:
            self.link.send("gamestart " + self.save_tid)

    def on_game_reply(self, line, reply):
        if not reply.startswith("+OK"):
            messagebox.showerror("Game", reply[5:] if reply.startswith("-ERR ") else reply, parent=self.root)
        elif line.startswith("gamestart"):
            self.status.config(text="The game is starting. Breeze has closed; press HOME on the Switch if it does not come back.")
        self.link.send("save")

    def redirect_on(self):
        j = self.save or {}
        return bool(j.get("flag")) and bool(j.get("setting_ini"))

    def restore_open(self):
        return self.restore_win is not None and self.restore_win.winfo_exists()

    def other_save(self):
        """The place the game is not using, if it holds a save: "nand", "sd" or None."""
        j = self.save or {}
        if self.redirect_on():
            return "nand" if j.get("nand_users") else None
        return "sd" if j.get("committed") else None

    def on_redirect(self):
        want = self.redirect_var.get()
        if want:
            ok = messagebox.askokcancel(
                "Save redirect to SD",
                "The game will keep its save as files on the SD card instead of inside the console, "
                "so it can be copied while the game runs.\n\n"
                "It starts the next time the game is started. The save inside the console is left as it is.\n\n"
                "If the game already has a save on the SD card from an earlier time, it uses that one. "
                "Restore can then bring the save from the console over.",
                parent=self.root)
        else:
            ok = messagebox.askokcancel(
                "Save redirect to SD",
                "The game will go back to the save inside the console, as it was when redirect was turned on. "
                "Progress made since then stays on the SD card and is not copied back by itself: "
                "with the box unticked, Restore can write the save from the SD card into the console.",
                parent=self.root)
        if not ok:
            self.redirect_var.set(not want)
            return
        self.save_cmd("redirect " + ("on" if want else "off"))

    def on_snapshot(self):
        self.save_cmd("snapshot " + time.strftime("%Y%m%d_%H%M%S"))

    def on_restore(self):
        if self.restore_open():
            self.restore_win.lift()
            return
        w = self.restore_win = tk.Toplevel(self.root)
        w.title("Restore a save")
        left = tk.Frame(w)
        left.pack(side="left", fill="y")
        self.snap_target = tk.Label(left, text="", anchor="w", justify="left", wraplength=260)
        self.snap_target.pack(fill="x")
        self.snap_list = tk.Listbox(left, width=40, height=16, exportselection=False)
        self.snap_list.pack(fill="y", expand=True)
        self.snap_list.bind("<<ListboxSelect>>", self.on_snap_select)
        row = tk.Frame(left)
        row.pack(fill="x")
        tk.Button(row, text="Restore", command=self.do_restore).pack(side="left")
        tk.Button(row, text="Delete", command=self.do_delete).pack(side="left")
        tk.Button(row, text="Close", command=w.destroy).pack(side="right")
        right = tk.Frame(w)
        right.pack(side="left", fill="both", expand=True)
        self.snap_blank = ImageTk.PhotoImage(Image.new("RGB", (480, 270), "black"))
        self.snap_pic = tk.Label(right, image=self.snap_blank)
        self.snap_pic.pack()
        self.snap_text = tk.Label(right, text="", anchor="w", justify="left")
        self.snap_text.pack(fill="x")
        self.snap_photo = None
        self.snap_names = []
        self.fill_restore_list()

    def fill_restore_list(self):
        if not self.restore_open():
            return
        self.snap_target.config(text="Restore writes to " + PLACE["sd" if self.redirect_on() else "nand"] + ".")
        names = [x["name"] for x in reversed((self.save or {}).get("snapshots", []))]  # newest first
        other = self.other_save()
        if other:
            names.insert(0, OTHER_SAVE[other])
        if names == self.snap_names:
            return
        picked = self.picked_snapshot()
        self.snap_names = names
        self.snap_list.delete(0, "end")
        for n in names:
            self.snap_list.insert("end", n)
        if picked in names:
            self.snap_list.selection_set(names.index(picked))

    def picked_snapshot(self):
        sel = self.snap_list.curselection()
        return self.snap_names[sel[0]] if sel and sel[0] < len(self.snap_names) else None

    def on_snap_select(self, _e):
        name = self.picked_snapshot()
        if not name:
            return
        self.snap_photo = None
        self.snap_pic.config(image=self.snap_blank)
        if name in OTHER_SAVE.values():
            self.snap_text.config(text="The save as it is now in the other place.\nIt is kept as a snapshot too.")
            return
        info = next((x for x in self.save.get("snapshots", []) if x["name"] == name), {})
        self.snap_text.config(text="%s\n%d file(s), %d KB" % (name, info.get("files", 0), info.get("bytes", 0) // 1024))
        if info.get("shot"):
            self.link.send("saveshot %s tid=%s" % (name, self.save_tid))

    def show_shot(self, name, data):
        if self.restore_win is None or not self.restore_win.winfo_exists() or self.picked_snapshot() != name:
            return
        img = Image.open(io.BytesIO(data))
        img.thumbnail((480, 270))
        self.snap_photo = ImageTk.PhotoImage(img)
        self.snap_pic.config(image=self.snap_photo)

    def do_restore(self):
        name = self.picked_snapshot()
        if not name:
            return
        if (self.save or {}).get("game_running"):
            messagebox.showwarning("Restore", "Close the game first. A running game would overwrite the restored save.",
                                   parent=self.restore_win)
            return
        to = "sd" if self.redirect_on() else "nand"
        other = next((k for k, v in OTHER_SAVE.items() if v == name), None)
        if not messagebox.askokcancel("Restore", "Replace %s with %s?\n\n"
                                      "What is there now is kept as a snapshot named before_restore_..." % (
                                          PLACE[to], PLACE[other] if other else "snapshot " + name),
                                      parent=self.restore_win):
            return
        stamp = time.strftime("%Y%m%d_%H%M%S")
        tail = " to=%s backup=before_restore_%s" % (to, stamp)
        if other:
            # The other place's save becomes a snapshot first, then that is restored.
            taken = "from_%s_%s" % (other, stamp)
            self.after_snapshot = (taken, "save restore %s%s tid=%s" % (taken, tail, self.save_tid))
            self.save_cmd("snapshot %s from=%s" % (taken, other))
        else:
            self.save_cmd("restore " + name + tail)

    def do_delete(self):
        name = self.picked_snapshot()
        if name in OTHER_SAVE.values():
            return
        if name and messagebox.askokcancel("Delete", "Delete snapshot %s?" % name, parent=self.restore_win):
            self.save_cmd("delete " + name)

    def update_info(self):
        m = self.state.get("menu", {})
        title = m.get("left_title") or m.get("text") or ""
        now = time.time()
        fps = self.frames / max(now - self.fps_t0, 1e-3)
        if now - self.fps_t0 > 2:
            self.frames, self.fps_t0 = 0, now
        self.info.config(text="  %s | %s | %.1f fps | %s" % (self.state.get("overlay", "?"), title[:60], fps, self.last_reply[:60]))

    def pump(self):
        latest_frame = None
        try:
            while True:
                item = self.out.get_nowait()
                if item[0] == "frame":
                    latest_frame = item[1]
                elif item[0] == "state":
                    self.apply_state(item[1])
                elif item[0] == "shot":
                    self.show_shot(item[1], item[2])
                elif item[0] == "reply" and item[1].split()[0] == "save":
                    self.on_save_reply(item[1], item[2])
                elif item[0] == "reply" and item[1].split()[0] in ("gamestop", "gamestart"):
                    self.on_game_reply(item[1], item[2])
                elif item[0] == "reply":
                    _, line, reply = item
                    if not reply.startswith("+OK"):
                        self.last_reply = "%s: %s" % (line.split()[0], reply)
                    else:
                        self.last_reply = ""
                elif item[0] == "status":
                    self.status.config(text=item[1])
        except queue.Empty:
            pass
        if latest_frame is not None:
            try:
                self.show_frame(latest_frame)
            except Exception as e:  # noqa: BLE001
                self.status.config(text="bad frame: %s" % e)
        self.update_info()
        self.root.after(30, self.pump)


def main():
    cfg = {}
    try:
        with open(CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    host = sys.argv[1] if len(sys.argv) > 1 else cfg.get("host")
    code = sys.argv[2] if len(sys.argv) > 2 else cfg.get("code")
    root = tk.Tk()
    if not host:
        host = simpledialog.askstring("Breeze PC", "Switch IP (Settings > PC connect):", parent=root)
    if not code:
        code = simpledialog.askstring("Breeze PC", "PC connect code:", parent=root)
    if not host or not code:
        return
    cfg.update(host=host, code=code)
    with open(CONFIG, "w") as f:
        json.dump(cfg, f)
    App(root, host, code, cfg)
    root.mainloop()


if __name__ == "__main__":
    main()
