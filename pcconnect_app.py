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

One connection is used for everything, so a script can still use PC connect's
second client slot.
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
    def __init__(self, root, host, code):
        self.root = root
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
    with open(CONFIG, "w") as f:
        json.dump({"host": host, "code": code}, f)
    App(root, host, code)
    root.mainloop()


if __name__ == "__main__":
    main()
