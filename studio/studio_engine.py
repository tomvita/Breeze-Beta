"""Breeze Studio: what the game is built with (Breeze's engine scan).

    python studio_engine.py [address] [code]

Shows engine_scan.txt from the game's folder: the engine and its version, middleware, the SDK,
the modules, which Breeze tools fit, then every pattern looked for with its count and first hit.
Breeze writes the file when it attaches to a game; an emulator host writes it when asked.
"Scan again" has the host redo it (`prep engine` on a Switch, `enginescan` on an emulator host).

It connects only while it reads, so it holds none of a Switch's connections.
Python 3 with tkinter only.
"""
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from pcconnect import Breeze, game_caption  # noqa: E402

FILE = "engine_scan.txt"


def fetch(address, code, scan):
    """(caption, text of the file, note). scan: have the host make the file again first."""
    b = Breeze(address, code, timeout=60, connect_timeout=5)
    try:
        meta = b.json("meta")
        note = ""
        files = b.files()
        have = {f["name"] for f in files.get("files", [])}
        if scan or FILE not in have:
            if "jobs" in b.caps():
                reply = b.cmd("enginescan")
                note = reply[4:].split(" -> ")[0] if reply.startswith("+OK") else reply
            else:
                reply = b.cmd("prep engine")
                note = "scanned again" if reply.startswith("+OK") else reply
                for _ in range(20):      # the job runs on Breeze's own thread, under a second
                    time.sleep(0.3)
                    try:
                        if not b.json("prep").get("running"):
                            break
                    except Exception:  # noqa: BLE001 - busy for a moment
                        pass
            files = b.files()
            have = {f["name"] for f in files.get("files", [])}
        if FILE not in have:
            return game_caption(meta), "", note or "the game's folder has no %s" % FILE
        text = b.get_file(files.get("dir", "") + FILE).decode("utf-8", "replace")
        return game_caption(meta), text, note
    finally:
        b.close()


class App:
    def __init__(self, root, address, code):
        self.root, self.address, self.code = root, address, code
        self.out = queue.Queue()
        self.busy = self.stop = False
        root.title("Engine")
        root.geometry("1100x760")

        bar = ttk.Frame(root, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="Read again", command=lambda: self.ask(False)).pack(side="left")
        ttk.Button(bar, text="Scan again", command=lambda: self.ask(True)).pack(side="left", padx=4)
        ttk.Button(bar, text="Copy all", command=self.copy).pack(side="left")
        self.status = tk.StringVar(value="reading...")
        ttk.Label(bar, textvariable=self.status, foreground="#555").pack(side="left", padx=10)

        frame = ttk.Frame(root)
        frame.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        sb = ttk.Scrollbar(frame)
        sb.pack(side="right", fill="y")
        self.text = tk.Text(frame, wrap="none", font=("Consolas", 10), yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.config(command=self.text.yview)
        self.text.tag_configure("head", font=("Consolas", 11, "bold"))
        self.text.tag_configure("dim", foreground="#777")
        self.text.config(state="disabled")

        self.ask(False)
        root.after(100, self.pump)
        root.protocol("WM_DELETE_WINDOW", self.close)

    def ask(self, scan):
        if self.busy:
            return
        self.busy = True
        self.status.set("scanning..." if scan else "reading...")

        def run():
            try:
                self.out.put(fetch(self.address, self.code, scan) + (None,))
            except Exception as e:  # noqa: BLE001 - shown in the status line
                self.out.put(("", "", "", e))

        threading.Thread(target=run, daemon=True).start()

    def pump(self):
        if self.stop:
            return
        try:
            while True:
                caption, text, note, error = self.out.get_nowait()
                self.busy = False
                if error is not None:
                    self.status.set("%s: %s" % (type(error).__name__, error))
                    continue
                self.show(text)
                self.status.set("  |  ".join(x for x in (caption, note) if x))
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def show(self, text):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        # The report first; the '#' lines (what Breeze reads back) and the pattern table after it.
        lines = text.splitlines()
        report = [l for l in lines if l and not l.startswith("#")]
        table = next((i for i, l in enumerate(lines) if l.startswith("# pattern")), len(lines))
        body = [l for l in lines[:table] if l and not l.startswith("#")]
        marks = [l for l in lines[:table] if l.startswith("#")]
        if not report:
            self.text.insert("end", "No engine scan for this game yet: Scan again.\n", "dim")
        for l in body:
            self.text.insert("end", l + "\n", "head" if l.lstrip().startswith(("Engine:", "Engine analysis")) else ())
        if lines[table:]:
            self.text.insert("end", "\n")
            for l in lines[table:]:
                # A pattern that was not found: its name (which may have spaces), then a lone 0.
                self.text.insert("end", l + "\n", "dim" if l.startswith("#") or re.search(r"\s{2,}0\s*$", l) else ())
        if marks:
            self.text.insert("end", "\n" + "\n".join(marks) + "\n", "dim")
        self.text.config(state="disabled")

    def copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.text.get("1.0", "end"))
        self.status.set("copied")

    def close(self):
        self.stop = True
        self.root.destroy()


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    code = sys.argv[2] if len(sys.argv) > 2 else "1234"
    root = tk.Tk()
    App(root, address, code)
    root.mainloop()


if __name__ == "__main__":
    main()
