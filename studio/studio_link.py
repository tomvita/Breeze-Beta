"""Breeze Studio: what the tabs share to hand an address to each other.

A tab's window (`root`) is a Studio panel when it runs inside Breeze Studio; `send` then opens
another tab on an address. Run alone, a tool has no other tab and `send` says so.

  send(root, "Memory", "goto", address)          the Memory tab at that address
  send(root, "Watch", "watch_address", a, n)     a data watch on n bytes at a
  send(root, "Objects", "field_view", address)   the object that holds the address, field by field

Python 3 only.
"""
import os
import re
import tkinter as tk

HERE = os.path.dirname(os.path.abspath(__file__))
LINKS = (("Memory", "Open in Memory", "goto"), ("Objects", "Field view (the object here)", "field_view"))


def in_studio(root):
    """True when the tool runs as a tab of Breeze Studio, whose title bar already names the game
    (the tabs then leave out their own TID / BID line)."""
    return getattr(root, "studio", None) is not None


def caption(root, meta):
    """The game's caption for a tool's status line: "" inside Studio."""
    if in_studio(root):
        return ""
    from game_title import game_caption
    return game_caption(meta)


def joined(*parts):
    """Status-line parts that are not empty, with "  |  " between them."""
    return "  |  ".join(p for p in parts if p)


def send(root, tab, method, *args):
    """Opens the tab and calls its method. Returns "" or why it could not."""
    studio = getattr(root, "studio", None)
    if studio is None:
        return "%s is a tab of Breeze Studio: start breeze_studio.py to use it from here" % tab
    return studio.send(tab, method, *args)


# The places any address in Studio can be taken to (the same in every tab):
#   (label, tab, method, takes the size)
ADDRESS_LINKS = (
    ("Work on this address (Workbench)", "Workbench", "open_address", True),
    ("Open in Memory", "Memory", "goto", False),
    ("Open in Code", "Code", "goto_address", False),
    ("Field view (the object here)", "Objects", "field_view", False),
    ("Watch who reads or writes it", "Watch", "watch_address", True),
    ("Find pointer chains to here...", "Memory", "ptrscan_address", False),
)


def address_menu(root, menu, address, say, size=None, skip=(), label=None):
    """Adds Studio's entries for an address to a right-click menu, after a separator:
    address() -> the picked address or None; say(text) shows a note in the tab; size() -> the
    value's width (4 when not given); skip: tabs left out (the tab the menu is in); label: a word
    for the entries' submenu title when the menu has several addresses ("Go to the target")."""
    def go(tab, method, with_size):
        a = address()
        if a is None:
            say("pick a row with an address first")
            return
        args = (a, size() if size else 4) if with_size else (a,)
        note = send(root, tab, method, *args)
        if note:
            say(note)

    def copy():
        a = address()
        if a is not None:
            root.clipboard_clear()
            root.clipboard_append("%X" % a)
            say("copied %X" % a)

    target = menu
    if label:
        target = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label=label, menu=target)
    elif menu.index("end") is not None:
        menu.add_separator()
    for text, tab, method, with_size in ADDRESS_LINKS:
        if tab not in skip:
            target.add_command(label=text, command=lambda t=tab, m=method, s=with_size: go(t, m, s))
    target.add_command(label="Copy address", command=copy)
    return target


def add_bookmarks(title_id, entries):
    """Adds (name, where, type) lines to the group Bookmarks of the game's view file
    (views/<title id>.txt, which the Bookmarks tab reads). Returns the file's path."""
    path = os.path.join(HERE, "views", "%s.txt" % title_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else "title %s\n" % title_id
    if not re.search(r"^group Bookmarks\s*$", text, re.M):
        text = text.rstrip("\n") + "\n\ngroup Bookmarks\n"
    lines = text.split("\n")
    at = next(i for i, l in enumerate(lines) if re.match(r"group Bookmarks\s*$", l)) + 1
    while at < len(lines) and lines[at][:1] in (" ", "\t"):
        at += 1
    for k, (name, where, type_) in enumerate(entries):
        lines.insert(at + k, "    %s = %s %s" % (name, where, type_))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")
    return path
