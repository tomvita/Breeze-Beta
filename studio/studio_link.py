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

HERE = os.path.dirname(os.path.abspath(__file__))
LINKS = (("Memory", "Open in Memory", "goto"), ("Objects", "Field view (the object here)", "field_view"))


def send(root, tab, method, *args):
    """Opens the tab and calls its method. Returns "" or why it could not."""
    studio = getattr(root, "studio", None)
    if studio is None:
        return "%s is a tab of Breeze Studio: start breeze_studio.py to use it from here" % tab
    return studio.send(tab, method, *args)


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
