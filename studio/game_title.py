"""The running game as one line for a window's title bar, from PC connect's game object.

`meta` replies with the game object; `state` carries it under "game". Both servers (Breeze on
a Switch, and the emulator) give title_id and build_id; newer ones add title_name and
version (the game's own name and the version its title screen shows).
"""


def game_caption(g):
    """'Pokemon Pokopia 2.0.1  TID 0400A3A01EE4C000  BID 76A489F3BD3642FA', or 'no game'."""
    if not g or g.get("attached") is False or not g.get("title_id"):
        return "no game"
    name = " ".join(x for x in (g.get("title_name", ""), g.get("version", "")) if x)
    parts = [name] if name else []
    parts.append("TID " + g["title_id"])
    if g.get("build_id"):
        parts.append("BID " + g["build_id"].upper())
    return "  ".join(parts)


def window_title(tool, g):
    """'<tool> - <game caption>' for root.title()."""
    return "%s - %s" % (tool, game_caption(g))
