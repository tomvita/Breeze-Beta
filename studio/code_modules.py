"""The game's code modules from PC connect `maps`, and names for addresses in them.

A process's code regions (r-x, type=3) come in module order: rtld, main, subsdk0..N, sdk last.
An address in main is M+<offset>; one in another module is <module>+<offset> (sdk+5B1E78).
"""


def code_modules(lines, main):
    """[(name, base, size)] of the code regions in `maps` lines; [] when main is not among them."""
    regions = []
    for line in lines:
        p = line.split()
        if len(p) >= 4 and "x" in p[2] and p[3] == "type=3":
            try:
                regions.append((int(p[0], 16), int(p[1], 16)))
            except ValueError:
                pass
    regions.sort()
    at = next((k for k, r in enumerate(regions) if r[0] == main), None)
    if at is None:
        return []
    out = []
    for k, (base, size) in enumerate(regions):
        if k == at:
            name = "M"
        elif k < at:
            name = "rtld" if k == at - 1 else "mod%d" % k
        elif k == len(regions) - 1:
            name = "sdk"
        else:
            name = "subsdk%d" % (k - at - 1)
        out.append((name, base, size))
    return out


def module_of(mods, address):
    """(name, base, size) of the code module holding address, or None."""
    for m in mods:
        if m[1] <= address < m[1] + m[2]:
            return m
    return None


def label(mods, address):
    """'M+1234' / 'sdk+5B1E78' for an address in code, None outside it."""
    m = module_of(mods, address)
    return None if m is None else "%s+%X" % (m[0], address - m[1])


def parse(mods, text):
    """'sdk+5B1E78' (any module's name, not M) -> the address; None when it is not one."""
    name, sep, off = text.strip().partition("+")
    if not sep:
        return None
    for m in mods:
        if m[0] != "M" and m[0].lower() == name.lower():
            try:
                return m[1] + int(off, 16)
            except ValueError:
                return None
    return None
