"""Breeze Studio: Make cheat, Breeze's Cheats > Make cheat (make_db_cheat.cpp) on the PC.

The game folder's make_cheat.ini names recipes; each takes a table (a .tsv in the game's folder,
or "[Section]" rows in the ini), and fills a code template from the chosen rows (the format is
in make_db_cheat.md). Same rules as Breeze:
  * a file holding addresses must name this build ("; build <BID>"), or nothing is made;
  * the cheat named by `requires` has to be loaded; it is turned on when it is off. Studio does
    not build a missing hook from requires_script: make one cheat in Breeze once, or load it;
  * {keycond} becomes C4000000 hi lo (key_mode down) or C4100000 (held); {key} the key text;
    in code every value becomes 8 hex digits; {col:names} a value's name from [col names];
  * a loaded cheat with the same name is replaced, the new one is on, the list is saved to SD.
{names} from the cheat source file's [build] section are not filled here (Breeze only).
"""
import re
import tkinter as tk
from tkinter import messagebox, ttk

KEYS = {"A": 0x1, "B": 0x2, "X": 0x4, "Y": 0x8, "LS": 0x10, "RS": 0x20, "L": 0x40, "R": 0x80,
        "ZL": 0x100, "ZR": 0x200, "PLUS": 0x400, "MINUS": 0x800, "+": 0x400, "-": 0x800,
        "LEFT": 0x1000, "UP": 0x2000, "RIGHT": 0x4000, "DOWN": 0x8000}


def key_mask(text):
    """'ZL+ZR+X' -> the mask; 0 when a name is not known."""
    mask = 0
    for part in text.upper().split("+"):
        part = part.strip()
        if not part:
            continue
        if part not in KEYS:
            return 0
        mask |= KEYS[part]
    return mask


def number(text):
    t = text.strip()
    try:
        return int(t[2:], 16) if t[:2].lower() == "0x" else int(t, 10)
    except ValueError:
        return None


def label_key(name):
    """cavemap.cpp cave_label_key: the name without the key hint glyphs in front."""
    i = 0
    while i < len(name) and (ord(name[i]) >= 0x80 or name[i] == " "):
        i += 1
    return name[i:]


def parse_ini(text):
    """(order, values{section: {key: value}}, lines{section: [raw lines]}), as parse_ini in Breeze."""
    order, values, lines = [], {}, {}
    section, last = "", ""
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line[0] == "[" and line[-1] == "]":
            section = line[1:-1].strip()
            if section not in values:
                order.append(section)
            values.setdefault(section, {})
            last = ""
            continue
        if not section:
            continue
        lines.setdefault(section, []).append(raw)
        indented = raw[:1] in (" ", "\t")
        if indented and last and "=" not in line:
            values[section][last] += "\n" + line
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        last = k.strip().lower()
        v = v.strip()
        if " ;" in v:
            v = v.split(" ;", 1)[0].strip()
        values[section][last] = v
    return order, values, lines


def file_build(text):
    for l in text.replace("\r", "").split("\n"):
        s = l.lstrip(" \t")
        if not s.startswith(";"):
            continue
        for m in re.finditer(r"build ([0-9A-Fa-f]{16})(?![0-9A-Fa-f])", s):
            return m.group(1)
    return ""


def has_addresses(values):
    """A recipe writing to main by literal address (type 0/1/4-with-address lines), or a requires_hook."""
    for sec in values.values():
        if sec.get("requires_hook"):
            return True
        for line in sec.get("code", "").split("\n"):
            w = line.split()
            if len(w) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{8}", w[0]) and re.fullmatch(r"[0-9A-Fa-f]{8}", w[1]) \
                    and w[0][0] in "01" and w[0][2] == "0":
                return True
    return False


class Recipe:
    def __init__(self, title, v):
        self.title = title
        self.name = v.get("name") or "{name}"
        self.data = v.get("data", "")
        self.show = v.get("show") or "{name}"
        self.search = [s.strip().lower() for s in v.get("search", "").split(",") if s.strip()]
        self.filter = v.get("filter", "").strip().lower()
        self.exclude = []
        for part in v.get("exclude", "").split(";"):
            words = part.split()
            for item in words[1:]:
                for it in item.split(","):
                    if not it:
                        continue
                    lo, _, hi = it.partition("-")
                    lo, hi = number(lo), number(hi) if hi else number(lo)
                    if lo is not None and hi is not None:
                        self.exclude.append((words[0].lower(), lo, hi))
        self.asks = []
        for a in v.get("ask", "").split(";"):
            words = a.split()
            if not words:
                continue
            ask = {"var": words[0].lower(), "lo": 0, "hi": 0xFFFFFFFF, "def": 0}
            i = 1
            while i < len(words):
                if words[i].lower() == "default" and i + 1 < len(words):
                    ask["def"] = number(words[i + 1]) or 0
                    i += 1
                elif "-" in words[i][1:]:
                    lo, hi = words[i].split("-", 1)
                    ask["lo"], ask["hi"] = number(lo) or 0, number(hi) if number(hi) is not None else 0xFFFFFFFF
                i += 1
            ask["def"] = min(max(ask["def"], ask["lo"]), ask["hi"])
            self.asks.append(ask)
        self.key = v.get("key", "")
        self.key_down = v.get("key_mode", "").lower() != "held"
        self.requires = v.get("requires", "")
        self.code = v.get("code", "")


class MakeCheatWindow:
    """open(app): app is studio_cheats.App (its client, cheats, run, refresh, status)."""

    def __init__(self, app, breeze):
        self.app, self.b = app, breeze
        bid = breeze.json("meta").get("build_id", "")
        files = breeze.files()
        self.dir = files["dir"]
        names = {f["name"] for f in files["files"]}
        if "make_cheat.ini" not in names:
            raise RuntimeError("No make_cheat.ini in %s\nIt describes which cheats Make cheat can build; "
                               "see make_db_cheat.md." % self.dir)
        text = breeze.get_file("make_cheat.ini").decode("utf-8", "replace")
        self.order, self.values, self.lines = parse_ini(text)
        other = file_build(text)
        if other and other.upper() != bid.upper():
            raise RuntimeError("make_cheat.ini was made for build %s, and this is build %s: its cheats would "
                               "write to that build's addresses.\nMove the cheats to this build in Breeze "
                               "(Cheats, Move cheats from earlier build)." % (other, bid))
        if not other and has_addresses(self.values):
            raise RuntimeError("make_cheat.ini holds addresses and does not say which build they are for.\n"
                               "If they are this build's, add this line to the file:\n; build %s" % bid)
        self.recipes = [Recipe(t, self.values[t]) for t in self.order
                        if "code" in self.values[t] and "data" in self.values[t]]
        if not self.recipes:
            raise RuntimeError("make_cheat.ini has no recipe: a section needs at least data = and code =")
        self.tables = {}

        top = self.top = tk.Toplevel(app.root)
        top.title("Make cheat - " + self.dir.rstrip("/").rsplit("/", 1)[-1])
        top.geometry("760x620")
        row = ttk.Frame(top, padding=6)
        row.pack(fill="x")
        ttk.Label(row, text="Recipe").pack(side="left")
        self.recipe_var = tk.StringVar(value=self.recipes[0].title)
        rc = ttk.Combobox(row, textvariable=self.recipe_var, state="readonly", width=28,
                          values=[r.title for r in self.recipes])
        rc.pack(side="left", padx=(4, 12))
        rc.bind("<<ComboboxSelected>>", lambda e: self.load())
        ttk.Label(row, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        se = ttk.Entry(row, textvariable=self.search_var, width=22)
        se.pack(side="left", padx=(4, 12))
        self.search_var.trace_add("write", lambda *a: self.fill())
        ttk.Label(row, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar(value="All")
        self.filter_box = ttk.Combobox(row, textvariable=self.filter_var, state="readonly", width=22)
        self.filter_box.pack(side="left", padx=4)
        self.filter_box.bind("<<ComboboxSelected>>", lambda e: self.fill())

        mid = ttk.Frame(top, padding=(6, 0))
        mid.pack(fill="both", expand=True)
        self.list = ttk.Treeview(mid, columns=("show",), show="headings", selectmode="extended")
        self.list.heading("show", text="")
        self.list.column("show", width=700)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.list.yview)
        self.list.configure(yscrollcommand=sb.set)
        self.list.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.list.bind("<Double-1>", lambda e: self.make())
        self.list.bind("<<TreeviewSelect>>", lambda e: self.preview())

        self.asks_row = ttk.Frame(top, padding=6)
        self.asks_row.pack(fill="x")
        self.code_view = tk.Text(top, height=6, font=("Consolas", 9), state="disabled")
        self.code_view.pack(fill="x", padx=6)
        bottom = ttk.Frame(top, padding=6)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Make cheat (on)", command=self.make).pack(side="left")
        ttk.Button(bottom, text="Close", command=top.destroy).pack(side="right")
        self.info = tk.StringVar()
        ttk.Label(bottom, textvariable=self.info).pack(side="left", padx=10)
        se.focus_set()
        self.load()

    # ---- the table
    def recipe(self):
        return next(r for r in self.recipes if r.title == self.recipe_var.get())

    def load(self):
        r = self.recipe()
        data = r.data.strip()
        if data.startswith("[") and data.endswith("]"):
            lines = self.lines.get(data[1:-1].strip(), [])
        else:
            if data not in self.tables:
                try:
                    self.tables[data] = self.b.get_file(data).decode("utf-8", "replace").replace("\r", "").split("\n")
                except Exception as ex:  # noqa: BLE001
                    messagebox.showerror("Make cheat", 'the table "%s" is not in the game\'s folder (%s)' % (data, ex),
                                         parent=self.top)
                    self.tables[data] = []
            lines = self.tables[data]
        self.columns, self.rows, excluded = [], [], 0
        for line in lines:
            if not line.strip() or line.strip()[0] == "#":
                continue
            cells = [c.strip() for c in line.split("\t")]
            if not self.columns:
                self.columns = [c.lower() for c in cells]
                continue
            if any(number(self.cell(cells, col)) is not None and lo <= number(self.cell(cells, col)) <= hi
                   for col, lo, hi in r.exclude):
                excluded += 1
                continue
            self.rows.append(cells)
        vals = sorted({self.cell(row, r.filter) for row in self.rows} if r.filter else set(),
                      key=lambda v: (number(v) is None, number(v) or 0, v))
        self.filter_values = vals
        self.filter_box["values"] = ["All"] + ["%s  %s" % (v, self.named(r.filter, v)) if self.named(r.filter, v) != v
                                               else v for v in vals]
        self.filter_var.set("All")
        for w in self.asks_row.winfo_children():
            w.destroy()
        self.ask_vars = {}
        for a in r.asks:
            ttk.Label(self.asks_row, text="%s (%d-%d)" % (a["var"], a["lo"], a["hi"])).pack(side="left")
            v = tk.StringVar(value=str(a["def"]))
            ttk.Entry(self.asks_row, textvariable=v, width=8).pack(side="left", padx=(4, 12))
            v.trace_add("write", lambda *x: self.preview())
            self.ask_vars[a["var"]] = v
        self.key_var = tk.StringVar(value=r.key)
        if "{keycond}" in r.code:
            ttk.Label(self.asks_row, text="Key (%s)" % ("once per press" if r.key_down else "while held")).pack(side="left")
            ttk.Entry(self.asks_row, textvariable=self.key_var, width=14).pack(side="left", padx=4)
            self.key_var.trace_add("write", lambda *x: self.preview())
        self.excluded = excluded
        self.fill()

    def column(self, name):
        return self.columns.index(name) if name in self.columns else -1

    def cell(self, row, name):
        c = self.column(name)
        return row[c] if 0 <= c < len(row) else ""

    def named(self, col, value):
        sec = self.values.get(col + " names")
        return sec.get(value.strip().lower(), value) if sec else value

    def fill(self):
        r = self.recipe()
        f = self.filter_box.current()
        want = self.filter_values[f - 1] if f > 0 else None
        words = self.search_var.get().lower().split()
        self.list.delete(*self.list.get_children())
        self.shown = []
        for i, row in enumerate(self.rows):
            if want is not None and self.cell(row, r.filter) != want:
                continue
            if words:
                hay = " ".join(self.cell(row, c).lower() for c in r.search) if r.search else " ".join(row).lower()
                if not all(w in hay for w in words):
                    continue
            self.shown.append(i)
            self.list.insert("", "end", iid=str(i), values=(self.fill_tpl(r.show, row, {}, "", 0, False)[0],))
        self.info.set("%d of %d rows%s" % (len(self.shown), len(self.rows),
                                           ", %d left out by the recipe" % self.excluded if self.excluded else ""))

    # ---- templates
    def fill_tpl(self, tpl, row, asked, key_text, mask, code):
        """(text, the first {name} with no value in code or None)"""
        r = self.recipe()
        out, missing, i = [], None, 0
        while i < len(tpl):
            if tpl[i] != "{":
                out.append(tpl[i])
                i += 1
                continue
            end = tpl.find("}", i)
            if end < 0:
                out.append(tpl[i:])
                break
            raw = tpl[i + 1:end].strip()
            var = raw.lower()
            i = end + 1
            want_name = var.endswith(":names") and len(var) > 6
            if want_name:
                var = var[:-6]
            if var == "keycond":
                out.append("C4%d00000 %08X %08X" % (0 if r.key_down else 1, mask >> 32, mask & 0xFFFFFFFF))
            elif var == "key":
                out.append(key_text)
            elif var in asked:
                out.append("%08X" % (asked[var] & 0xFFFFFFFF) if code else str(asked[var]))
            else:
                value = self.cell(row, var)
                if want_name:
                    out.append(self.named(var, value))
                elif code:
                    if not value and missing is None:
                        missing = raw
                    n = number(value)
                    out.append("%08X" % (n & 0xFFFFFFFF) if n is not None else value)
                else:
                    out.append(value)
        return "".join(out), missing

    def asked(self, quiet=False):
        out = {}
        for a in self.recipe().asks:
            v = number(self.ask_vars[a["var"]].get())
            if v is None or not a["lo"] <= v <= a["hi"]:
                if not quiet:
                    messagebox.showerror("Make cheat", "%s must be %d to %d" % (a["var"], a["lo"], a["hi"]), parent=self.top)
                return None
            out[a["var"]] = v
        return out

    def key(self, quiet=False):
        if "{keycond}" not in self.recipe().code:
            return "", 0
        text = self.key_var.get().strip().upper()
        mask = key_mask(text)
        if not mask:
            if not quiet:
                messagebox.showerror("Make cheat", "Keys are written like ZL+ZR+X: A B X Y L R ZL ZR LS RS PLUS MINUS "
                                     "UP DOWN LEFT RIGHT", parent=self.top)
            return None
        return text, mask

    def build(self, i, asked, key_text, mask):
        r = self.recipe()
        row = self.rows[i]
        name, _ = self.fill_tpl(r.name, row, asked, key_text, mask, False)
        code, missing = self.fill_tpl(r.code, row, asked, key_text, mask, True)
        if missing:
            return name, None, "{%s} has no value: it is not a column of the table (names from the cheat source " \
                               "file's [build] section are filled by Breeze's Make cheat only)" % missing
        words = re.findall(r"[0-9A-Fa-f]+", code)
        if not words or any(len(w) != 8 for w in words) or re.search(r"[^0-9A-Fa-f\s]", code):
            return name, None, "its code is not whole 8 digit words: " + code
        return name, [int(w, 16) for w in words], None

    def preview(self):
        sel = self.list.selection()
        text = ""
        asked, key = self.asked(quiet=True), self.key(quiet=True)
        if sel and asked is not None and key is not None:
            name, words, why = self.build(int(sel[0]), asked, key[0], key[1])
            text = "[%s]\n" % name + (why if why else "\n".join(
                " ".join("%08X" % w for w in words[j:j + n]) for j, n in self.lines_of(words)))
        self.code_view.configure(state="normal")
        self.code_view.delete("1.0", "end")
        self.code_view.insert("1.0", text)
        self.code_view.configure(state="disabled")

    @staticmethod
    def lines_of(words):
        import studio_cheats
        j = 0
        while j < len(words):
            n = max(1, studio_cheats.opcode_len(words, j))
            yield j, n
            j += n

    # ---- making
    def make(self):
        rows = [int(i) for i in self.list.selection()]
        if not rows:
            return
        asked, key = self.asked(), self.key()
        if asked is None or key is None:
            return
        built = []
        for i in rows:
            name, words, why = self.build(i, asked, key[0], key[1])
            if why:
                messagebox.showerror("Make cheat", "Nothing made: " + why, parent=self.top)
                return
            built.append((name[:63], words))
        r = self.recipe()
        app = self.app
        need = None
        if r.requires:
            want = label_key(r.requires)
            need = next((cid for cid, (_on, n, _w) in app.cheats.items() if label_key(n) == want), None)
            if need is None:
                messagebox.showerror("Make cheat", 'Nothing made: it needs the cheat "%s", which is not loaded.\n'
                                     "Studio does not build it from its script: make one of these cheats in Breeze "
                                     "once (Cheats, Make cheat), or load the cheat." % r.requires, parent=self.top)
                return
        same = {n: cid for cid, (_on, n, _w) in app.cheats.items()}

        def fn():
            out = []
            if need is not None and not app.cheats[need][0]:
                out.append(app.client.cmd("cheats on %d" % need))
            made, failed = [], []
            for name, words in built:
                if name in same:
                    app.client.cmd("cheats remove %d" % same[name])
                reply = app.client.cmd("cheats add on [%s] %s" % (name, " ".join("%08X" % w for w in words)))
                (made if reply.startswith("+OK") else failed).append(name if reply.startswith("+OK") else
                                                                     "%s: %s" % (name, reply))
            saved = app.client.cmd("cheats save") if made else ""
            return made, failed, saved

        def done(res):
            made, failed, saved = res
            msg = "".join('Made "%s" (on)\n' % m for m in made) + "".join("Not made, %s\n" % f for f in failed)
            if saved:
                msg += saved[4:] if saved.startswith("+OK ") else saved
            app.status.set(msg.replace("\n", "  "))
            app.refresh()
            app.root.after(700, app.refresh)
            self.info.set("made %d%s" % (len(made), ", %d failed" % len(failed) if failed else ""))
        app.run(fn, done)
