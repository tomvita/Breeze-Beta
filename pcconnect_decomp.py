#!/usr/bin/env python3
"""Breeze PC decompiler: the C pane of the disassembler (pcconnect_asm.py), made by Ghidra's decompiler.

Decompile (F6) in the disassembler opens a pane beside the listing with the
function shown there as C. It follows the listing: going to another function
decompiles that one, the C lines of the instruction under the cursor are
marked, and a click on a C line puts the listing's cursor on its first
instruction. Double-click a call to go to the function it calls.

Only the function itself is loaded into Ghidra, read from the console through
PC connect, with the names Breeze knows for the functions it calls and the
strings it uses; nothing is analysed beforehand, so a function takes well
under a second once Ghidra is up. Field offsets show as offsets: Ghidra has no
types here. Addresses in main show as M+offset, the way the listing does
(DAT_M1234, func_1234, M+1234).

It needs Ghidra, a Java 21 JDK and the pyghidra package. The first time, the
pane offers to download and set them up (about 800 MB, into
%LOCALAPPDATA%\\BreezePC); an installed Ghidra and JDK can be picked instead.
The folders are kept in ~/.breeze_pc.json as ghidra_dir and java_home.
Starting Ghidra takes a few seconds (about 20 the very first time).
"""
import glob
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import zipfile
from tkinter import filedialog

HOME = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "BreezePC")
GHIDRA_RELEASE = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
JDK_URL = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
LANGUAGE = "AARCH64:LE:64:v8A"
PAGE = 0x1000
PROGRAMS_KEPT = 3            # games kept loaded in Ghidra at once

BG, FG, FG_DIM, BG_PANEL, BG_CUR = "#1b2030", "#d8dce6", "#6f7890", "#262c3f", "#3a4a78"
COLOURS = {"call": "#7fc8ff", "type": "#8fd0c0", "comment": "#6f9a6f", "str": "#e0b0ff", "num": "#ffd27f",
           "kw": "#ff9fbf", "label": "#ffd27f", "var": FG}
KEYWORDS = {"if", "else", "while", "do", "for", "return", "goto", "break", "continue", "switch", "case", "default"}


# ------------------------------------------------------------------ finding and installing the tools
def is_ghidra(path):
    return bool(path) and os.path.isfile(os.path.join(path, "Ghidra", "application.properties"))


def is_jdk(path):
    exe = "java.exe" if os.name == "nt" else "java"
    return bool(path) and os.path.isfile(os.path.join(path, "bin", exe)) and \
        os.path.isfile(os.path.join(path, "bin", "javac.exe" if os.name == "nt" else "javac"))


def newest(paths):
    paths = sorted(paths, key=lambda p: [int(x) for x in re.findall(r"\d+", os.path.basename(p))])
    return paths[-1] if paths else None


def find_ghidra(cfg):
    for p in (cfg.get("ghidra_dir"), os.environ.get("GHIDRA_INSTALL_DIR")):
        if is_ghidra(p):
            return p
    roots = [HOME, os.path.expanduser("~"), os.path.join(os.path.expanduser("~"), "Downloads"), "C:\\", "C:\\Tools",
             os.environ.get("ProgramFiles", "C:\\Program Files")]
    return newest([p for r in roots for p in glob.glob(os.path.join(r, "ghidra_*")) if is_ghidra(p)])


def find_jdk(cfg):
    for p in (cfg.get("java_home"), os.environ.get("JAVA_HOME")):
        if is_jdk(p) and jdk_version(p) >= 21:
            return p
    pf = os.environ.get("ProgramFiles", "C:\\Program Files")
    pats = [os.path.join(HOME, "jdk-*")] + [os.path.join(pf, v, "jdk-*") for v in
                                            ("Eclipse Adoptium", "Java", "Microsoft", "Zulu", "Amazon Corretto")]
    return newest([p for pat in pats for p in glob.glob(pat) if is_jdk(p) and jdk_version(p) >= 21])


def jdk_version(path):
    try:
        with open(os.path.join(path, "release")) as f:
            m = re.search(r'JAVA_VERSION="(\d+)', f.read())
        return int(m.group(1)) if m else 0
    except OSError:
        m = re.search(r"jdk-?(\d+)", os.path.basename(path))
        return int(m.group(1)) if m else 0


def have_pyghidra():
    import importlib.util
    return importlib.util.find_spec("pyghidra") is not None


def pip_install_pyghidra(ghidra):
    """pyghidra and JPype from the wheels Ghidra carries, so they match it."""
    dist = os.path.join(ghidra, "Ghidra", "Features", "PyGhidra", "pypkg", "dist")
    args = [sys.executable, "-m", "pip", "install", "--no-index", "-f", dist, "pyghidra"]
    if not os.path.isdir(dist):
        args = [sys.executable, "-m", "pip", "install", "pyghidra"]
    exe = sys.executable
    if os.path.basename(exe).lower() == "pythonw.exe":
        args[0] = os.path.join(os.path.dirname(exe), "python.exe")
    r = subprocess.run(args, capture_output=True, text=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise RuntimeError("pip install pyghidra failed:\n" + (r.stderr or r.stdout)[-800:])
    import importlib
    importlib.invalidate_caches()


def download(url, path, note):
    req = urllib.request.Request(url, headers={"User-Agent": "BreezePC"})
    with urllib.request.urlopen(req, timeout=60) as r, open(path + ".part", "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        got, shown = 0, 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
            if time.time() - shown > 0.5:
                shown = time.time()
                note("%s: %d of %d MB" % (os.path.basename(path), got >> 20, total >> 20) if total else
                     "%s: %d MB" % (os.path.basename(path), got >> 20))
    os.replace(path + ".part", path)


def unzip(path, dest, note):
    note("unpacking %s..." % os.path.basename(path))
    with zipfile.ZipFile(path) as z:
        top = z.namelist()[0].split("/")[0]
        z.extractall(dest)
    return os.path.join(dest, top)


def install(cfg, note):
    """Downloads what is missing into HOME, installs pyghidra; returns (ghidra_dir, java_home)."""
    if os.name != "nt":
        raise RuntimeError("the download is for Windows: install Ghidra, a JDK 21 and pyghidra, then pick the folders")
    os.makedirs(HOME, exist_ok=True)
    dl = os.path.join(HOME, "dl")
    os.makedirs(dl, exist_ok=True)
    ghidra = find_ghidra(cfg)
    if ghidra is None:
        note("asking GitHub for the latest Ghidra...")
        req = urllib.request.Request(GHIDRA_RELEASE, headers={"User-Agent": "BreezePC"})
        with urllib.request.urlopen(req, timeout=30) as r:
            rel = json.load(r)
        asset = next(a for a in rel["assets"] if a["name"].endswith(".zip") and "PUBLIC" in a["name"])
        zpath = os.path.join(dl, asset["name"])
        download(asset["browser_download_url"], zpath, note)
        ghidra = unzip(zpath, HOME, note)
        os.remove(zpath)
    jdk = find_jdk(cfg)
    if jdk is None:
        zpath = os.path.join(dl, "jdk21.zip")
        download(JDK_URL, zpath, note)
        jdk = unzip(zpath, HOME, note)
        os.remove(zpath)
    if not have_pyghidra():
        note("installing pyghidra...")
        pip_install_pyghidra(ghidra)
    shutil.rmtree(dl, ignore_errors=True)
    return ghidra, jdk


# ------------------------------------------------------------------ the engine
class Engine(threading.Thread):
    """Owns the JVM. Jobs are requests made by Game.decomp_input(); only the newest waiting one is done.
    Results go to .out as (request, result, error)."""

    def __init__(self, ghidra, jdk):
        super().__init__(daemon=True)
        self.ghidra, self.jdk = ghidra, jdk
        self.jobs, self.out = queue.Queue(), queue.Queue()
        self.ready = False
        self.programs = {}           # key -> {"prog", "ifc", "pages": {addr: digest}, "results": {start: lines}}

    def submit(self, req):
        self.jobs.put(req)

    def run(self):
        try:
            self.start_ghidra()
        except Exception as e:  # noqa: BLE001 - shown in the pane
            err = e
            while True:              # every request gets the same answer
                req = self.jobs.get()
                self.out.put((req, None, err))
        while True:
            req = self.jobs.get()
            while not self.jobs.empty():
                req = self.jobs.get()
            try:
                self.out.put((req, self.decompile(req), None))
            except Exception as e:  # noqa: BLE001
                self.out.put((req, None, RuntimeError(str(e).splitlines()[0] if str(e) else type(e).__name__)))

    def start_ghidra(self):
        if sys.stdout is None:       # pythonw: Ghidra writes to the console
            sys.stdout = sys.stderr = open(os.devnull, "w")
        os.environ["JAVA_HOME"] = self.jdk
        os.environ["PATH"] = os.path.join(self.jdk, "bin") + os.pathsep + os.environ.get("PATH", "")
        import pyghidra
        pyghidra.start(install_dir=self.ghidra)
        from ghidra.program.model.lang import LanguageID, CompilerSpecID
        from ghidra.program.util import DefaultLanguageService
        self.lang = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(LANGUAGE))
        self.cspec = self.lang.getCompilerSpecByID(CompilerSpecID("default"))
        self.ready = True

    def program(self, key):
        p = self.programs.get(key)
        if p is not None:
            return p
        from java.lang import Object
        from ghidra.program.database import ProgramDB
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        while len(self.programs) >= PROGRAMS_KEPT:
            old = self.programs.pop(next(iter(self.programs)))
            old["ifc"].dispose()
            old["prog"].release(old["owner"])
        owner = Object()
        prog = ProgramDB(key, self.lang, self.cspec, owner)
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        p = {"prog": prog, "owner": owner, "ifc": ifc, "pages": {}, "results": {}, "opened": False}
        self.programs[key] = p
        return p

    def decompile(self, req):
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.app.cmd.function import CreateFunctionCmd
        from ghidra.program.model.address import AddressSet
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor
        mon = TaskMonitor.DUMMY
        p = self.program(req["key"])
        prog = p["prog"]
        space = prog.getAddressFactory().getDefaultAddressSpace()
        addr = space.getAddress
        mem, listing, fm = prog.getMemory(), prog.getListing(), prog.getFunctionManager()
        start, end = req["start"], req["end"]
        changed = False
        tx = prog.startTransaction("load")
        try:
            for at, data in sorted(req["pages"].items()):
                digest = hashlib.sha1(data).digest()
                old = p["pages"].get(at)
                if old == digest:
                    continue
                if old is None:
                    blk = mem.createInitializedBlock("p_%X" % at, addr(at), len(data), 0, mon, False)
                    code = at not in req["ro"]
                    blk.setRead(True)
                    blk.setWrite(False)
                    blk.setExecute(code)
                else:
                    listing.clearCodeUnits(addr(at), addr(at + len(data) - 1), False)
                mem.setBytes(addr(at), data)
                p["pages"][at] = digest
                changed = True
            if changed:
                p["results"].clear()
            for at, length in req["strings"].items():
                if listing.getDefinedDataAt(addr(at)) is None and listing.getInstructionAt(addr(at)) is None:
                    from ghidra.program.model.data import TerminatedStringDataType
                    try:
                        listing.createData(addr(at), TerminatedStringDataType.dataType, length + 1)
                    except Exception:  # noqa: BLE001 - overlaps something already defined
                        pass
            for at, name in req["callees"].items():
                if at == start:
                    continue
                f = fm.getFunctionAt(addr(at))
                try:
                    if f is None:
                        fm.createFunction(clean(name, at), addr(at), AddressSet(addr(at), addr(at + 3)),
                                          SourceType.USER_DEFINED)
                    elif f.getName() != clean(name, at):
                        f.setName(clean(name, at), SourceType.USER_DEFINED)
                except Exception:  # noqa: BLE001 - a name Ghidra will not take, or an overlap
                    pass
            f = fm.getFunctionAt(addr(start))
            if f is None or changed or f.getBody().getNumAddresses() <= 4:
                # Ghidra follows the code from the entry to find where the function ends; [start, end) only
                # bounds it: the unwind table can be thin, so the next start Breeze knows may be far away.
                if f is not None:
                    fm.removeFunction(addr(start))
                DisassembleCommand(addr(start), AddressSet(addr(start), addr(end - 1)), True).applyTo(prog, mon)
                if req.get("end_is_next"):
                    self.no_return_at_end(prog, req)
                f = fm.getFunctionAt(addr(start))
                if f is None:
                    CreateFunctionCmd(clean(req["name"], start), addr(start), None,
                                      SourceType.USER_DEFINED).applyTo(prog, mon)
                    f = fm.getFunctionAt(addr(start))
                else:
                    CreateFunctionCmd.fixupFunctionBody(prog, f, mon)
                if f is None:
                    raise RuntimeError("Ghidra found no function at M+%X" % (start - req["main"]))
                # A plain b out of the function is a tail call. The decompiler follows it as a jump into
                # memory it does not have ("bad instruction data") unless it is marked call-return, as
                # Ghidra's own analysis would.
                from ghidra.program.model.listing import FlowOverride
                body = f.getBody()
                for ins in listing.getInstructions(body, True):
                    flow = ins.getFlowType()
                    if flow.isJump() and not flow.isConditional() and not flow.isComputed():
                        to = ins.getFlows()
                        if to and not body.contains(to[0]) and fm.getFunctionAt(to[0]) is not None:
                            ins.setFlowOverride(FlowOverride.CALL_RETURN)
            try:
                f.setName(clean(req["name"], start), SourceType.USER_DEFINED)
            except Exception:  # noqa: BLE001
                pass
        finally:
            prog.endTransaction(tx, True)
        cached = p["results"].get(start)
        if cached is not None:
            return cached
        if not p["opened"]:
            if not p["ifc"].openProgram(prog):
                raise RuntimeError("the decompiler did not start: " + str(p["ifc"].getLastMessage()))
            p["opened"] = True
        res = p["ifc"].decompileFunction(f, 60, mon)
        if not res.decompileCompleted():
            raise RuntimeError("Ghidra could not decompile it: " + str(res.getErrorMessage()).strip())
        lines = self.lines(res, req)
        p["results"][start] = lines
        return lines

    @staticmethod
    def no_return_at_end(prog, req):
        """A call in the function's last word (before nop or zero padding) runs into the next function, so it
        never returns: IL2CPP ends a function with its null and range throws. Ghidra does not know that and
        follows the call into code it was not given ("bad instruction data"). The callee is marked no-return
        (here and in every function that calls it); a call through a register is marked call-return."""
        from ghidra.program.model.listing import FlowOverride
        space = prog.getAddressFactory().getDefaultAddressSpace()
        mem, at = prog.getMemory(), req["end"] - 4
        while at > req["start"] and mem.getInt(space.getAddress(at)) & 0xFFFFFFFF in (0xD503201F, 0):
            at -= 4
        ins = prog.getListing().getInstructionAt(space.getAddress(at))
        if ins is None or not ins.getFlowType().isCall():
            return
        flows = ins.getFlows()
        callee = prog.getFunctionManager().getFunctionAt(flows[0]) if flows else None
        if callee is not None:
            callee.setNoReturn(True)
        else:
            ins.setFlowOverride(FlowOverride.CALL_RETURN)

    def lines(self, res, req):
        from ghidra.app.decompiler import (ClangCommentToken, ClangFuncNameToken, ClangLabelToken,
                                           ClangTypeToken, ClangVariableToken)
        from ghidra.app.decompiler.component import DecompilerUtils
        main, main_end = req["main"], req["main_end"]
        out = []
        for ln in DecompilerUtils.toLines(res.getCCodeMarkup()):
            segs, addrs, call = [(str(ln.getIndentString()), "")], set(), None
            for t in ln.getAllTokens():
                text = str(t.getText())
                a = t.getMinAddress()
                # The entry is left out: Ghidra ties stack variables all over the function to it.
                if a is not None and main <= a.getOffset() < main_end and a.getOffset() != req["start"]:
                    addrs.add(a.getOffset() - main)
                if isinstance(t, ClangFuncNameToken):
                    tag = "call"
                    op = t.getPcodeOp()
                    if op is not None and op.getNumInputs() > 0 and op.getInput(0).isAddress():
                        target = op.getInput(0).getAddress().getOffset()
                        if main <= target < main_end:
                            call = target - main
                elif isinstance(t, ClangTypeToken):
                    tag = "type"
                elif isinstance(t, ClangCommentToken):
                    tag = "comment"
                elif isinstance(t, ClangLabelToken):
                    tag = "label"
                elif text.startswith('"') or text.startswith("L\"") or text.startswith("u\""):
                    tag = "str"
                elif isinstance(t, ClangVariableToken) and t.getVarnode() is not None and t.getVarnode().isConstant():
                    tag = "num"
                elif text in KEYWORDS:
                    tag = "kw"
                else:
                    tag = ""
                segs.append((rename(text, main, main_end), tag))
            out.append({"segs": segs, "addrs": addrs, "call": call})
        while out and not "".join(s for s, _ in out[0]["segs"]).strip():
            out.pop(0)
        return out


NAME_BAD = re.compile(r"\s+")
AUTO_NAME = re.compile(r"^(_*)(FUN|DAT|PTR|LAB|UNK|SUB|switchD|caseD)_([0-9a-fA-F]{6,16})(.*)$")
HEX = re.compile(r"^0x([0-9a-fA-F]{6,16})$")
RAM = re.compile(r"^([a-zA-Z]{0,4})Ram([0-9a-fA-F]{8,16})$")     # a global outside the pages loaded: bRam0000003183...


def clean(name, at):
    name = NAME_BAD.sub("_", name or "").strip()
    return name or "func_%X" % at


def rename(text, main, main_end):
    """Ghidra's addresses in main as the listing writes them."""
    m = AUTO_NAME.match(text)
    if m:
        a = int(m.group(3), 16)
        if main <= a < main_end:
            if m.group(2) == "FUN":
                return "%sfunc_%X%s" % (m.group(1), a - main, m.group(4))
            return "%s%s_M%X%s" % (m.group(1), m.group(2), a - main, m.group(4))
        return text
    m = RAM.match(text)
    if m:
        a = int(m.group(2), 16)
        if main <= a < main_end:
            return "%sRam_M%X" % (m.group(1), a - main)
        return text
    m = HEX.match(text)
    if m:
        a = int(m.group(1), 16)
        if main <= a < main_end:
            return "M+%X" % (a - main)
    return text


ENGINE = None                # one per process: a JVM cannot be started twice


def engine(ghidra, jdk):
    global ENGINE
    if ENGINE is None:
        ENGINE = Engine(ghidra, jdk)
        ENGINE.start()
    return ENGINE


def exit_process():
    """A started JVM keeps Python from exiting: when Ghidra was started, leave at once (the windows are closed)."""
    if ENGINE is not None:
        os._exit(0)


# ------------------------------------------------------------------ the pane
class CPane:
    """The C pane. owner is the Disassembler: it gives .cfg, .save_cfg, .font, .cur, .set_cur(rva), .goto(rva),
    .request_c(), .status, .game_dir."""

    def __init__(self, parent, owner):
        self.owner = owner
        self.engine = None
        self.lines = []
        self.rows_of = {}            # rva -> C rows holding it
        self.title_text = ""
        self.want = None             # (key, start) the pane should show
        self.installing = False
        self.frame = tk.Frame(parent, bg=BG_PANEL)
        head = tk.Frame(self.frame, bg=BG_PANEL)
        head.pack(fill="x")
        self.title = tk.Label(head, text="C", anchor="w", bg=BG_PANEL, fg="white")
        self.title.pack(side="left", fill="x", expand=True)
        tk.Button(head, text="Copy", command=self.copy, takefocus=0).pack(side="left")
        tk.Button(head, text="Save...", command=self.save, takefocus=0).pack(side="left")
        tf = tk.Frame(self.frame)
        tf.pack(fill="both", expand=True)
        bar = tk.Scrollbar(tf)
        bar.pack(side="right", fill="y")
        xbar = tk.Scrollbar(tf, orient="horizontal")
        xbar.pack(side="bottom", fill="x")
        self.text = tk.Text(tf, wrap="none", bg=BG, fg=FG, font=owner.font, insertwidth=0, bd=0, highlightthickness=0,
                            selectbackground="#4c6fb0", yscrollcommand=bar.set, xscrollcommand=xbar.set, cursor="arrow")
        self.text.pack(side="left", fill="both", expand=True)
        bar.config(command=self.text.yview)
        xbar.config(command=self.text.xview)
        for tag, colour in COLOURS.items():
            self.text.tag_configure(tag, foreground=colour)
        self.text.tag_configure("cur", background=BG_CUR)
        self.text.tag_raise("sel")
        self.text.config(state="disabled")
        self.text.bind("<ButtonRelease-1>", self.on_click)
        self.text.bind("<Double-Button-1>", self.on_follow)
        self.text.bind("<Control-c>", lambda e: (self.copy(), "break")[1])
        self.setup = None            # the frame offering to install, while it is shown

    # ---------------------------------------------------------- engine
    def ensure_engine(self):
        """True when an engine is there or starting; shows the setup offer otherwise."""
        if self.engine is not None:
            return True
        cfg = self.owner.cfg
        ghidra, jdk = find_ghidra(cfg), find_jdk(cfg)
        if ghidra and jdk and have_pyghidra():
            cfg["ghidra_dir"], cfg["java_home"] = ghidra, jdk
            self.hide_setup()
            self.engine = engine(ghidra, jdk)
            if not self.engine.ready:
                self.message("starting Ghidra (a few seconds; about 20 the very first time)...")
            return True
        self.show_setup(ghidra, jdk)
        return False

    def submit(self, req):
        self.want = (req["key"], req["start"])
        if self.ensure_engine():
            self.engine.submit(req)
            if self.engine.ready:
                self.title.config(text="decompiling %s..." % req["name"])

    def pump(self):
        if self.engine is None:
            return
        try:
            while True:
                req, lines, err = self.engine.out.get_nowait()
                if (req["key"], req["start"]) != self.want:
                    continue
                if err is not None:
                    self.message("%s: %s" % (type(err).__name__, err))
                    self.title.config(text=req["name"])
                else:
                    self.show(req, lines)
        except queue.Empty:
            pass

    # ---------------------------------------------------------- setup
    def show_setup(self, ghidra, jdk):
        self.hide_setup()
        self.message("")
        f = self.setup = tk.Frame(self.frame, bg=BG_PANEL)
        f.place(relx=0, rely=0, relwidth=1, relheight=1)
        missing = [n for n, ok in (("Ghidra", ghidra), ("a Java 21 JDK", jdk), ("the pyghidra package", have_pyghidra()))
                   if not ok]
        listed = missing[0] if len(missing) == 1 else ", ".join(missing[:-1]) + " and " + missing[-1]
        tk.Label(f, text="Decompiling needs %s." % listed, bg=BG_PANEL, fg="white",
                 anchor="w", justify="left", wraplength=420).pack(fill="x", padx=10, pady=(14, 4))
        tk.Label(f, text="Download and set up puts what is missing into\n%s\n(Ghidra about 570 MB, the JDK about 200 MB),"
                         " and installs pyghidra into this Python." % HOME,
                 bg=BG_PANEL, fg=FG, anchor="w", justify="left").pack(fill="x", padx=10)
        self.setup_btn = tk.Button(f, text="Download and set up", command=self.on_install)
        self.setup_btn.pack(anchor="w", padx=10, pady=8)
        row = tk.Frame(f, bg=BG_PANEL)
        row.pack(anchor="w", padx=10)
        tk.Button(row, text="Ghidra folder...", command=lambda: self.pick("ghidra_dir")).pack(side="left")
        tk.Button(row, text="JDK folder...", command=lambda: self.pick("java_home")).pack(side="left", padx=4)
        self.setup_note = tk.Label(f, text="Ghidra: %s\nJDK: %s" % (ghidra or "not found", jdk or "not found"),
                                   bg=BG_PANEL, fg=FG_DIM, anchor="w", justify="left", wraplength=420)
        self.setup_note.pack(fill="x", padx=10, pady=8)

    def hide_setup(self):
        if self.setup is not None:
            self.setup.destroy()
            self.setup = None

    def pick(self, key):
        path = filedialog.askdirectory(parent=self.frame, title="Ghidra folder" if key == "ghidra_dir" else "JDK folder")
        if not path:
            return
        ok = is_ghidra(path) if key == "ghidra_dir" else is_jdk(path) and jdk_version(path) >= 21
        if not ok:
            self.setup_note.config(text="%s is not %s" % (path, "a Ghidra folder" if key == "ghidra_dir" else
                                                         "a JDK of version 21 or later"))
            return
        self.owner.cfg[key] = path
        self.owner.save_cfg()
        self.retry()

    def retry(self):
        if find_ghidra(self.owner.cfg) and find_jdk(self.owner.cfg) and have_pyghidra():
            self.hide_setup()
            self.owner.request_c()
        else:
            self.show_setup(find_ghidra(self.owner.cfg), find_jdk(self.owner.cfg))

    def on_install(self):
        if self.installing:
            return
        self.installing = True
        self.setup_btn.config(state="disabled")
        notes = queue.Queue()

        def work():
            try:
                notes.put(("done", install(self.owner.cfg, lambda t: notes.put(("note", t)))))
            except Exception as e:  # noqa: BLE001
                notes.put(("fail", e))

        def poll():
            try:
                while True:
                    kind, value = notes.get_nowait()
                    if kind == "note":
                        self.setup_note.config(text=value)
                    elif kind == "done":
                        self.installing = False
                        self.owner.cfg["ghidra_dir"], self.owner.cfg["java_home"] = value
                        self.owner.save_cfg()
                        self.retry()
                        return
                    else:
                        self.installing = False
                        self.setup_btn.config(state="normal")
                        self.setup_note.config(text="Set up failed: %s" % value)
                        return
            except queue.Empty:
                pass
            if self.frame.winfo_exists():
                self.frame.after(200, poll)

        threading.Thread(target=work, daemon=True).start()
        poll()

    # ---------------------------------------------------------- showing
    def message(self, text):
        self.lines, self.rows_of = [], {}
        t = self.text
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", text, ("comment",))
        t.config(state="disabled")

    def show(self, req, lines):
        self.lines = lines
        self.title_text = "%s   M+%X" % (req["name"], req["start"] - req["main"])
        self.title.config(text=self.title_text)
        self.rows_of = {}
        t = self.text
        t.config(state="normal")
        t.delete("1.0", "end")
        for n, line in enumerate(lines, 1):
            if n > 1:
                t.insert("end", "\n")
            for text, tag in line["segs"]:
                t.insert("end", text, (tag,) if tag else ())
            for a in line["addrs"]:
                self.rows_of.setdefault(a, []).append(n)
        t.config(state="disabled")
        t.yview_moveto(0)
        if self.owner.cur is not None:
            self.highlight(self.owner.cur)

    def highlight(self, rva):
        t = self.text
        t.tag_remove("cur", "1.0", "end")
        rows = self.rows_of.get(rva)
        if not rows:
            return
        for r in rows:
            t.tag_add("cur", "%d.0" % r, "%d.0" % (r + 1))
        t.see("%d.0" % rows[0])

    def row_at(self, e):
        row = int(self.text.index("@%d,%d" % (e.x, e.y)).split(".")[0])
        return self.lines[row - 1] if 1 <= row <= len(self.lines) else None

    def on_click(self, e):
        if self.text.tag_ranges("sel"):
            return
        line = self.row_at(e)
        if line is not None and line["addrs"]:
            self.owner.set_cur(min(line["addrs"]))

    def on_follow(self, e):
        line = self.row_at(e)
        if line is not None and line["call"] is not None:
            self.owner.goto(line["call"])
        return "break"

    def plain(self):
        return "// " + self.title_text + "\n" + "\n".join("".join(s for s, _ in l["segs"]) for l in self.lines) + "\n"

    def copy(self):
        try:
            text = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            text = self.plain()
        self.frame.clipboard_clear()
        self.frame.clipboard_append(text)
        self.owner.status.config(text="copied %d lines of C" % (text.count("\n") + 1))

    def save(self):
        if not self.lines:
            return
        folder = None
        if self.owner.game_dir is not None:
            try:
                folder = self.owner.game_dir("asm")
            except OSError:
                folder = None
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", self.title_text.split("   ")[0])[:80]
        path = filedialog.asksaveasfilename(parent=self.frame, initialdir=folder, defaultextension=".c",
                                            initialfile="%s.c" % name, filetypes=[("C", "*.c"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.plain())
        except OSError as e:
            self.owner.status.config(text="save: %s" % e)
            return
        self.owner.status.config(text="saved to " + path)
