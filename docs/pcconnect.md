# PC connect

PC connect lets a PC on the same network work with Breeze over Wi-Fi:

- **see** what Breeze is showing: the menu, its rows, its buttons, the open
  keyboard, the game it is attached to;
- **drive** it: press buttons, pick a row, type into the keyboard, show or hide
  the overlay;
- **read and write the game's memory** through dmnt, with the game running;
- **collect data for developing Breeze**: frame times, heap use, logs, crash
  reports, screenshots.

It is a small text protocol on TCP port **6801**, so a Python script, `nc`, or
an AI assistant can use it.

## Why not the GDB stub

The Atmosphere GDB stub stops the game on every attach, holds the only debug
session (IDA and Breeze's gen2 watch contend for it), and runs alongside dmnt's
cheat VM, which can overwrite its software breakpoints.
PC connect never attaches: memory goes through the handle dmnt already has, so
the game keeps running and nothing else is disturbed. Keep the stub for
breakpoints and watchpoints.

## Turning it on

Settings > **PC connect**. When on, the label shows where to connect:

```
PC connect=192.168.1.65:6801 code 0303
```

The right panel says whether a PC is connected. The setting survives a
restart, and the code is generated once and kept, so a script can reuse it.
Both live in `/switch/Breeze/config.ini`:

```ini
[PC connect]
enable=1
code=0303
port=6801
```

Adding that section over FTP while Breeze is closed turns it on without
touching the console.

## When it answers

PC connect runs inside Breeze, so it answers while Breeze is running. With the
SwitchU HOME daemon, Breeze keeps running behind the game:

| Breeze is | `state`, memory, logs, capture | `press`, `button`, `select` |
|---|---|---|
| full screen | yes | yes |
| overlay shown over the game | yes | yes |
| overlay hidden (game in front, overlay mode) | yes | no -- send `show` first |
| held behind the game (keep mode) | yes | not tested yet |
| closed | no | no |

With **Breeze first**, the daemon reopens Breeze after it exits, and PC connect
starts again with it.

## The client

`pcconnect.py` in the repo root works as a shell, a one-shot command, or a
Python library:

```
python pcconnect.py 192.168.1.65 0303            # interactive
python pcconnect.py 192.168.1.65 0303 state      # one command
```

```python
from pcconnect import Breeze
b = Breeze("192.168.1.65", "0303")
s = b.state()                                   # dict
hdr, samples = b.watch(0x2E9E3DD000, 4, 60, 2000)
b.cmd("show"); b.cmd("button 34")               # open Bookmarks over the game
```

From Git Bash, quote or prefix paths (`sdmc:/config/...`): Git Bash rewrites an
argument that starts with `/config/` into a Windows path.

## Protocol

One command per line. Replies start with `+OK` or `-ERR`. Multi-line replies
(`help`, `watch`, `holds`, `maps`, `refs`, `chain`, `cheats`, `cheats get`) end
with a line holding a single `.`. `tail` and `capture` send a header with
`bytes=<n>` and then exactly n raw bytes. Three clients are served at once, each
on its own thread (a fourth is refused with `-ERR busy`), so the PC app, its
file manager and a script can all be connected. `events` is per client.

Only `ping`, `help`, `auth <code>` and `quit` work before `auth`.

### Breeze's screen

These run on Breeze's UI thread, one per frame, so a command sees the result of
the one before it. They wait up to 3 s; a Breeze stuck in a long blocking
operation answers `-ERR busy`.

| command | does |
|---|---|
| `state [rows]` | JSON, see below; `rows` around the cursor, default 60 |
| `rows <start> <count> [depth]` | more rows of the current list; with `depth`, of a screen further down the stack (1 = the screen this one was opened from), as it was left |
| `events on` / `off` | sends `*EVENT state <json>` whenever the screen changes (checked every 100 ms). A change in any row near the cursor, in a button or in an action counts, not only the cursor's row |
| `press <keys>` | presses buttons for one frame; combine with `+` (`press L+ZR`) |
| `keydown <keys>` / `keyup [keys]` | holds buttons down until `keyup` (no keys = all), 30 s at most. `press` adds to them, so `keydown ZL` then `press Y` is ZL+Y. Use it to see a Dynamic view layer: `keydown ZL`, `state`, `keyup` |
| `button <id>` | selects that button on the current page and presses A |
| `action <id>` | runs an action of the screen by id whether or not its button is on the page or shift layer in view (`state`'s `actions` lists them). On the page it is `button`; off it, the screen's handler gets the id on its next frame and the reply is `+OK off page` |
| `tap <x> <y>` | touches the screen there for two frames (1280x720), exactly as a finger would: Breeze's keyboard keys, rows, buttons. A tap on a menu button selects it; a second tap presses it |
| `select <row>` | moves the list cursor |
| `text <string>` | fills the open keyboard with the string and confirms it |
| `cancel` | cancels the open keyboard |
| `show` / `hide` | shows or hides the overlay over the game (HOME daemon interface 3+) |
| `keys` | every action of the current menu with its programmed key, its custom-shortcut slot, the key in use, and actions whose keys collide |
| `restart [now]` | relaunches `/switch/Breeze/Breeze.nro`, like the focus manager's Restart Breeze. Refused unless Breeze is on Main and on screen; `now` overrides |
| `focus` / `focus show <name>` / `focus load <name>` | the focus layout in effect; a layout file listed by screen and button id; apply a layout (like Load layout). See `focus_layouts.md` |

Key names: `A B X Y L R ZL ZR PLUS MINUS UP DOWN LEFT RIGHT LS RS`, and stick
directions `LSUP LSDOWN LSLEFT LSRIGHT RSUP RSDOWN RSLEFT RSRIGHT`.

`state` returns:

```json
{
  "breeze": "beta122.01",
  "overlay": "normal | hidden | shown",
  "menu": {
    "kind": "air | box | alert | main | file | menu",
    "menu_id": 8, "uid": "8C042AE50",
    "left_title": "...", "left_status": "...", "left_help": "...",
    "right_title": "...", "right_status": "...", "right_help": "...",
    "context_help": "...",
    "row_count": 17, "index": 16, "current_row": "...",
    "rows_start": 0, "rows": ["..."],
    "selected_button": 2,
    "buttons": [{"id": 1, "text": "Back", "enabled": true, "selected": false,
                 "rect": [1060, 544, 180, 56]}],
    "actions": [{"id": 10, "label": "Write Cheat to atm", "key": "ZL+RSDOWN",
                 "enabled": true, "on_page": false}],
    "row_rects": [[4, 60, 330, 950, 40]]
  },
  "stack": [{"kind": "air", "menu_id": 8, "uid": "8C042AE50", "title": "Cheats",
             "row_count": 14, "index": 7, "current_row": "..."}],
  "keyboard": {"header": "Edit Value", "subheader": "...", "text": "31"},
  "game": {"attached": true, "title_id": "0100853015E86000",
           "build_id": "27749f7144b46203", "main": "0x1289006000", "...": "..."}
}
```

`air` menus are the list-and-buttons screens (rows, cursor); `box` menus are
button grids like Main and Settings; `alert` menus are message boxes (`text`,
`subtext`). `keyboard` is present only while the keyboard is open. Button text
carries Switch button glyphs (Unicode private-use characters).

`buttons` are the ones on the page; `actions` is every action the screen has,
in its programmed order, with the key in use (`-` for none), whether it is
enabled and whether its button is on the page now. `uid` tells one menu object
from another: a screen that keeps its `uid` while its title changes was rebuilt
in place. A screen whose rows have columns also reports `column` and
`columns`. The file picker (`file`) reports its entries as rows, and `select`
moves its cursor.

`stack` is the screens this one was opened through, nearest first. Each list
screen there gives its row count, cursor and cursor row; `rows <start> <count>
<depth>` reads its rows, which stay as they were when it was left.

`rect` and `row_rects` are screen pixels (1280x720, the size of `capture`):
`rect` is `[x, y, w, h]` of a button on the current page, and `row_rects`
lists the rows on screen as `[index, x, y, w, h]`, clipped to the list, as the
screen last drew them. A click inside a rect maps to `button <id>` or
`select <index>`.

### The game's memory

These run on the network thread, so they are not held to Breeze's frame rate,
and the game keeps running. They need a game Breeze is attached to (`-ERR no
cheat process` otherwise).

| command | does |
|---|---|
| `meta` | JSON: title id, pid, build id, main / heap / alias regions |
| `maps` | every mapped region: `addr size perm type=<n>` |
| `peek <hexaddr> <len>` | up to 4096 bytes, as hex |
| `poke <hexaddr> <hexbytes>` | writes them |
| `watch <hexaddr> <len> <hz> <ms>` | samples on the console, then sends one hex line per sample |
| `hold <hexaddr> [width]` / `unhold <hexaddr>` / `holds` | dmnt's frozen addresses |
| `freeze` / `resume` | pauses and resumes the game |
| `cheats` | every cheat: `id on\|off name`; the header gives the counts and how many are parked |
| `cheats off [all\|<id>...]` | turns cheats off (all when no id is given) and remembers which ones it turned off |
| `cheats on <all\|id...>` | turns cheats on (and forgets them) |
| `cheats restore` | turns back on everything `cheats off` turned off since the last restore; cheats that were already off stay off |
| `cheats get [<id>...]` | every cheat (or the ones given) as `id on\|off [name] word word ...`, the form `cheats add` takes |
| `cheats add [on] [name] words... [name] words...` | adds cheats (off unless `on`) and prints their ids. Several cheats per line; the words are the cheat file's, without line breaks. The master code (`{...}`) cannot be added |
| `cheats remove <id>...` | removes cheats (refused while Breeze is on Edit Cheats) |
| `cheats save` | writes Breeze's cheat file for the game (`/switch/breeze/cheats/<tid>/<bid>.txt` and toggles), like Write Cheat to file |
| `refs <addr> [hexrange] [max] [seconds]` | every 8-aligned qword in the game's writable memory whose value is in `[addr - range, addr]`: who points at an object, or into it. Defaults: range 0, 64 hits, 30 s. Prints `where region+off -> value (+distance)` |
| `chain <base> <hexoff>... [+<hexoff>]` | the cheat VM's walk in one round trip: reads `[base]`, then `[value + off]` for each offset; a final `+off` is only added. Prints every hop and the 8 bytes at the end as hex, u32, f32 and u64 |

Addresses for `refs` and `chain` are hex, or `main+X`, `heap+X`, `alias+X`.
`chain main+6DDAF60 B8 0 28 80 10 20 10 20 28 18 0 +58` is the same walk as a
cheat starting `580F0000 06DDAF60`, `580F1000 000000B8`, ... `780F0000 00000058`.

`cheats add`, `remove` and `save` run on Breeze's UI thread, and the Cheats
screen's copy of the list (with its folders) is rebuilt in the same step, so
what Breeze shows always matches dmnt. Load Cheats from file, by contrast,
replaces every cheat and turns them all off.

`cheats off` stops the cheat VM writing to the game, for example while you try
a code patch with `poke` that an enabled cheat also writes. It toggles cheats
rather than closing dmnt's cheat process (what Reset CheatVM does), so `peek`,
`poke`, `watch` and the held addresses keep working, and nothing is lost. The
master code (id 0) cannot be turned off; dmnt refuses it. The Cheats screen
shows the new state the next time it refreshes.

`watch` samples locally and ships the samples afterwards, so the network is
never inside the sampling loop.

### Engine preparation and the game's files

Most of what Breeze knows about a game it works out once and keeps in the game's
folder: which engine it is, where its code caves can go, and for Unity and
Unreal the maps that name every method and field. These two commands start that
work and say what is there, so a session does not have to know which screen
builds which file.

| command | does |
|---|---|
| `prep` | JSON: the game's `engine`, every preparation job (`job`, `engine`, `applies`, `blocking`, `what`, and its `outputs` with `exists`, `size`, `age_s`), the job `running` (`job`, `seconds`, `progress`) and how the `last` one ended (`ok`, `seconds`, `result`) |
| `prep <job>` | starts a job. One at a time |
| `prep abort` | stops a job that runs in slices; what it wrote so far stays |
| `files` | JSON: the game folder (`dir`), `title_id`, `build_id`, `engine`, and every file in it with `size`, `mtime`, `age_s`, a `kind` and, for the ones worth knowing, a `use` line. `global` lists `Klass.dat`, which lives outside the folder |

| job | engine | makes | |
|---|---|---|---|
| `engine` | any | `engine_scan.txt` | what the game is built with; also runs by itself at attach |
| `cave_floor` | any | `cave_floor.txt` | the lowest address a code cave may take, per code region |
| `il2cpp_functions` | Unity | `il2cpp_function_map.txt` | every method by name with its address |
| `il2cpp_fields` | Unity | `il2cpp_field_map.txt` | every class, its slot, and every field's offset and type |
| `ue_profile` | Unreal | `ue_profile.ini` | the engine globals and layout offsets |
| `ue_objects` | Unreal | `ue_object_cache.bin` | Rescan objects; can take minutes |
| `ue_fields` | Unreal | `ue_field_map.txt` | every reflected property; needs `ue_objects` first |
| `ue_functions` | Unreal | `ue_function_map.txt` | reflected native functions with their addresses |
| `gm_functions` | GameMaker (YYC) | `gm_function_map.txt` | every GML event and script by name with its address, from the table in the running game |

`prep` and `files` are answered on the network thread. The jobs themselves run
on Breeze's UI thread, where its caches live, started by the next frame. That
frame comes while Breeze is hidden behind the game as well, so a job can be
started and followed without showing Breeze.

- The two Unity jobs run in slices (12 ms of each frame on screen, 40 ms of each
  50 ms while hidden), so Breeze stays usable and `prep` shows progress. The
  klass scan, when one has to run first, is done in one go at the start.
- A `blocking` job runs to its end in one go. `state`, `button` and the other
  UI commands answer `-ERR busy` meanwhile; `prep` still answers. Poll it every
  15 to 20 seconds, not faster.
- A job for another engine than the game's is refused. When the scan named no
  engine every job is allowed: the scan can be wrong.

`kind` is `map` (made for a session to read: fetch these), `notes` (names and
types someone gave by hand; earlier findings), `state` (a tool's saved state),
`cache`, `cheats`, `log` or `other`. Fetch a file with `fsget`, or
`Breeze.get_file(name)` in the client, which reads it in pieces.

Checked on a console: see *Measured on the console*. The four Unreal jobs call
the same functions as their buttons but have not been run from here.

### Working by name: instances, probe, xref, notes

| command | does |
|---|---|
| `instances <hex class pointer>` | starts Breeze's scan for the live objects of a Unity class and of its subclasses. The class pointer is the first word of any object of the class |
| `instances` | the scan: `done`, `progress`, `objects` (addresses). About 9 s on a 4 GB game |
| `probe <ms> <hz> <hexaddr>:<len>... [press <keys> <at_ms> <hold_ms>]` | samples up to 16 values (1 to 16 bytes each) on one clock for `ms`, and can press game buttons at `at_ms` of the same run. One line per sample: the time in ms, then each value as hex (`?` where a read failed) |
| `xref call <addr>` | every `b` / `bl` in main's code whose target is `addr`, as `M+<offset> <word>` |
| `xref insn <hexmask> <hexvalue> [<hexlo> <hexhi>] [max]` | every instruction word `w` in main's code with `(w & mask) == value`; `lo` / `hi` are offsets from main that limit the stretch scanned |
| `cheats state` | every cheat as `id:on` / `id:off`, on one line |
| `cheats state <id>:on <id>:off ...` | makes exactly those so. Use it to put a list back as it was found; `cheats restore` turns on whatever `cheats off` turned off, including cheats that were off to begin with |

`probe` is for "press this, what changes?": the press and the samples share
the console's clock, so the delay between them is real. Its press attaches the
virtual controller as `gamepress` does; see the notes on `gamepad` below.

`ai_notes.md` in the game folder is where a session leaves what it learned for
the next one: the route to the player, object layouts, controls, what failed.
`files` lists it as kind `notes` with "READ FIRST", and names it in
`read_first` together with `engine_scan.txt`. `Breeze.notes()` and
`Breeze.write_notes(text)` in the client read and replace it.

**`breeze_unity.py`** (next to `pcconnect.py`) joins the two Unity maps to the
running game, on the PC:

```python
u = Unity(Breeze(ip, code))            # fetches the maps into ~/.breeze_pc/<title>_<build>/ when the Switch has newer ones
r = u.resolve("ServiceLocator._services[CharacterSelectionService]._currentPlayerObject.Cheats._isGodModeOn")
u.cheat(r, 1, "God mode")              # the cheat VM words that walk the same path and write 1
u.dry_run(words)                       # where a pointer cheat lands right now, before it is switched on
u.describe(address)                    # the object there: class, every field, type, live value
u.instances("Players.PlayerController")  # or instances(like=<an object>) for a class with no slot in the map
u.method(0x27A4518)                    # 'AgentStats::ReceiveHealthDamage+0xB8'
u.callers("AgentStats::ReceiveHealthDamage")
u.field_users(0x58, "AgentStats::ReceiveHealthDamage")   # loads / stores of [reg, #0x58] inside those methods
u.fieldwatch(address, "w"); u.fieldwatch_fields()         # a field watch sized from the class, bytes named
```

A path is `Class.staticField`, then `.field` for each object reached (looked up
in the class the object really is), `[3]` to index a List or array, and
`[SomeClass]` on a Dictionary for the entry whose value is an object of that
class. The last field is the target.

- `callers` returning nothing does not make a method dead: a small method is
  often inlined, and virtual and delegate calls go through a pointer. Use
  `methodwatch` for whether it runs.
- `field_users` matches the plain `[reg, #offset]` form and does not know which
  object the register holds, so it is only meaningful inside the methods named.

### gen2 and Field watch

The gen2 fork's watches, without Breeze's screens. These run on the UI thread
(the watch state lives there), so they need Breeze answering: on screen, or
hidden over the game.

| command | does |
|---|---|
| `gen2` | JSON: what gen2 holds -- `gen2` (its version) and `breeze_expects`, `attached`, `address`, `read`, `write`, `size`, `type`, `rows`, `trig`, `max_trig`, `failed`, `stopped` |
| `gen2 rows` | the same with `list`: one entry per captured row. For a memory watch `pc` (the instruction that touched the address), `call_site` (from x30), `stack` (pairs of stack offset and return address) and `count` |
| `gen2 watch <hexaddr> [r\|w\|rw] [size] [stack=<0-5>]` | attaches gen2 and starts a memory watch: who reads or writes those 1, 2, 4 or 8 bytes. Write only and 4 bytes unless said. `stack=` records that many return addresses from the stack with each row |
| `gen2 break <hexaddr\|M+hexoffset> [x<n>=<hex>]` | Break and Trace on that instruction: the game stops when it is reached. With `x<n>=<hex>` only when register n (0 to 30) holds that value; other hits pass without stopping |
| `gen2 cont` | lets a game stopped at the break run on, to the next hit |
| `gen2 stop` | detaches gen2. The rows stay readable |
| `gen2 watch <hexaddr\|M+hexoffset> x<n>` | an instruction watch: every time that instruction runs, what register `n` holds is recorded, one row per different value with its count. At a method's first instruction `x0` is the object, so the rows are every object the method ran on |
| `gen2 repair` | puts back any instruction a method or code watch's break still sits on, from `watch_originals.bin`; answers `repaired`. Refused while such a watch runs |
| `fieldwatch` | JSON: the field watch -- `state` (`capturing`, `sweeping`, `stopped`, `none`), `class`, `base`, `size`, `read`, `write`, `trig`, `bytes` (every run of accessed bytes as `[offset, length]`) and `fields` (`off`, `name`, `type`, `value`, `new`) |
| `fieldwatch start <hexaddr> <hexsize> [r\|w\|rw]` | watches every byte of an instance; write only unless said |
| `fieldwatch sweep` | goes on with only the bytes not accessed yet, at full game speed |
| `fieldwatch stop` / `clear` / `mark` | detach; forget what was accessed (and restart when it was running); take the `new` mark off |

| `methodwatch` | JSON: the method watch -- `state` (`capturing`, `stopped`, `none`), `methods`, `called`, `overwritten`, `not_set`, and `list`: per method `at`, `name`, `state` (`called`, `not called`, `overwritten`, `not set`) and, once called, `caller`, `caller_name` and, for an instance method, `this`: the object it was called on |
| `methodwatch start <text>` | watches every method whose name in the function map contains the text (`AgentStats::`, a namespace, a word like `Damage`): 768 at most, 3 characters or more |
| `methodwatch stop` / `clear` | take the breaks off and detach; start again with every method waiting |

| `codewatch` | JSON: the code watch -- `state`, `functions` (watched), `called`, `new` (first called after the mark), `mark`, `not_set`, and how long the start took (`map_ms`, `send_ms`, `arm_ms`) |
| `codewatch start [own\|all\|<text>]` | a one-shot break on every function in the function map: `own` (the default) leaves out the runtime and the engine (`System.`, `UnityEngine.`, `Unity.` ...), `all` is the whole map, anything else is text the name must contain |
| `codewatch mark` | from here `new` counts only functions called for the first time after this |
| `codewatch classes [new] [n]` | the classes by how many of their functions were called (or were new), most first: `class`, `methods`, `called`, `new`; `n` rows, 100 unless given |
| `codewatch list [new] [text]` | the called (or new) functions, newest first, 300 at most: `order`, `at`, `caller`, `name`; `text` narrows by name |
| `codewatch search <words>` | every watched function whose name has all the words (any case), called or not, the called ones first, 300 at most: `state` (`new`, `called`, `not called`), `order`, `at`, `caller`, `name` |
| `codewatch clear` / `stop` | every function waiting again; take the breaks off, detach and write `code_watch.txt` |

| `gmvars [global\|<hex object>] [text]` | GameMaker (YYC). JSON: the object's variables by name -- `name`, `id`, `slot`, `at` (where the 16-byte value is), `kind` (`real`, `bool`, `int32`, `int64`, `string`, `array`, `object`, `ref`, `unset`) and `value`; `text` narrows by name; 600 at most. No argument is the global object |
| `gmvars set <global\|hex object> <name> <number>` | writes a number into that variable, in the form it already has |
| `gmvars objects [name]` | a sweep of the heap for every GameMaker object (instances, structs, the global object), or only those holding a variable of that name: `objects`, `candidates`, `ms`, `list` (400 at most). Takes about 5 s, longer than the answer window: it replies busy, and `gmvars last` gives the answer |
| `gmvars owner <hexaddr>` | the object that owns the variable whose value (or map element) is at that address, by the same sweep: `object`, `id`, `name`. Answer through `gmvars last` |
| `gmvars open <global\|hex object>` | opens the GameMaker variables screen on that object |
| `gmvars last` | the answer of the last `objects` or `owner` |

Code addresses are `M+<hex>` from main, as the gen2 menu shows them, or a plain
address outside it.

**Method watch** answers "is this method ever called?" before any time goes
into hooking it. gen2 writes a break over the first instruction of each method
and takes it off at the method's first call, recording who called. A live
method stops the game once; a method never called costs nothing. `clear`, one
action in the game, then `methodwatch` lists the methods that action ran.

- `not called` means not called during the run, and says nothing about the
  data: a small getter is often inlined, so its field is read with no call.
- `overwritten`: something else rewrote the method's first instruction while
  the watch ran -- an enabled cheat that hooks it does that twelve times a
  second -- so whether it was called is not known.
- The breaks are in the game's code for as long as the watch runs. `stop`
  removes every one. Since gen2 v0.20 they also come off when gen2 loses the
  game any other way (the console sleeping, a GDB client), and Breeze keeps
  what was under them in `watch_originals.bin`: `gen2 repair` puts back any
  that are left, and every `start` and `stop` does the same first.
  `xref insn FFFFFFFF E7FFFFFF` lists breaks still in main's code; with no
  watch running it should find none. Do not leave a watch running across anything that detaches
  gen2 another way (a GDB client): a break left behind crashes the game when its
  method is called.
- `start` reads the function map from the SD card first; if it answers
  `-ERR busy`, it is still starting: ask `methodwatch` a few seconds later.

**Code watch** is the method watch for the whole game, for when the class is
not known yet. Every function in the function map gets the one-shot break, so
the code that runs all the time is found in the first seconds (the game
stutters while it is) and never stops the game again. Then `mark`, do one thing
in the game, and `classes new` names the classes that thing ran:

```
codewatch start          39,557 functions armed
  ... wait until `called` stops climbing ...
codewatch mark
  ... one action in the game ...
codewatch classes new    the classes with a function first called by it
codewatch list new       the functions, with who called each
codewatch stop
```

- A function that already ran before the mark is not new. For an action that
  has happened once already: `clear`, wait for the count to settle, `mark`, do
  it again.
- The list is in `switch/breeze/code_watch.bin` and the calls in
  `code_watch_hits.bin`; gen2 keeps almost nothing in memory. `stop` writes
  `code_watch.txt` in the game folder: every called function in the order of
  the first calls, with its first caller, and a `*` on the ones after the mark.
- The cautions of the method watch apply: the breaks are in the game's code
  until `stop`, and `not called` says nothing about inlined code.
- `clear` and `stop` on the whole map take longer than the 3 s the UI thread is
  given and answer `-ERR busy`; they finish all the same. Ask `codewatch` again.

Measured (The Walking Dead: Streets of Survival, Unity, 106,022 functions in
the map): `start` armed the game's own 39,557 functions in 0.7 s; 1,300 were
called in the first second and the count settled near 2,000 in about ten.
`start all` armed 106,022 in 2.1 s and settled near 3,650 in five. Six seconds
after a `mark`, standing still: 0 new. The first `gamepress` after it: 508 new
functions in 165 classes, the game's controller-connected handlers among them
(`PlayerInput::HandleControllerConnected`). A second press: 1 new. After
`stop`, a scan of main's code found no break left.

**GameMaker (YYC).** A YYC game has no classes, but every GML event and
script is a native function and the game keeps a table of them by name.
`prep gm_functions` writes it as `gm_function_map.txt`, and `codewatch start`
makes it by itself when it is missing. The object plays the part of the class:
`gml_Object_oPlayer_Step_0` is listed under `oPlayer`, scripts under
`(scripts)`. Measured on Well Dweller: 9,616 functions in the map, armed in
0.2 s, 144 called and still within five seconds. After a `mark`, one attack
gave 16 new functions in 4 classes with `o_attack` at the top (9 of its 12
events); the item button gave `o_molotov` alone (3); the spell button
`o_seep_spell` and `scr_screenshake`. No break was left after `stop`.

**GameMaker variables.** `gmvars` lists `global.` variables by name with
their live values; `gmvars <object>` does the same for one instance or struct.
An instance comes from a method watch: `methodwatch start gml_Object_oPlayer_`
and the `this` of any called event is the player's instance. A value of kind
`object` reads `struct @<address>` when it has variables of its own (pass the
address to `gmvars`) and `function @...` when it is a script, which every
global script is. Every number is a 64-bit float. Before relying on a write,
check that the game does not work the value out again every frame.

`gmvars` gives each variable's `slot`; its offset in the object is
`slot * 16`, and from a pointer to the object the value is
`[[[object+8]+10]+offset]+0`. On the console the variables screen shows that
offset and the id on every line, and its Make cheat button writes the cheat:
a pointer chain from main for a global, and for an instance a hook on the
object's Step event that finds the variable by id on every instance
(`gmobj_<object>`, which needs Add ASM in the cheat editor once).

Measured on Well Dweller: 5,060 names, 1,233 globals (413 once the functions
and unset ones are left out) in 0.9 s; `currency` read 6161 and took a write;
the player's instance, from `oPlayer_Step_0`'s `this`, held 229 variables
(`walksp`, `jumpheight`, `grv`, `stamina_max` ...).

`bytes` is the result itself and needs no field list. `fields` has names only
when the same instance was last watched from a field view (*Watch fields*),
which saves the list; started from here every line is `(unnamed)`, and the
offsets are looked up in `il2cpp_field_map.txt` or `ue_field_map.txt` on the PC.

An instruction watch (which register values reach an instruction) is not
offered here: the gen2 menu reads the register off the disassembly.

**A break on one object.** At a method's first instruction X0 is the object
the method was called on. `gen2 break M+27A4060 x0=<the hero's stats object>`
stops the game only when that method runs for the hero, however many other
objects it is called on. While it is set, `gen2` reports `break`, the
condition as `when`, and once stopped: `at` and `lr` (with `at_name` /
`lr_name` from the function map), `sp`, and `x`, the 31 registers X0 to X30.
`gen2 cont` runs to the next hit; `gen2 stop` ends it.

- Every call reaches the breakpoint and costs a stop, matching or not: a
  method called thousands of times a second slows the game while it is set.
- X0 is the object only at the method's entry. Further in, the object is
  usually in X19 or X20: read the code and give that register.
- Breeze opens its Break and Trace view when the game stops. Leave it with B
  before driving other screens.
- `this` in `methodwatch` is such an object, recorded at the method's first
  call: a live instance of the class with no search. One per method; `clear`
  starts again and may catch another.

A watch runs while the game runs. gen2 is attached for as long as it does, and
an ordinary watch slows a busy address; `gen2 stop` or `fieldwatch stop` when
done.

### The debugger

`dbg` drives Break and Trace's debugger (UI thread). Its breakpoints are the
ones Breeze's Break and Trace view lists, so a break set from the PC and one
set on the Switch are the same breaks, and when the game stops Breeze opens
its own view as it always does. Addresses are `M+<offset>` or absolute hex.

| command | does |
|---|---|
| `dbg` | where things stand: `attached`, `stopped`, `ours` (stopped at a break of Breeze's), `armed`, the Break and Trace `watch` address, `main`, `thread`, and `bps` (each with `at`, the `word` it replaced, `temp`, `enabled`, `armed`). Stopped, also `pc`, `sp`, `pstate` and `x` (x0 to x28, fp, lr) |
| `dbg attach` | attaches gen2 to the game if it is not attached; a watch that is running is left alone |
| `dbg bp <addr> [temp]` | sets a breakpoint there, or takes it off when there is one of that kind; `temp` is one that goes when it is hit. Attaches first when needed. Up to 0x80 |
| `dbg bp clear` | takes every breakpoint off |
| `dbg runto <addr>` | a one-shot breakpoint there, and the game runs on if it is stopped |
| `dbg step` / `dbg over` | one instruction; `over` runs a call as one step. Replies once the game has stopped again |
| `dbg cont` | lets the game run to the next break (the breakpoints that are enabled go back in first) |
| `dbg stop` | disarms every breakpoint and the Break and Trace watch and lets the game run |
| `dbg reg <x0-x30\|fp\|lr\|sp\|pc\|pstate\|v0-v31> <hex>` | changes a register of the stopped thread |
| `dbg v` | the vector registers (low and high halves), `fpcr`, `fpsr` |
| `dbg threads` / `dbg thread <id>` | every thread with its pc, lr, sp and name; picks the one step, cont and the registers work with |

Every form but `v` and `threads` answers with the status `dbg` gives.
Memory is read with `peek` as usual while the game is stopped.

Measured on The Walking Dead (Oct 13 2026): a breakpoint on
`PlayerController::Update` stopped the game 0.6 s after it was set, three
steps moved the pc 4 bytes each, `over` went on to the next line, a register
written read back, `cont` and `runto` behaved, and after `stop` the code held
no break word.

### Search

There is no search command yet. A memory search is driven through Breeze's
own screens with `state`, `button`, `select` and `text`, and a long one answers
`-ERR busy` until it ends.

### The game's save

A running game keeps its save locked: no other program can open it, not even to
read. Atmosphere can give a game a folder of plain files on the SD card instead
of its save (`fsmitm_redirect_saves_to_sd` in `system_settings.ini`, plus a
`redirect_save` flag for the game), and plain files can be copied at any time.
Breeze uses that for save snapshots. Details are in `savesnap.hpp`.

| Command | Does |
|---|---|
| `save` | the state for the running game: whether the setting is on in `system_settings.ini` (`setting_ini`) and still waiting for a reboot (`needs_reboot`: Breeze turned it on since the console started), whether the game is flagged, whether its save is on the SD card (`users`) and has been saved there (`committed`), and the snapshots |
| `save redirect on\|off` | flags the game and writes the setting, or removes the flag |
| `save snapshot <name> [from=sd\|nand]` | copies the save as the game last wrote it into a new snapshot, with a picture of the game taken at that moment. From the SD card it works while the game runs; from the console (`nand`) the game has to be closed |
| `save restore <name> [to=sd\|nand] [backup=<name>]` | makes a snapshot the game's save, on the SD card or inside the console. `backup` first keeps what is there as another snapshot, and nothing is changed if that fails. Refused while the game runs |
| `save delete <name>` | removes a snapshot |
| `saveshot <name>` | the snapshot's picture: header line, then the JPEG |
| `gamestop` | ends the running game at once, as if it had crashed: what it has not saved is lost. Works with Breeze behind the game |
| `gamestart <title id>` | asks the system to start a game, the way a homebrew menu does. Refused while a game runs. The HOME program acts on it once the applet in front has closed, so Breeze exits, and comes back the way it does after any exit |
| `gamepad` | the virtual controller: attached or not, its player slot, what it holds, and every pad the system has |
| `gamepad player <1-8>` | attaches it and takes that slot; a pad already there takes the slot it leaves. A game for one player reads player 1 only, so with a real controller connected the virtual one (player 2) is ignored until this is sent |
| `gamepad off` | puts the slots back as they were and removes it. Also done when PC connect stops |
| `gamepress <keys> [ms]` | presses buttons for `ms` (80 unless given, 20 to 5000) and releases; the reply (`+OK player 2`) comes after the release and names the slot. Key names as for `press`, joined with `+`, plus `HOME` and `CAPTURE`; no stick directions |
| `gamedown <keys>` / `gameup [keys]` | holds buttons until `gameup`; no keys = everything up |
| `gamestick <L\|R> <x> <y>` | tilts a stick, -32767 to 32767, until set again (`0 0` = centre) |
| `gamestate <keys\|-> <lx> <ly> <rx> <ry>` | the whole pad in one command: the buttons named are down, all others up, both sticks as given. For passing a PC controller on; when the client that sent it disconnects, everything is released |
| `gametouch <x> <y> [ms]` | a finger on the screen (1280x720) for `ms` (50 unless given) |

Every one of them takes `tid=<title id>`, for a game that is not running.
`from` and `to` default to where the game's save is now: the SD card when the
game is flagged, the console when it is not. A save is carried from one place
to the other by taking a snapshot `from` one and restoring it `to` the other;
`nand_users` in the state says whether the console holds a save for the game. Names are letters, digits, `_`, `-` and `.`. Snapshots are kept in
`sdmc:/switch/Breeze/save_snapshots/<title id>/<name>/`: one folder per user and
`shot.jpg`.

The `game...` commands drive a virtual Pro Controller (hid:dbg, the method
sys-botbase uses), attached by the first command that needs it. The system
sends its input to whatever is in front: the game while Breeze is behind it
(keep or overlay mode, overlay hidden), Breeze itself while Breeze is on
screen. `gamepress HOME` is a real HOME press, so it is also the way to put a
full-screen Breeze behind the game from the PC. They run on the network
thread and work while `state` answers busy.

Turning redirect on does nothing to a game that is already running: the game
gets the SD folder the next time it opens its save, which for almost every game
means the next time it is started. The setting is read when the console starts,
so the very first time it also needs a reboot. The first time, Atmosphere copies
the save from the console to the SD card, but only into the working copy; until
the game has saved once there is nothing to snapshot, and a game closed before
that comes up with an empty save. The save inside the console is never changed,
and turning redirect off returns the game to it.

### Files

For the PC app's file manager. Paths name a device: `sdmc:/` is the SD card,
`game:/` the running game's own files (its RomFS, read-only; see `gamefs.hpp`
for why a game has to be allowed first) and `album:/` the screenshots and
videos on the SD card.

| Command | Does |
|---|---|
| `fs roots` | the places worth showing for the running game, with its `title_id` and `title_name` (the name Breeze uses for the game's folder): Breeze's directory for it under its title id and under its name (a `*` marks the one Breeze is set to use; the other is listed when it exists), Atmosphere's directory for it, its own files, its save on the SD card, its save snapshots, today's album folder when there is one, the album, Breeze's folder, the SD card |
| `fs ls <path>` | a folder: `entries` is a list of `[name, 1 for a folder, size]`, folders first |
| `fs mkdir <path>` / `fs rm <path>` | make a folder; delete a file, or a folder with everything in it (top-level folders of the SD card are refused) |
| `fs mv <from><TAB><to>` | rename or move |
| `fsget <offset> <length> <path>` | up to 4 MB of a file: a header line with `bytes=` and the whole file's `size=`, then the bytes |
| `fsput <offset> <length> <path>` | followed by that many raw bytes: writes them at the offset. Offset 0 creates the file, or empties an existing one first |

A file is copied a piece at a time (`pcconnect.py`: `fs_get`, `fs_put`), so a
copy can be cancelled between pieces. PC connect takes three clients: the app,
its file manager, and a script.

### Developing Breeze

| command | does |
|---|---|
| `stats` | frames, average and worst frame time since the last `stats`; heap used and free (from the sbrk break); `last_press_real_held`; `time_service` (the clock Breeze got at start); `uptime_s` (the console's, not Breeze's: it does not reset when Breeze restarts); background counters: `bg_refreshes` (background retaken), `bg_game_captures` / `bg_fallbacks` (from the game via caps:sc, or the old applet capture), `bg_gap_refreshes` (retaken because a frame gap over 1 s meant Breeze was behind the game), `focus_events` / `focus_state` (focus messages; they stay 0 in No restart mode) |
| `tail <path> [bytes]` | the end of a file under `/switch/`, `/config/` or `/atmosphere/crash_reports/`, 64 KB at most. `sdmc:/config/SwitchU/` holds the HOME daemon's `daemon*.log` and `power.log` |
| `capture` | a JPEG of the screen (caps:sc), including Breeze's overlay when shown |
| `capture game` | the same from the screenshot layer stack |
| `capture <n>` | the same from vi layer stack n. **6** (`ApplicationForDebug`) is the game alone, even with Breeze full screen in front; 0, 1, 2 and 4 include Breeze; 3 is refused |
| `capture raw <n>` | 1280x720 RGBA from stack n, saved as `capture.raw`. Refused on this console (0x7FECE) on every stack |
| `timeprobe` | the six steps libnx takes to open the time service, done in a fresh session, each with its result, plus `uptime_s` and the game |
| `timecount [time:u\|time:s\|time:a] [max]` | how many more sessions, clocks of each type and time zones the time service will hand out right now (taken until refused, then released). Clock objects are one small pool shared by every program; see `timeprobe_log.py` |
| `romfsprobe [path]` / `find <name>` | mounts the running game's own files (RomFS) as `game:/`, reports the result codes, table sizes, mount time and heap growth, lists the folder or reads the file, then unmounts. Refused (`open_rc` 0x320002) until the game is in the Profile loader's list |
| `romfsprobe list` / `enable` / `fetch` | the games the Profile loader lets Breeze read (see `gamefs.hpp`), add the running game to that list (Breeze must then be closed and reopened), copy `global-metadata.dat` into the game directory |
| `saveprobe` | every save of the running game and whether it opens right now: normal, read-only, and the raw container on the user partition. A game normally holds its save locked (2002-0007) |

Connections and errors are logged to `/switch/Breeze/pcconnect.log`.

## Measured on the console

No Man's Sky, overlay mode, game in front:

- `watch` 4 bytes at 60 Hz for 2 s: **120 samples, 0 failed, 2000 ms**, while a
  heap counter advanced about 90 per second -- the game ran throughout.
  breezehand-net measured the same 120 in 2 s.
- `state` round trip: 20-50 ms, also with the overlay hidden.
- `capture`: 49-90 ms for a 200-310 KB JPEG. Hidden, it is the live game;
  shown, it is the overlay over the game.

The Walking Dead: Streets of Survival (Unity), Breeze hidden over the game
(Oct 11 2026):

- `prep il2cpp_fields`: **234 s** for 59,437 klass and 51,952 fields. The klass
  scan at the start took about 27 s of that, during which `progress` reads
  `starting`. `prep` answered every 5 s throughout.
- `prep engine`: 1 s. `files`: 21 files, the two maps at 6.3 and 8.0 MB.
- `gen2 watch` and `fieldwatch start`: 0.4 s to attach and arm.
- `gen2 watch <PlayerStats + 0x48> rw 4 stack=2`, 6 s in a level: 366 hits in 3
  rows. Both instructions reported (`M+27A81D0`, `M+27A4060`) disassemble to
  `ldr s0, [xN, #0x48]`, and each call site is the instruction after a `blr`.
- `fieldwatch start <PlayerStats> F0 rw`: 2,513 hits in 8 s, seven runs of
  accessed bytes. `fieldwatch sweep`: 0 hits in the next 8 s, same bytes.
  With the game sitting in a menu instead, the same commands recorded nothing:
  no hits means look at the game before doubting the watch.

- `breeze_unity.py`: the path to `PlayerCheats._isGodModeOn` resolved live and
  gave the same cheat words as the cheat built by hand the day before.
  `instances` found 8 `PlayerController` objects in 9 s, the player's among
  them; a scan from the PC through `refs` took 51 s and missed it.
- `probe 3000 20 <cooldown>:4 <attacking>:1 <hp>:4 press X 500 150`: the
  cooldown read 0.00 to 450 ms, 1.97 at 600 ms, counted down to -0.03 by
  2700 ms, and the attacking flag was set from 900 to 1050 ms.
- `xref call`: `ReceiveHealthDamage` has 1 caller (`AgentHitbox::SolveDamage`),
  `get_IsGodModeOn` none, `get_IsDead` 49; the three scans took 2.9 s.
  `field_users(0x58, "AgentStats::ReceiveHealthDamage")` found the one read of
  the god-mode flag in 0.6 s.
- `cheats state`: two cheats changed, the saved state put back, and the list
  read the same as before with nothing left for `restore`.
- `gen2 rows` now names each row: `AgentGraphics::OnUpdate+50` called from
  `PlayerController::Update+E8`.
- `methodwatch` with objects: of the 6 `AgentStats` methods called, two were
  called on the player's `PlayerStats` (the same address the name path
  reaches) and four on an enemy's `AgentStats`.
- `gen2 break` on `get_IsDead` (49 callers, called for every character): with
  `x0=1234` the game ran 4 s without a stop; with `x0=<the player's stats>` it
  stopped three times out of three, each with X0 the player's object, and ran
  on after each `gen2 cont`.
- `methodwatch start Components.Stats.AgentStats::`: 61 methods. After 10 s
  standing in a level 6 were called, each with its caller named
  (`get_CurrentSpeed` from `CustomCameraTarget::LateUpdate`, `get_IsDead` from
  a footstep coroutine, `OnUpdate` from `EnemyController::EnemyUpdate`), and
  `ReceiveHealthDamage` was not: nothing was hitting anyone. While it ran the
  55 uncalled entries held the break and the 6 called ones their own
  instruction; after `stop` none of the 61 held a break and the game ran on.

Graveyard Keeper II, No restart mode, Breeze full screen in front (Sep 25 2026):

- `capture 6`: 100-180 ms, the game's current frame with nothing of Breeze.
  Breeze uses the same stack for search screenshots and its background.
- `text` into the Search Setup **A=** keyboard set `u64 ==*A 1234`; reopening
  the keyboard showed 1234. `cancel` left the value alone.

## Things to know when driving Breeze

- **Button ids belong to the menu on screen.** `button 1` is Back in most
  menus, but on Main it is **Exit**. Read `state` first and use the ids it
  lists.
- **B on Main exits Breeze** too, the same as the controller.
- **A remote press replaces the controller for its frame.** Breeze's shortcuts
  fire only when the held buttons equal the shortcut exactly. A player still
  tilting the stick after `show` used to spoil that, so B did nothing, or UP
  ran the wrong action. The real buttons are now ignored for that one frame
  and do not register as a new press on the frame after. `stats` reports what
  the controller held at the last remote press in `last_press_real_held`.
- `press`, `button` and `select` are refused while the overlay is hidden, since
  the game has the controller. `show`, act, `hide`.
- Game data (`peek`, `watch`, ...) needs Breeze to be attached to the game. It
  does not attach on its own.
- **A long job blocks the UI thread before its first tick.** Starting a field
  map build answers nothing for about 20 s while it prepares; `state` and
  `restart` reply `-ERR busy` meanwhile. Wait, then poll `left_status`.
- **The IL2CPP map screen** is under Main > Unity, or ASM Explorer > IL2CPP map.
- **After `restart`, Breeze reopens its last menu**, not Main. Press B until
  `state` says Main, checking before every press, since B on Main exits.

### Recipes

**Unity menu:** from Main, the button labelled `Unity`. Its results lists page
with *Page Down*; `select <row>` picks a row on the current page.

**Memory Explorer at an address** (then *Class field* opens the object's field
view):

1. Press *A=*. The keyboard edits A in the explorer's current data type, shown
   in its subheader (`Current input type is u32`). If it is not `u64`,
   `cancel`, press *Change Type ->* and try again.
2. `text <address in decimal>`. In a float type the same digits become a
   double; in u32 the high bits are lost.
3. *Move to A*, then *Class field*.

The buttons are spread over several pages: press `button 99` until the label
appears in `state`.

## The PC app

`pcconnect_app.py` (Python 3 with Pillow) shows Breeze's screen in a window on
the PC and drives it:

```
python pcconnect_app.py 192.168.1.65 0303
```

The ip and code are remembered in `~/.breeze_pc.json`, so later it is just
`python pcconnect_app.py`.

- **Screen:** PC connect's `capture`, refreshed while the window has focus
  (1-15 fps, default 6). With the overlay hidden it is the game.
- **Breeze's keyboard:** when Breeze opens its keyboard, a text box opens at
  the bottom of the window with the keyboard's header and current text. Type,
  then Enter sends it (`text`); Esc cancels. Watch the header: a number pad
  reads digits as decimal.
- **Keys:** arrows = D-pad, Enter or A = A, Esc, Backspace or B = B, X, Y, L, R,
  Q = ZL, E = ZR, + and - = PLUS and MINUS, I J K O = right stick, S = LS,
  T = RS. Page Up / Page Down move the cursor 10 rows, Home / End to the first
  and last row. Ctrl adds ZL and Shift adds ZR, so Shift+Down is ZR+DOWN. The
  *Keys* box sends any chord (`L+ZR`).
- **Mouse:** click a button to press it; click a row to select it,
  double-click to select it and press A; the wheel scrolls. While Breeze's
  keyboard is open, and anywhere outside the menu's buttons and rows, a click
  is a touch (`tap`), so the keyboard's keys can be clicked.
- **Show / Hide** bring the overlay over the game and back.
- **Reset** restarts Breeze (`restart now`) from whatever screen it is on,
  after asking. It is the way out of a menu that cannot be left with buttons;
  the game and its cheats are not touched, and the app reconnects by itself.
- **Save redirect to SD** (check box) turns Atmosphere's save redirect on or
  off for the running game, and says what has to happen next: a reboot the
  first time, a restart of the game, and one save in the game. The text beside
  it shows where that stands.
- **Save snapshot** copies the game's save as it was last written, with a
  picture of the game. With the box ticked it works while the game runs; with
  it unticked the save is inside the console and the game has to be closed.
- **Restore...** lists the snapshots, newest first, with their pictures.
  Restore puts the chosen one back and first keeps the current save as
  `before_restore_...`; the game has to be closed. It writes to wherever the
  game's save is: the SD card while the box is ticked, the console while it is
  not. The first line of the list is the save in the other place, which is how
  a save is carried from the console to the SD card or back. Delete removes a
  snapshot. The app remembers the last game, so this works with no game
  running.
- **Game input** (check box) sends the keyboard and a Windows controller to
  the game instead of to Breeze's menus, through the virtual controller
  (`gamepad player <n>`, then `gamestate` on every change, on a connection of
  its own so a press never waits behind a capture). It reaches whatever is in
  front on the Switch: the game while Breeze is hidden, Breeze while it is on
  screen. Unticking it removes the virtual controller (`gamepad off`).
  - **Player** is the slot it takes. A game for one player reads player 1
    only; the real controller that was there moves to the slot the virtual
    one leaves, so it cannot play until the box is unticked.
  - **Controller:** any XInput one (Xbox layout), read whether or not the
    window has focus; no extra Python package. Buttons go by position (the
    bottom button is the Switch's B) unless **A/B by label** is ticked.
    Triggers = ZL / ZR, Back / Start = MINUS / PLUS, stick clicks = LS / RS,
    Guide = HOME.
  - **Keyboard** (window in focus), held for as long as the key is down:
    WASD = left stick, I J K O = right stick, arrows = D-pad, Enter or Space
    = A, Esc or Backspace = B, X, Y, L, R, Q = ZL, E = ZR, + and -, Z = LS,
    C = RS, H = HOME.
  - **Mouse:** with Breeze hidden a click is a touch on the game's screen
    (`gametouch`).
- **HOME** presses the Switch's HOME button (`gamepress HOME`): with a game
  running it puts a full-screen Breeze behind the game, or brings it back.
- **Screenshot** (or F12) saves the picture on the Switch's screen, as
  `capture` returns it (1280x720 JPEG), into `album` inside the game's folder on
  the PC: the folder the file manager uses, named after the game under the
  base folder. **Album** opens that folder as thumbnails (`pcconnect_album.py`):
  double-click opens a picture, Delete removes the selection, and pictures can
  be dragged out into Explorer or another program (Windows).
  The file manager's PC panel can be dragged from in the same way.
- **Record** (check box) keeps every picture the app receives, in
  `record/<date_time>/` inside the game's folder, each named by the milliseconds
  since the box was ticked. `log.txt` beside them lists, on the same clock,
  every picture, every command sent, every controller state sent by Game input
  and every change of Breeze's screen (tab-separated: time, kind, text). It
  goes on while the window is not in front. About 5 pictures a second at the
  default fps setting. Made so that a session can be gone through afterwards,
  by a person or a script, instead of being watched live.
- **Text view** opens a second window that draws Breeze's screen from `state`
  instead of showing a picture of it (`pcconnect_text.py`). Measured on the
  Cheats screen: a full `state` takes 16 ms and 2.7 KB where a picture takes
  136 ms and 284 KB.
  - **The list** shows the 400 rows around the cursor in Breeze's colours,
    button glyphs written as `[A]`, `[ZL]`. A click moves Breeze's cursor to
    the row, a double-click presses A on it, a drag selects text and Ctrl+C
    copies it. A row whose text has just changed is shown in orange for a
    moment.
  - **The actions** are every action of the screen at once, each with its
    key, in as many columns as the panel is wide; the ones not on Breeze's
    page are a shade darker. A click runs one (`action <id>`).
  - **Earlier screens** stay to the left of the current one as they were
    left: the screens on Breeze's stack, and a copy of the screen before when
    Breeze rebuilt a screen in place. *Earlier screens* sets how many (0 to
    6). They are for reading: search, copy and save work in them, keys do
    not go to them. **Pin** on any panel keeps a copy of it until it is
    closed, so two screens can be compared side by side.
  - **Find** looks through every row of the list, fetching the rows the
    window does not have yet; Enter or F3 goes to the next match and moves
    Breeze's cursor there, Shift+Enter or Shift+F3 to the one before.
    **Filter** shows only the rows that match. **Copy row**, **Copy all** and
    **Save...** act on the panel last clicked; Save writes a text file into
    `panels` inside the game's folder on the PC, the title and status lines
    first.
  - **Font** and **Actions** set the two font sizes; the bars between the
    panels are dragged to resize them; **Column gap** is the space between
    the columns of rows that have them (Memory Explorer); **Detach actions** puts the action
    panel in a window of its own. **Picture too** keeps the main window's
    picture updating; without it the connection is left to the text.
  - Keys are the Switch's buttons as in the main window, apart from Ctrl+F,
    Ctrl+C, Ctrl+S and F3. Breeze's keyboard opens as a text box in this
    window while it is open.
  - While **Record** is on, the screen's text goes into `log.txt` too, as
    `rows` lines (JSON: title, status, cursor, rows) whenever it changes.
- **Disassembler** opens the running game's code in a window of its own
  (`pcconnect_asm.py`; it needs the `capstone` package, `pip install capstone`).
  The code is read with `peek`, 4 KB at a time, kept, and disassembled on the
  PC, on a connection of its own.
  - **The listing** is one whole function, however long: the address as
    main+offset, the instruction word, the instruction, and a comment column
    with the function a `bl` goes to, whether a branch lands above or below
    (its target line carries a `>`), and the address an `adrp` pair builds with
    what is there: a string, a pointer into the game, or a number. Double-click
    or Enter follows a line's call, branch or address; **Back** / **Forward**
    (Alt+Left / Alt+Right) retrace; **Func up** / **Func down** step through
    the functions.
  - **Functions** (left) is the game's function map when Breeze has made one
    (Unity, Unreal, GameMaker), else the unwind table's list as
    `func_<offset>`, with script-table names where there are any. Typing in
    the box filters it by every word typed, or by address. The files are
    fetched once and kept in `~/.breeze_pc/<title id>_<build id>/`.
  - **Go** takes `M+1CBC40`, `1CBC40`, an absolute address, or words from a
    function's name.
  - **Callers** lists every `b` / `bl` to the function shown (`xref call`,
    about 0.1 s on a small game), each with the function it is in.
  - **Code watch** (left) is `code_watch.txt`, the last code watch: the
    functions in the order they were first called, a `*` on the ones after
    the mark; **new only** shows just those. A click opens the function, a
    double-click the place it was first called from.
  - **Debugging** (the second row of buttons; PC connect's `dbg`, on the
    breakpoints of Breeze's Break and Trace). **Break** (F9) sets or takes off
    a breakpoint on the line under the cursor, shown in red; **Run to** (F4)
    runs the game to that line once. When the game stops the listing goes to
    the line it stopped on, shown in green, and the panel on the right fills:
    the registers, the ones that changed since the stop before in orange, each
    value that is an address named; under them the stack, 48 values from sp.
    **Step** (F11) runs one instruction, into a call; **Over** (F10) runs a
    call as one step; **Continue** (F5) lets the game run to the next break;
    **Stop** takes every breakpoint off and lets it run; **Show PC** goes
    back to the line the game is stopped on. Click a register to see the
    memory it points at in place of the stack (click `sp` for the stack
    again); double-click one to change its value; double-click a stack or
    memory line whose value is an address in the game to go there. A line
    under a breakpoint shows the instruction that was there, not the break.
    **Float** above the registers shows v0 to v31 in their place, each as a
    double, as a float and as its 128 bits, with `fpcr` and `fpsr`; the list
    beside it shows all four floats (`4 s`) or both doubles (`2 d`) of
    each register instead, lane 0 first; a new
    value is typed as hex or as a number (`1.5` = double, `1.5f` = float).
    The memory panel shows the stack, or memory at whatever is typed into
    its box, read again at every stop: an address, `M+offset`,
    `heap+offset`, a register, or a sum such as `x0+48`; `<` and `>` move a
    page. The list beside the box picks the format: 8-byte values with what
    each points at, 4-byte hex, signed, float, double, 2-byte, or bytes
    with their text. Memory at an address shows while the game runs too.
  - **Find** searches the function shown; **Copy** takes the selection or the
    whole function; **Save...** writes it into `asm` inside the game's folder
    on the PC. **Reload** reads the code again, for after a cheat or a hook
    has changed it.
- **Files...** opens the file manager (`pcconnect_files.py`): the Switch on the
  left, with a list of places for the running game (Breeze's directory for it
  by title id and by name, with a `*` on the one in use, Atmosphere's directory
  for it, its own files, its save on the SD card, its snapshots, today's album,
  the album, the SD card), and this PC on the right. The list is read again
  when the window gets the focus back, so it follows a change of game.
  The PC side has a list of its own: the game's folder on this PC, named after
  the title (the default) or after its title id, under a base folder chosen
  with **Base folder...**. The folder is made when it does not exist, and with
  a game running the PC side starts there. The base folder is kept in
  `~/.breeze_pc.json` as `pc_game_base`; until one is chosen it is
  `Breeze games` in the home folder. F5 or the Copy buttons copy the selection to the other
  side, folders included; F7 makes a folder, F2 renames, F8 deletes, Backspace
  goes up, Tab changes side. The game's own files can only be copied out, and
  the first time for a game Breeze has to be allowed to read them and reopened.
  The window uses a connection of its own, so a long copy does not stall the
  screen.
- **Stop game** ends the running game after asking (`gamestop`); **Start game**
  starts the last game again (`gamestart`). Breeze closes to let the game
  start, so the app loses its connection until Breeze is back. Restoring a
  save from the PC is Stop game, Restore, Start game.

It uses one connection (commands first, captures in between) and a second one
while the file manager is open, leaving a slot for scripts. Its state comes from `events on`.

## Updating Breeze from the PC

Breeze unmounts its romfs right after loading its shaders at start-up, so
`breeze.nro` is not held open and can be replaced over FTP while Breeze runs.
hbloader runs the NRO from memory, so the running Breeze is unaffected. Push
the new NRO, then send `restart` (from Main) and wait for `ping` to answer.

## Security

Anyone on the network who knows the code can read and write the game's memory
and drive Breeze. The server is off by default, closes with Breeze, and refuses
every command but `ping` and `help` until `auth <code>`. Change `code=` in
`config.ini` to rotate it.

## How it is built

- `source/pcconnect.cpp` / `.hpp`. A network thread owns the listening socket
  and starts a thread per client (two at most). Commands that touch menus go
  into a queue that `pcconnect::Poll()` empties on the UI thread, one per call.
  Memory commands run on the client's thread. `cheats off`/`restore` and
  `capture` are serialised between the clients.
- `cheats add`/`remove`/`save` end in `air::pc_cheats_changed()` and
  `air::pc_write_cheat_file()` at the end of `action.cpp`.
- Row rectangles: `AirMenu::Draw` records where it drew the rows
  (`m_drawn_row_*`, `air.hpp`).
- `Poll()` is called at the top of `onFrame` in `main.cpp`, before the overlay
  state is examined, so it runs in every overlay state (about 20 Hz while
  hidden), and from the in-app keyboard's loop, so requests are answered while
  the keyboard is open.
- There is no RTTI, so `Menu::Kind()` (`ui.hpp`, overridden in `air.hpp`) names
  the class a menu really is. `Menu::ButtonAt()`, `ButtonCount()` and
  `RemoteSelectButton()` expose the buttons.
- `pcconnect::ApplyRemotePad()` runs right after each `padUpdate` of Breeze's
  pad (`ui.cpp` `UpdateInput`, and the keyboard loop).
- `pcconnect::SetKeyboard()` / `TakeKeyboardInput()` connect the in-app
  keyboard (`inapp_keyboard.cpp`).
- Settings button: `Setting_menu_ID PcConnect` in `setting.cpp`. The state is in
  `config.ini`, not in `Options`, so saved settings are unaffected.
- The server starts after `socketInitializeDefault()` and stops before
  `socketExit()`.

## Generated Files

- `/switch/Breeze/pcconnect.log` -- connections, auth results, bind errors.
- `[PC connect]` in `/switch/Breeze/config.ini` -- `enable`, `code`, `port`.
- `capture.jpg` in the PC's working directory, written by `pcconnect.py`.
- `~/.breeze_pc.json` on the PC -- the PC app's last ip and code.
