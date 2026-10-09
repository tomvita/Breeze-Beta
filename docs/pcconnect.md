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
| `rows <start> <count>` | more rows of the current list |
| `events on` / `off` | sends `*EVENT state <json>` whenever the screen changes (checked every 200 ms) |
| `press <keys>` | presses buttons for one frame; combine with `+` (`press L+ZR`) |
| `keydown <keys>` / `keyup [keys]` | holds buttons down until `keyup` (no keys = all), 30 s at most. `press` adds to them, so `keydown ZL` then `press Y` is ZL+Y. Use it to see a Dynamic view layer: `keydown ZL`, `state`, `keyup` |
| `button <id>` | selects that button on the current page and presses A |
| `tap <x> <y>` | touches the screen there for two frames (1280x720), exactly as a finger would: Breeze's keyboard keys, rows, buttons. A tap on a menu button selects it; a second tap presses it |
| `select <row>` | moves the list cursor |
| `text <string>` | fills the open keyboard with the string and confirms it |
| `cancel` | cancels the open keyboard |
| `show` / `hide` | shows or hides the overlay over the game (HOME daemon interface 3+) |
| `keys` | every action of the current menu with its programmed key, its custom-shortcut slot, the key in use, and actions whose keys collide |
| `restart [now]` | relaunches `/switch/Breeze/Breeze.nro`, like the focus manager's Restart Breeze. Refused unless Breeze is on Main and on screen; `now` overrides |
| `focus` / `focus show <name>` / `focus load <name>` | the focus layout in effect; a layout file listed by screen and button id; apply a layout (like Load layout). See the [Focused Actions Guide](focus%20mode.md) |

Key names: `A B X Y L R ZL ZR PLUS MINUS UP DOWN LEFT RIGHT LS RS`, and stick
directions `LSUP LSDOWN LSLEFT LSRIGHT RSUP RSDOWN RSLEFT RSRIGHT`.

`state` returns:

```json
{
  "breeze": "beta122.01",
  "overlay": "normal | hidden | shown",
  "menu": {
    "kind": "air | box | alert | main | file | menu",
    "menu_id": 8,
    "left_title": "...", "left_status": "...", "left_help": "...",
    "right_title": "...", "right_status": "...", "right_help": "...",
    "context_help": "...",
    "row_count": 17, "index": 16, "current_row": "...",
    "rows_start": 0, "rows": ["..."],
    "selected_button": 2,
    "buttons": [{"id": 1, "text": "Back", "enabled": true, "selected": false,
                 "rect": [1060, 544, 180, 56]}],
    "row_rects": [[4, 60, 330, 950, 40]]
  },
  "stack": [{"kind": "box", "menu_id": 1, "title": "Main"}],
  "keyboard": {"header": "Edit Value", "subheader": "...", "text": "31"},
  "game": {"attached": true, "title_id": "0100853015E86000",
           "build_id": "27749f7144b46203", "main": "0x1289006000", "...": "..."}
}
```

`air` menus are the list-and-buttons screens (rows, cursor); `box` menus are
button grids like Main and Settings; `alert` menus are message boxes (`text`,
`subtext`). `keyboard` is present only while the keyboard is open. Button text
carries Switch button glyphs (Unicode private-use characters).

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
