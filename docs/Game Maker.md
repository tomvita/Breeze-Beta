# GameMaker support

Breeze can now recognise GameMaker Studio games (YYC and VM builds) and
help you find variable names. 

This page describes what is available and how to use it.

---

## Quick start

1. Launch your GameMaker game, then open Breeze.
2. Open **Memory Explorer**.
3. Press the **Extra** button, then choose **RValue mode**. Default short cuts ZR + Dpad up then ZR + Lstick down.

Breeze scans the game's memory for the `data.win` container the first
time you enter RValue mode. This takes a while the very first
time on a given game. After that, the result is cached and entering
RValue mode is instant — even if you close and reopen Breeze, as long
as the game is still running.

Once in RValue mode, the panel title shows **`Memory Edit [RValue
mode]`** and each 16-byte row is rendered as a typed value.

---

## What you'll see

### Standalone values

Each 16-byte row that looks like a real `RValue` is shown as:

```
REAL = 42.5             fl=00000000
STRING = "hello world"  fl=00000000
OBJECT = obj_player     fl=00000000
PTR -> 0x32A8C04400     fl=00000080
```

If the row doesn't look like an `RValue` at all it's shown as raw hex
with a `non-RValue` tag so you still see the surrounding memory.

### Variable slots

A variable slot is the 16-byte block GameMaker uses internally to bind
a variable id to its current value. When Breeze recognises one it
shows the variable's name and where its value lives:

```
slot "hp"#1042 -> 0x32A91234B0
slot "ch3azae_count"#5117 -> 0x32A911EC00
```

Move the cursor onto the row and press **X** to jump to the value
pointer, or **X+ZL** to edit the value in place (Breeze writes only the
8-byte payload and preserves the kind/flags bytes).

---

## Browsers

Three browsers list GameMaker resources by name. All three are
paginated, support keyboard filtering, and live on the left panel.

### Scripts (SCPT)

From the **Extra** palette in Memory Explorer choose **Script list**.

- Rows: `[id] RVA=0x… script_name` (once Breeze has resolved the
  script's code address) or `[id] code_id=N script_name` (when it
  hasn't yet, e.g. VM builds).
- Press **A** on a row to jump into ASM Explorer at that script's
  code. If Breeze hasn't located the script's address yet, a popup
  explains why.
- Press **A + ZL** to show id / code_id / name in a popup.
- **Y** opens the keyboard filter, **X** clears it.

### Objects (OBJT)

Shortcut: **L + ZR** from Memory Explorer.

- Rows: `[index] obj_name`.
- Useful for matching the index shown in `OBJECT = …` rows.

### Variables

From the **Extra** palette choose **Variable list**.

- Rows: `[id] variable_name`. If the game ships variable scope
  information (some builds don't), a `(scope)` tag is added — e.g.
  `(Global)`, `(Self)`, `(Local)`, `(obj_player)`.
- **A** runs **Find slots** for the highlighted variable (see below).
- **Y** opens the keyboard filter, **X** clears it.

---

## Find slots (heap scan)

When you don't know where a variable lives in RAM, Breeze can sweep the
game's heap and list every address that looks like a slot for that
variable.

1. Open the variable list, highlight the variable you want.
2. Press **A** → **Find slots**.
3. Breeze scans the heap and opens a results sub-menu showing each hit
   as `0x…address  -> 0x…value`.
4. Press **X** (or **A**) on any hit to open Memory Explorer at that
   address. Memory Explorer automatically switches into RValue mode so
   the row reads `slot "name"#id -> 0x…`.

The scan is capped at 4096 hits and the results are paginated 50 rows
at a time.

---

## What can affect the first scan

The very first time you enter RValue mode after starting Breeze takes
about 2 seconds while Breeze locates the `data.win` container in the
game's heap. After that the location is cached to your SD card, so:

- Re-entering RValue mode in the same Breeze session: instant.
- Closing and reopening Breeze while the game is still running:
  instant.
- Restarting the game: the cache is automatically discarded and Breeze
  rescans on next entry (~2 s).

Cached data is stored under your game folder on the SD card and is
keyed to that specific game build — no manual cleanup needed.

---

## Known limitations

- **No variable scope tags on some games.** Several shipped
  GameMaker builds (notably Undertale and Deltarune on Switch) strip
  the variable metadata from `data.win`. The variable browser still
  works; it just hides the scope column.
- **Find slots is a heuristic.** False positives are rare but
  possible, especially for low-numbered or built-in variables.
- **Object labels on slot rows show only the variable name.**
  Identifying *which* object instance owns a slot is not yet supported.
- **`OBJECT` and `STRING` decoding require Breeze to have located
  `data.win`.** If you see `(k=6)` instead of `OBJECT = obj_player`,
  press **Minus** in the RValue palette to re-run the scan.

---

## Troubleshooting

- **Entering RValue mode does nothing useful / values look like
  garbage.** Press **Minus** ("Locate data.win (rescan)") to force a
  fresh scan. This invalidates the cache.
- **Find slots returns 0 hits.** The variable id may be from a chunk
  Breeze couldn't reach, or the variable simply isn't allocated in the
  current game state (e.g. it only exists inside a room you haven't
  entered).
- **The first RValue entry feels slow.** That's the one-time per-game
  cold scan (~2 s). Subsequent entries on the same running game are
  instant.

---

## Compatibility

- Supported: GameMaker Studio 2 YYC builds on Switch.
- Supported: GameMaker Studio 2 VM builds where the runtime keeps a
  resident `data.win`.
- Untested but expected to work: older bytecode-15+ YYC builds.
- Not supported: bytecode ≤ 14 builds with the old variable-record
  layout.
