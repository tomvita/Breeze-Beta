# Cheat source: one file per game, for every build

`<TitleID>.ini` in the game's Breeze folder (`sdmc:/switch/breeze/cheats/<game>/`,
e.g. `0100839022642000.ini`) holds the source of the game's cheats: ASM caves,
routines they share, and plain cheat codes. Anything that only holds for one
build (hook sites, function and data addresses, stock words, cave pins) is
written once in a `[build <BID>]` section and used by name. A game update
needs a new build section with the same names, not new copies of the code.

A cheat defined here is built from here. A script file named in the old
`<BID>.ini` registry is still used for cheats that have no section.

## Sections

```ini
// Lines starting with // ; or # at the left edge are comments.

[routine move speed]
code =
    ldrb w9, [x19, #0x2c]
    cbz w9, plain
    fmov s11, #{factor}
    fmul s11, s0, s11
    b code1+4
  plain:
    {original}
    b code1+4

[cheat Move speed x2.0 (player)]
source = move speed
set    = factor 2.0
hook   = speed_site
place  = fixed
on     = no

[cheat Moon jump (hold ZL+B)]
codes = 04000000 {moon_jump_flag} 00000000
        80000102
        04000000 {moon_jump_flag} 00000001
        20000000

[build 3DCC79312B977CD1]
speed_site     = M+27D72C0 stock 1E20400B
moon_jump_flag = M+A8BE114
pin Move speed x2.0 (player) = M+265FB10
```

A value starts at the left edge (`key = value`); every indented line after it
continues it, kept as written, so assembly comments and `x = 5` lines stay code.
Every line of code is indented, labels too: a line at the left edge is a key,
a section or a comment, never code.

| Section | Meaning |
|---|---|
| `[cheat <label>]` | One cheat. The label is the cheat's name in the list (key hints are ignored when matching). |
| `[routine <name>]` | Code used by cheats (`source =` or `{include <name>}`); not a cheat itself. |
| `[mod <name>]` | Values a data slot of an ASM cheat's cave can be set to, one cheat each (see Mods). |
| `[build <BID>]` | Names for one build: `name = M+offset` (main relative) or `name = 0x...` (a plain value), optionally followed by `stock XXXXXXXX` (the game's word there); and `pin <label> = M+offset` for a cave's address. | `free = M+X..M+Y`: space a cave left behind (its bytes are still in the game but belong to no cheat), which Build lets a growing cave take; Breeze writes these when a cave is shelved, discarded or moved.

| Cheat key | Meaning |
|---|---|
| `code` | An ASM cave, assembled by Add ASM after its usual header (`code1`, `cave_start`, `data_start`, `data_end`, `{original}`, `{target}` as always). |
| `codes` | Plain cheat words instead, 8 hex digits each. |
| `template` | `yes`: only there for its mods to copy (a chain cheat whose values are the cheats): not put in the cheat list itself; its mod's values get a folder of their own. |
| `chain` | A pointer cheat: the base (a name or `M+X`), the offsets read through, and the last offset, which is added. With `write`. |
| `write` | What a chain cheat writes at the end of its chain: `<type> <value>` (f32 f64 u8 u16 u32 u64). |
| `source` | Use the code of that routine or cheat, with this cheat's `set`. |
| `set` | Template values: `var value`, several separated by `;`. |
| `hook` | The name of the hook site. Needed to install an ASM cheat from source. With a `stock` word Breeze refuses a build whose word differs; without one it refuses a site that is already a branch. |
| `key` | `ZL+ZR+X` style (A B X Y L R ZL ZR LS RS PLUS MINUS UP DOWN LEFT RIGHT): the cheat runs while the keys are held. |
| `on` | `no`: installed switched off. Without it a cheat is installed switched on. |
| `place` | `fixed`: the cave always goes at its build's pin and Assemble all ASM never moves it. For caves placed by hand in a spot the planner would not choose. |
| `shelved` | `yes`: deleted from the cheat list and kept here (see The shelf). Install from source and Make cheat's `requires` leave it alone. |
| `part_of` | The cheat this one belongs with, such as the key cheat that sets the flag a hook's cave reads: it goes in that cheat's folder (see Units). |
| `unit` | The name of the folder this cheat and its parts go in; the cheat's name without " hook" when not given; `none` for no folder of its own. Kept in step with the list on every save (see Units). |
| `was_after`, `was_in` | Written with `shelved`: the cheat it followed and the folder it was in, where Restore puts it back. |

## Pointer cheats

```ini
[cheat Money 999,999]
chain = {game_info_slot} B8 0 68 58
write = u32 999999
```

is built as the walk every pointer cheat makes:

```
580F0000 0A740640    R = [main + game_info_slot]
580F1000 000000B8    R = [R + B8]
580F1000 00000000    R = [R + 0]
580F1000 00000068    R = [R + 68]
780F0000 00000058    R = R + 58        (the last offset is added, not read)
640F0000 00000000 000F423F             [R] = 999999, 4 bytes
```

A chain of the base alone is a plain store at main + base. `key` puts it in a
key block as for any cheat. After a game update the base usually moves and the
offsets stay, so the base is a name in the `[build]` section; an offset that
moves can be a `{name}` too.

A `[mod]` with `cheat = <a chain cheat>` and no `at` gives the chain a list of
values: each is the chain writing that value, one on at a time. There is no
default to put back when one is turned off (it is the game's own value), so
the first value is not marked `(default)`.

In the Cheat composer (Edit Cheat > Cheat composer on the cheat) a pointer
cheat shows as its `chain =`, `write =` and `key =` lines, edited like code.
The status line walks the chain in the running game: every pointer on the way,
where it ends and what is there now. Check shows the words it makes, Build
rebuilds it from the lines, Name address on the chain line gives its base a
name in the build section (`M+A740580` becomes `{clock_slot}`), Make mod makes
a `[mod]` of values for it, and Key sets its key.

A value can carry a label, written `label = value`: the cheat is then named
`<mod> <label>` instead of `<mod> = <value>`. Six clock cheats that differ only
in the time they write become one template and one mod:

```ini
[cheat Set clock (turn off after)]
template = yes
chain = {clock_slot} B8 0 40 18 54
write = f32 0

[mod Set clock]
cheat = Set clock (turn off after)
values = 6:00 AM = 0; 9:00 AM = 180.0; 12:00 PM = 360.0; 3:00 PM = 540.0; 6:00 PM = 720.0; 9:00 PM = 900.0
```

Install from source then gives a `Set clock` folder of "Set clock 6:00 AM" to
"Set clock 9:00 PM". Cheats already in the list under other names are taken
over in their place, and a mod's name has to be its own (Make mod refuses one
in use).

Import scripts to source also takes the loaded pointer cheats of that shape
that have no section: the base becomes the `[build]` name with its value when
there is one, a 4 byte value is written `f32` when its bits read as a plain
float, `u32` otherwise.

## Templates

| Written | Becomes |
|---|---|
| `{var}` | the `set` value, as written |
| `{name}` | the name's value for the running build: `0x...` in `code`, 8 hex digits in `codes` |
| `{name:page}` / `{name:lo12}` | its 4 KB page and low 12 bits, for `adrp xN, {name:page}` / `[xN, #{name:lo12}]` (keystone refuses an `adrp` to an unaligned address and an `adrp` to an assembler symbol) |
| `{include <name>}` | that routine's code, filled the same way |

A name the running build does not have stops the cheat with the builds that
do have it, so code is never assembled with another build's addresses.

`make_cheat.ini` recipes can use the same `{name}`s in their `code`, and a
recipe's `requires` is installed from here when this file defines it (no
`requires_script`, `requires_hook` or `requires_stock` needed).

## On the Cheats menu

| Action | What it does |
|---|---|
| Install from source (ZL+ZR+Y) | Every cheat here that is not loaded, built for the running build; the cheat file is saved. Reports each one that could not be built and why. |
| Import scripts to source | Every loaded ASM cheat with a script file and no section yet gets one: its hook as a name with the stock word, its key, on/off, and a pin (from the script's own `cave_start =` line, or the cave's address for a cheat Assemble all ASM was leaving alone, which also becomes `place = fixed`). The code is copied as it is: give the addresses written inside it names with Name address in the Cheat composer. |
| Assemble all ASM | Rebuilds the cheats defined here (except `place = fixed`) from source. A pin of a cheat that is not fixed is rewritten in place to where the cave went. |

## In the Cheat composer

Opening the Composer on a cheat defined here (Edit cheat, as for any ASM
cheat) edits its section instead of the script file: the left panel says
which. A cheat with `source =` edits that routine, so the change reaches every
cheat using it. The code shows as written, `{names}` and all.

| Action | What it does |
|---|---|
| Save / Save & Back | Writes the code back into its section. Only those lines change; the rest of the file, the `[build]` sections and the line endings stay. Leaving with no change writes nothing. |
| Check ASM | Checks the code as the running build fills it, and puts the notes on the lines as you wrote them. A name the build lacks is noted on its line. `{original}`, `{target}` and `{include ...}` lines are not checked here. |
| Name address (ZR+X) | The number on the cursor's line becomes a name of the running build: you type the name (Breeze suggests the function or field it knows the address as), `name = M+...` goes into the `[build]` section and the code gets `{name}`. On an `adrp xN, 0x...` line the page and the low 12 bits of the next `[xN, #...]` or `add ..., xN, #...` become `{name:page}` and `{name:lo12}`. An address of 0x10000 or more is replaced on every line that has it. An existing name with the same value is reused; with another value it is refused. |

To test a change, Save & Back, then Add ASM on the cheat as usual: it is built
from the section.

The way in for a cheat made the old way: write and test it with a script
file, then Import scripts to source, then open it in the Composer again and
Name address each number that changes between builds. From then on the section
is the only place to edit it; the script file is left as it was and no longer
used.

## Split ASM cheats: hook, cave fill and off cheat

An ASM cheat defined here is installed in three parts:

| Part | Where | What it does |
|---|---|---|
| Hook | where the cheat is in the list, under its own name | `1405000H <cave> <first word>` / `04000000 <hook> <branch>` / `20000000`: it branches only while the cave holds its code, so it can never jump into an empty cave. With a key it sits inside the key block. |
| Cave fill | the `[code cave]` folder at the end of the cheat file, same name | Only type 0 stores: the cave's code. |
| Off cheat | the same folder, `<name> (off)` | One store: the instruction the hook replaced. |

Breeze keeps the fills and off cheats out of dmnt (no cheat slot, no opcodes)
and writes them itself: a fill when the file is loaded, when a cheat is
installed or rebuilt, and when a hook is turned on and its cave is not in the
game; an off cheat when a hook is taken back to the game's own code. With
another cheat manager, turn the cave fill on once (and off again) before
turning on its hook, and the off cheat on once after turning the hook off.

On the Cheats screen a hook has the three stages of any ASM cheat: on; off
with the branch still in the game (green: it keeps working and costs the cheat
VM nothing); off with the original instruction back. Install from source
splits the source cheats that are loaded in the combined form, in place, and
gives hooks of the first split form (an Else writing the original every pass)
the new form and an off cheat. Assemble all ASM joins them back for its pass
and splits them again, keeping the list order. Cheats with no section here
stay combined.

## Units

A source ASM cheat with parts, that is the values of its mods and the cheats
with `part_of = <its name>`, is put in a folder of its own with them where the
cheat is in the list (inside the folder it is in, if any):

```
[Teleport to brown map marker]                 20000000
[Teleport to brown map marker hook]
[Teleport to brown map marker (ZL+ZR+LEFT)]    part_of = Teleport to brown map marker hook
[Teleport to brown map marker end]             20000001
```

Install from source, Build and Assemble all ASM do this; a unit already in
order is left alone. Cheats without parts that give the same `unit` go in one
folder of that name too.

The list is where cheats are arranged, so the file follows it: every time the
cheat file is saved, Breeze writes the list's layout into the `unit` lines. A
folder holding only source cheats and their parts is their unit (rename the
folder and `unit` follows); a cheat loose in a bigger folder of your own gets
`unit = none` when it has parts (so it is not put in a folder again) and no
`unit` when it has none. A `part_of` cheat goes with its cheat and has no
`unit` of its own.

Editing `unit` by hand (or in the PC editor) is fine: Breeze keeps a hash of
the file as it last left it in `<TitleID>.ini.synced`, and when the file has
changed since, the next save applies its units to the list instead of
writing over them. Install from source applies them at once.

## Mods

A mod is a data slot in a cheat's cave and the values it can hold:

```ini
[mod Teleport height]
cheat  = Teleport to brown map marker hook
at     = teleport_height        ; the slot's label in that cheat's code
type   = f32                    ; f32 f64 u8 u16 u32 u64
values = 10.0; 20.0; 50.0       ; the first is the default: what the code holds
key    = ZL+ZR+UP               ; optional: written while the keys are held
```

and in the cheat's code, after its last branch:

```
    ldr s3, teleport_height
    ...
    b code1+4
    teleport_height: .float 10.0
```

Install from source puts one cheat per value right after the cheat, named
`<name> = <value>` (`(default)` on the first), each a single store into the
slot. Only one is on at a time: turning one on turns the others off, and
turning one off writes the default back. When the cave is rebuilt somewhere
else (Assemble all ASM), the values follow it. A shelved cheat's values leave
the list with it.

A value cheat is known by its name, so every mod needs a name of its own. Two
`[mod]` sections of one name are both left alone (their value cheats stay as
they are) and Install from source and Build say so until one is renamed. One
name may start another (`Gil` and `Gil earned`): a value cheat belongs to the
longest mod name its own name starts with.

To add, change or take out values, Edit Cheat on any of the value cheats: the
keyboard shows the whole list (`1.0; 2.0; 4.0`). What is written goes into the
section's `values` and the cheats follow it: a value still in the list keeps
its cheat and its on / off, a changed one takes the cheat of a value taken out,
new ones are added off, the rest leave the list (the default is written back
if one of them was on), and the cheats are put in the list's order. A new
first value is a new default: it goes into the code's slot line and the cheat
is rebuilt. Editing `values` in the file and then Install from source (or
Build in the PC editor) does the same.

To take a mod out, clear the list in that keyboard: the `[mod]` section leaves
the file, its value cheats the list, and its unit folder opens up (what it held
stays where it was). Deleting a slot line in the Cheat composer and going Back
(or Build) does the same for every mod of that cheat whose slot is gone; a mod
whose slot was never in the code goes that way too.

## Building in the Cheat composer

| Action | What it does |
|---|---|
| Build (ZR+B) | Saves the section, closes the Cheat composer and rebuilds the cheat where it is (its pin holds), split again, its mods brought up to date and back on if it was on. Before anything is written the new code is assembled to learn its size: a cave that grows takes the words after it, and they have to be free (zero in the game and no other cave's). When they are not, a cheat that may move is placed again by the cave planner (its pin goes); when no gap anywhere is big enough, every movable cave is packed again as one set (Assemble all ASM, with the cheats that were on turned back on) and the cheat tried once more, and if that fails too the caves in the game are listed by size; a `place = fixed` one is not built, and what is in the way is named (the game's own code, or another cave). |
| Key (ZR+Right) | Asks for the keys held for the cheat to run (`ZL+ZR+X`; empty for none), writes the section's `key =` and builds. |
| Make mod (ZR+Down) | On a line holding a value: asks for a name and the values (the first one the default) and makes the value a data slot after the code, writes the `[mod]` section and builds. It takes `fmov sN, #value` / `fmov dN, #value` (the line becomes `ldr sN, <slot>`, the slot `.float` / `.double`), `mov wN, #value` / `mov xN, #value` (`.word` / `.quad`), and a constant built with `movz` / `movk`: with the `fmov sM, wN` that moves it into a float register after them, that fmov becomes the load and the slot holds the float the pair builds (the movz / movk stay); without one, the movz / movk lines become one `ldr wN, <slot>`. An 8 byte slot goes after `.align 3`. On a slot line itself (`move_speed_factor: .float 1.0`) nothing in the code changes: a new `[mod]` is written for it, or, when a mod already uses that slot, its values are opened for editing (a new first value is also written into the slot line). The code has to end in a branch (`b`, `br` or `ret`), or the slot would run as an instruction. |

## The shelf

Deleting a cheat defined here from the cheat list (Cut Cheat, or any other
way) does not lose it. The next time the cheat file is saved, its section gets
`shelved = yes` with `was_after` and `was_in`, its hook's original instruction
goes back, its cave fill leaves the `[code cave]` folder and the running
build's pin is taken out, so the cave is free for other cheats (a `place =
fixed` cheat keeps its pin: that spot was chosen by hand). Moving a cheat with
Cut and Paste is not a delete: it is back in the list before the save.

Cheats menu > **Shelf** lists the shelved cheats:

| Action | What it does |
|---|---|
| Restore (X) | Installs it again with a new cave, off, after the cheat it followed (else at the end of its folder, else at the end of the list), and takes `shelved` off. When it cannot be built (for example no room for its cave) it stays on the shelf and the caves in the game are listed, largest first, so one can be shelved to make room. |
| Discard (Minus, twice) | Removes its section and its pins in every build from this file for good, with its mods, and the `[build]` names it used (its hook, the `{names}` in its code) that nothing else in this file or in make_cheat.ini uses. A `[build]` section left empty goes too. A `place = fixed` cave's place becomes a `free` range, merged with the ones it touches. |

## On the PC

The Breeze PC app's **Cheat source** button opens this file in an editor
(pcconnect_source.py): the whole file as text, its sections listed with each
cheat's state in Breeze (on / off, split, fixed, shelved, not loaded). Save
(Ctrl+S) writes it to the Switch. Check (F7), Listing (F8) and Build (F9) work
on the cheat the cursor is in and are done by Breeze, so what the PC shows is
what the Switch assembles: Check's notes mark their lines, Listing shows each
code line's address and the word the game holds there (double-click a row to
go to its line), Build saves first and rebuilds the cheat where it is.
Install from source is there too.

Name address (Ctrl+N) and Make mod (Ctrl+M) do what the Cheat composer's do,
on the code line the cursor is on (on a pointer cheat: its chain's base, and
the values it can write). Breeze works out what the line holds and suggests a
name; the PC asks for the name (and the values) and Breeze makes the change in
the file, so both sides change a line the same way. The editor reloads the file
afterwards. Make mod rebuilds the cheat; one on the shelf is only saved. Shelf
lists the shelved cheats with where they were, for Restore or Discard.

## After a game update

Moving the cheats to the new build (Cheats, Move cheats from earlier build)
writes the `[build <new BID>]` section itself: every name of the old build's
section is looked for with the cheats' own addresses (by code, by IL2CPP method
name, by what loads a static), with the new `stock` words and pins. It goes at
the end of the file, in the file's own line endings; the file as it was is kept
as `codedump/<TID>_<old BID>.ini`. A name that was not found is written as a
`// name = ?` comment with the reason, and `cheat_update.txt` lists it. Then
Install from source. Cheats whose names are missing are reported and left out.

A plain value can say which field it is the offset of:

```ini
[build 8B335CCAAF09C7C8]
game_info_slot = M+A744820
App.Savedata.ItemInfo._money = 0x58 field App.Savedata.ItemInfo._money
```

Building ignores `field ...`; the move gives the new section the offset the
field has in the new build, read through the moved cheats' chains (Unity and
Unreal, from the names Breeze records), and reports a change. A field no moved
cheat goes through keeps its value, with a `?` line in `cheat_update.txt`. A
plain value without `field` is the same in every build and is not carried.

Make cheat (Memory Explorer, the field views, the Unity chain screen) writes a
pointer cheat of the plain chain shape into this file when the game has one:
the base as a `[build]` name (an existing one with that address, else
`<Class>_slot`) and every step Breeze can name as a field name, e.g.
`chain = {game_info_slot} B8 0 {App.Savedata.GameInfo._itemInfo}
{App.Savedata.ItemInfo._money}`. Loops, copies and conditions are not of that
shape and stay in the cheat file only.

By hand: add a `[build <new BID>]` section with the same names (an AOB search
or the function map finds them).

Write an address in code as a name, also where a register holds a page made
earlier: `ldr w0, [x19, #{give_id:lo12}]`, not `#0x10c`. A number typed into
the code stays the old build's.
