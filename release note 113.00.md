# Breeze beta113.00 Release Note

## Function Names From Script Binding Tables

A game that exposes functions to a script layer registers them in a table of
`{ const char *name, function pointer }` pairs -- the shape Lua's `luaL_Reg`
uses, and what most in-house binding layers end up with. That table is plain
data in the module, so the names survive in a fully stripped binary.

Breeze now sweeps module data for those pairs and uses them as a function map.
On a native C++ title with no game symbols at all -- 65 exported names, every one
of them libc++ or SDK -- this recovered **168 engine-authored names**:

```
main+0x8850C0  createCreature
main+0x8860C0  addCreatureBonus
main+0x8862B0  addCreatureSkill
main+0x3A2D00  equipHero
main+0x88CBF0  getHeroPosition
main+0x876900  defineSpell
```

These are real names, so they rank with the UE / IL2CPP / GameMaker maps rather
than with the synthetic `func_<rva>` fallback. Both the exact lookup and the
Function Up / Down search consult them, and `.eh_frame_hdr` is still reached only
after every named source has failed, so a synthetic name can never displace one
of these.

Three rules keep unrelated data out: the name must be a plain identifier of 3 to
48 characters, the pointer must land in executable module memory, and the pair
must have a neighbour within 0x80 bytes -- a table is an array, so a real entry
always has company, while a coincidence sits alone. Fewer than eight surviving
pairs is reported as "no binding table" rather than offered as a map.

Two tempting narrowings turned out to be wrong, both caught by measurement:

- **Scanning only writable data.** A binding table is relocated at load and then
  usually made read-only again (RELRO), so it is *not* in writable memory.
  Restricting the sweep that way cut a real 168-entry table down to 19 stray
  pairs.
- **Requiring a run of consecutive entries at a fixed stride.** Sounds tighter,
  and threw away 58 of the 168 -- including `execScript` and `startEditor` --
  because entries are separated by padding and a game keeps several small tables
  beside the big one.

### Reaching the names

Without a list the names exist but there is no way to get to one: they only
surface if you already happen to be standing on the right address. **ASM Explorer
-> Script functions (L + ZL)** now lists them, twenty to a page.

- **Y** filters by substring of the name.
- **X** opens the selected function in ASM Explorer.
- **Minus + ZR** writes the map to `script_functions.txt`.
- **Right stick up / down** pages.

The sweep runs once per game. Its result is saved to `script_functions.txt` in
the game directory and reloaded on the next launch instead of sweeping again, and
the file records the module size, so the map from a different build of the same
game is rejected rather than reused -- stale names are worse than none.

**Why this matters for field hunting.** On a stripped native game the question is
usually "what writes this field". With these names, watching a write and reading
back `addCreatureBonus` says far more than `func_8860C0`.

## Where a Pointer Field Points

Two changes to the native C++ (RTTI) class field view, both about pointers.

**A mined type no longer hides the target.** A field type mined from the class's
own code was preferred over the value sitting in the field, which is right for a
scalar and wrong for a pointer: the mined hint can only ever say "eight bytes",
while following the value names the class on the other end. A pointer-width hint
now defers to the resolved target, and falls back to `void*` -- not `long` --
when the target has no class, so a field that can be followed no longer looks
like an integer.

**A pointer into the middle of another object now says so.** This case is common
and easy to misread. Measured example: `cEntityCreature+0x168` holds an address
that is readable but carries no vtable of its own; it lands 0x80 bytes inside a
`cMouseInventory`. The row now reads

```
void* -> cMouseInventory+0x80
```

so the field can be recognised without opening View class on it. The class name
is kept as a suffix on `void*` rather than replacing the type, because it is an
inference: the scan takes the nearest object header behind the target, which in a
malloc heap is not provably the containing one. The offset is shown for the same
reason -- an implausible one is visible. A vtable carrying a non-zero
offset-to-top is skipped, since taking one of those would name a base subobject
rather than the object the pointer is inside.

## First Visit After a Relaunch

Three things the class field view used to re-derive on every visit are now
remembered.

**What a class's code says about its fields** is mined from the class's own
methods, and depends only on the build. It is now kept per class -- keyed by the
method table's module-relative address, which is what makes it survive ASLR --
in memory for the session and in `class_field_hints.txt` for later launches. A
class with no hints is recorded as a fact too, so a second visit does not re-mine
it hoping for a different answer.

**Whether the game is Unreal at all.** A positive engine-tag hit was cached, but
a negative one was not -- so on a game that is not Unreal, the whole read-only
main module was swept again on every Class field press, because
`ue_game_detected()` is asked first every time. The tag is a static property of
the module: if it is not there now it will not appear later. The result, negative
included, is now latched for the session and written to `ue_version.txt`. When
the sweep does run it uses `memchr` to jump to the next `+` instead of running
two `memcmp` calls per byte across tens of megabytes.

**Interior pointer lookups** read one window in a single bulk read and walk it
locally, instead of reading each candidate address in turn -- up to 512 reads per
field, per view build -- and each answer is cached by address.

Delete a cache file to force the work to be done again. All three are keyed to
the module size and ignored when it does not match.

## Class Field From Memory Explorer Was Paying for a Scan It Did Not Need

In the unknown-engine case the order was IL2CPP, static block, Unreal, then
native RTTI, so on a native game every Class field press from Memory Explorer ran
an Unreal scan first and threw the result away. Navigating inside a field view
never did, which is why only the Memory Explorer route felt slow. RTTI is a
handful of reads either way, so it now comes before the Unreal attempt.

## Fixes

**`key hint to file=0` was ignored for some cheats.** The conditional-key glyphs
are written into the stored cheat name, and the option takes effect by stripping
them again when the file is saved. The strip was skipped whenever the cheat's
first opcode was not a key press condition -- which is exactly the case Add
conditional key produces when the key ends up at opcode 3, over a master-code
style header. Those cheats kept the glyph in the label no matter how the option
was set. Turning the hint off now strips the name whatever the first opcode is;
adding the hint is unchanged.

**Make AOB and Make AOB M could not write a file for a cheat with a key hint.**
The `.aob` file name came straight from the cheat label, and the key hint glyphs
are private use area code points that the sdmc file system rejects, as are
`\ / : * ? " < > |` and trailing spaces or dots in a label. `fopen` failed, and
the only trace was a line in `aob.log` and a lower "created N of M" count. File
names are now built from a sanitised copy of the label: hint glyphs and control
characters are dropped, reserved characters become `_`, leading and trailing
padding is trimmed, and a name left empty becomes `unnamed`. Make AOB M's
byte-limited `label.index` copy can cut a multi-byte character in half, and that
partial character is dropped as well. When the name changes, `aob.log` records
`file name sanitised from "..." to "..."`. Other Unicode is left alone, and the
name stored inside the file -- the label Load AOB puts back on the cheat -- is
still the original.

## Generated Files

- `script_functions.txt` -- recovered script binding names, `rva<TAB>name`, keyed
  to the module size. Also written on demand with Minus + ZR.
- `class_field_hints.txt` -- field types mined from each class's own methods,
  per method table.
- `ue_version.txt` -- the detected Unreal major and minor, `0 0` meaning the game
  is not an Unreal title.

All three live in the game's Breeze directory and are safe to delete; they are
rebuilt on demand.
