Unity metadata support and class-exploration workflow.

See also: [class_primer.md](class_primer.md) for class/instance fundamentals and practical discovery mindset.

## Feature guide

- `dump.cs` view to inspect C# class definitions directly in Breeze.
- `Class Field View` to inspect fields from a live class instance, including pinning resolved addresses for live tracking.
- Class navigation tools:
  - `View class` to follow field types.
  - `Class Link` to find parent/up links.
- Memory Explorer bridge:
  - `Class view` (`Y + ZR + ZL`, label may appear as `Class field` in some builds) to jump directly from cursor address into class Field View resolution flow.
- Enhanced class-link resolution so discovering one instance can lead to many related instances for exploration.
- Save/load for class views, including instance links when the address is still valid.
- `Extract` in Field View to pick which of a class's fields are shown inline on
  every row that points at that class, remembered per title.
- Cheat generation support when linked addresses resolve from valid `main`-region targets.
- Runtime metadata path that needs no `dump.cs` at all:
  - `Methods` (`L + ZR`) in Field View for method names, addresses and signatures.
  - `IL2CPP map` (`Y + ZR`) in ASM Explorer to generate function names for the
    whole binary, enabling `Function Up` / `Function Down`.
  - `Visit type` to navigate from a method signature to a parameter's class.

## Focus and shortcut notes

- If you are using Focus mode and some new buttons are not visible, apply the newer `default.focus` included in later releases.
- You can open Focus Manager directly with `FocusManager_key` (default: `L + ZR`).
- `default.focus` is applied when:
- you activate the "Full Menu" button in Main Menu, or
- it is loaded directly in Focus Menu.
- Shortcut keys shown in this guide are default mappings.
- Users can customize shortcuts when custom shortcuts are enabled.

## Preparation

### Do you need dump.cs at all?

No longer required. Breeze can read class fields, methods, signatures and
function names directly from live memory. `dump.cs` is still preferred when you
have it — it carries richer detail and parameter names on every build — but the
runtime path covers titles where Il2CppDumper fails, which is common on older
games.

Runtime-only route: run **Search → Klass**, then build the function map from
ASM Explorer with **IL2CPP map** (`Y + ZR`). See
[`il2cpp_runtime_metadata.md`](il2cpp_runtime_metadata.md).

### Get il2cpp Breeze helper

To generate `dump.cs` and its index files for the richest experience.

Get from here: <https://github.com/tomvita/Il2CppDumper/releases/latest>

### No-PC (Switch-only) workflow

- You can prepare IL2CPP files directly on Switch from Main Menu (`IL2CPP` / `Launch dumptool`) without using a PC.
- Processing on Switch is much slower. Expect around 5 minutes (sometimes more) depending on game size.
- Some games need more memory for this step. If it fails or stops early, run Breeze in title takeover mode (high-memory applet replacement) and retry.

### Compatibility notes (`main` vs `main.elf`)

- Some very old Unity/IL2CPP titles may fail with the Switch-side workflow.
- For those cases, use the PC Il2CppDumper workflow instead — or skip the dumper
  entirely and use the runtime path, which is generally the better option when
  Il2CppDumper cannot handle the title at all.
- On PC:
- Use `main` for better compatibility with older games.
- Use `main.elf` for better compatibility with newer games.

## Views guide

### ASM Explorer

- `Function Up` (`StickRLeft`): jump to the nearest function above the current cursor line.
- `Function Down` (`StickRRight`): jump to the nearest function below the current cursor line.
- `Detail` (`X + ZR`): open `dump.cs` details for the current function. When the
  name came from the runtime map instead, opens the Runtime Method List for the
  owning class with the cursor on that method.
- `IL2CPP map` (`Y + ZR`): generate function names from live klass data. Needed
  once per session for `Function Up` / `Function Down` when there is no
  `dump.cs`; requires `Search -> Klass` first.

Function names resolve from `dump.cs` when present, otherwise from the generated
`il2cpp_function_map.txt`.

### dump.cs View

- `Search` (`+`): text search inside `dump.cs`.
- `Add bookmark` (`A + ZL`): bookmark current `dump.cs` line/offset.
- `Bookmarks` (`R`): open `dump.cs` bookmark list.
- `Find definition` (`X`): jump to class/field/type definition.
- `Field view` (`X + ZR`): open Field View for the selected class/field context.
- `Goto Namespace` (`L`): jump to namespace block.
- `Goto RVA` (`Y`): jump to function/class area by RVA.
- `Page Up/Down` and `Line Up/Down`: fast/precise navigation in `dump.cs`.

### Field View

- `Pin selected offset` (`X`): pin the selected field using the active source address/bookmark.
- `Pin gen2 offset` (`ZR`): pin using gen2 offset flow when applicable.
- `Memory Explorer` (`R`): jump to live memory at current field context.
- `Dump.cs` (`L`): jump back to `dump.cs` context.
- `View class` (`R + ZL`): open field-type class details.
- `Class Link` (`Y`): find classes/fields that link to the current class.
- `Descendent` (`Y + ZL`): find direct child classes.
- `Methods` (`L + ZR`): list this class's methods from live memory — names,
  addresses, static/virtual flags and signatures. Works without `dump.cs`.
- `Extract` (`Minus + ZL`): pick which fields of the pointed-to class are shown
  inline on every row of that type. See *Extract (inline field display)* below.
- `Jump Back` (`StickL + ZR`): open jump-back style source navigation.
- `Make cheat` (`+ + ZR`): generate cheat from valid linked field context.
- `Save field view` (`StickR + ZR`): save current field view state for reload.

### Extract (inline field display)

A row holding an object pointer shows only an address, so a list of `Item*`
reads as a list of addresses — nothing on screen says which item is which.
`Extract` lets you pick the fields that identify such an object once, and Breeze
then shows those values on every row of that type.

1. Put the cursor on a row whose type is a class pointer, for example
   `[3] : Idle.Datas.Item*`, and press `Extract` (`Minus + ZL`). Breeze follows
   the pointer and opens that object's Field View as a **pick session**: the
   panel title gains `[Extract pick]` and every row gains a marker column.
2. Press `Extract` on each field you want shown. `*` marks a chosen field.
   Pressing `Extract` again on a marked field removes it.
3. Press `Back`. There is no save step — the picks are written to disk on every
   toggle, so a session cannot be lost by leaving the wrong way.

Rows of that type then read:

```
+0x0038 [3] : Idle.Datas.Item* (u64) @0xFF31E1B18 = A+10B14E600 "灵气" 18914
```

To change the display later, press `Extract` on such a row again: the pick
session reopens with the current set already marked.

Notes:

- Picks are keyed on the row's **declared** type with any `*` removed, so
  `Idle.Datas.Item*` and `Idle.Datas.Item` share one setting. A field typed as a
  base class is keyed on that base class, not on the object's runtime class.
- Strings show as `"text"`; every other type is formatted exactly as it would be
  on its own field row.
- `Extract` on a string row is refused — the row already shows its own text.
- The extracted values also land in `field_view.log` when you use
  `Write to file`.
- Per-row limits: 24 characters per extracted string, 72 bytes for the whole
  suffix. The suffix shares the row with the field name, type and address.
- The setting is per title and survives a relaunch. With no picks recorded,
  Extract costs nothing — no extra memory reads are made.

`field_extract.txt` in the title's Breeze directory holds the picks and is
hand-editable:

```
# Breeze field extract - inline display picked with the Extract button
# type|offset|field name|field type
Idle.Datas.Item|0x38|<itemName>k__BackingField|System.String*
Idle.Datas.Item|0x20|amount|long
```

Line order is display order: picks append rather than sort by offset, so the
values read in the order you chose them. Delete the file to clear every type at
once.

## Instance Search guide

### How to use Instance Search

1. Open `Field view` for your target class.
2. Press `Search instance` (`X + ZL`) to start candidate discovery.
3. Wait for scan stages to complete (`c-string`, pointer stage 1/2, finalize).
4. Open a candidate with `Open` (`R`) and verify values against in-game behavior.

### How to do screening

Screening reduces false candidates by applying a field-based filter:

- Class-type screen: pick a field expected to point to a known class type.
- Pointer-valid screen: require a non-null, readable pointer field.
- Range screen: require integer/float values to be inside expected bounds.

Tips:
- Start with strict screen rules if you get too many candidates.
- Use `No screen` (`L`) if your screen is too strict and returns nothing.
- You can use `Back` to change screening options without repeating the full search.
- Search results are discarded when the Field View that initiated the search is exited.

### What second c-string is

- Instance search first matches the runtime type-name c-string.
- The optional second c-string is usually the first method-name hint for that class.
- Enabling second c-string narrows candidates to stronger matches and improves precision.

### If c-string nodes are zero

Possible reasons:

1. The class is not active/instantiated in the current game state.
2. The class name/method string is not present in current memory region.
3. The second c-string filter is too strict for this target.

What to try:

1. Move to a game state where that class should be active, then retry.
2. Retry with second c-string disabled (`Retry no 2nd cstr`).
3. Retry with `No screen` if screening was enabled and may be over-filtering.

### Related Main / Memory Explorer Buttons

- Main Menu: `Load field view`
- Purpose: open saved Field View entries and resume previous class-analysis sessions.
- Main Menu: `IL2CPP` / `Launch dumptool`
- Purpose: run on-device IL2CPP prep and extraction flow (creates files under `sdmc:/switch/breeze/cheats/<TITLE_ID>/`).
- Main Menu: `Launch dumptool`
- Purpose: launch `nxdumptool` to extract `main` and `global-metadata.dat` into `sdmc:/switch/breeze/cheats/<TITLE_ID>/`.
- Memory Explorer: `Load field view` (`StickLUp + ZR`)
- Purpose: use current cursor context as source input for Field View pinning workflow.
- Memory Explorer: `Class view` / `Class field` (`Y + ZR + ZL`)
- Purpose: resolve class from cursor base (with aligned fallback scan down to `-0x2000`) and open pinned Field View directly.
- Memory Explorer: `SetBreakPoint` (`Up + ZL`)
- Purpose: set watch/breakpoint on validated address to capture code that accesses it.

## Memory Explorer to Field Pin Workflow

1. In Memory Explorer, move cursor to the address you want to use as the live source instance.
2. Press `Load field view` (`StickLUp + ZR`) to use current memory context as the source and enter Field View flow.
3. In Field View, highlight the target field and press `Pin selected offset` (`X`).
4. Breeze computes pinned base from source and field offset, then shows live values for that class instance.
5. Optional: use `Save field view` for later restore or `Make cheat` when target resolves from a valid `main` region.

### Illustrated pin example (memory -> class instance)

Example goal: attach a live `Player` object base to Field View so you can inspect real instance fields.

1. In-game, identify a value tied to player state (for example HP), and locate its live memory address in Memory Explorer.
2. Keep cursor on that address and press `Load field view` (`StickLUp + ZR`).
3. Choose/open the matching class Field View (for example `Player`).
4. In Field View, highlight the field you want as anchor (for example `health` or a stable pointer field).
5. Press `Pin selected offset` (`X`).
6. Breeze resolves: `instance_base = source_address - field_offset`, then rebinds the view to that instance base.
7. Confirm by checking nearby fields update consistently with gameplay (HP, state flags, nested pointers).

Quick check that pin worked:
- multiple related fields now look coherent (not random)
- values change in expected direction while playing
- reopening the same saved field view restores the same live object context

Offset tip from ASM:
- The field offset can often be read from the ASM instruction that accesses the value.
- Example pattern: `[Xn, #0x1F0]` means the accessed field is at offset `0x1F0` from the object base in `Xn`.
- If you know the accessed address and offset, compute base as: `base = accessed_address - offset`.
- This is a fast way to pick the correct field anchor before pressing `Pin selected offset`.

### Pin gen2 offset (why and when)

- `Pin gen2 offset` is an added convenience feature for the user.
- User flow is: select a captured watch-result line -> jump to Memory Explorer for that captured address -> press Memory Explorer `Load field view` (`StickLUp + ZR`) to open Field View from that context.
- It lets the user quickly view memory with class context to judge whether the target is the real instance.
- When you watch an instruction to see what it accesses, you often collect multiple touched addresses from a group of live instances.
- Watch results are not always exclusive to one class instance; the same instruction can touch different objects or unrelated contexts.
- In many Unity/IL2CPP access patterns, an instruction with an immediate offset is reading/writing a class field.
- Typical shape is `base_register + offset` (for example `[Xn, #0x1F0]`), where:
- `Xn` is the object base (instance pointer)
- `0x1F0` is the field offset inside that class layout
- In that case, the useful part is usually the instruction offset itself (the `gen2 offset`), not just one single captured address.
- `Pin gen2 offset` (`ZR`) uses that instruction-derived offset to attach Field View quickly, without requiring manual offset lookup/re-entry each time.
- This is especially helpful when inspecting many instances in the same structure because one offset pattern can be reused across that whole group.

### Gen2 `Class field` button

- In `Gen2 Menu`, `Class field` (`Y + ZR`) is a direct bridge from selected Gen2 entry to class Field View.
- This flow expects register-watch style entry data (base-like rows), not instruction-watch (`read/write`) rows.
- Breeze uses the selected Gen2 base and resolves class name with aligned fallback scanning:
- start at aligned `base`, then scan smaller addresses down to `base - 0x2000`
- check `class_info = [candidate_base]`
- check `class_name = [[candidate_base] + 0x10]` (c-string)
- If `dump.cs` index has that class, Breeze opens its Field View and pins using current `gen2 offset`.
- Pin relation used is:
- `pin_source = base + gen2_offset`
- `instance_base = pin_source - gen2_offset` (same selected base)
- On success, Field View cursor is moved to the row matching `gen2 offset` when that offset exists in the class layout.

## Practical examples

### Example A: `View class` usage

Goal: you are on a `Player` field that points to `WeaponData`, and you want to inspect weapon internals quickly.

1. In `dump.cs View`, find `Player` and open `Field view` (`X + ZR`).
2. Highlight the field with class type (for example `currentWeapon : WeaponData`).
3. Press `View class` (`R + ZL`) to open the linked class definition/details.
4. Review important fields in the linked class (damage, spread, cooldown references, nested pointers).
5. If useful, use `Class Link` (`Y`) from that view to find parent/up references and expand to related classes.

Result: `View class` lets you pivot from one class to connected classes without leaving the analysis flow.

### Example B: button-driven live instance workflow

Goal: find a live player-health instance, verify it, then keep it for reuse.

1. In Memory Explorer, locate a candidate health address that changes in-game.
2. Press `SetBreakPoint` (`Up + ZL`) to capture code touching that address.
3. Open ASM Explorer and use `Detail` (`X + ZR`) on a promising function to jump into related `dump.cs` context.
4. In `dump.cs View`, open `Field view` (`X + ZR`) for the relevant class.
5. Back in Field View, press `Pin selected offset` (`X`) on the health field to resolve a live instance path.
6. Confirm behavior while in-game value changes; if stable, press `Save field view` (`StickR + ZR`).
7. Optional: press `Make cheat` (`+ + ZR`) when the linked result is valid for cheat generation.

Result: this button sequence converts a visible gameplay value into a class-instance view.

Alternative faster path (new button):

1. In Memory Explorer, locate a candidate health address that changes in-game.
2. Press `SetBreakPoint` (`Up + ZL`) to capture code touching that address.
3. In `Gen2 Menu`, press `Class field` (`Y + ZR`) on captured data row to jump directly to Field View live instance pinned to that selected address.
4. Confirm value behavior in-game and save with `Save field view` (`StickR + ZR`).

## Make cheat notes (pointer-chain driven)

- `Make cheat` generates cheats from a resolved pointer chain, not just a one-time absolute address.
- This is useful when a class has many interesting fields, because once the base chain is valid you can generate many cheats quickly from the same instance view.
- In practice, this is the fastest way to produce a large set of related cheats (HP, ammo, cooldowns, flags, etc.) from one workflow.

### Base pointer requirement

`Make cheat` needs a stable starting base pointer for the chain. You can get that base in two common ways:

1. Search-driven base:
- Find a stable base pointer through normal search and pointer validation.

2. ASM-hook-driven base:
- Capture/set the starting chain address from a reliable ASM hook context, then store that start in `main` area.
Reference guide: [base pointer illustration.md](./base%20pointer%20illustration.md)

### Important dependency for ASM-hook base

- If your generated pointer cheats depend on a pointer-setup cheat (the cheat that initializes/writes the chain start), that setup cheat must stay enabled.
- If the setup cheat is disabled, downstream generated pointer cheats may fail because the chain root is no longer initialized.
- If the ASM-hook-derived base changes, disable the old setup path and update/regenerate it before using dependent pointer cheats.

### Safety pattern to avoid stale-pointer corruption

- Add a final cleanup cheat that blanks/resets the stored pointer in `main` area.
- Purpose: if the ASM hook does not run, dependent cheats should not execute against an old reused address.
- This helps prevent corruption when memory gets reused and a stale chain root would otherwise still look valid.

## Start from Scratch Workflow

1. Search for a target memory value/address with Breeze search workflow until you have stable candidate addresses.
2. Validate the candidate address in Memory Explorer by checking that it changes with in-game behavior as expected.
3. From Memory Explorer, use `SetBreakPoint` (`Up + ZL`) on the validated address to capture code access.
4. Review the captured result and move into ASM Explorer for code analysis.
5. Review captured access points, then use `Function Up` and `Function Down` to move to nearby method boundaries and find promising functions.
6. For a promising function, press `Detail` (`X + ZR`) to open its `dump.cs` context.
7. In `dump.cs` view, navigate to the relevant class/field and open `Field view` (`X + ZR`).
8. Save the field view (`Save field view`, `StickR + ZR`) so it can be reused in the next phase.
9. Continue with the Memory Explorer to Field Pin Workflow to pin live instance addresses and finalize cheat/validation work.
