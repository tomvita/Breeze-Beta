# Changelog

## [Beta 125.01] - 2026-10-14

- Same gen2 fork as 124.07 (v0.20).
- **Fixed:** a list could be drawn empty, or with its cursor off the screen or past the end (a title like "71/18"), after a screen changed its rows: opening a class and going back, a filter, a search, another saved result. Fixed for every list screen.
- **Fixed:** Code watch said "No function matches" on Unreal games. It now reads the Unreal function map: classes like `/Script/Zenith.HPComponent`, Search by name, and one row for the Blueprint script interpreter. Only functions Unreal knows by name are watched.
- **Fixed:** Jump to target and Trace cheat (Edit Cheats) opened Memory Explorer without the pointer chain when the cheat's last line was a type 0 write such as `044F0000 00000110 000000C8`.
- **Code watch:** Back from a class's functions returns to that class.
- **PC app debugger:** in the Float view, a double-click changes one value of a vector register. Take the new `pcconnect_asm.py`.
- **PC connect:** `dbg reg v<n> <low> <high>` writes all 128 bits.

## [Beta 125.00] - 2026-10-13

- Same gen2 fork as 124.07 (v0.20).
- **Fixed:** an ordinary watch started from the gen2 menu after a code watch started another code watch instead, and after a change of game this could freeze the game (beta124.05 to 124.08). If a game froze this way, restart it once.
- **Code watch on any game.** A game with no function map (native C or C++) is watched from its unwind table: functions are `func_<offset>`, grouped by the block of code they sit in.
- **PC app: Text view.** Breeze's screen as text: 400 rows at once, every action as a button, the screens you came through side by side, Find, Filter, Copy and Save. See the [PC App Guide](docs/pc%20connect%20app.md).
- **PC app: Disassembler** (needs `pip install capstone`): a whole function at a time with calls, branches and data addresses worked out, the function list, Callers, and the last code watch's result.
- **PC app: Debugger**, in the disassembler window, on Break and Trace's breakpoints: Break, Run to, Step, Over, Continue; registers (general and float), stack, and memory in seven formats.
- **PC connect:** `action`, `rows` with a stack depth, more in `state`, quicker change events, `dbg`.

## [Beta 124.08] - 2026-10-13

- Same gen2 fork as 124.07 (v0.20).
- **GameMaker: from a memory search to a cheat.** In Memory Explorer, **Class field** (ZL+ZR+Y) on a value opens the object that owns it, with the cursor on that variable; Make cheat works from there. A global opens at once, an object's variable after a sweep of the heap (about 5 s on Well Dweller). See the [GameMaker walkthrough](docs/gamemaker%20walkthrough.md).
- **Code watch: Search** (ZL+R): watched functions by name, words separated by spaces, all must match. See the [Code watch walkthrough](docs/code%20watch%20walkthrough.md).
- **Fixed:** Mark in a code watch did nothing with the Home toggle on Fast restart.
- **Fixed:** a field view could show a pointer chain left over from another object.
- **Fixed:** the GameMaker button on Main is lit only on a GameMaker game.
- **PC connect:** `codewatch search`, `gmvars objects`, `gmvars owner`, `gmvars open`, `gmvars last`.

## [Beta 124.07] - 2026-10-12

- **Needs the new gen2 fork (v0.20):** Settings > Install gen2 fork, then reboot.
- **Fixed:** a method watch or code watch running when the console went to sleep left its breaks in the game's code, and the game crashed when one of those functions was next called (beta124.04 to 124.06). The watch now cleans up when it is cut off, and Breeze keeps what it changed and repairs it whenever a watch starts or stops. If the console slept during a watch on an earlier version, restart the game once.
- **GameMaker: Make cheat** on the variables screen. A global gets a pointer cheat through the Make cheat screen; an object's variable gets a hook on the object's Step event (`gmobj_<object>`, Add ASM once) that holds the value on every instance.
- The variables screen shows each variable's offset and id; **Class field** in the gen2 menu opens a captured GameMaker object's variables.
- **PC connect:** `gen2 repair`, `gen2 watch <address> x<n>`.

## [Beta 124.06] - 2026-10-12

- For **GameMaker** games exported with the YoYo Compiler (YYC). Same gen2 fork as 124.05.
- **Main > GameMaker:** the game's global variables by name with live values; Edit value, Filter, Sort, Open on a struct.
- **Code watch** works on GameMaker with no preparation and lists by game object.
- **Watch methods**, then **Field view of object**, opens an instance's own variables by name (walking speed, jump height and the like).
- GML function names show in ASM Explorer on GameMaker games without a map made on a PC.
- **PC connect:** `gmvars`, `prep gm_functions`.

## [Beta 124.05] - 2026-10-12

- **Needs the new gen2 fork (v0.19):** Settings > Install gen2 fork, then reboot.
- **Code watch** (gen2 menu): a one-shot break on every function in the game's function map. The game stutters for a few seconds while the code that runs all the time is found, then plays at full speed. **Mark**, do one thing in the game, and the classes with a function called for the first time are listed, the most first.
- **Select** on a class lists its functions with their first callers; **Watch methods** hands the class to the method watch, which gives the live objects.
- Stop writes `code_watch.txt` in the game's folder: every called function in order.
- **PC connect:** `codewatch`.

## [Beta 124.04] - 2026-10-11

- **Needs the new gen2 fork (v0.18):** Settings > Install gen2 fork, then reboot.
- **Watch methods:** which methods of a class are ever called, by whom and on which object. Each live method stops the game once; **Field view of object** opens the object a method was called on.
- **Break on one object:** Break and Trace can stop only when a method runs for one instance (**Break on pinned object** in a class's Methods list).
- Field and method watches are kept when stopped; **Pre results** / **Next results** step through them, and the gen2 menu has **Field watch** and **Method watch** buttons. **Expand screen** on both.
- Fixed: **Sweep unseen** with nothing found yet stopped the running field watch.
- **PC connect:** `prep`, `files`, `gen2`, `fieldwatch`, `methodwatch`, `instances`, `probe`, `xref`, `cheats state`; `breeze_unity.py` works on a Unity game by class and field name.

## [Beta 124.03] - 2026-10-11

- **Needs the new gen2 fork (v0.17).**
- **Watch fields:** from a field view, gen2 watches a whole object and lists the fields the game reads or writes as it happens. **Sweep unseen** goes on checking the rest at full game speed.
- The box over the game lists the fields as they are found.

## [Beta 124.02] - 2026-10-10

- **Make cheat** (Memory Explorer, ZL + Down): a cheat from the pointer chain for one value, or a loop over an array (every enemy); write always, only where above or below a value, or copy another field.
- Fixed: a secondary search on candidates saved from the Unity menu crashed Breeze.

## [Beta 124.01] - 2026-10-09

- **Game input:** PC connect drives a virtual controller on the Switch.
- **PC app:** play the game with the PC keyboard or an Xbox-style controller; HOME, Screenshot, Album and Record.

## [Beta 124.00] - 2026-10-08

- **Game files:** Breeze reads the running game's own files (RomFS) through the system, with no keys and no dump tool. A game is allowed once and Breeze reopened with HOME twice.
- **Unity without dump.cs:** Class Link, Descendent, Dump.cs and Load field view answer from Breeze's IL2CPP maps. **Il2Cpp** and **Launch dumptool** are removed from Main.
- **Save snapshots:** copy a game's save with a picture, and restore one, through Atmosphere's save redirect to the SD card.
- **PC app:** Stop game, Start game, save controls and a two-panel file manager. PC connect serves three clients.

## [Beta 123.11] - 2026-10-07

- **Dynamic view:** the action panel shows the buttons of the shift keys you hold (none, ZL, ZR, ZL + ZR). New built-in **Dynamic** layout.
- Built-in layouts are shown in green and cannot be overwritten.
- Many shortcuts added or moved so that every one can work.
- Engine scan recognises Pixel Game Maker MV and Luau.

## [Beta 123.10] - 2026-10-06

- Title-name game folders work for games with Japanese names; bundled sys-ftp updated to match.
- The overlay responds while the game is in front.
- **Cheat folders:** rename, cut and paste a folder on the Cheats screen.
- **ASM cheats:** the cave is written before the branch, and Toggle Cheat has three stages (on, off with the hook left in, off with the original instruction back).
- **Main:** Exit is renamed **hbmenu** and moves from B to ZR + B.
- Long lists page one screenful (11 rows) at a time; field views refresh on their own.

## [Beta 123.09] - 2026-10-03

- Fixed IL2CPP field maps and field views that lost most of a class's fields.
- Unity: a component's field view lists the other components on its GameObject; row filter for long field views.

## [Beta 123.08] - 2026-10-02

- **Jump to target** runs the whole cheat as a dry run. New **Trace cheat** lists every hop, read, compare and write.
- Godot games: Find chain walks the object graph from the root.
- Unity Find chain: GameObject steps, lasting chains, and a reason when nothing is found.
- PC connect: cheat commands, pointer tools, two clients. New **Breeze PC** app.

## [Beta 123.07] - 2026-10-01

- Unity: Instances include subclasses; Search maps takes several words.
- Overlay mode shows in screenshots.

## [Beta 123.06] - 2026-10-01

- Unreal Engine 5 games without a version banner are recognised; UWorld Explorer reads the chain instead of guessing it.
- Browse UE Objects lists every object. New **Attributes (GAS)** view.

## [Beta 123.05] - 2026-09-30

- Fixed three bugs in the Unity dictionary view: Make cheat on `_count`, Extract through a dictionary, and value types in a fresh session.

## [Beta 123.04] - 2026-09-30

- **In-app keyboard:** copy, cut, paste and undo with ZL as a modifier; STR and WSTR formats.
- **Copy stack** shared by the keyboard and the Memory Explorer, kept across restarts. New **Copy address**; Address to A and Value to A removed.

## [Beta 123.03] - 2026-09-30

- **Game information** reports the engine and its version, the scripting language, middleware, renderer and SDK version.
- The engine scan and the code cave floor are measured once per game when Breeze attaches.

## [Beta 123.02] - 2026-09-29

- **Add ASM** can place a code cave below main (nnrtld). Jump to target, Jump to ASM and the disassembly understand these caves.

## [Beta 123.01] - 2026-09-28

- Find chain reaches values in a dictionary, behind a generic singleton and through an interface field.
- Match by Extract, and **Make cheat (scan)** for lists the game reorders.

## [Beta 123.00] - 2026-09-26

- **Unity menu:** usual suspects, map search, singletons and instances with a pointer chain to each.
- **IL2CPP field map:** every field of every class with its offset and type.
- Field view reads statics from the right block.

## [Beta 122.03] - 2026-09-24

- Download menu reworked: each check button turns into its install button; new **Install / Update Sphaira**.
- Fixed downloads that stopped working until a reboot, and Add Bookmark in the Memory Explorer's u8 view closing Breeze.

## [Beta 122.02] - 2026-09-23

- **PC connect:** a PC on the same network can see and drive Breeze and read the game's memory without stopping the game.
- **Built-in focus layouts:** Player, Beginner maker, Advanced maker and Engine tools, with a choice on first run.
- Fixed sys-ftp using up the Switch's clock objects.

## [Beta 122.01] - 2026-09-22

- **HOME daemon** button in Settings installs and manages the daemon without the SwitchU menu. New **Breeze first** setting.
- Fixed a crash when opening the Break and Trace view.

## [Beta 122.00] - 2026-09-22

- Break and Trace **Registers** screen reworked: separate X and V pages, new formats, every part of a V register editable.
- **Restart Breeze** in the Focus Menu, which now tracks the layout file in effect.

## [Beta 121.02] - 2026-09-21

- Disassembler and Break and Trace unified into one **ASM Explorer**.
- Normal mode keeps the programmed button order; Simple Menu and Full Menu buttons removed from Main.
- Settings: Reset general settings, Backup and Restore custom shortcuts; one-step **Reinstall gen2 fork**.

## [Beta 121.01] - 2026-09-19

- Tesla / Ultrahand overlays work alongside Overlay mode.

## [Beta 121.00] - 2026-09-17

- **Overlay mode:** Breeze is shown on top of the running game, with HOME to show and hide it.
- Fixed a crash at the end of installing an update.

## [Beta 120.00] - 2026-09-15

- **Rebase** carries cheats to a new version of the same Unity game.

## [Beta 119.01] - 2026-09-15

- Install SwitchU fork always installs the newest release.

## [Beta 119.00] - 2026-09-15

- **HOME toggle:** HOME switches between Breeze and the game, with tomvita's SwitchU fork as the HOME menu.
- Downloads and installs wait on a progress screen.

## [Beta 118.07] - 2026-09-14

- Class field opens the object the cursor is inside; Function Up stops at every function; loadable modules supported.

## [Beta 118.06] - 2026-09-13

- Field annotations reach the native C++ field view; a struct RTTI cannot see can be declared.

## [Beta 118.05] - 2026-09-11

- Static fields are recognised by their type; Class field works inside a static block.

## [Beta 118.04] - 2026-09-08

- The Lua detector finds the Lua state where it lives, on a progress screen; large tables open.

## [Beta 118.03] - 2026-09-06

- Gen2 attach and detach no longer reset the cheat VM. New **Reset CheatVM** button.
- A failed attach no longer freezes the game.

## [Beta 118.02] - 2026-09-04

- Lua paths are resolved in native code, shared by every Lua cheat.

## [Beta 118.01] - 2026-09-03

- Lua: self-resolving cheats accept keys that are not array indexes and values that are not always there.

## [Beta 118.00] - 2026-09-03

- **Lua tool** for games that keep their data in a Lua state: browse by name, bookmarks that are paths, cheats that survive a game restart.

## [Beta 117.02] - 2026-08-31

- Trimming the node map is a scan with progress; label lookups are much faster; the label list is paged.

## [Beta 117.01] - 2026-08-27

- Fixed the Gen2 method label naming the caller instead of the row.

## [Beta 117.00] - 2026-08-27

- **Add field label** and **Class field** on the Candidate, Bookmark and Jump Back lists.
- Gen2: **Add method label** and **View caller**. Jump Back: node list pages and **Trim** by label.

## [Beta 116.02] - 2026-08-26

- Fixed Assemble all ASM packing caves above an off cheat and losing cheats with no script.

## [Beta 116.01] - 2026-08-26

- **Unreal Engine 4.16 - 4.22** support.

## [Beta 116.00] - 2026-08-25

- **GameMaker** cheats from a shared hook (**Make GM cheat**).
- Code caves are allocated from the cheats themselves; new **Code Cave Map**; Assemble all ASM rebuilds and packs every cheat together.

## [Beta 115.00] - 2026-08-23

- Pointer searches no longer store the paths they find, so deep searches do not run out of memory.
- Free memory is measured and a search stops before it fails; **Rewind to depth**; a saved map resumes the whole search.

## [Beta 114.02] - 2026-08-22

- Pointer chains keep their depth; Extract works on a class without `dump.cs` and over more than one hop.
- Jump Back: **Land on class**. Assembler save guard.

## [Beta 114.00] - 2026-08-20

- Field view reads a list of objects, shows strings, and walks arrays of objects with the right stride.
- Faster IL2CPP function map build; enum names without a dump.

## [Beta 113.00] - 2026-08-20

### Added

- Added native C++ function discovery from script binding tables, with a searchable Script functions list and `script_functions.txt` export/cache.
- Added native function boundaries from `.eh_frame_hdr` and recovered AAPCS64 parameter shapes for ASM Explorer and virtual method lists.
- Added native C++ class-field resolution through Itanium RTTI, including inheritance, virtual methods, inferred field types, and interior-pointer targets.
- Added persistent `class_field_hints.txt` and `ue_version.txt` caches to make later class-field visits faster.
- Added improved Unity array-of-struct and dictionary inspection, including resolved element layouts and generic key/value types.

### Changed

- Function Up/Down now chooses the nearest boundary across every available map and uses synthetic names only when no real name exists.
- Class field resolution tries the lightweight native RTTI path before an expensive Unreal scan for unknown engines.
- Unity static-field views can resolve and pin static blocks, navigate pointer rows, and create cheats from static fields.
- AOB file names are sanitized when cheat labels contain key-hint glyphs or filesystem-reserved characters.

### Fixed

- Fixed `key hint to file=0` leaving conditional-key glyphs in some saved cheat names.
- Fixed Make AOB and Make AOB M failing to create files for labels containing key hints or invalid filename characters.
- Fixed pointer-width field hints hiding the class or interior offset of the pointed-to object.

See [the beta113.00 release note](release%20note%20113.00.md) for workflows, generated files, implementation details, and limitations.

## [Beta 110.00] - 2026-08-18

### Added

- Added a graph-driven Unreal object browser with class filtering, paging, class summaries, deep scanning, and pointer-chain bookmarks.
- Added `ue_field_map.txt` with nested struct expansion and inherited-property ownership.
- Added validated object and class-summary caches for reuse while the same game process remains active.

### Changed

- Reworked Unreal field traversal around `UStruct::PropertyLink` for reliable own and inherited property discovery.
- Added runtime `FFieldVariant`, field-name, field-offset, `FNamePool`, and broader Unreal version detection.
- Simplified the Unreal entry menu so UWorld Explorer performs profile scanning and root resolution on demand.

### Fixed

- Fixed blank or inconsistent Unreal field names caused by per-node offset guessing and stale saved name-pool addresses.
- Fixed function frame locals and unrelated UObject slots being mistaken for object properties.
- Fixed object-browser navigation continuously resetting its selection and expand state.

See [the beta110.00 release note](release%20note%20110.00.md) for controls, generated files, and limitations.

## [Beta 109.01] - 2026-08-17

### Changed

- Runtime IL2CPP method browsing, type resolution, and function-map generation now run a lightweight Klass scan automatically when `Klass.dat` is missing or stale.
- Automatic discovery skips the slower Klass instance scan and reuses valid class data when available.
- Updated runtime status and error messages for automatic Klass discovery and outdated maps.

See [the beta109.01 release note](release%20note%20109.01.md) for workflow details.

## [Beta 109.00] - 2026-08-17

### Added

- Added live IL2CPP method browsing with names, addresses, flags, return types, and parameters, without requiring `dump.cs`.
- Added on-device `il2cpp_function_map.txt` generation for ASM Explorer function names and Function Up/Down navigation.
- Added navigation from parameter and return types to runtime class field and method views.

### Changed

- ASM Explorer Detail can open the owning runtime class and select the current method when using a runtime-generated function name.
- Improved Klass name-cache performance with bulk string reads.

### Fixed

- Fixed the Klass name cache becoming latched empty when accessed before a Klass search.
- Fixed automatic cheat download validation and database fallback when no URL cheat is available.
- Fixed opening Focused Actions from the Candidate menu causing a spurious file-open error.

See [the beta109.00 release note](release%20note%20109.00.md) for usage and compatibility details.

## Tutorial Help System

### Added

- Added context-sensitive topic tutorials and selected-button Action Help throughout Breeze.
- Added ZR then A as the ordered global help toggle, with underlying input blocked while help is open.
- Added persistent per-menu tutorial state and a separate Focused Actions tutorial context.
- Added dedicated Sysmodule help, including runtime On/Off semantics and `sys-ftp-breeze` configuration guidance.

### Changed

- Main Menu Help now opens the Main Menu tutorial.
- Moved Prerelease updates from the legacy Help screen to Settings.
- Renamed unclear Gen2, JumpBack, ASM Composer, and Cheat Editor actions; see [release note tutorial help.md](release%20note%20tutorial%20help.md).
- Excluded the Gen2 fork Title ID `010000000000D609` from Sysmodule Manager.

## [Beta 108.7c] - 2026-07-16

### Changed

- Renamed the simplified and complete action views to **Focused Actions** and **All Actions**.
- Reworked the Focused Actions manager so all management controls are always visible. **Switch action view** is now the top-left and initially selected control.
- Added four-column, full-screen customization with `A` toggle, `-` cut, `+` paste, and `B` finish controls.
- Added optional Training mode for learning actions as they are used without clearing or switching the current view.
- Made layout saving and focus clearing operate on only the menu currently being managed.
- Split top status information from bottom contextual help and removed the obsolete Help toggle.

### Fixed

- Menus now fall back to the lower-right page button when their configured initial action is absent from Focused Actions.
- Any normal action can be removed without causing menu initialization crashes.
- Reset All Shortcuts now restores the Focused Actions manager defaults as well as Search Manager defaults.
- The Focused Actions shortcut is ignored during customization, preventing a crash caused by re-entering the manager.

## [Beta 99s] - 2026-01-25
### Added
- **Radial Selection**: Hold `ZL` and use the stick to quickly select buttons in the right panel.
- **Dynamic Module Support**: Enhanced support for Unity/Unreal Engine games with automatic `R1` register setup for module offsets.
- **Pointer Search Improvements**: Integrated `JumpBackMatch` concepts for higher quality and faster pointer search results.
- **Assemble GUI Enhancements**:
  - Tandem scrolling for code and data views.
  - Visual error highlighting for assembly lines with errors.
  - Click on error log to scroll to the corresponding error line.
- **New Documentation**:
  - [Dynamic Modules Guide](docs/dynamic_module.md)
  - [Pointer Search Method Primer](docs/pointer search.md)
  - [x30 Match Examples](docs/x30 match example.md)
- **Updated Manual**: Comprehensive updates to `README.md` and `Breeze.md`.

### Fixed
- Various bug fixes and stability improvements in the ASM Composer.
- Improved master code generation for dynamic modules.

## [Beta 99m] - 2025-08-27
- Readme update to 99m level.
- Initial preparation for major documentation overhaul.
