# Changelog

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
