# Changelog

## [Beta 128.02] - 2026-10-25

- **Needs the v0.21 gen2 fork:** Settings > Install gen2 fork, then reboot. The HOME daemon and sys-ftp are the same as 128.01.
- **Launch for gen2** (Games, **ZR+Y**): starts a game with gen2 on it, held before its first instruction. Press HOME and Breeze opens Break and Trace there: set breaks, step or Continue, and catch code that only runs while the game starts up. PC connect `gamestart <title id> held`. See [Break on a game's start-up](docs/break%20on%20game%20start.md).
- **Launch** on Games has a key of its own: **ZR+X**.
- Breeze started while the game is stopped at a break now loads the game (main, cheat list); before, it showed main as 0.
- Break and Trace shows real addresses for code below the game's main module instead of `M+0xffffffff...`.
- gen2 fork v0.21: GDB `monitor wait application` is fixed (it failed while the cheat engine ran); not yet tried on a console.

## [Beta 128.01] - 2026-10-24

- Same gen2 fork (v0.20) and HOME daemon (SwitchU 1.2.0o) as 128.00; only Breeze.nro changed.
- **Overlay at start:** with the Home toggle on Overlay, the controller now reaches Breeze as soon as it starts over a game. In 128.00 the buttons did nothing in Breeze until HOME was pressed twice.
- **Faster start in Unreal games:** about a second less on every start and restart (FINAL FANTASY RESONANCE: 2.0 s to 0.8 s).

## [Beta 128.00] - 2026-10-24

- Same gen2 fork as 124.07 (v0.20). The package's HOME daemon is SwitchU **1.2.0o**: install it from Settings for the overlay change.
- **Cheats follow a game update:** for a game with cheats, Breeze saves each game version's code in the game folder (`codedump/`, in the background). When the game is updated and the new version has no cheats, Breeze moves the old version's cheats to it by itself and the Cheats screen loads them; `cheat_update.txt` says what moved and what did not. Well Dweller's update: 28 of 28 moved. PC connect `cheatupdate` does it on demand.
- **Overlay from the start:** with the Home toggle on Overlay, Breeze started over a game opens as the overlay, not full screen (needs the 1.2.0o daemon). See [HOME toggle and overlay](docs/home%20toggle%20and%20overlay.md).
- **Toggle overlay pause** (ZR+Y on Focused Actions, L+ZR): pauses or runs the game under the overlay at once and keeps the choice for the next HOME.
- **sys-ftp:** new FTP commands `HOME` (starts Breeze after a game restart), `MEM` (memory pools and the largest programs) and `KEY` (presses buttons, e.g. `KEY A` for the user picker). PC connect `ftp <command>`, and the PC app's **System...** window, which works without Breeze. See [PC connect](docs/pcconnect.md).

## [Beta 127.02] - 2026-10-23

- Same gen2 fork as 124.07 (v0.20).
- **Cheat source file and the list stay in step:** renaming a cheat in Edit Cheat renames it in the `.ini`; folders you arrange in the list become the units in the `.ini` (`unit = none` for a cheat kept loose); a hand-edited `.ini` wins over the list. See [Cheat source](docs/cheat%20source.md).
- **Build follows a changed `hook =`:** the old site gets the game's code back and the cheat keeps its place in the list.
- The `[code cave]` folder no longer keeps the pieces of removed cheats.
- **PC connect:** when the virtual pad gets no player slot, the reply says why, and `gamepad borrow` (automatic from the PC app) sends its input through the real controller; `pcconnect.log` records the pad. See [PC connect](docs/pcconnect.md).
- FINAL FANTASY RESONANCE cheats in MyNXCheats (WIP): encounter rate, move speed, teleport to the map cursor, moon jump.

## [Beta 127.01] - 2026-10-23

- Same gen2 fork as 124.07 (v0.20).
- **Get Latest Cheat from TomVita:** when a game has no released cheats, Breeze loads the ones committed to MyNXCheats so far and says "WIP loaded": work in progress, maybe unfinished or untested.
- **Cheat source fixes:** a unit rename no longer nests folders; Build moves a cave that grew too big; two mods of one name are reported instead of mixed up; `Gil earned` values stay on next to a `Gil` mod; Shelf Discard also removes the cheat's mods and the names only it used; Import adds to the existing build section. See [Cheat source](docs/cheat%20source.md).
- **ASM Check** accepts `mrs` / `msr nzcv`.
- **Breezehand 0.10.4** reads these cheat files (code caves, mods) and finds the game folder as Breeze does.

## [Beta 127.00] - 2026-10-22

- Same gen2 fork as 124.07 (v0.20).
- **Cheat source file:** one `<TitleID>.ini` per game holds the source of its ASM and pointer cheats; addresses that change with a game update are names in a section per game version. Cheats menu: Import scripts to source, Install from source (ZL+ZR+Y), Shelf. See [Cheat source](docs/cheat%20source.md).
- **Split ASM cheats:** a cheat from the file is a guarded hook in the list; its cave code sits in a `[code cave]` folder that Breeze writes itself, with an `(off)` cheat for other cheat managers.
- **Cheat composer** (was the ASM Composer) edits a cheat of the file in place: Name address (ZR+X), Build (ZR+B), Make mod (ZR+Down), Key (ZR+Right). Build checks that a grown cave has room and finds it a new place if not.
- **Mods:** a value in a cheat becomes a list of cheats, one on at a time (`Move speed = 2.0`), with labels (`Set clock 6:00 AM`). Edit Cheat on a value changes the list; clearing it removes the mod.
- **Shelf:** a cheat of the file deleted from the list is kept; Restore puts it back where it was.
- **PC app: Cheat source** editor for the same file (Check, Listing, Build, Name address, Make mod, Shelf). New app file: `pcconnect_source.py`.
- **Diagnostics** (Main, ZR+R): the facts for a problem report; Write to file saves `/switch/Breeze/diagnostics.txt`.

## [Beta 126.00] - 2026-10-20

- Same gen2 fork as 124.07 (v0.20). Install the SwitchU daemon **1.2.0n** for the Nintendo applets below.
- **Games** (Main, `ZR + X`): your installed games with icons, last played first, so Breeze can be the HOME screen on its own (SwitchU's Breeze first). A launches a game, or goes back to the running one; launching another while one runs asks before closing it. X closes the running game after a warning. Minus shows details, ZL + Y searches, R switches grid / list, L toggles airplane mode (Wi-Fi), Plus opens Nintendo's applets (Controllers, Change Button Mapping, Album, Mii Maker, Internet connection, Add user).
- With Jump to Last Menu on and no game running, Breeze opens on Games.
- **Fixed:** a game started from homebrew showed an old picture of another game while it loaded.
- **Fixed:** a PC that went to sleep while connected over PC connect could hang the Switch later.
- **Fixed:** Breeze could crash at start while the PC app was showing its screen.
- **PC app:** the screen is about twice as fast (`capture ahead`): up to 18 fps on Breeze's menus, 9 with a game in front. The fps box goes to 30.
- **Field view:** Make cheat on an Extract row makes the cheat for the extracted value; a cheat made from another screen shows on the Cheats screen at once, also with folders.

## [Beta 125.06] - 2026-10-18

- Same gen2 fork as 124.07 (v0.20).
- **Make cheat** (Cheats menu, `R + ZL`): makes cheats from a recipe and a table that a cheat maker puts in the game's folder (`make_cheat.ini` and a `.tsv`). Search, filter, mark rows, and make one cheat or one per marked row. A helper cheat the recipe needs is installed from its script if missing. First recipe: give any item in Harvest Moon The Winds of Anthos. See [Make Cheat Recipes](docs/make%20cheat%20recipes.md).
- **Fixed: Assemble all ASM** could crash the game (every rebuilt cave got the previous cheat's original instruction), and each run pushed the caves further up. It is now safe to run again and again.
- **Fewer split ASM cheats:** caves up to about 125 instructions stay one cheat.
- **Assemble all ASM moves caves that have no script**, when the move is safe: it lists them, and moves them if you press it again within a minute. **Relocate Code Cave is removed**; its key `R + ZL` is now Make cheat.
- **Unity field view:** a game's own structs inside an object (a date, a time) open into their fields, once the field map is built. Const fields are no longer shown.

## [Beta 125.05] - 2026-10-16

- gen2 fork v0.20 rebuilt on Atmosphere 1.12.1; reinstalling it is optional.
- **Games with code in a module** (Tales of Eternia Remastered): ASM Explorer names the module's functions and Function Up / Down steps through them; Code watch lists and watches the module's functions; watch rows name callers in the module. Game information's engine analysis reports each module on its own.
- Breeze.nro is about 700 KB smaller, with searches as fast as before.

## [Beta 125.04] - 2026-10-15

- Same gen2 fork as 124.07 (v0.20).
- **Games with code in a module** (Tales of Eternia Remastered): the automatic master code takes R1 from the system loader's records, so it works every time; the cheat makers that use R1 and code caves were fixed for such games.
- **Fixed:** cheat lines like `580F3100` (type 2 and 3 with a second register) were decoded with the wrong register in the cheat text, the trace and Jump to target.

## [Beta 125.03] - 2026-10-15

- Same gen2 fork as 124.07 (v0.20).
- **PC app: Decompile** (F6 in the disassembler) shows the function as C beside the listing, made by Ghidra's decompiler on the PC. The first time it offers to download and set up Ghidra and Java (Windows, about 740 MB). The C follows the listing; a double-click on a call opens it. New app file: `pcconnect_decomp.py`. See the [PC App Guide](docs/pc%20connect%20app.md#decompile).
- **PC app disassembler on Unreal games:** function names (there were none), and every call target opens as its own function.
- **Unreal:** C++ virtual functions are named from class vtables as `Class::vf_<slot>` in code watch, method watch and the disassembler. Method watch reads Unreal names.
- **PC app:** Connect... changes the address and code without a restart; starting the app again brings the open window forward (tick Multiple instances for more).
- **PC app disassembler** (added after publishing, in the re-uploaded `pc_app.zip`): the mouse's back and forward buttons go Back and Forward.

## [Beta 125.02] - 2026-10-14

- Same gen2 fork as 124.07 (v0.20).
- **Unreal object view: the pointer chain by name.** The bottom line shows how Breeze reached the object, by property name: `GWorld > OwningGameInstance > LocalPlayers[0] > PlayerController > Pawn > HPComponent`. It comes from the object browser, a bookmark, or Open on a pointer row.
- **Unreal: Find chain** (ZR+Down in the object view) searches back from the object to a static slot in main or to the GWorld route, and lists that route first. Use chain hands it to Make cheat; Bookmark saves it. A few seconds a search on ENDER LILIES.
- **Breezehand watch overlay 0.10.3c** in the package: works with the v0.20 fork again (it said "version mismatch"), names a Breeze field, method or code watch with its total instead of misreading it, and turns L3+Y off for those.

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
