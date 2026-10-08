# Breeze beta124.00

Breeze can now read the running game's own files, and it can take snapshots of a game's save and put one back. The PC app gains a two-panel **file manager**, **save snapshot** controls, and **Stop game** / **Start game** buttons.

With that, Breeze no longer needs a `dump.cs`. The field view buttons that asked for one now answer from Breeze's own IL2CPP maps, and **Load field view** reopens a saved view from the running game. **Il2Cpp** and **Launch dumptool** are gone from Main: one made `dump.cs`, the other fetched the files for it.

A shorter note written for users is in `beta124.00_user_note.md`.

**Needs:** Breeze started from **Profile**, and the SwitchU HOME daemon, for game files. Atmosphere's save redirect for snapshots of a save the game keeps locked. SwitchU fork **1.2.0l** for Start game on games that read their launch parameter (section 4).

---

## 1. Game Files

A game's own files -- its RomFS -- were out of reach from Breeze. Getting one meant leaving Breeze for a dump tool with no game running.

Breeze now mounts the running game's RomFS through the system. No keys are needed, and nothing is decrypted or parsed by Breeze.

**Allowing a game.** The system only hands a game's files to a program whose own permissions name that game, and it reads those permissions once, when the program starts. So a game has to be allowed first, and Breeze reopened once:

- Breeze adds the game to the list inside the Profile loader (`atmosphere/contents/0100000000001013/exefs.nsp`). The list keeps the system entry and the 48 games added most recently. A new file replaces the loader only after it has been rebuilt, parsed again and read back from the SD card.
- Breeze has to be a new process to get the new permission. **Restart Breeze** is not enough, and neither is exiting to hbmenu: both stay in the same process. With the SwitchU daemon the way is **Fast restart**, where HOME closes Breeze and the next HOME opens a new one. Breeze remembers the Home toggle, sets it to Fast restart, and asks for **HOME twice**. The new Breeze puts the toggle back when it starts.
- This works only when Breeze was started from Profile. Started from the album or hbmenu, Breeze says so and changes nothing.

**Launch dumptool and Il2Cpp are removed** from Main, and the Engine tools layout has **Unity** where Il2Cpp was. Both existed to produce `dump.cs` with a helper program run outside Breeze, which often needed more memory than an applet has; section 2 is what replaces it. Their button ids stay reserved, so the ids after them and saved shortcut keys do not move. `global-metadata.dat` can still be copied out of a game, with the file manager (section 5) or `romfsprobe fetch`.

Measured on the console (HOS 22.5.0):

- Mounting takes 9 to 79 ms and loads a few KB of tables; the heap did not grow. The slower mounts were a game with an update installed.
- `global-metadata.dat` of 16.0 MB was copied into the game directory in 1.4 s.
- A list of 64 games starts. A list of 124 does not: the applet fails to launch. Hence the limit of 48.
- A game with an update installed (base plus patch) mounts and reads. Whether the content is the merged one was not proven.

Checked on the console: allowing a game from the PC app's file manager, HOME twice, the Home toggle back on Overlay afterwards, and the game's files then listing and reading.

## 2. Unity Without dump.cs

`dump.cs` came from a helper program run outside Breeze. Breeze has long read fields, methods and function names from the running game instead, but a few buttons still stopped with "dump.cs not found". On a Unity game with no `dump.cs` they now work from the IL2CPP maps (**Unity > IL2CPP map** builds them):

| Field view button | Shows |
|---|---|
| **Class Link** (Y) | every field declared as the class, or as a list, array or dictionary of it |
| **Descendent** (Y + ZL) | the classes derived from it, and the ones implementing it when it is an interface |
| **Dump.cs** (L) | the class with its fields and its methods |

They open the result screen of **Unity > Search maps**, so Open, Instances and Find chain continue from there. If the maps are not built, the message says so.

**Load field view** (Main and Memory Explorer) used to answer "Field view prep required". Without a `dump.cs` a saved view is now reopened from the running game: Breeze follows the view's saved pointer chain to the object as it is now and reads the class from it, so a view saved in one run of the game opens in the next. A view saved without a chain is tried at its saved address, which only holds within one run, and a view saved with only its class opens unpinned. The reopened view keeps its chain; it does not get back its label or its cursor row.

A game that has a `dump.cs` in its directory behaves as before, and so do Unreal and native games. The `dump.cs View` itself, with its text search and bookmarks, still needs the file.

Checked on the console, on Kingdom Two Crowns with no `dump.cs`: Main no longer lists Il2Cpp or Launch dumptool; Class Link and Load field view work; Descendent on `Enemy` lists its 7 derived classes, the same 7 the field map names, and Open on one opens that class; Dump.cs on `Enemy` lists 67 rows, the class with its 20 fields and 46 methods.

## 3. Save Snapshots

A running game keeps its save locked. Every way of opening it from Breeze is refused while the game runs -- normal, read-only, and the save's container file underneath (all 2002-0007 on Kingdom Two Crowns).

Atmosphere can give a game a folder of plain files on the SD card instead of its save: `fsmitm_redirect_saves_to_sd` in `system_settings.ini`, plus a `redirect_save` flag for the game. Plain files can be copied at any time. In that folder `0/` is the save as the game last wrote it and `1/` is its working copy.

The controls are in the PC app (section 6 lists the commands behind them):

- **Save redirect to SD** (check box) turns this on or off for the running game. Breeze writes the flag, and the setting when it is missing. It starts the next time the game is started; the very first time on a console it also needs a reboot. The text beside the box says what is still needed.
- **Save snapshot** copies the save together with a picture of the game at that moment. With the box ticked it works while the game runs. With it unticked the save is inside the console, and the game has to be closed.
- **Restore...** lists the snapshots, newest first, with their pictures. It needs the game closed, and first keeps the current save as `before_restore_...`; if that cannot be done, nothing is changed.

**Where Restore writes.** To wherever the game's save is: the SD card while the box is ticked, the save inside the console while it is not. The first line of the list is the save in the other place, so a save can be carried from the console to the SD card or back. Nothing copies between the two by itself:

- Turning redirect on copies the console save to the SD card once, when the game first opens it -- and only if the game has no folder there yet. A game that was redirected before picks up its old SD save.
- Turning it off copies nothing back. The game returns to the console save as it was.

**The first save.** That first copy lands in the working copy only. Until the game has saved once there is nothing to snapshot, and a game closed before that comes up with an empty save on its next start. The save inside the console is not changed by any of this; unticking the box returns the game to it. The app says so when the box is ticked.

A restore to the SD card builds the new save beside the old one and swaps them. A restore into the console save empties it and fills it file by file, so it is not all or nothing; the `before_restore_...` snapshot is the way back.

Checked on the console with Kingdom Two Crowns: a snapshot of 2 files and 347 KB took 185 ms, with the game's own frame as its picture; a restore to the SD card and a restore into the console save were each loaded by the game. **Not** checked: the first line of the Restore list (carrying a save across), turning redirect on for a game that never had it, any other game, and save file names with characters the SD card does not take.

## 4. Stop Game and Start Game

Two buttons in the PC app, so a save can be restored from the PC: Stop game, Restore, Start game.

- **Stop game** ends the running game at once, as if it had crashed. What it has not saved is lost; the app asks first. It works with Breeze behind the game.
- **Start game** starts the last game again, the way a homebrew menu does. The HOME daemon acts on the request once the program in front has closed, so Breeze closes. It comes back the way it does after any exit.

**Games that crashed when started this way.** A program running as an applet can only ask for a launch by handing the system a launch parameter, so an empty one went along. *Pixel Game Maker Series: Timothy and the Tower of Mu* takes its launch parameter as the path of the project to load, found nothing, and crashed -- from Start game, and from sphaira and DBI in applet mode. This is fixed in the SwitchU daemon, **fork 1.2.0l**, which starts such a game without the parameter. Breeze cannot avoid sending it.

Checked on the console: both buttons, and Timothy starting from applet mode with the 1.2.0l daemon.

## 5. The File Manager

**Files...** in the PC app opens a window with the Switch on the left and the PC on the right (`pcconnect_files.py`).

The Switch side has a list of places for the running game:

- **Game directory (title id)** and **Game directory (title name)**: Breeze's folder for the game. A `*` marks the one Breeze is set to use; the other is listed when it exists.
- **Atmosphere's game directory**: `atmosphere/contents/<title id>/`.
- **Game files (RomFS, read-only)**: section 1. Picking it for a game that is not allowed yet offers to allow it.
- **Game save (SD card)** and **Save snapshots**: section 3.
- **Today's Album**, when the Switch has a clock and something was captured today; **Album**; **Breeze**; **SD card**.

Copy in both directions with folders (F5 or the Copy buttons), new folder (F7), rename (F2), delete (F8), reload. Backspace goes up, Tab changes side. A copy shows its progress and can be cancelled between pieces.

- The game's files can only be copied out.
- Top-level folders of the SD card, such as `atmosphere` and `switch`, cannot be deleted from here. Every delete asks, and so does a copy over existing names.
- A file coming to the PC is written as `.part` and renamed when it is complete.
- The list of places is read again when the window gets the focus back, so it follows a change of game.

The window uses a PC connect connection of its own, so a long copy does not stall the screen in the main window. PC connect serves **three** clients now: the app, its file manager, and a script.

Measured on the console over Wi-Fi: 2.6 MB/s to the Switch and 3.2 MB/s from it for a 5 MB file, the copy identical byte for byte; 2.3 MB/s for 16 MB out of a game's files. The same day the bundled sys-ftp did 3.7 MB/s from the Switch and 1.1 MB/s to it.

Checked on the console: the commands behind the window, and the allow-and-reopen prompt. The window's own copy, rename and delete were run against a stand-in on the PC; on the console they have been used, not measured.

## 6. PC Connect Commands

| Command | Does |
|---|---|
| `romfsprobe [path]`, `romfsprobe find <name>` | mounts the game's files, reports what the mount cost, lists the folder or reads the file |
| `romfsprobe list` / `enable` / `fetch` | the games Breeze is allowed to read, allow the running one, copy `global-metadata.dat` into the game directory |
| `saveprobe` | every save of the running game and whether it opens right now |
| `save`, `save redirect on\|off` | the save state of the game; turn Atmosphere's redirect on or off for it |
| `save snapshot <name> [from=sd\|nand]` | take a snapshot |
| `save restore <name> [to=sd\|nand] [backup=<name>]`, `save delete <name>` | put a snapshot back; remove one |
| `saveshot <name>` | a snapshot's picture |
| `gamestop`, `gamestart <title id>` | section 4 |
| `fs roots`, `fs ls`, `fs mkdir`, `fs rm`, `fs mv` | section 5 |
| `fsget <offset> <length> <path>`, `fsput <offset> <length> <path>` | a piece of a file, up to 4 MB |

The save commands take `tid=<title id>` for a game that is not running. All of them are described in `pcconnect.md`.

## 7. Key Changes

| Screen | Button | Before | Now |
|---|---|---|---|
| Main | Launch dumptool | ZR + X | removed |
| Main | Il2Cpp | ZR + R | removed |

## 8. Documents

- `Kong_Survivor_Instinct_cheats.md`: moon jump no longer dies on a hard landing, and an air steering cheat.
- `Star_Wars_Force_Unleashed_cheats.md`: cheats made from the game's own cheat flags.

---

## File Summary

- `source/gamefs.cpp`, `gamefs.hpp` (new): the game's files, the Profile loader's list, the Home toggle for the reopen.
- `source/savesnap.cpp`, `savesnap.hpp` (new): save redirect, snapshots, restore.
- `source/pcfiles.cpp`, `pcfiles.hpp` (new): file access for the file manager.
- `source/pcconnect.cpp`: the commands of section 6; three clients.
- `source/asmdisp.cpp`: Class Link, Descendent and Dump.cs from the IL2CPP maps; Load field view from the running game.
- `source/action.cpp`, `action.hpp`, `focus_layouts.cpp`: Launch dumptool and Il2Cpp removed.
- `source/main.cpp`: the Home toggle is put back at start.
- `pcconnect_app.py`: the save row, Stop game, Start game, Files.
- `pcconnect_files.py` (new): the file manager.
- `pcconnect.py`: `fs_roots`, `fs_ls`, `fs_do`, `fs_get`, `fs_put`, `close`.
- `pcconnect.md`, `UnityGuide.md`, `focus_layouts.md`: brought up to date.

## Generated Files

- `sdmc:/switch/Breeze/save_snapshots/<title id>/<name>/`: one folder per user, and `shot.jpg`.
- `sdmc:/atmosphere/contents/<title id>/flags/redirect_save.flag`, and the line `fsmitm_redirect_saves_to_sd=u8!0x1` in `sdmc:/atmosphere/config/system_settings.ini`.
- `sdmc:/switch/Breeze/save_redirect_reboot`: present while that setting still waits for a reboot.
- `sdmc:/atmosphere/contents/0100000000001013/exefs.nsp`: rewritten when a game is allowed.
- `sdmc:/config/SwitchU/breeze_home_toggle.saved` and `.pid`: the Home toggle to put back; removed when it has been.
- `global-metadata.dat` in the game directory, when `romfsprobe fetch` copies it.
