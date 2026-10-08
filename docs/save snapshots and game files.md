# Save Snapshots and Game Files

From beta124.00 Breeze can copy a game's save while the game runs, put an earlier save back, and read the files inside the running game. All of it is driven from the **[Breeze PC app](pc%20connect%20app.md)**; this page explains what happens on the Switch and what each feature needs.

## What you need

| Feature | Needs |
|---|---|
| Save snapshot while the game runs | Atmosphere's save redirect, turned on per game from the PC app |
| Save snapshot with the game closed | Nothing extra |
| Stop game / Start game | The HOME daemon. Fork 1.2.0l for games that read their launch parameter |
| Game files | Breeze started from **Profile**, and the HOME daemon |

See **[HOME Toggle and Overlay Mode](home%20toggle%20and%20overlay.md)** for the HOME daemon.

## Save snapshots

A snapshot is a copy of the save, with a picture of the game at that moment, that can be put back later.

### Why a redirect is needed

A running game keeps its save locked. It cannot be opened from Breeze while the game runs, not even to read it.

Atmosphere can give a game a folder of plain files on the SD card instead of its save inside the console. Plain files can be copied at any time. **Save redirect to SD** in the PC app turns this on for the running game.

### Setting it up for a game, once

1. Start the game and open the PC app.
2. Tick **Save redirect to SD**.
3. The first time ever on this console: reboot it.
4. Start the game again. Its save is copied to the SD card when the game opens it.
5. **Let the game save once before you close it.**

Step 5 matters. The first copy lands in the game's working copy only. Until the game has saved once there is nothing to snapshot, and a game closed before that starts next time with an empty save. The save inside the console is not touched by any of this, so unticking the box returns the game to it.

### Where the save is afterwards

- With the box ticked, the game uses its save on the SD card. The save inside the console stays as it was on the day the box was ticked.
- With the box unticked, the game goes back to that save inside the console. Nothing is copied back by itself.
- A game that was redirected before picks up its old save on the SD card when redirect is turned on again.

To carry a save from one place to the other, use the first line of the **Restore...** list in the PC app: it is the save in the other place.

### Restore

Restore needs the game closed, and writes to wherever the game's save is: the SD card while the box is ticked, the console while it is not.

Before anything is replaced, the current save is kept as a snapshot named `before_restore_...`. If that cannot be done, nothing is changed.

- A restore to the SD card builds the new save beside the old one and swaps them.
- A restore into the console empties the save and fills it file by file, so it is not all or nothing. The `before_restore_...` snapshot is the way back.

### Where the files are

| What | Path on the SD card |
|---|---|
| Snapshots | `/switch/Breeze/save_snapshots/<title id>/` |
| The redirected save | `/atmosphere/saves/...` for the game; the PC app's file manager lists it as **Game save (SD card)** |

Inside the redirected save, `0/` is the save as the game last wrote it and `1/` is its working copy. A snapshot copies `0/`.

## Stop game and Start game

- **Stop game** ends the running game at once, as if it had crashed. What it has not saved is lost.
- **Start game** starts the last game again. The HOME daemon acts once the program in front has closed, so Breeze closes and comes back the way it does after any exit.

Restoring a save from the PC is: Stop game, Restore, Start game.

If a game started this way crashes at once, update the HOME daemon to 1.2.0l or newer (Settings > **Update HOME daemon**).

## Game files

The running game's own files (its RomFS) can be listed and copied out, with no keys and no dump tool. They cannot be changed.

### Allowing a game

The system hands a game's files only to a program whose permissions name that game, and it reads those permissions when the program starts. So each game has to be allowed once, and Breeze reopened:

1. In the PC app's file manager, pick **Game files (RomFS, read-only)**. The app asks whether to allow the game. Say yes.
2. **Press HOME twice on the Switch.** The first press closes Breeze, the second opens a new one.
3. Pick **Game files** again.

Breeze sets the Home toggle to Fast restart for this and puts it back when it starts again. **Restart Breeze** and leaving for hbmenu are not enough, because both stay in the same process.

Limits:

- Breeze must have been started from **Profile**. Started from the album or hbmenu, it says so and changes nothing.
- Breeze remembers the 48 games allowed most recently.

### Unity games no longer need dump.cs

**Il2Cpp** and **Launch dumptool** were removed from the main menu in beta124.00. They existed to produce a `dump.cs` file with a helper program. Breeze now builds its own maps from the running game: **Unity > IL2CPP map**. See the **[Unity Guide](UnityGuide.md)**.

`global-metadata.dat` can still be copied out of a game with the file manager.
