# Breeze beta124.00 -- what you will see

Most of this release is in the **PC app** (`pcconnect_app.py`), on a new row of buttons under the screen:

**Save redirect to SD** | **Save snapshot** | **Restore...** | **Stop game** | **Start game** | **Files...**

Take the three Python files from this release: `pcconnect.py`, `pcconnect_app.py` and the new `pcconnect_files.py`. They belong in one folder.

## Save snapshots

Some games save the moment you die, and you start again from far back. A snapshot is a copy of your save, with a picture of the game at that moment, that you can put back later.

**To set it up for a game, once:**

1. Start the game and open the PC app.
2. Tick **Save redirect to SD**. The app explains what happens next.
3. The first time ever on your Switch: reboot it.
4. Start the game again.
5. **Let the game save once before you close it.** Until it has, the copy on the SD card is not complete.

The text beside the check box tells you where you are: reboot needed, restart the game, waiting for the game to save, or ready.

**To take a snapshot:** press **Save snapshot** while you play. It takes a moment and does not interrupt the game.

**To go back to one:**

1. Press **Stop game** (or close the game yourself). The game must not be running.
2. Press **Restore...**, pick a snapshot -- the picture shows where you were -- and press **Restore**.
3. Press **Start game**.

Before it restores, Breeze keeps your current save as a snapshot named `before_restore_...`, so a restore can itself be undone.

**Good to know:**

- With the box ticked, the game keeps its save on the SD card, not inside the console. The save inside the console stays as it was on the day you ticked the box.
- If you untick the box, the game goes back to that older save inside the console. Nothing is copied back by itself.
- To carry a save across, use the first line of the Restore list: it is the save in the other place. With the box ticked it copies the console's save to the SD card; with the box unticked it copies the SD card's save into the console.
- With the box unticked you can still take and restore snapshots, but only while the game is closed.

This has been tried with one game, Kingdom Two Crowns.

## Stop game and Start game

- **Stop game** ends the game at once, like a crash. Anything the game has not saved is lost, so the app asks first.
- **Start game** starts the last game again. Breeze closes to let it start, and the app reconnects when Breeze is back. Press HOME on the Switch if it does not come back by itself.

If a game started this way crashes right away, update the SwitchU HOME daemon to 1.2.0l (Settings > HOME daemon). One known case, *Timothy and the Tower of Mu*, needs it.

## Files

**Files...** opens a window with your Switch on the left and your PC on the right.

On the Switch side, the list at the top offers the places that matter for the game you are playing:

- its Breeze folder, by title id and by name -- a `*` marks the one Breeze uses,
- Atmosphere's folder for the game,
- the game's own files,
- its save on the SD card and its snapshots,
- today's screenshots, the whole album, Breeze's folder, and the SD card.

Select files or folders and press **F5** (or a Copy button) to copy them to the other side. **F7** makes a folder, **F2** renames, **F8** deletes. **Backspace** goes up, **Tab** changes side, **Enter** opens a folder.

Start another game and click on the window: the list follows the new game.

## The game's own files

**Game files** in that list shows what is inside the game itself. They can be copied out, not changed.

The first time for each game, the app asks whether to allow it. Say yes, then **press HOME twice on the Switch**: the first press closes Breeze, the second opens it again. Pick **Game files** once more and they are there. Breeze switches Home toggle to Fast restart for this and puts it back by itself.

This needs Breeze started from **Profile**. Breeze remembers the last 48 games you allowed.

## Unity games: no more dump.cs

**Il2Cpp** and **Launch dumptool** are gone from Main. They were there to make a `dump.cs` file with a helper program, which was slow and often ran out of memory. Breeze no longer needs that file.

On a Unity game, build the maps once with **Unity > IL2CPP map**. After that, in a field view:

- **Class Link** (Y) lists every field that holds this class.
- **Descendent** (Y + ZL) lists the classes derived from it.
- **Dump.cs** (L) lists the class with its fields and methods.

Each opens the same list as **Unity > Search maps**; from there Open, Instances and Find chain work as usual.

**Load field view** now works on these games too: a field view you saved is found again by following its pointer chain, also after the game has been restarted.

If you have a `dump.cs` for a game, made on a PC, Breeze still uses it.
