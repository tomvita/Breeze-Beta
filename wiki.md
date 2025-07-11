Welcome to the Breeze-Beta wiki!

# Table of Contents
1.  [Installing / Updating](#installing--updating)
2.  [Launching the App](#launching-the-app)
3.  [Navigating the UI](#navigating-the-ui)
4.  [Getting / Loading Cheats](#getting--loading-cheats)
    *   [Cheat Sources](#cheat-sources)
    *   [A Note About Code Compatibility](#a-note-about-code-compatibility)
5.  [Customizing Cheats](#customizing-cheats)
    *   [Basic Customization](#basic-customization)
    *   [Advanced Customization](#customizing-cheats-for-adventurous-users)
6.  [How Cheats Work](#how-cheat-code-works)
    *   [CheatVM Operation](#cheatvm-operation)
    *   [Cheat Code File Syntax](#syntax-of-cheat-code-file)
7.  [Memory Hacking](#hacking-the-game-memory)
    *   [Finding Memory Addresses](#reacquiring-addresses)
    *   [Hacking Game Memory](#hacking-the-game-memory-1)
8.  [Searching for Values](#if-you-see-a-number-on-game-screen-and-want-to-change-it)
9.  [Settings Menu](#setting-menu)
10. [Breeze File Management](#breeze-file-management-and-game-state-handling)
11. [Advanced Techniques](#advanced-techniques)
    *   [Using Gen2 Menu for Watches](#watch-the-memory-location-with-gen2-menu-and-get-a-list-of-candidates)
    *   [Array of Bytes (AOB) Scanning](#aob-array-of-bytes-scanning)
    *   [ASM Explorer](#getting-to-asm-explorer)

# Installing / Updating

1.  **In-app Updates:** Use "Download" -> "Check for app update". If an update is available, "Install app update" will be enabled. To reinstall, use "Redownload" to enable the install button.
2.  **Manual Install:** Download `Breeze.zip` and extract its contents to the root of your SD card, overwriting existing files if prompted.

# Launching the App

1.  This is an applet, not an overlay. Launch it from the home screen's hbmenu.
2.  **Profile Forwarder:** For faster access, enable the profile forwarder in "Setting" -> "Profile shortcut =". Once enabled, press `Home -> up -> A` to launch Breeze from a game. Press `Home -> Home` to return to the game.
3.  **hbmenu Forwarder:** On older atmosphere versions, you can use "Switch to HBM on Breeze directory" to have the profile shortcut launch hbmenu focused on the Breeze directory.

# Navigating the UI

1.  **Panels:** The UI has a data panel (left) and a button panel (right). The data panel shows data to be acted upon by the buttons.
2.  **Data Panel Navigation:** Use either the L-stick or D-pad (configurable in settings). Up/Down moves one step, Left/Right moves 10 steps.
3.  **Button Panel Navigation:** The unused stick/d-pad navigates the button panel. Press `A` to activate a button.
4.  **Shortcuts:** Buttons can have shortcut keys assigned to them.
5.  **Touch Control:** Full touch control is supported.

# Getting / Loading Cheats

## Cheat Sources

### Cheat URL List
1.  Breeze searches a list of URLs in a fixed order to find cheats if none are loaded.
2.  The process stops when a cheat is found or the list is exhausted.
3.  Pressing "Fetch Cheat" in the download menu cycles through the URLs.

### Cheat Database
1.  Breeze can use a local cheat database, which it will load automatically on launch if no cheats are active.
2.  To get the database, use the in-app downloader: "Download" -> "Check for cheat database update" -> "Install Cheat database update".
3.  Alternatively, download `titles.zip` from [the NXCheatCode repo](https://github.com/tomvita/NXCheatCode/releases/latest) and place it in `sdmc:/switch/breeze/cheats`.

### Manual Placement
1.  `sdmc:/atmosphere/contents/{titleid}/cheats/{buildid}.txt`: This is the standard location for cheats that are automatically loaded by the cheatVM.
2.  `sdmc:/switch/breeze/cheats/{titleid}/{buildid}.txt` or `sdmc:/switch/breeze/cheats/{title_name}/{buildid}.txt`: Use the "Load Cheats from file" button.
3.  `sdmc:/switch/breeze/cheats/{any_filename}`: For any other cheat file. Use "More" -> "any cheats from breeze/cheats" to load. No Build ID check is performed with this option.

### Combining and Picking Cheats
*   **Picking Individual Cheats:** Use "More" -> "Choose individual cheats from breeze/cheats", select the file and the cheats, then save your changes. This is useful for adding specific cheats to an existing file.
*   **Combining Files:** Load one cheat file, then use the "Picking individual cheats" method to add more cheats from other files. Remember to save.

## A Note About Code Compatibility
1.  Cheats are developed for a specific version of a game, identified by a **Build ID (BID)**. The BID is a hash of the game's code.
2.  The cheatVM will only load cheats if the BID matches the running game.
3.  You can check your game's BID using the "Game information" button in Breeze while the game is running.
4.  It is risky to use cheats for a different BID. It may work if the game versions are similar, but it can also lead to crashes or save data corruption. Use with caution and back up your saves.

# Customizing Cheats

## Basic Customization

### Saving Changes
*   **"Write Cheat to atm"**: Saves changes to the file used by atmosphere's cheatVM.
*   **"Write Cheat to file"**: Saves changes to Breeze's cheat directory. These cheats must be loaded manually.

### Editing Cheats
*   **Change Name:** Use "Edit Cheat" and edit the first line.
*   **Change Value:** Use "Edit Cheat" and find the value to change (usually code type 0, 3, or 6). Use the "Edit u32", "Edit f32", or "Edit f64" buttons to modify the value.
*   **Conditional Keys:** Use "Remove conditional key" or "Add conditional key" to manage hotkeys for cheats. The number of keys in a combo is set in the settings menu.
*   **Moon Jump to Hover:** Duplicate a moon jump cheat, rename it, and edit the value (usually an f32) to a smaller number until the character hovers.

## Customizing Cheats for Adventurous Users

### CheatVM Instruction Format
An instruction is 1-4 opcodes (8 hex digits each). The first opcode defines the action. For more details, see the [Atmosphere documentation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md).

### Master Code
*   A cheat file can have one master code, marked with `{}` instead of `[]`.
*   It is always on and executed first.
*   Commonly used to set up ASM code caves or register content for other cheats.

### Disassembler and Assembler
*   Use "Cheats" -> "Edit Cheat" -> "Toggle Disassembly" to view a more readable version of the cheat code.
*   Use the "Assemble" button for an interactive assembler to make code changes.

# How Cheat Code Works

## CheatVM Operation
The CheatVM runs at a fixed frequency, performing these steps:
1.  Clears the 15 cheat registers.
2.  Assembles the opcodes to be executed, starting with the master code, followed by any enabled cheat sections.
3.  Executes the assembled opcodes.

## Syntax of Cheat Code File
*   `{}` or `[]` create labels.
*   `{}`: Marks the start of the **master code**, which is always executed.
*   `[]`: Marks the start of an **optional cheat**, which can be toggled on or off.
*   Only 8-digit hex opcodes are allowed outside of labels.

## Memory Hacking vs. ASM Hacking
*   **Memory Hack:** The cheatVM periodically writes values to memory. This needs to be timed correctly to work.
*   **ASM Hack:** The cheatVM modifies the game's own code to change memory. This is a one-time patch (per game session) and is generally more reliable for hacks that need to be active constantly (e.g., infinite health).

# Hacking the Game Memory

## Reacquiring Addresses
Address Space Layout Randomization (ASLR) and dynamic memory mean that memory addresses change. Here's how to find them again:
*   **Base address + offset:** Some addresses have a constant offset from the main or heap base address.
*   **Pointer chain:** A series of pointers and offsets can lead to the target address.
*   **Register content:** Hooking game code can reveal memory addresses stored in registers.

## Hacking the Game Memory
*   **Directly with CheatVM:** The CheatVM writes to memory at a fixed frequency, which is not synchronized with the game process.
*   **Injecting ASM:** The hack is performed by the game's own code, synchronized with the game process. This is done by hooking game code and branching to a **code cave**.

# If you see a number on game screen and want to change it

1.  **Mind the game state:** Memory addresses often change on major state transitions (e.g., loading screens).
2.  **Search for the value:** Use the search feature with the appropriate data type (u32, f32, f64 are common). The `*` search looks for both.
3.  **Refine the search:** Change the value in-game, then search again to narrow down the candidates.
4.  **Test candidates:** Modify the values of the remaining candidates to see which one has the desired effect.
5.  **Unknown value search:** If you can't see a number, use an unknown value search (`++`, `--`, `same`, `diff`) to find addresses that change in a certain way.

![Search example](https://user-images.githubusercontent.com/68505331/221757376-0a924d43-199d-4426-b98c-a34534a08e99.jpg)

# Setting Menu

![Settings Menu](https://user-images.githubusercontent.com/68505331/221738544-3ef95f03-9f57-49b7-b355-1753a40e7d1b.jpg)

*   **Sysmodule manager:** Enable/disable optional sysmodules like Tesla, sys-ftpd, and NoExes.
*   **Profile shortcut:** Toggle whether the profile button launches Breeze.
*   **Combo keys:** Set the maximum number of keys for a hotkey combo.
*   **Use titleid:** Use title names instead of title IDs for cheat folders.
*   **Use starfield as background:** Toggle the starfield background.
*   **Install gen2 fork:** Install the gen2 fork for gen2 features.
*   **Use Dpad for Left panel item select:** Switch between D-pad and L-stick for the left panel.
*   **Search Code Segment:** Include the code segment in searches.
*   **Search Main only:** Limit searches to the `main` memory region.
*   **Install dmnt fork:** Install a fork with extended code types.
*   **VisibleOnly:** If enabled, shortcuts only work for visible buttons.

# Breeze: File Management and Game State Handling

Breeze uses a file-based search system to track memory changes.

*   **Process:** `Dump -> Play -> Diff -> Diff -> Play -> Diff`
*   Each search or diff creates a new file (e.g., `File 1`, `File 1(00)`, `File 1(01)`), storing address-value pairs and a screenshot. This allows you to track changes across multiple game states.

# Advanced Techniques

## Watch the memory location with Gen2 menu and get a list of candidates

1.  In the memory explorer, point to an address and press "SetBreakPoint".
2.  In the Gen2 menu, use "Gen2Attach" then "Execute Watch".
3.  Play the game to trigger memory access.
4.  Return to Breeze and use "Gen2Detach".
5.  Examine the captured list of code that accessed the memory.

## AOB (Array of Bytes) Scanning

AOB scanning helps find code that has shifted after a game update.
*   **"Make AOB"**: Creates a file with an AOB pattern from a cheat created with "Add ASM".
*   **"Load AOB"**: Loads the pattern and starts a search. You can edit the pattern to remove lines that are likely to have changed.

## Getting to ASM explorer
*   **From a cheat:** Use the "Jump to ASM" button.
*   **From memory explorer:** Use the "ASM explorer" button.
