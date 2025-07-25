# Breeze: A Nintendo Switch Game Cheating Tool

Breeze is a powerful, user-friendly cheating tool for the Nintendo Switch, designed to work seamlessly with Atmosphere's CheatVM. It is a modern successor to EdiZon SE, offering an improved user interface, streamlined codebase, and advanced features for cheat creation and management.

---

## Overview

Breeze was developed to address the maintenance challenges and usability issues of EdiZon SE. It introduces significant optimizations, a more intuitive UI, and a robust feature set, making it faster and more powerful. Breeze aims to be an all-in-one tool for cheat creation and management directly on the Nintendo Switch.

### Objectives
-   **Enhanced User Interface**: Make the tool accessible to a wider audience.
-   **Streamlined Codebase**: Simplify development and future extensions.
-   **Leverage Experience**: Build on lessons from EdiZon SE for a solid foundation.
-   **Comprehensive Functionality**: Enable all cheat-related tasks within Breeze.

---

## Getting Started

### Installing and Updating

1.  **In-App Updates**: Use **Download > Check for app update**. If an update is available, **Install app update** will be enabled. To reinstall, use **Redownload** to enable the install button.
2.  **Manual Install**: Download the latest `Breeze.zip` from the [official repository](https://github.com/tomvita/Breeze-Beta/releases). Extract its contents to the root of your SD card, overwriting existing files if prompted.

### Launching Breeze

Breeze runs as a homebrew application (applet), not an overlay. You must start your game *before* launching Breeze.

-   **Standard Launch**: Navigate to the homebrew menu (hbmenu) and select Breeze.
-   **Profile Shortcut**: For faster access, go to **Settings > Profile shortcut** and enable it. Once enabled, you can launch Breeze from your game by pressing **Home -> Up -> A**.
-   **Return to Game**: To return to your game from Breeze, press **Home -> Home**.

---

## Navigating the UI

Breeze uses a dual-panel interface for efficient navigation:

-   **Left Panel (Data Panel)**: Displays selectable data such as memory addresses or cheats.
    -   Use the L-Stick or D-Pad to navigate (configurable in **Settings**).
    -   **Up/Down**: Move the cursor one step.
    -   **Left/Right**: Move the cursor 10 steps.
-   **Right Panel (Button Panel)**: Contains actionable buttons.
    -   Navigate with the unused L-Stick or D-Pad.
    -   Press **A** to activate a selected button.
    -   Assign custom shortcut keys for quick access.
-   **Touch Support**:
    -   Scroll through data by dragging your finger.
    -   Tap to select data or activate buttons.

---

## Features

Breeze offers a comprehensive set of tools for cheat management, memory hacking, and debugging:

-   **Cheat Code Management**:
    -   Toggle cheats on/off.
    -   Add/remove conditional key combos.
    -   Cut, paste, duplicate cheats.
    -   Collect cheats in folders.
    -   Load cheats from a database or multiple files.
-   **Cheat Code Editor**:
    -   Edit cheats directly in the app.
    -   Show cheat opcode in disassembled mode.
    -   Interactive opcode assembly.
    -   Show ASM cheats in ARM assembly instruction.
    -   Directly edit ARM assembly instruction.
    -   Shortcuts to facilitate cheat code composition.
-   **Memory Tools**:
    -   Search, edit, and freeze memory values.
    -   Bookmark memory locations with static offsets (main/heap).
    -   Search for pointer chains.
    -   Bookmark memory locations with pointer chains.
    -   Create cheats from bookmarks and vice-versa.
    -   Memory explorer to view memory and navigate pointer chains.
-   **Advanced Debugging**:
    -   Set memory breakpoints to track instructions accessing specific addresses.
    -   Monitor instructions for memory access patterns.
    -   Capture caller, register state, and memory target information.
    -   Support parallel use of external debuggers like IDA Pro for instruction tracing.
-   **ASM Composer**:
    -   Build ARM assembly-based cheats.
-   **Auto-Update**:
    -   Automatically update the app and cheat database.
-   **Consistent UI**:
    -   Intuitive navigation with full touch support.

---

## Cheat Management

### Loading Cheats

Breeze supports multiple methods to load cheats:

1.  **Cheat URL List**: Breeze searches a list of URLs in a fixed order to find cheats if none are loaded. The process stops when a cheat is found. Pressing "Fetch Cheat" in the download menu cycles through the URLs.
2.  **Cheat Database**: Breeze can use a local cheat database, which it will load automatically on launch if no cheats are active. To get the database, use the in-app downloader: **Download > Check for cheat database update > Install Cheat database update**. Alternatively, download `titles.zip` from the [NXCheatCode repository](https://github.com/tomvita/NXCheatCode/releases/latest) and place it in `sdmc:/switch/breeze/cheats/`.
3.  **Manual Cheat Files**:
    -   **Atmosphere Path**: `sdmc:/atmosphere/contents/{titleid}/cheats/{buildid}.txt` (auto-loaded by CheatVM).
    -   **Breeze Path**: `sdmc:/switch/breeze/cheats/{titleid or title name}/{buildid}.txt` (load via **Load Cheats from File**).
    -   **Custom Path**: Place any cheat file in `sdmc:/switch/breeze/cheats/` and load via **More > Any Cheats from breeze/cheats**.

### Combining and Customizing Cheats

-   **Combining Files**: Load one cheat file, then use **More > Choose individual cheats from breeze/cheats** to add more cheats from other files. Remember to save.
-   **Editing Cheats**:
    -   Edit cheat names or values via **Edit Cheat**.
    -   Modify conditional keys with **Add/Remove Conditional Key**.
    -   Convert moon jumps to hovers by duplicating cheats and adjusting values (e.g., reduce `f32` values).
    -   Edit cheat value directly using buttons for common formats (u32, f32, f64).
    -   Edit cheat multipliers.
-   **Saving Changes**:
    -   **"Write Cheat to atm"**: Saves changes to the file used by Atmosphere's cheatVM.
    -   **"Write Cheat to file"**: Saves changes to Breeze's cheat directory. These cheats must be loaded manually.

### Build ID (BID) and Compatibility

-   **What is BID?**: A hash of the game code ensuring cheat compatibility. The cheatVM will only load cheats if the BID matches the running game.
-   **Checking BID**: Use **Game Information** to view the BID of the running game.
-   **Using Mismatched BIDs**: It is risky to use cheats for a different BID. It may work if the game versions are similar, but it can also lead to crashes or save data corruption. Always back up saves before trying. Load mismatched cheats via **More > Any Cheats from breeze/cheats** (no BID check).

---

## How Cheats Work

### CheatVM Operation

The CheatVM runs at a fixed frequency, performing these steps:
1.  Clears the 15 cheat registers.
2.  Assembles the opcodes to be executed, starting with the master code, followed by any enabled cheat sections.
3.  Executes the assembled opcodes.

For more details, see the [Atmosphere CheatVM Documentation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md).

### Cheat Code File Syntax

-   `{}` or `[]` create labels.
-   `{}`: Marks the start of the **master code**, which is always executed. It is commonly used to set up ASM code caves or register content for other cheats.
-   `[]`: Marks the start of an **optional cheat**, which can be toggled on or off.
-   Only 8-digit hex opcodes are allowed outside of labels.

### Memory Hacking vs. ASM Hacking

Both approaches modify game memory, but they do so in fundamentally different ways:

-   **Memory Hack (Direct Write)**: The CheatVM periodically writes a value to a specific memory address. Its effectiveness depends on timing, as the game might overwrite the value immediately. This is simpler but can be less reliable.
-   **ASM Hack (Code Modification)**: The CheatVM patches the game's own code. The modified code then alters memory whenever it is executed by the game. This is a one-time patch (per game session) that is synchronized with the game's logic, making it far more reliable and precise, especially for values that change frequently. An ASM hack is generally more accurate than a pointer chain, as it hooks directly into the game's behavior rather than relying on memory structures that might be coincidental.

---

## Memory Search

### Key Principles

1.  **Static Memory Locations**: Some game data remains at fixed addresses for a short time (e.g., during a game mode).
2.  **Game State Dependency**: Memory addresses may change during transitions (e.g., loading screens). Searches must occur within the valid state window.
3.  **Data Types**: Common types are `u8`, `u16`, `u32`, `f32`, `f64`, `pointer`. Search in the order of `u32`, `f32`, `f64`, then `u16`, `u8` for best results.

### Search Strategies

-   **Known Value Search**: Search for visible values (e.g., health, gold) with guessed data types.
-   **Fuzzy Search**: Use ranges (e.g., `3 to 300` for a three-heart health bar).
-   **Unknown Value Search**: Dump memory and compare changes to narrow down candidates. Use search modes like `++` (increased), `--` (decreased), `SAME` (unchanged), or `DIFF` (changed).

### Search Modes

| Mode      | Description                      |
|-----------|----------------------------------|
| `==`      | Equal to value                   |
| `*=`      | Equal to value in u32, f32, f64  |
| `**=`     | Same as '*=' but allow +-1 exclusive |
| `!=`      | Not equal to value               |
| `>`       | Greater than value               |
| `<`       | Less than value                  |
| `>=`      | Greater or equal to value        |
| `<=`      | Less or equal to value           |
| `[A..B]`  | Inclusive range                  |
| `<A..B>`  | Exclusive range                  |
| `++`      | Value increased                  |
| `--`      | Value decreased                  |
| `DIFF`    | Value changed                    |
| `SAME`    | Value unchanged                  |

---

## Breeze Search Manager

### Workflow and File Management

Breeze uses a file-based search system. Each search or diff creates a new file (e.g., `File 1`, `File 1(00)`), storing address-value pairs and a screenshot. This allows you to track changes across multiple game states.

-   **Dump File**: A dump of the RW memory accessible to the game. It needs to be converted into a candidate file.
-   **Candidate File**: Stores address-value pairs and screenshots.

**Search Process Example (starting with a search):**
1.  **Search**: (Game State A) Candidates meeting the search condition go into **File 1**.
2.  **Play**: Transition to Game State B.
3.  **Search**: Compare candidates from **File 1** to current memory (State B). Create **File 1(00)**.

**Search Process Example (starting with a dump):**
1.  **Dump**: Capture full memory (Game State A) into **File 1** (dump file).
2.  **Play**: Transition to Game State B.
3.  **Search**: Compare **File 1** (State A dump) to current memory (State B), saving results in **File 1(00)** (candidate file with State A values).

---

## Game Hacking Techniques

### ASLR and Dynamic Memory

-   **Address Space Layout Randomization (ASLR)**: Memory addresses vary between game sessions.
-   **Solutions**:
    -   Use static offsets from `main` or `heap`.
    -   Employ pointer chains or ASM hacks for dynamic addresses.

### Pointer Chains

-   A series of offsets starting from a base address (e.g., `main`) leading to the target memory.
-   Validity depends on game state; test across sessions to ensure reliability.

### ASM Hacks

-   Modify game code to write desired values.
-   Permanent until the game is reloaded; requires an "off" code to revert changes.
-   Use **ASM Composer** to build hacks efficiently.

---

## Advanced Techniques

### Memory Breakpoints and Watches (Gen2 Menu)

1.  In the memory explorer, point to an address and press **SetBreakPoint**.
2.  In the Gen2 menu, use **Gen2Attach** then **Execute Watch**.
3.  Play the game to trigger memory access.
4.  Return to Breeze and use **Gen2Detach**.
5.  Examine the captured list of code that accessed the memory.

### Array of Bytes (AOB) Scanning

AOB scanning helps find code that has shifted after a game update.
-   **"Make AOB"**: Creates a file with an AOB pattern from a cheat created with "Add ASM".
-   **"Load AOB"**: Loads the pattern and starts a search. You can edit the pattern to remove lines that are likely to have changed.

### ASM Explorer

-   **From a cheat**: Use the "Jump to ASM" button.
-   **From memory explorer**: Use the "ASM explorer" button.

---

## Settings

-   **Sysmodule manager**: Enable/disable optional sysmodules like Tesla, sys-ftpd, and NoExes.
-   **Profile shortcut**: Toggle whether the profile button launches Breeze.
-   **Combo keys**: Set the maximum number of keys for a hotkey combo.
-   **Use titleid**: Use title names instead of title IDs for cheat folders.
-   **Use starfield as background**: Toggle the starfield background.
-   **Install gen2 fork**: Install the gen2 fork for gen2 features.
-   **Use Dpad for Left panel item select**: Switch between D-pad and L-stick for the left panel.
-   **Search Code Segment**: Include the code segment in searches.
-   **Search Main only**: Limit searches to the `main` memory region.
-   **Install dmnt fork**: Install a fork with extended code types.
-   **VisibleOnly**: If enabled, shortcuts only work for visible buttons.

---

## Data Types

| Type      | Description                     |
|-----------|---------------------------------|
| `u8`      | Unsigned 8-bit integer         |
| `s8`      | Signed 8-bit integer           |
| `u16`     | Unsigned 16-bit integer        |
| `s16`     | Signed 16-bit integer          |
| `u32`     | Unsigned 32-bit integer        |
| `s32`     | Signed 32-bit integer          |
| `u64`     | Unsigned 64-bit integer        |
| `s64`     | Signed 64-bit integer          |
| `flt`     | Single-precision float (f32)   |
| `dbl`     | Double-precision float (f64)   |
| `pointer` | Memory address pointer         |

---

## Acknowledgments

Breeze builds on the UI framework from Daybreak and incorporates lessons from EdiZon SE. Special thanks to Werwolv, the Atmosphere team, and the broader hacking community for their support and inspiration.

---

## Disclaimer

Using cheats can be risky and may lead to unexpected behavior, including game crashes or save data corruption. Always back up your save data before using cheats. The developers of Breeze are not responsible for any damage caused by the use of this tool.

---

## Further Resources

-   [Breeze Wiki](https://github.com/tomvita/Breeze-Beta/wiki)
-   [Breeze Repository](https://github.com/tomvita/Breeze-Beta)
-   [NXCheatCode Repository](https://github.com/tomvita/NXCheatCode)
-   [CheatVM Documentation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md)