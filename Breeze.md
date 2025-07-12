# Breeze: A Nintendo Switch Game Cheating Tool

Breeze is a powerful, user-friendly cheating tool for the Nintendo Switch, designed to work seamlessly with Atmosphere's CheatVM. It is a modern successor to EdiZon SE, offering an improved user interface, streamlined codebase, and advanced features for cheat creation and management.

---

## Overview

Breeze was developed to address the maintenance challenges and usability issues of EdiZon SE. It introduces significant optimizations, a more intuitive UI, and a robust feature set, making it faster and more powerful. Breeze aims to be an all-in-one tool for cheat creation and management directly on the Nintendo Switch.

### Objectives
- **Enhanced User Interface**: Make the tool accessible to a wider audience.
- **Streamlined Codebase**: Simplify development and future extensions.
- **Leverage Experience**: Build on lessons from EdiZon SE for a solid foundation.
- **Comprehensive Functionality**: Enable all cheat-related tasks within Breeze.

---

## Features

Breeze offers a comprehensive set of tools for cheat management, memory hacking, and debugging:

- **Cheat Code Management**:
  - Toggle cheats on/off.
  - Add/remove conditional key combos.
  - Cut, paste, duplicate cheats.
  - Collect cheats in folders.
  - Load cheats from a database or multiple files.

- **Cheat Code Editor**:
  - Edit cheats directly in the app.
  - Show cheat opcode in disassembled mode.
  - Interactive opcode assembly.
  - Show ASM cheats in ARM assembly instruction.
  - Directly edit ARM assembly instruction.
  - Shortcuts to facilitate cheat code composition.

- **Memory Tools**:
  - Search, edit, and freeze memory values.
  - Bookmark memory locations with static offsets (main/heap).
  - Search for pointer chain.
  - Bookmark memory locations with pointer chain.
  - Create cheat from bookmark and create bookmark from cheat.
  - Memory explorer to view memory in supported data types and navigate pointer chain to explore data structure of the game.

- **Advanced Debugging**:
  - Set memory breakpoints to track instructions accessing specific addresses.
  - Monitor instructions for memory access patterns.
  - Capture caller, register state and memory target information. 
  - Support parallel use of external debugger such as IDA pro for instruction tracing.

- **ASM Composer**:
  - Build ARM assembly-based cheats.

- **Auto-Update**:
  - Automatically update the app and cheat database.

- **Consistent UI**:
  - Intuitive navigation with full touch support.

---

## Getting Started

Follow these steps to install and launch Breeze on your Nintendo Switch.

### Installation

1.  Download the latest `Breeze.zip` from the [official repository](https://github.com/tomvita/Breeze-Beta/releases).
2.  Extract the contents of the ZIP file.
3.  Copy the extracted files to the root of your SD card.

### Launching Breeze

Breeze runs as a homebrew application (applet), not an overlay. You can launch it directly from the Switch's home screen after you have started the game. (You can't cheat if the game isn't running)

-   **Standard Launch**:
    -   Navigate to the homebrew menu and select Breeze.
-   **Quick Launch Shortcut**:
    -   In Breeze, go to **Settings > Profile Shortcut** and enable the shortcut. Once enabled, you can launch Breeze form you game by pressing in sequence **Home, Up, A**.

To return to your game, press in sequence **Home, Home**.

---

## Navigating the UI

Breeze uses a dual-panel interface for efficient navigation:

- **Left Panel (Data Panel)**: Displays selectable data such as memory addresses or cheats.
  - Use the L-Stick or D-Pad to navigate (configurable in **Settings**).
  - **Up/Down**: Move the cursor one step.
  - **Left/Right**: Move the cursor 10 steps.

- **Right Panel (Button Panel)**: Contains actionable buttons.
  - Navigate with the unused L-Stick or D-Pad.
  - Press **A** to activate a selected button.
  - Assign custom shortcut keys or use pre-defined shortcut keys (configurable in **Settings**) for quick access to buttons

- **Touch Support**:
  - Scroll through data by dragging your finger.
  - Tap to select data or activate buttons.

---

## Cheat Code Management

### Loading Cheats

Breeze supports multiple methods to load cheats:

1. **Cheat Database**:
   - Automatically loads cheats from a list of URLs and the local database if no cheats are found in the Atmosphere path.
   - To get updated local database, go to **Download > Check for Cheat Database Update > Install Cheat Database Update**. Alternatively, you can download `titles.zip` from the [NXCheatCode repository](https://github.com/tomvita/NXCheatCode/releases/latest) and place it in `sdmc:/switch/breeze/cheats/`.

2. **Manual Cheat Files**:
   - Atmosphere Path: `sdmc:/atmosphere/contents/(titleid)/cheats/(buildid).txt` (auto-loaded by CheatVM).
   - Breeze Path: `sdmc:/switch/breeze/cheats/(titleid or title name)/(buildid).txt` (load via **Load Cheats from File**).
   - Custom Path: Place any cheat file in `sdmc:/switch/breeze/cheats/` and load via **More > Any Cheats from breeze/cheats**.

3. **Combining Cheats**:
   - Load a primary cheat file.
   - Use **More > Choose Individual Cheats from breeze/cheats** to add cheats from other files.
   - Save changes with **Write Cheat to File** or **Write Cheat to atm**.

### Customizing Cheats
   - Edit cheat names or values via **Edit Cheat**.
   - Modify conditional keys with **Add/Remove Conditional Key**.
   - Convert moon jumps to hovers by duplicating cheats and adjusting values (e.g. reduce `f32` values).
   - Edit cheat value (using button to directly modify value in commonly used format u32, f32, f64 etc).
   - Edit cheat multiplier.

### Build ID (BID) Considerations

- **What is BID?**: A hash of the game code ensuring cheat compatibility. Mismatched BIDs may cause instability.
- **Checking BID**: Use **Game Information** to view the BID of the running game.
- **Using Mismatched BIDs**:
  - Does not work most of the time.
  - Risky; may cause crashes or save corruption. Automatic BID check is for your protection.
  - Always back up saves before using cheats with a different BID. Restore if cheats don't work as damage may be latent.
  - Load mismatched cheats via **More > Any Cheats from breeze/cheats** (no BID check).

---

## Memory Search Concepts

### Key Principles

1. **Static Memory Locations**: Some game data remains at fixed addresses for a short time (e.g., during a game mode).
2. **Game State Dependency**: Memory addresses may change during transitions (e.g., loading screens). Searches must occur within the valid state window.
3. **Data Types**:
   - Common types: `u8`, `u16`, `u32`, `f32`, `f64`, `pointer`.
   - Search order: `u32`, `f32`, `f64`, then `u16`, `u8`.

### Search Strategies

- **Known Value Search**: Search for visible values (e.g., health, gold) with guessed data types.
- **Fuzzy Search**: Use ranges (e.g., `3 to 300` for a three-heart health bar).
- **Unknown Value Search**: Dump memory and compare changes to narrow down candidates.

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

### Workflow

1. Start with **Start Search** or **Memory Dump**. 
2. Play the game to change values, then use  **Continue Search** or **Dump Compare** (only as follow up to memory dump).
3. Repeat step 2 until the candidates list is short enough to start hacking.
4. Hack memory to see if desired result can be achieved.

### File Management

- Dump file is a dump of the RW memory accesible to the game and screenshots of the game when the search is performed. Dump file needs to be converted into candidate file for subsequent use.
- Candidate Files store address-value pairs and screenshots of the game when the search is performed. 
- Files are valid only within the current game state where target memory remain static.
- Every itteration of step 1 or 2 produce a file. 
- Choose a dump file to create a candidate file. This file will have the address-value pair that has the value that is from the dump and will have the screen short that was captured on the dump file. Only the last four search mode listed above is supported on dump file. 
- Choose a candidate file to create the next candidate file which satisfy the search condition. The file you choose will have the "previous value" and the file produce by the search will have the current value in memory.
- You can choose to name the output file or have Breeze create the file name to help track you search progress.

### An illustration of a Search Process not starting from dump

1. **Search**: (Game State A) Candidate meeting search condition goes into into **File 1** (candidate file with State A values).
2. **Play**: Transition to Game State B.
3. **Search**: Compare candidate list from **File 1** to current memory (State B). Create **File 1(00)** (candidate file with State B values)
4. **Play**: Transition to Game State C.
5. **Search**: Compare **File 1(00)** (State B) to current memory (State C), saving results in **File 1(01)** (State C values).

### An illustration of a Search Process starting from dump

1. **Dump**: Capture full memory (Game State A) into **File 1**(this is a dump file).
2. **Play**: Transition to Game State B.
3. **Search**: Compare **File 1** (State A dump) to current memory (State B), saving results in **File 1(00)** (candidate file with State A values)
4. **Search**: Compare candidate list from **File 1(00)** to current memory (State B). Create **File 1(01)** (candidate file with State B values)
4. **Play**: Transition to Game State C.
5. **Search**: Compare File 1(01) (State B) to current memory (State C), saving results in **File 1(02)** (State C values).


---

## Game Hacking Techniques

### Approaches

1. **Direct Memory Modification**: Change game data values directly.
2. **Code Modification (ASM Hacks)**: Alter game code to modify data behavior.

### ASLR and Dynamic Memory

- **Address Space Layout Randomization (ASLR)**: Memory addresses vary between game sessions.
- **Solutions**:
  - Use static offsets from main or heap.
  - Employ pointer chains or ASM hacks for dynamic addresses.

### Pointer Chains

- A series of offsets starting from a base address (e.g., main) leading to the target memory.
- Validity depends on game state; test across sessions to ensure reliability.

### ASM Hacks

- Modify game code to write desired values.
- Permanent until the game is reloaded; requires an "off" code to revert changes.
- Use **ASM Composer** to build hacks efficiently.

---

## Advanced Features (Gen2 menu)

### Memory Breakpoints and Watches

- **SetBreakPoint**: Monitor a memory address to identify accessing instructions.
- **Execute Watch**: Capture instructions accessing the target memory (via **Gen2Attach**).
- **Gen2Detach**: Stop the watch and review results.

### X30 Matching

- Use **X30_cmp** in ASM Composer to filter instructions based on the X30 register value, distinguishing between friend and foe data.


---

## CheatVM Operation

CheatVM runs at a fixed frequency, performing:

1. **Clear Registers**: Reset 15 cheat registers to zero.
2. **Assemble Opcodes**:
   - Execute master code (inside `{}`).
   - Include enabled optional codes (inside `[]`).
3. **Execute Opcodes**: Apply the assembled instructions.

### Cheat Code Syntax

- `{}`: Master code label (always executed).
- `[]`: Optional code label (toggled on/off).
- Opcodes: 8-digit hex values, 1–4 per instruction.
- Nothing other than white space character or 8-digit hex values are allowed outside of `{}` or `[]`

---

## Settings

| Setting                     | Description                                                                 |
|-----------------------------|---------------------------------------------------------------------|
| **Profile Shortcut**        | Enable to launch Breeze with **Home + Up + A**.                     |
| **Combo Keys**              | Set number of keys (1–6) for conditional key combos.                |
| **Use TitleID**             | Use title ID (1) or title name (0) for cheat file paths.           |
| **Starfield Background**    | Disable (0) to show game screen as background.                     |
| **Search Code Segment**     | Enable (1) to include code segment in searches.                    |
| **Search Main Only**        | Limit searches to main memory for faster results.                  |
| **VisibleOnly**             | Restrict shortcut keys to visible buttons (1) or allow all (0).    |
| **Install Gen2 Fork**       | Install Gen2 fork (requires Atmosphere 1.4+ and system settings).  |

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

- [Breeze Wiki](https://github.com/tomvita/Breeze-Beta/wiki)
- [Breeze Repository](https://github.com/tomvita/Breeze-Beta)
- [NXCheatCode Repository](https://github.com/tomvita/NXCheatCode)
- [CheatVM Documentation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md)