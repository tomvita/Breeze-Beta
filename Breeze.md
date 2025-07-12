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
  - Cut, paste, dublicate cheats.
  - Collect cheats in folders.
  - Load cheats from a database or multiple files.

- **Cheat Code Editor**:
  - Edit cheats directly in the app.
  - Show cheat opcode in disassembled mode.
  - Interative opcode assembly.
  - Show ASM cheats in ARM assembly instruction.
  - Directly edit ARM assembly instruction.
  - Short cuts to facilitae cheat code composition.

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

## Installation

1. Download `Breeze.zip` from the [official repository](https://github.com/tomvita/Breeze-Beta/releases).
2. Extract and copy the contents to the root of your SD card.

---

## Launching Breeze

Breeze runs as an applet, not an overlay, and is launched from the home screen.

- **Quick Launch**:
  - Enable the profile shortcut in **Settings > Profile Shortcut** to launch Breeze with **Home + Up + A**.
  - Return to the game with **Home + Home**.

---

## Navigating the UI

Breeze uses a dual-panel interface for efficient navigation:

- **Data Panel** (Left): Displays selectable data (e.g., memory addresses, cheats).
  - Navigate with L-Stick or D-Pad (configurable in **Settings**).
  - Up/Down: Move cursor one step; Left/Right: Move 10 steps.
- **Button Panel** (Right): Contains actionable buttons.
  - Navigate with the unused L-Stick or D-Pad; press **A** to activate.
  - Shortcut keys can be assigned to buttons for quick activation.
- **Touch Support**: Scroll and tap to select data or activate buttons.

---

## Cheat Code Management

### Loading Cheats

Breeze supports multiple methods to load cheats:

1. **Cheat Database**:
   - Automatically loads cheats from list of urls and local database if none are present.
   - Update local database via **Download > Check for Cheat Database Update > Install Cheat Database Update**. Alternatively, download `titles.zip` from [NXCheatCode](https://github.com/tomvita/NXCheatCode/releases/latest) and place it in `sdmc:/switch/breeze/cheats/`.

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
  - Always back up saves before using cheats with a different BID. Restore if cheat don't work as damage may be latent.
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

| Mode      | Description                     |
|-----------|---------------------------------|
| `==`      | Equal to value                 |
| `!=`      | Not equal to value             |
| `>`       | Greater than value             |
| `<`       | Less than value                |
| `>=`      | Greater or equal to value      |
| `<=`      | Less or equal to value         |
| `[A..B]`  | Inclusive range                |
| `<A..B>`  | Exclusive range                |
| `++`      | Value increased                |
| `--`      | Value decreased                |
| `DIFF`    | Value changed                  |
| `SAME`    | Value unchanged                |

---

## Breeze Search Manager

### Workflow

1. Start with **Memory Dump** or **Start Search**.
2. Play the game to change values, then use **Dump Compare** or **Continue Search**.
3. Pause searches with **Pause Search** and resume later.
4. Files (`.dat`) are stored in `sdmc:/switch/Breeze/`.

### File Management

- Files store address-value pairs and screenshots for each game state.
- Files are valid only within the current memory state.
- Manually manage files or let Breeze clean up during new sessions.

### Search Process

Breeze tracks memory changes across game states using a file-based system:

1. **Dump**: Capture full memory (Game State A) into **File 1**.
2. **Play**: Transition to Game State B.
3. **Diff**: Compare File 1 (State A) to current memory (State B), saving results in **File 1(00)** (State A values) and **File 1(01)** (State B values).
4. **Play**: Transition to Game State C.
5. **Diff**: Compare File 1(01) (State B) to current memory (State C), saving results in **File 1(02)** (State C values).

This process ensures accurate tracking of memory changes across states.

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

## Advanced Features (Gen2)

### Memory Breakpoints and Watches

- **SetBreakPoint**: Monitor a memory address to identify accessing instructions.
- **Execute Watch**: Capture instructions accessing the target memory (via **Gen2Attach**).
- **Gen2Detach**: Stop the watch and review results.

### Array of Bytes (AOB) Search

- Used to locate unchanged or slightly modified game code after updates.
- **Make AOB**: Create a file capturing eight instructions from the original code.
- **Load AOB**: Search for the pattern in the current game version, adjusting for offsets.

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

- `{}`: Master code (always executed).
- `[]`: Optional code (toggled on/off).
- Opcodes: 8-digit hex values, 1–4 per instruction.

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

### System Settings for Gen2

Add to `atmosphere/config/system_settings.ini`:

```
[atmosphere]
enable_standalone_gdbstub = u8!0x1
enable_htc = u8!0x0
```

Reboot the Switch after editing.

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

## Sysmodule Manager

- **Tesla**: Optional overlay sysmodule; disable if it causes issues (e.g., with Monster Hunter Rise).
- **sys-ftpd-10k**: FTP sysmodule with enlarged buffer for faster transfers (bundled, off by default).
- **NoExes**: Enables communication with pointer searcher SE (bundled, off by default).

---

## Acknowledgments

Breeze builds on the UI framework from Daybreak and incorporates lessons from EdiZon SE. Special thanks to Werwolv, the Atmosphere team, and the broader hacking community for their support and inspiration.

---

## Further Resources

- [Breeze Wiki](https://github.com/tomvita/Breeze-Beta/wiki)
- [NXCheatCode Repository](https://github.com/tomvita/NXCheatCode)
- [CheatVM Documentation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md)