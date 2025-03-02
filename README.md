# Breeze  
A Nintendo Switch game cheating tool designed to work seamlessly with Atmosphere's cheatVM.  

This project started as a rewrite of the features implemented in EdiZon SE. Over time, the code for EdiZon SE became increasingly difficult to maintain, and its UI posed challenges for many users.  

Over time, numerous features were added, along with significant optimizations, making Breeze much faster and far more powerful than EdiZone SE

## Objectives  
1. **Improve the User Interface**: Ensure more users can access and enjoy the tool’s features.  
2. **Streamline Codebase**: Make the code easier to develop and extend.  
3. **Leverage Experience**: Apply lessons learned from SE tools to create a robust foundation for future development.
4. **All in one tool**: Every task involved in cheat creations can be perform with Breeze alone on Switch.   

---

## Features  
- **Cheat Code Management**:  
  - Toggle codes on/off.  
  - Add/remove conditional keys easily.  
  - Load cheats from a database.  
  - Select cheats from multiple files.  
  - Edit cheats directly in the app.  

- **Cheat Code Editor**:  
  - Integrated disassembler and assembler assistant.  
  - Create loop codes from a single starting point.  

- **ARM64 Instruction Support**:  
  - Assemble and disassemble ARM64 instructions.  

- **Memory Tools**:  
  - Search, edit, and freeze memory.  
  - Bookmark with static offsets from main and heap.  

- **Advanced Debugging**:  
  - Set memory breakpoints to track instructions accessing memory.  
  - Watch specific instructions for memory access.  

- **ASM Composer**:  
  - Build ASM cheats efficiently.  

- **Auto-Update**:  
  - Keep the app and database up to date automatically.  

- **Consistent UI**:  
  - A user-friendly interface designed for seamless navigation.  

---

## Search Concepts  
### Key Ideas  
1. **Static Memory Locations**: Memory storing relevant data can remain static for a window of time. Searches aim to locate these locations during that window.  
2. **Game-Specific Conditions**: In most cases, critical memory locations remain consistent during specific periods, such as between loading screens. However, some locations are stable only under certain conditions, such as within a specific game mode or screen, and may become invalid once the state changes (e.g., exiting the screen). It is up to the user to infer the conditions under which these memory addresses remain static and attempt to complete the search within that limited window of opportunity. 
3. **Data Types**:  
   - Common formats include `u32`, `f32`, `f64`, `u16`, `u8`, obfuscated types, and packed integers.  
   - Try searching in this order for best results.  

### Search Strategies  
- **Known Value Search**: Begin with what you see, guessing the data type and searching for visible values.  
- **Fuzzy Search**: Use range searches when values aren't directly represented. For example, search for "3 to 300" for a health bar representing three hearts.  
- **Full Unknown Search**: When all else fails, dump memory and compare changes to refine the results.  

---

## Game Hacking Concepts  
1. **Approaches**:  
   - Modify game data directly.  
   - Alter the game code that modifies the data.  
2. **Memory Address Value**: Some addresses store effective values, while others only display values.  
3. **ASLR Impact**: Address Space Layout Randomization means memory addresses differ between game sessions.  
   - Use static addresses relative to main or heap, or employ pointer chains or ASM hacks when necessary.  

---

## Breeze Search Manager  
- **Commands**:  
  1. `memory dump`  
  2. `dump compare`  
  3. `start search`  
  4. `continue search`  

- **File Management**:  
  - Generated files (`.dat`) are stored at `sdmc:/switch/Breeze/`.  
  - Files remain valid only within the current memory state window.  
  - Manage files manually or let Breeze handle cleanup during new sessions.  

- **Workflow**:  
  - Start a search using `memory dump` or `start search`.  
  - Follow up with `dump compare` or `continue search`.  
  - Pause searches with `Pause Search` and resume later.  

---

## Data Types  
| Data Type | Description            |  
|-----------|------------------------|  
| `u8`      | Unsigned 8-bit integer |  
| `s8`      | Signed 8-bit integer   |  
| `u16`     | Unsigned 16-bit integer|  
| `s16`     | Signed 16-bit integer  |  
| `u32`     | Unsigned 32-bit integer|  
| `s32`     | Signed 32-bit integer  |  
| `u64`     | Unsigned 64-bit integer|  
| `s64`     | Signed 64-bit integer  |  
| `flt`     | Floating point         |  
| `dbl`     | Double precision float |  
| `pointer` | Memory address pointer |  

---

## Search Modes  
| Mode      | Description |  
|-----------|-------------|  
| `==`      | Equal       |  
| `!=`      | Not Equal   |  
| `>`       | Greater Than|  
| `<`       | Less Than   |  
| `>=`      | Greater or Equal |  
| `<=`      | Less or Equal |  
| `[A..B]`  | Range (inclusive)|  
| `<A..B>`  | Range (exclusive)|  
| `++`      | Increment   |  
| `--`      | Decrement   |  
| `DIFF`    | Value Changed |  
| `SAME`    | Value Unchanged |  

---

## Installation  
1. Copy the contents of `Breeze.zip` to the root of your SD card.  

## Usage  
Detailed instructions are available on the [Breeze Wiki](https://github.com/tomvita/Breeze-Beta/wiki).  

---

## Cheat Code Database  
- [NXCheatCode Repository](https://github.com/tomvita/NXCheatCode)  
- For offline use, place `titles.zip` in `/switch/breeze/cheats/`.  

---

## Acknowledgments  
This project builds on the UI framework from Daybreak. The knowledge gained from developing EdiZon SE and insights from contributors like Werwolv have been invaluable. Special thanks to the Atmosphere team and the broader hacking community for their support and inspiration.  
