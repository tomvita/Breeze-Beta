# Menu Documentation

Welcome to the comprehensive guide for all button functionalities within Breeze. This document is designed to help you understand and master the controls across various menus, from basic navigation to advanced cheat implementation.
The menus are designed to be intuitive, but the extensive features mean there are many buttons and shortcuts available. This guide breaks down each menu, detailing what every button does, along with its default shortcut.
Whether you're a new user getting acquainted with the application or an experienced user looking for a specific function, this documentation will serve as your go-to reference for all controls.

## Table of Contents

- [Context-Sensitive Help](#context-sensitive-help)
- [Focused Actions / All Actions](#focused-actions--all-actions)
- [Global Navigation Buttons](#global-navigation-buttons)
- [Focused Actions Menu](#focused-actions-menu)
- [Main Menu](#main-menu)
- [Simple Cheat Menu](#simple-cheat-menu)
- [Advance Cheat Menu](#advance-cheat-menu)
- [Extended Cheat Menu (More Menu)](#extended-cheat-menu-more-menu)
- [Edit Cheat Menu](#edit-cheat-menu)
- [Asm Composer Menu](#asm-composer-menu)
- [Search Setup Menu](#search-setup-menu)
- [Search Setup Menu 2](#search-setup-menu-2)
- [Search Manager Menu](#search-manager-menu)
- [Candidate Menu](#candidate-menu)
- [Bookmark Menu](#bookmark-menu)
- [Memory Explorer Menu](#memory-explorer-menu)
- [ASM Explorer Menu](#asm-explorer-menu)
- [Runtime Method List (Unity / IL2CPP)](#runtime-method-list-unity--il2cpp)
- [IL2CPP Function Map Menu](#il2cpp-function-map-menu)
- [Jump Back Menu](#jump-back-menu)
- [Gen2 Menu](#gen2-menu)
- [Gen2 Extra Menu](#gen2-extra-menu)
- [Search Items Editor (Advance Search)](#search-items-editor-advance-search)
- [Pointer Search Menu](#pointer-search-menu)
- [Game Information](#game-information)
- [Segment Map](#segment-map)
- [Code Cave Map](#code-cave-map)
- [Download Menu](#download-menu)
- [Unity Menu](#unity-menu)
- [Unreal Menu](#unreal-menu)
- [Lua Menu](#lua-menu)
- [Rebase Menu](#rebase-menu)
- [Trace Cheat](#trace-cheat)
- [Sysmodule Manager](#sysmodule-manager)
- [Setting Menu](#setting-menu)

## Context-Sensitive Help

Hold **ZR first**, then press **A** to open help for the current menu. Use the D-Pad and A for topics, Left/Right for pages, X for the selected action's help, and B to return or close. Help blocks the underlying menu and saves its state per menu. See the [Help System Guide](help%20system.md).

## Focused Actions / All Actions

Focused Actions shows a smaller set of frequently used actions. All Actions shows every action available in the current menu. Open **Focused Actions** management with the configured key (default `L + ZR`) and choose **Switch view** to change between them.

**Dynamic view** sorts the buttons by the shift keys in their shortcuts instead. Hold nothing to see the buttons whose shortcut has no ZL or ZR in it; hold **ZL**, **ZR** or **ZL + ZR** to see the buttons of that key. Turn it on per menu with **Dynamic=ON/OFF** in the Focused Actions manager, or load the built-in **Dynamic** layout. Shortcuts keep working whether their button is shown or not.

Choose **Customize actions** to edit the focused set. Breeze opens the action panel full screen in four columns and hides the left panel while editing. Press `A` to include or remove any action, `-` to cut an included action to the stack, and `+` to pop the last cut action into the position at the cursor. Press `B` to finish. If a menu's usual selected action is not included, selection starts on the lower-right page button instead.

Status and other menu information remain below the panel title. Help for the selected action is shown separately in the footer below the action buttons.

**Training mode** adds actions to Focused Actions as you use them. Turning it on leaves the existing focused set and action view unchanged.

Breeze comes with six built-in layouts, shown in green in the layout list: **Player**, **Beginner maker**, **Advanced maker**, **Engine tools**, **All** and **Dynamic**. They are written again at every start and cannot be overwritten; to change one, load it and save the result under your own name.

For a complete walkthrough, see the **[Focused Actions Guide](focus%20mode.md)**.

## Global Navigation Buttons

The following button is on every menu.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Focused X/Y / All X/Y / Dynamic | (none) | The lower-right button shows the current action view and page. Press it to go to the next page. In Dynamic view it shows each shift key with the number of buttons on it. Green means Focused, olive means All. |

## Focused Actions Menu

This menu manages the actions shown in Focused Actions and lets you save or load named layouts. The manager itself is never filtered, so all of its buttons remain visible. Its title names the menu you came from.

The left panel lists the layout files. The one in effect is marked `(in effect)`, or `(in effect, changed)` when your focus has drifted from it, and the status line names the menus that differ. Loading a layout applies it at once.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Switch view (to All) | L + ZR | Switches the menu you came from between Focused Actions and All Actions. The label names the view it will switch to. |
| Dynamic | (none) | Turns Dynamic view on or off for the menu you came from. With it on, the action panel shows only the buttons of the shift keys you are holding: none, ZL, ZR or ZL + ZR. |
| Load layout | Y | Loads the selected layout file and applies it at once. Built-in layouts are shown in green. |
| Customize actions | L | Opens the action panel full screen in four columns to choose which actions are in Focused Actions. `A` includes or removes, `-` cuts, `+` pastes at the cursor, `B` finishes. |
| Training mode: OFF | (none) | Turns Training mode on or off. While it is on, every action you use is added to Focused Actions. |
| Save layout | X | Saves the current focus of every menu into the selected layout file. Refused on a built-in layout. |
| Rename layout | (none) | Renames the selected layout file. Refused on a built-in layout. |
| New layout | + | Saves the current focus under a new name. |
| Delete layout | - | Deletes the selected layout file. Refused on a built-in layout. |
| Reset all shortcuts | Left Stick Click | Resets all shortcuts to their factory defaults, including the Focused Actions manager and Search Manager shortcuts that share the same menu. |
| Clear all shortcuts | Right Stick Click | Removes all custom shortcuts. |
| Clear focus for this menu | (none) | Clears Focused Actions only for the menu you were working on and shows All Actions there. Other menus are unchanged. |
| Restart Breeze | B + ZR | Saves the settings and restarts Breeze. |
| Back | B | Returns to the previous menu. |

## Main Menu

The main entry point of the application, providing access to all major features.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Cheats | Y + ZL | Opens the Simple Cheat Menu. |
| Cheat Menu | R | Opens the Advance Cheat Menu. |
| SearchManager | L | Opens the Search Manager Menu. |
| Bookmarks | Right Stick Up | Opens the Bookmark Menu. |
| Help | ZR + Plus | Opens the Help Screen. |
| Download | - | Opens the Download Menu. |
| hbmenu | B + ZR | Leaves Breeze and returns to hbmenu. This was **Exit** on `B` before beta123.10. |
| Settings | + | Opens the Settings Menu. |
| SwitchU | Left Stick Click | Exits to hbmenu so that the next HOME press opens the SwitchU menu. Shown only when the SwitchU menu is installed. |
| Game Information | Y | Opens the Game Information screen. |
| Gen2 Action | Right Stick Click | Review break point data and generate ASM script. |
| Launch ftpsrv | X | Launches the FTP server to access the SD card and saves from a PC. |
| Launch sphaira | B + ZL | Leaves Breeze and starts the sphaira homebrew menu. |
| Unity | L + ZL | Opens the Unity Menu: IL2CPP maps, usual suspects, map search and singletons. For Unity (IL2CPP) games. |
| Unreal | R + ZL | Open the Unreal Engine workflow for profiles, UWorld chains, functions, objects, and field exploration. |
| Lua | ZL + Plus | Open the Lua workflow. Finds the game's Lua state, measures its struct layout, and browses game data by name instead of by address. |
| JumpBack Menu | Y + ZR | Opens the JumpBack Menu. |
| Memory Explorer | ZL + Minus | Opens the Memory Explorer at the last saved address. |
| Load field view | ZR + Left Stick Up | Load a saved structured field layout over the current memory. Use a layout created for the same class, engine version, and game build. |
| Segment Map | X + ZL | Opens the Segment Map. |

## Simple Cheat Menu

This is the default, simplified view of the cheat menu.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Cheat | X | A solid square indicates the cheat is on, a hollow square indicates it is off. |
| Back | B | Go to the previous menu. |
| Change size | R | Toggles the width of the left panel. |
| Left-Right swap | L | Swaps the left and right panels. |
| Advance Cheatmenu | ZL + ZR + Plus | Opens the Advance Cheat Menu. |

## Advance Cheat Menu

This menu provides more advanced cheating functionalities.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Cheat | X | Turns the selected cheat on or off. An ASM cheat steps through three stages: on, off with its hook left in the game (green row), and off with the original instruction put back. On a folder row it opens or closes the folder. |
| Add to bookmark | + | Create a bookmark from a static or pointer cheat. |
| Add conditional key | Right Stick Click | Setup a conditional key combo, up to the number defined in options. |
| Remove conditional key | Left Stick Click | Remove the key combo condition required to execute the cheat. |
| Edit Cheat | L | Opens the Edit Cheat Menu for the selected cheat. On a folder row it edits the folder's name. |
| Cut Cheat | - | Cuts the selected cheat and pushes it onto the clipboard stack. On a folder row it takes the whole folder with its cheats. |
| Paste/Duplicate Cheat | Right Stick Left | Pops a cheat or a cut folder from the stack and puts it in front of the cursor row, or duplicates the current cheat if the stack is empty. |
| Write Cheat to atm | ZL + Right Stick Down | Write from cheatVM to atmosphere's content directory. |
| Load Cheats from atm | Right Stick Up | Load cheats from the atmosphere's content directory. |
| Add freeze game code | X + ZL | Freeze / Unfreeze the game. |
| Bookmark | R | Go to the bookmark menu. |
| Back | B | Go to the previous menu. |
| Write Cheat to file | Right Stick Down | Write from the cheatVM to Breeze's cheat directory. |
| Load Cheats from file | Y | Load cheats from Breeze's cheat directory. |
| Load from DB | Right Stick Right | Load a cheat from the database. |
| More | ZL + ZR + Plus | Opens the Extended Cheat Menu. |
| key hint to file | Right Stick Click + ZL | Save conditional key combo in cheat name. |
| Assemble all ASM | L + ZL | Clear all ASM in memory and re-assemble them. |
| Type0 map toggle | ZR + Plus | Map type 0 address to cheats. |
| Expand Screen | R + ZR | Toggle the left panel width between half and full. |
| Clear clipboard | ZR + Right Stick Left | Clears the clipboard, which is useful for duplicating cheats. |
| Watch ASM | B + ZR | Apply and watch line 1 of the selected cheat. |
| Module loaded cheats only | Y + ZL | Toggle to only show cheats for the currently loaded module. |
| Get Latest Cheat from TomVita | ZR + Right Stick Down | Download the latest cheats from TomVita's repository. |
| Relocate Code Cave | R + ZL | Relocate an ASM cheat's code cave when its current allocation is unsuitable or conflicts with other code. Retest all branches and return paths after relocation. |
| Edit Note | ZL + Plus | Create or edit the note associated with the selected cheat. Record important conditions and warnings so they remain available with the cheat workflow. |
| Show Notes | ZL + Minus | Display saved notes for the selected cheat. Notes can record requirements, conflicts, controls, provenance, or testing results. |
| AOB 2 cheat | B + ZL | Select one .aob file and create a cheat containing one original-instruction write line for every matching occurrence. Review all lines; target_index identifies the original hook's position. |
| Reset CheatVM | Left Stick Click + ZL | Closes and reopens the cheat process and reloads the cheats from file. Frozen addresses and cheat edits not written to file are lost, so it asks twice. |

## Extended Cheat Menu (More Menu)

This menu provides extended functionalities for cheat management.

Accessed by pressing `ZR + ZL` in the Advance Cheat Menu.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Turn off all Cheats | X | Turns off every cheat and puts the original instruction back for every ASM cheat. |
| Make off Cheat | Y + ZR | Create an "off" cheat by gathering the revert code from all cheats. |
| Make AOB | ZR + Right | Create or retain version-3 `.aob` files for all eligible ASM cheats. |
| Make AOB M | (none) | For cheats skipped by Make AOB, create `label.index.aob` for type-0 code writes outside the final 4 KB code-cave page. |
| Load AOB | ZR + Left | Process every `.aob` in the game directory; each resulting cheat has one line per occurrence. |
| Rebase | ZR + Down | Opens the Rebase Menu, which carries cheats to a new version of the same game. |
| Remove atm cheats | (none) | Remove cheat file from atmosphere's content directory. |
| Delete all Cheats | - | Remove all cheats from the cheatVM. |
| Create Group | Right Stick Click | Create a grouping to organize cheats. |
| Turn on all Cheats | Y | Turns on all cheats. |
| Expand Data Screen | + | Toggle the left panel width between half and full. |
| any cheats from Breeze's Game directory | L | Load all cheats from Breeze's game-specific directory into the active list. Existing in-memory work may be replaced. |
| signature | R | Set a signature to save with cheats. |
| any cheats from Atm's TID directory | L + ZL | Load any file from atmosphere's cheat directory, ignoring the BID. |
| Choose individual cheats from Breeze's Game directory | L + ZL + ZR | Open a file picker and choose individual cheats from Breeze's game directory rather than importing the entire file. |
| Add R2 | Left Stick Click + ZR | Create a cheat that will result in R2 having the address of main. |
| Back | B | Go back to the previous menu. |
| Watch ASM | B + ZR | Apply and watch line 1 of the selected cheat. |
| Create Cheat | X + ZR | Create a dummy cheat. |
| Clear clipboard | ZR + Right Stick Left | Clears the clipboard, which is useful for duplicating cheats. |
| Make Master | (none) | Create a master cheat. Master entries are treated specially by Atmosphere and should contain only setup code that must run as a master. |

## Edit Cheat Menu

This menu allows for direct editing of cheat codes.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Edit | X | Edit the selected line of the cheat. |
| Edit f32 | L | Edit an opcode as a single-precision float. |
| Edit u32 | L + ZL | Edit an opcode as an unsigned 32-bit integer. |
| Edit f64 | R | Edit an opcode as a double-precision float. |
| copy | Y | Push the selected line to the clipboard stack. |
| paste above | + | Pop from the stack and paste above the selected line. |
| paste below | Right Stick Left | Pop from the stack and paste below the selected line. |
| Delete line | - | Delete the selected line and push it to the clipboard stack. |
| Toggle Disassembly | Right Stick Down | Toggle between raw opcode and disassembled view. |
| Assemble | Right Stick Up | Guided assembly of cheat code. |
| ASM/keycombo edit | Right Stick Click | Edit ASM or a key combo. |
| Save | B | Upload changes to the cheatVM and return to the previous menu. |
| Save to file | Right Stick Right | Save the left panel text to a file. |
| Expand Menu | ZL + ZR + Plus | Show more buttons. |
| Add loop | ZL + Plus | Assistant to create loop code. |
| Add ASM | ZL + Up | Assemble ARM code into a cheat. |
| Load register | ZL + Down | Insert cheat code to load a register. |
| Alt ASM | Right Stick Click + ZL | With 1, Add ASM places the code cave in the roomiest region other than main that a plain branch reaches, usually below main. With 0, main is used first. |
| Add utility codes | ZL + Left | Create utility cheat codes. |
| ASM Group | Left Stick Click + ZL | Place utility cheat codes in a group. |
| Expand Screen | R + ZR | Toggle the width of the left panel. |
| Get original values | Left Stick Click | Create recovery code from the original values. |
| Jump to target | ZL + Right | Runs the cheat as a dry run and opens the address it reads or writes. With more than one target it opens the Trace cheat list. |
| Trace cheat | ZR + Right | Runs the cheat as a dry run and lists every pointer hop, read, compare and write it makes. Nothing is written to the game. |
| Clear ASM space | ZL + Minus | Fill the code cave with 00s. |
| Asm Composer | Y + ZL | Go to the assembly code editor. |
| Extract ASM | ZL + Right Stick Down | Extracts embedded assembly code from a cheat, generating labels for memory addresses and saving it to `{cheat_name}_extract.txt`. |
| Jump to ASM | X + ZL | Go to the ASM explorer to examine code in memory. |
| Nop | ZL + Right Stick Up | Replace the selected code with a NOP instruction. |
| ,lsl# | ZL + Right Stick Right | Modify code by appending a logical shift left. |
| Transform opcode 1 | ZR + Right Stick Left | Apply Transform 1 to the selected decoded CheatVM opcode. It toggles supported pairs such as assign versus match, key-held versus key-down, and load-register versus write-register forms. |
| Transform2 | ZL + Right Stick Left | Increment load register, toggle between load/begin condition, or convert store static to load. |
| type0 expand | (none) | Sorts type 0 codes by address and expands them to width 4 for better ASM visibility. |
| type0 condense | (none) | Condenses type 0 codes to width 8 for a more compact representation. |
| Adj | ZR + Left Stick Up | Utility to port code to a new offset. |
| Addr | ZR + Left Stick Down | Utility to port code to a new offset. |
| Search code | ZR + Left Stick Right | Search the code space for the code written by the cheat code. |
| Line 2 Cheat | ZR + Left Stick Left | Make a cheat code from the selected line of code. |
| R1 | Y + ZL + ZR | Display the base address of the module. |
| 4,6 to 0 | R + ZL | Convert type 4 and type 6 cheats into type 0 cheats. |

## Asm Composer Menu

The Asm Composer Menu serves as a specialized Integrated Development Environment (IDE) tailored for assembly programming within Breeze. It’s engineered to streamline the entire cheat development workflow, from initial hook to final implementation.

### Workflow
After identifying a target instruction to hook (e.g., via Gen2 menu and ASM explorer), you first create a new cheat for it. Access the `Asm Composer` through the `Edit Cheat` menu to begin writing your custom assembly logic.

### Key Features
- **File Operations**: Load and save `.asm` files from the main `/breeze/` directory or game-specific folders.
- **Efficient Code Editing**: A syntax-aware editor with a multi-level clipboard stack simplifies managing and reusing code snippets.
- **Assembly-Specific Tools**: Accelerate development with one-tap shortcuts for common ARM instructions (`ldr`/`str`, `mov`/`fmov`) and templates for recurring patterns like data storage and button-activated code.
- **Seamless Integration**: For crucial context, you can instantly insert the original, hooked code for reference and jump directly into the Memory Explorer to examine relevant memory regions.

The Asm Composer equips both novices and experts with the essential tools to build precise and complex assembly cheats efficiently.

| Button Name | Default Shortcut | Action |
|---|---|---|
| {dynamic} | Left + ZL | Multipurpose insert template that now supports dynamic button labels (e.g., "Cycle Data Type," "Stack Template"). |
| Edit | X | Edit the selected line of assembly. |
| Load file | R | Load an assembly file from `/switch/breeze`. |
| Load file(game dir) | R + ZL | Load an assembly file from `/switch/breeze/cheats/{game dir}`. |
| Load extract | StickRDown + ZL | Loads a `_extract.txt` file directly into the composer for editing. If no ASM file exists, the extracted ASM will be loaded automatically when entering via the "Extract ASM" button. |
| Load | L | Reload from file (unsaved changes will be lost). |
| Save | L + ZL | Save the current assembly to file. |
| Check ASM | Y + ZR | Validate the assembly code and add comments for issues. |
| Copy | Y | Copy and push the current line to the stack. |
| Cut | - | Cut and push the current line to the stack. |
| Paste | + | Pop from the stack and insert the line. |
| PasteBelow | + + ZL | Pop from the stack and insert the line below. |
| Original | X + ZL | Insert the original assembly code that is being hooked. |
| MergeNext | Right + ZL | Append the next line into the current one. |
| ldr_str | Up + ZL | Multipurpose modification of ldr and str instructions. |
| mov_fmov | Down + ZL | Change between mov and fmov instructions. |
| X30_cmp | Right Stick | Not needed, use gen2 menu to create full script. |
| paste A | Left Stick | Paste the value of A. |
| Cut the rest | - + ZL | Cut all lines below the cursor. |
| Expand screen | R + ZR | Toggle the width of the left panel. |
| cave_start | Y + ZL | Fix the starting address of the code cave. |
| data_save | Right Stick Right + ZL | Insert template for data save. |
| button_save | Right Stick Left + ZL | Insert template for using button and create button cheat. |
| toggle comment | B + ZL | Comment/uncomment the current line. |
| clear copy stack | + + ZR | Empty the copy stack (inserts blank line if stack is empty). |
| Go to memory | Right Stick Up + ZL | Go to memory explorer if on a defined address. |
| Set GrabA | Left Stick Down + ZR | Set data define as GrabA target. |
| Save & Back | B | Save changes and return to the previous menu. |

## Search Setup Menu

Configure and initiate basic memory searches.

| Button Name | Default Shortcut | Action |
|---|---|---|
| A= | X | Perform an 'equal to A for u32 and equal to A+-1 for f32 and f64' memory search. |
| B= | Y | Set value of B for comparison. |
| C= | Y + ZL | Set value of C for comparison. |
| ==A | L | Perform an 'equal to A for u32 and equal to A+-1 for f32 and f64' memory search. |
| ==*A | L + ZL | Perform an 'equal to A for u32 and equal to A+-1 for f32 and f64' memory search. |
| [A..B] | R + ZL | Search memory for values within the range (A..B), excluding both A and B. |
| u32 | R | Search for unsigned 32-bit integers. |
| f32 | Right Stick Click | Search for single-precision floating-point numbers. |
| f64 | Left Stick Click | Search for double-precision floating-point numbers. |
| Same | Right Stick Up | Search for values identical to previous values. |
| Diff | Right Stick Down | Search for values differing from previous values. |
| ++ | Right Stick Right | Search for values that have incremented from previous values. |
| -- | Right Stick Left | Search for values that have incremented from previous values. |
| <A..B> | - | Search memory for values within the range (A..B), excluding both A and B. |
| More | ZL + ZR + Plus | Show more choices. |
| Back | B | Go back to the previous menu. |
| Toggle Hex mode | (none) | Toggle between hex and decimal display modes. |
| Use BE | (none) | Toggle use of big-endian mode. |
| ==**A | (none) | Perform an 'equal to A for u32 and equal to A+-1 for f32 and f64' memory search. |
| Heap pointer | (none) | Configure search for pointer to heap. |
| Main pointer | (none) | Configure search for pointer to main code and data segment. |
| Main code pointer | (none) | Configure search for pointer to main code segment. |

## Search Setup Menu 2

Configure advanced memory searches with more data types and conditions.

| Button Name | Default Shortcut | Action |
|---|---|---|
| u8 | Y | Search for unsigned 8-bit integers. |
| s8 | L | Search for signed 8-bit integers. |
| u16 | R | Search for unsigned 16-bit integers. |
| s16 | Right Stick | Search for signed 16-bit integers. |
| s32 | Left Stick | Search for signed 32-bit integers. |
| u64 | Right Stick Down | Search for unsigned 64-bit integers. |
| s64 | Right Stick Left | Search for signed 64-bit integers. |
| ptr | ZL | Search for possible pointer values. |
| Hex | - | Change to hexadecimal format. |
| Dec | Right Stick Up | Change to decimal format. |
| != | Right Stick Right | Search for values not equal to a specified value. |
| [A,B] | (none) | Search for value A immediately followed by value B (B in the very next element after A). |
| [A,,B] | (none) | Search for A with B located within the configured distance on either side of A (B can be before or after A). |
| ++Val | (none) | Search for values incremented by a specified amount from previous values. |
| --Val | (none) | Search for values decremented by a specified amount from previous values. |
| STRING | (none) | Search for string values. |
| SAMEB | (none) | Search for values that are identical to the previously stored values in the file marked as B. |
| DIFFB | (none) | Search for values that differ from the previously stored values in the file marked as B. |
| B++ | (none) | Search for values that have increased compared to the previously stored values in the file marked as B. |
| B-- | (none) | Search for values that have decreased compared to the previously stored values in the file marked as B. |
| NotAB | (none) | Search for values that are different from both this file and file marked as B. |
| [A.B.C] | (none) | Search for A with both B and C located within the configured distance of A. B and C can each be on either side of A (not required to be in sequence), and must be at distinct positions. Uses the same distance setting as [A,,B]. |
| A bflip B | (none) | Search for bit-flipping identical to bit-flipping between A and B. |
| Back | B | Go back to the previous menu. |

## Search Manager Menu

The **Search Manager** is the core of Breeze’s powerful file-based memory hacking system.  
Unlike traditional search sessions that are temporary, Breeze saves each step as a distinct file, enabling precise tracking of memory changes over time.

There are two types of files involved:

- **Memory Dump** – a full snapshot of the game’s memory at a specific moment.
- **Candidate File** – a list of address-value pairs that meet your search criteria.

### Workflow

- A **Start Search** or **Memory Dump** creates the initial file.
- A **Continue Search** then refines results by comparing current memory with a previous file — but its behavior depends on the **source file**.

#### Continuing from a Candidate File
- The new file will reflect **current memory values**.

#### Continuing from a Memory Dump
- The first **Continue Search** creates a **Candidate File** using values from the moment the dump was made.
- To get a file reflecting **current memory values**, perform a second **Continue Search** on the candidate file just created.

This design enables accurate, step-by-step refinement while preserving the original state of memory snapshots.

### Search Criteria
The search functionality relies on up to three user-definable values: `A`, `B`, and `C`. These values serve as the primary criteria for memory searches. You can set and modify these values using dedicated buttons within the Search Manager, such as `Edit A`, `Edit B`, `Inc A`, etc.

The specific search mode you select will determine how these values are used. For example, a simple `==A` search will look for memory addresses containing the value of `A`, while a range search `[A..B]` will find values between `A` and `B`.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Simple Search | (none) | Search for value you see on screen in integer, float and double. |
| Search Setup | Y | Select the search type, data type and set value for search. |
| Start Search | X | Start a new search with the current settings. |
| Continue search | Right Stick Click | Continue the previous search. |
| Show Candidates | L | Examine the search results. |
| memory dump | Left Stick Click | Make a full RW memory dump, preparation for unknown search. |
| Copy condition | Right Stick Click + ZR | Copy the search condition of the selected file. |
| Rename | Left Stick Click + ZR | Rename the selected file. |
| Delete file | - | Delete the selected file. |
| Look | ZR + Plus | Look at the game screen. |
| CapturedScreen | + | Choose between captured screen or current screen. |
| MJ preset | Right Stick Click + ZL | Set to search float between 0.1 and 3000. |
| Invert | R + ZL | Flip the sign of the current search. |
| [A..B]f.0 | ZL + Right Stick Left | Search for floating point value without decimal. |
| ExpandMenu | ZL + ZR + Plus | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Select B | X + ZL | Choose the file to use for previous value. |
| GetB | B + ZR | Make a new file with previous value==A retrived from B file. |
| GetB | ZR + Right Stick Down | Make a new file with previous value==A retrived from B file. |
| Advance search | R | Setup advance search. |
| Pointer Search | Y + ZR | Experimental exploration on forward search of pointers, not ready for daily use. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Edit String | ZR + Right Stick Left | Setup a string search. |
| Toggle Hex mode | ZR + Right Stick Right | Switch search values and related addresses between hexadecimal and decimal presentation. The underlying bits do not change. |
| Main only | X + ZR | Save time, if you know it is in main then only search main. |
| A,,B distance | ZR + Right Stick Up | Set the maximum distance (in elements) between A and the other value(s) for proximity searches [A,,B] and [A.B.C]. The window extends this many elements on both sides of A. |
| AutoContinue | ZR + Right | Automatic naming based on the filename of the previous file. |
| AutoStart | ZR + Left | Choose the smallest available number when you start a new search. |
| ConfirmDelete | ZR + Down | Whether ask for comfiramtion before deleting file. |
| VisibleOnly | ZR + Left Stick Down | Choose whether you can use short cut to buttons not visible. |
| Edit A | Right Stick Left | Set value of A for comparison. |
| Edit B | Right Stick Right | Set value of B for comparison. |
| Inc A | Right Stick Up | Increment value A. |
| Dec A | Right Stick Down | Decrement value A. |
| Express Search Setup | (none) | Perhaps a faster way to setup search. |
| EQ cycle | L + ZL | Cycle through equality search modes. |
| SAME cycle | ZL + Up | Cycle through same value search modes. |
| DIFF cycle | ZL + Down | Cycle through different value search modes. |
| LESS cycle | ZL + Left | Cycle through less than search modes. |
| MORE cycle | ZL + Right | Cycle through greater than search modes. |
| uint type | Y + ZL | Cycle through unsigned integer types. |
| Float type | Left Stick Click + ZL | Cycle through float types. |
| RANGE type | ZL + Plus | Cycle through range search modes. |
| Edit C | ZL + Right Stick Right | Set value of C for comparison. |
| Rebase | ZL + Minus | Rebase search results from previous game session when posible. |
| Inc B | ZL + Right Stick Up | Increment value B. |
| Dec B | ZL + Right Stick Down | Decrement value B. |
| Klass | ZR + Left Stick Left | Starts the Unity class (Klass) search that the runtime IL2CPP tools use. |
| KlassGlobals | ZR + Left Stick Right | Finds the IL2CPP TypeInfo globals in the main module and creates named bookmarks for them. |

## Candidate Menu

The Candidate Menu is where you can view and interact with the results of a memory search. After performing a search in the Search Manager, the addresses that match your criteria are listed here as "candidates." This menu provides a powerful set of tools to inspect, modify, and analyze these candidates, helping you pinpoint the exact memory addresses you need for your cheats.

If you have a large list of candidates, there are two primary methods for narrowing them down:

1.  **Refine the Search**: Return to the **Search Manager Menu** and perform a **Continue Search** with more specific criteria (e.g., searching for values that have changed, increased, or decreased). This iterative process is key to isolating the exact address you are looking for.
2.  **Batch-Test Candidates**: The Candidate Menu also includes powerful tools to test changes on many candidates at once. Functions like `Freeze100`, `Set1000`, and `Inc1000` allow you to apply a change to hundreds or thousands of candidates simultaneously. By observing the effect in-game, you can quickly determine if any of the modified candidates control the desired behavior, providing another method for rapidly narrowing down a large result set.

3.  **Label the Candidates**: `Add field label` names the class and field each address falls inside, using live runtime data -- no dump.cs required. This is less useful as a filter than it sounds, since most heap addresses do land inside some object, but it is very useful as a *reading*: a candidate on `Inventory.numberOfSlots` is worth testing and one on `Image.m_Maskable` is not.

    > **Warning:** Be cautious when batch-modifying integer values. An integer candidate may actually be part of a pointer or other critical data structure. Modifying it can easily lead to crashes or other unexpected behavior. Batch-testing is generally safer with floating-point values, which are less likely to be integral parts of the game's core structure.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Freeze Memory | X | Freezes or unfreezes the value at the selected memory address, preventing it from changing. |
| Edit Memory | Y | Opens an editor to modify the value at the selected memory address. |
| Add Bookmark | + | Saves the selected memory address to your bookmarks for easy access later. |
| Mode toggle | Left Stick Click | Cycles through different display modes for memory values: `smart` (context-aware), `base` (decimal), and `hex` (hexadecimal). |
| Memory Explorer | Right Stick Click | Opens the Memory Explorer at the selected address for a more detailed view of the surrounding memory. |
| Bookmark | L | Opens the Bookmark Menu. |
| Page Up | Right Stick Up | Navigates to the previous page of candidates. |
| Page Down | Right Stick Down | Navigates to the next page of candidates. |
| Freeze100 | (none) | Freezes the next 100 candidate values starting from the cursor. |
| Unfreeze100 | (none) | Unfreezes the next 100 candidate values starting from the cursor. |
| Inc1000 | (none) | Incrementally adds a specified value to the next 1000 candidates. |
| Set1000 | (none) | Sets the next 1000 candidates to a specified value. |
| Revert1000 | (none) | Reverts the next 1000 candidates to their original values. |
| Revert | L + ZL | Reverts the value at the selected address to its original value from the search. |
| Change Type -> | R | Cycles backward through the available data types. |
| Change Type <- | Y + ZL | Cycles backward through the available data types. |
| Expand menu | ZL + ZR + Plus | Switch between focused/compact and expanded action presentation so additional buttons can be selected. |
| Back | B | Returns to the previous menu. |
| Expand screen | R + ZR | Toggles the width of the left panel to show more or less information. |
| Last Page | - | Jumps to the last page of the candidate list. |
| First Page | Right Stick Left | Jumps to the first page of the candidate list. |
| First Target | ZL + Minus | In pointer search mode, this jumps to the first target in the list. |
| GotoSource | Right Stick Click + ZL | In pointer search mode, this jumps to the source of the pointer. |
| Klass view | R + ZL | Interpret candidates through the Unity/IL2CPP class view. Class metadata and field layouts must match the running build. |
| Write info to file | (none) | Exports the current list of candidates to a text file for external analysis. |
| Save Position | Left Stick Click + ZL | Remembers the current position in the candidate list. |
| Goto Position | Left Stick Click + ZR | Returns to the position remembered with Save Position. |
| Add field label | X + ZL | Names what each candidate address is: the class and field it lies in. Use it to group a candidate list by label. |
| Class field | Y + ZL + ZR | Opens the class field view of the object the selected candidate lies in. |
| Lua bookmark | X + ZR | Saves the selected value as a Lua bookmark, which stores its path by name so that it survives a game restart. |
| Find chain | Y + ZR | Searches for a pointer chain from a static root to the object that holds the selected candidate (Unity and Godot games). |

## Bookmark Menu

Save, manage, and utilize memory address bookmarks.

| Button Name | Default Shortcut | Action |
|---|---|---|
| SearchBookmark | Y + ZR | Search for a value and put the entries that match into the chosen bookmark file. |
| SearchSetup | X + ZR | Setup the search, default is the value on the cursor. |
| Toggle Freeze Memory | X | Remember the current value and periodically revert to it. |
| Edit Memory | Y | Edit the value at the bookmarked memory address. |
| Edit Label | + | Edit the label of the selected bookmark. |
| Bookmark to Cheat | Y + ZL | Create a cheat based on the information in the selected bookmark. |
| Mark To Delete | - | Select an entry to be deleted upon Perform Clean up. |
| Perform Clean up | ZL + Minus | Remove entries marked for delete or that have bad pointers that cannot be resolved. |
| Memory Explorer | Right Stick Click | Open the Memory Explorer at the bookmarked address. |
| Add field label | L + ZL | Names what each bookmark address is: the class and field it lies in. |
| Class field | Y + ZL + ZR | Opens the class field view of the object the selected bookmark lies in. |
| Pointer Search | X + ZL | Search for pointers to this memory address. |
| JumpBackMatch | B + ZL | Use the pointer in this bookmark to assist with a pointer search. |
| ChangeType | R + ZL | Change the data type of the bookmark. |
| Page Up | Right Stick Up | Go to the previous page of bookmarks. |
| Page Down | Right Stick Down | Go to the next page of bookmarks. |
| ExpandMenu | ZL + ZR + Plus | Show more buttons. |
| Back | B | Go back to the previous menu. |
| AppPtrSearch | (none) | Change the target to this bookmark or setup an application pointer search. |
| Delete All Bookmark | (none) | Deletes all bookmarks in the current file. |
| FileSelection | R | Select a different bookmark file to use. |
| RememberLast | (none) | Toggle whether to remember the last bookmark file used. |
| Expand screen | R + ZR | Toggle the width of the left panel. |
| Import Bookmarks | ZL + Plus | Import bookmarks from Pointersearcher SE. |
| Toggle Absolute Address | L | Toggle between relative and absolute addresses. |
| Mode Toggle | Left Stick Click | Toggle between smart, base, and hex display modes. |
| Last Page | Right Stick Right | Go to the last page of bookmarks. |
| First Page | Right Stick Left | Go to the first page of bookmarks. |
| MiscPointers | (none) | Add some useful bookmarks. |
| Export text | ZL + Right Stick Down | Export bookmarks to a text file. |
| ADRP pointer | (none) | Scans the main module's code for `ADRP` instructions, follows them to static pointers and adds the results to the bookmark file as `ADRP_1`, `ADRP_2` and so on. |

## Memory Explorer Menu

Directly view and edit memory, and navigate pointer chains.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Jump Forward | Y | Go to pointer target address. |
| MoveLeft | B + ZL | Move left on the pointer chain (jumpback). |
| MoveRight | Y + ZL | Move right on the pointer chain (jumpforward). |
| Edit Memory | X | Edit memory according to the displayed type. |
| Add Bookmark | + | Add cursor address to bookmark. |
| Change Type -> | R + ZL | Cycle to the previous data type. |
| Mode Toggle | Left Stick Click | Toggle between smart, base, and hex display modes. |
| Expand menu | ZL + ZR + Plus | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Expand screen | R + ZR | Toggle the width of the left panel. |
| JumpBack | Y + ZR | Go to jumpback menu for pointer search. |
| Align address | R | Make current address the center of the page. |
| Page Up | Right Stick Up | Go to the previous page. |
| Page Down | Right Stick Down | Go to the next page. |
| Last Page | Right Stick Right | Go to last page of segment. |
| First Page | Right Stick Left | Go to first page of segment. |
| Toggle ValueBookMark | ZR + Right Stick Up | Show or hide the datatype line at the bottom of the left panel. The pointer chain holds the top line either way. |
| Load field view | ZR + Left Stick Up | Reopens a saved field view. On a Unity game with no `dump.cs` it follows the view's saved pointer chain to the object as it is now. |
| SetBreakPoint | ZL + Up | Set break point on address. |
| ASM Explorer | X + ZL | Go to ASM explorer. |
| Save to file | ZL + Right Stick Down | Write data on left panel to file. |
| Copy | ZL + Left | Copies the value at the cursor to the explorer's paste buffer and pushes it as text onto Breeze's copy stack. |
| Copy address | L + Left | Pushes the cursor's address as `0x...` onto Breeze's copy stack. Paste it into any keyboard with `ZL + X`. |
| Paste | ZL + Right | Paste value. |
| Move to A | ZL + Right Stick Left | Move to address A. |
| Extra_menu | ZL + Minus | Switch to button arrangement for temdem display. |
| Look | ZR + Plus | Look at game screen. |
| Left | ZR + Left | Set and move left by set amount. |
| Right | ZR + Right | Set and move right by set amount. |
| =0000 | ZR + Left Stick Left | Shows the offset built up with the Left and Right steps and resets it to 0. |
| A | L + Right Stick Left | Enter a value for search. |
| Find next | L + Right Stick Down | Search forward for address that has value A. |
| Find previous | L + Right Stick Up | Search barkward for address that has value A. |
| Frz_setting | B + L | Chooses how Toggle Freeze behaves for the value at the cursor. |
| Dump_Segment | Y + L | Dump current segment to file for search manager use. |
| Dump_area | X + L | Dump area around current address for search manager use. |
| Class field | Y + ZL + ZR | Opens the class field view of the object the cursor is inside. |
| Class field down | X + ZL + ZR | Opens the class field view of the object that starts at the cursor. |
| Toggle_align | Left Stick Click + ZR | Toggle between aligned column or simple display line with no alignment. |
| Change Type <- | L + ZL | Cycle to the previous data type. |
| Set tandem | X + ZR | Push current address to tandem list. |
| Clear tandem | B + ZR | Clear tandem list. |
| Save tandem list | ZR + Right Stick Down | Save tandem list. |
| Load tandem list | ZR + Down | Load saved tandem list. |
| Append tandem list | ZR + Left Stick Right | Append current address to saved tandem list. |
| Edit String | ZR + Right Stick Left | Edit current address as c string, also make a copy. |
| Paste String | ZR + Right Stick Right | Paste string form Edit String to address. |
| CopyPasteQty | ZL + Right Stick Up | Set copy paste quantity. |
| PasteMultiple | Right Stick Click + ZR | Paste multiple values from the clipboard. |
| EditOffset | ZL + Plus | Edit the offset of the bookmark. |
| ClearTilEndofPage | Left Stick Click + Right Stick Click + ZL | Writes zero from the cursor to the end of the page. It wipes memory, so it keeps a deliberate three-button shortcut. |

## ASM Explorer Menu

The ASM Explorer allows for in-depth analysis of disassembled code directly from memory. It is an essential tool for reverse engineering and understanding how a game functions at a low level. You can set breakpoints, edit instructions on the fly, and navigate through code to identify key logic for cheat development.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Step into | R + ZL | Executes one instruction and stops, following a call into the function. Enabled while the game is stopped by Break and Trace. |
| Stop Break and Trace | ZL + Minus | Ends Break and Trace, removes its breakpoints and lets the game run. |
| Step over | L + ZL | Executes one instruction and stops, running a called function to its return. Enabled while the game is stopped. |
| Goto PC | ZR + Right Stick Up | Moves the cursor to the instruction the game is stopped on. |
| Continue | ZL + Plus | Lets the game run again until the next breakpoint. Enabled while the game is stopped. |
| Threads | ZR + Right Stick Down | Lists the game's threads while it is stopped. |
| Break point | X + ZL | Sets or clears a breakpoint on the instruction at the cursor. The row is marked `*BP`. |
| Follow branch | R | Go to the target of this branch instruction. |
| Temp break point | - | Sets a one-shot breakpoint on the instruction at the cursor. The row is marked `*bp`. |
| Detail | X + ZR | Shows details of the instruction at the cursor. When the function name came from the runtime IL2CPP map, it opens the method list of the owning class with the cursor on that method. |
| Breakpoints | ZL + Right Stick Left | Lists the breakpoints that are set. |
| ASMedit | X | Directly edit game code (not recommended). |
| Memory at operand | ZL + Right Stick Right | Opens the Memory Explorer at the memory address the instruction at the cursor refers to, in the data type the instruction uses. Enabled while the game is stopped. |
| MemoryExplorer | Right Stick Click + ZL | View this address in memory explorer. |
| Registers | ZR + Plus | Shows and edits the CPU registers, with X and V registers on separate pages. Enabled while the game is stopped. |
| Add to Cheat | Y + ZL | Make a cheat with this ASM as the hook. |
| Stack | Left Stick Click + ZR | Shows the stack of the stopped thread. Enabled while the game is stopped. |
| Back | B | Return to the previous menu. |
| Watch instruction | L | Place a watch on this instruction and go to the Gen2 Menu for dynamic analysis. |
| Copy instruction | Y | Push code to the paste stack of cheat editor and asm composer. |
| Write info to file | + | Write information on the left panel to a file. |
| Expand screen | R + ZR | Toggle the width of the disassembly panel. |
| Page Up | Right Stick Up | Go to the previous page of disassembly. |
| Page Down | Right Stick Down | Go to the next page of disassembly. |
| Branch_to above | ZL + Right Stick Up | Perform a scan for and move to the branch target above the current address. |
| Branch_to below | ZL + Right Stick Down | Perform a scan for and move to the branch target below the current address. |
| Goto Source | Right Stick Click | Jump to the caller or base pointer of this instruction. |
| Function Up | Right Stick Left | Moves to the start of the previous function, using every function map that is available. |
| Function Down | Right Stick Right | Moves to the start of the next function. |
| IL2CPP map | Y + ZR | Opens the IL2CPP map screen to build function and field names for a Unity game. |
| Script functions | (none) | Lists the functions found in a native game's script binding tables, with a filter. Select one to open it here. |
| AutoSave | (none) | Toggle whether to automatically save the cheat list to file after using "Add to Cheat". |

## Runtime Method List (Unity / IL2CPP)

Lists a class's methods read directly from `Il2CppClass.methods` in live memory,
with no `dump.cs` required. Open it from the class Field View with **Methods**
(`L + ZR`), or from ASM Explorer's **Detail** when the current function name came
from the runtime function map.

Rows show `flags name(parameters) : return type` and the live address, for
example `S TakeDamage(float amount) : void  main+0x1A42F0`. Flags are `S` static,
`V` virtual, `A` abstract. `<no code>` means the method was inlined or stripped
and cannot be hooked.

| Button Name | Default Shortcut | Action |
|---|---|---|
| ASM Explorer | X | Open the selected method in ASM Explorer. |
| Class field | R | Open the Field View for this class. |
| Visit type | Y | List the classes and structs in the selected method's signature. |
| Resolve type names | L + ZR | Resolve `class` / `valuetype` placeholders to real type names. One-time cost. |
| Build function map | Y + ZR | Open the IL2CPP Function Map menu. |
| Write to file | Minus + ZR | Append the list and layout diagnostics to `runtime_methods.log`. |
| Page Up | StickRUp | Previous page. |
| Page Down | StickRDown | Next page. |
| Back | B | Return to the previous menu. |

### Visit Type Menu

Lists every class or struct appearing in one method's signature, so you can move
from a signature to the type's own definition.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Class field | X | Open the Field View for the selected type. |
| Methods | Y | Open the Runtime Method List for the selected type. |
| Back | B | Return to the previous menu. |

## IL2CPP Function Map Menu

Generates `il2cpp_function_map.txt` by walking every klass in `Klass.dat` and
recording each method's name and address. Once built, ASM Explorer shows Unity
function names and **Function Up / Function Down** work without `dump.cs`.

Requires **Search → Klass** first. The screen reports klasses scanned, methods
written and methods skipped, and reloads the names on completion so no restart
is needed. The build can be aborted; a partial file is still usable.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Build / Abort | X | Builds the IL2CPP function map from the running game, or stops a build that is running. The map is saved as `il2cpp_function_map.txt` in the game folder. |
| Back | B | Return to the previous menu. |
| Build field map | Y | Builds the IL2CPP field map: every field of every class with its offset and type, saved as `il2cpp_field_map.txt` in the game folder. |

## Jump Back Menu

The Jump Back Menu is designed for multi-level pointer searching, a powerful technique for finding stable pointers to dynamic memory addresses.

### What is Pointer Searching?
In game hacking, the memory address for a value like player health can change each time the game is launched. A pointer is simply a memory address that holds the value of another memory address. Pointer searching is the process of finding a sequence of pointers—a "pointer chain"—that starts from a static, unchanging base address (usually in the game's main code) and, after applying a series of offsets, reliably leads to the desired dynamic data. This allows cheats to work across different game sessions.

### The Methodology
The Jump Back menu automates this by working backward from a target address you've identified (the "node"). It scans memory for any addresses that point to your target, building a "pointer map" of potential chains. The process is iterative:
1.  **Start**: Begins a search for pointers pointing to the initial set of target addresses (nodes).
2.  **Next Depth**: Takes the pointers found in the previous step and searches for pointers that point to *them*, effectively moving one level up the chain toward a static base address.
This continues until a stable path from a static address is found.

A node does not store the chains that reach it. It stores one edge per parent and offset, and complete chains are rebuilt from those edges only where one is actually needed -- writing a bookmark, drawing a row, saving a map. This is why a deep search stays within memory: storage grows with the number of hops recorded rather than with the number of distinct paths, which multiplies at every depth. One consequence is that the map for every depth is kept, so a search can be rewound to an earlier depth and continued from there, and a saved map restores that whole history.

The heap is watched while a search runs. The scan and the expansion both stop and report while there is still memory to report with, rather than failing on an allocation, and `free` on the scan status line shows what is left. If a depth does run out, next depth is blocked until the search is rewound or restarted -- the map that filled the heap is still in it. Every stage is written to `jumpback_memory.log` with the settings that applied to that depth, so a run can be read back afterwards.

### Search Parameters
The search process is governed by several key parameters that help refine the results and manage performance:
- **`search_depth`**: Sets the maximum number of levels (jumps) the search will automatically perform in "Goto depth" mode.
- **`num_offsets`**: Restricts the search to using only the specified number of nearest-offset pointers for the next depth, pruning less likely candidates.
- **`search_range`**: Defines the maximum valid offset value for a pointer. This helps filter out invalid pointers and focus the search.
- **`Max per node`**: Limits how many pointers are found for each target address in a given search step, preventing the results from being flooded by a single, heavily-referenced node.
- **`Max edge/node`**: Limits how many incoming edges one node keeps, bounding fan-in. `0` means unlimited, which is usually the right setting -- paths are no longer stored, so this is far less load-bearing than it sounds.
- **`Final offset range`**: The largest offset that will still produce a bookmark. A landing further from the node than this is used to continue the search but does not record a chain.
- **`Land on class`**: Controls whether a hop is accepted when its pointer does not land on an object base. A pointer landing on offset 0 of a class records a real field offset; one landing inside an array records an index times a stride, which shifts as soon as the game inserts an element earlier in that array. `strict` skips landings that are not object bases and drops a node that has none; `prefer` does the same but falls back to a node's ordinary landings when it has no class landing, so no node is lost; `off` is the original behaviour. The decision is made per node, and the mode is read when a depth is expanded, so it can be changed between depths.

When the filter is on, `num_offsets` counts *class* landings -- a landing that fails the filter is skipped without consuming the budget. A node still yields between zero and `num_offsets` of them and nothing can make it produce landings it does not have, so the Analyse list marks which ones it will really use.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Select | X | Go to memory address of the node. |
| Analyse | Y | Details on the pointers to this node. Rows are marked `>` for a landing this node will actually use, `*` for one that starts an object, and `^` for one stored under a lower node. With field labels on, the label says *which* class a landing starts. |
| Start | L | Start search for pointers to node addresses. |
| Unity B8 pointer scan | (none) | Run JumpBack's Unity-oriented special scan for a two-step chain whose first structure offset is 0xB8, a layout frequently encountered in Unity objects. |
| next depth | R | Recode bookmark and move search back to source by one jump. |
| get depth+1 ptr | (none) | Recode bookmark without moving to next depth. |
| Goto depth | ZL + Plus | Continue search until specified depth is reach or out of memory. |
| Rewind to depth (now 0) | ZR + Left | Returns the search to an earlier depth without starting again. |
| search_depth | + | Set depth to stop for auto mode. |
| num_offsets | ZL + Left | Number of nearest offset to use for next step. |
| search_range | ZL + Right | The maximum offset accepted by the search. |
| Final offset range | ZR + Right | Largest offset that will still record a bookmark. |
| Name | X + ZL | Name the search, bookmark recorded will bear this name. |
| Max per node | ZL + Down | Set max pointer per node. |
| Max edge/node | ZR + Down | Incoming edges kept per node. 0 = unlimited. |
| Land on class | Y + ZL | Cycles off / prefer / strict. Strict skips a landing that is not the start of an object; prefer falls back to an unfiltered depth when nothing would be found. |
| Unity | ZL + Up | Toggle Unity-aware pointer analysis. Enable it for appropriate Unity/IL2CPP targets; engine assumptions may exclude valid results in other games. |
| Bookmark menu | R + ZL | Bring you to bookmark menu. |
| Save_Map | ZL + Right Stick Down | Save every depth of the search, with the root and the bookmark list. Sources are not saved. |
| Load_Map | ZL + Right Stick Up | Restore a saved search, its depth history included. Press Start afterwards to rebuild that depth's sources. Only valid while the game session that produced it is still running. |
| Delete Offset | - | You can delete an offset if you know it is not the right one. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Back | B | Go back to the previous menu. |
| Write info to file | (none) | Write data on left panel to file. |
| Screen Map | ZL + Minus | Implementation incomplete, ignore this. |
| Add field label | L + Up | Cycles off, on, filtered. Names the class and field each node, landing or pointer-map address falls inside. |
| Page Up | Right Stick Up | Move the data list upward by one page without changing its contents. |
| Page Down | Right Stick Down | Move the data list downward by one page without changing its contents. |
| Trim | Y + ZR | Scan every node in the map, tally the distinct labels, and open the Trim screen below. |

### Trim by Label

Trim scans every node in the current map, resolves the class field each one
falls inside, and lists the distinct labels largest group first with a count and
a keep flag. It is the practical way to cut a large map down: removing the
unlabelled nodes only takes about 18% off a list, but a few thousand nodes
typically carry only a couple of hundred distinct labels, and most of the big
groups are engine and UI noise that announce themselves as things to skip.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle keep | X | Mark this label's nodes to survive an Execute. |
| Analyse this label | Y | Show only this label's nodes in the node list, with every normal node action available. Back returns here with the selection and cursor intact. |
| Execute | R | Remove every node whose label was not kept. Takes two presses: the first reports how many nodes would go, the second does it. Changing any selection disarms it. |
| Save to file | L | Write the list, keep flags included, to `node_labels.txt` in the game folder. |
| Keep all / Clear all | + / - | Set or clear every keep flag. |
| Back | B | Return to the node list, changing nothing. |

The scan is bounded by reads rather than by nodes, and reports `[scan
truncated]` when it stops early. **A truncated scan blocks Execute**: nodes past
the point the scan reached were never labelled, and removing everything not
selected would delete them on the strength of labels that were never read.
Analyse still works, since it only looks at what is on screen.

## Gen2 Menu

The Gen2 Menu is a powerful dynamic analysis tool for creating advanced cheats by watching memory and capturing data about how and when it's accessed. Instead of just searching for static values, you can monitor a memory address or region to see exactly what code is reading from or writing to it. The core workflow involves setting up a watch, specifying the access type to look for (read/write), and defining what data to capture when a trigger occurs—most importantly, the return address (X30) of the function that accessed the memory. This is invaluable for understanding game logic and finding the precise code to modify.

Attaching gen2 no longer disturbs dmnt's cheat engine. dmnt and dmnt.gen2 share a single debug handle, so gen2 joins it rather than taking the game away — your cheat list, toggles and frozen addresses survive an attach/detach cycle untouched, and cheats keep running while a capture is in progress. One consequence worth knowing: your cheats keep being applied 12 times a second while you debug, so anywhere a cheat writes, it keeps writing. A value frozen on the address you are watching will trigger the watch with the cheat VM's own writes; and a breakpoint set on an instruction that an enabled cheat writes to — an ASM hack re-applying its patch, a type-0 write, a code cave — is overwritten within a tenth of a second and never fires. The symptom is a breakpoint that hits when execution reaches it immediately but never when you have to go and do something in game first; disable that cheat while debugging that address. If you do want the cheat VM reset, it is now an explicit action — `Reset CheatVM` in the cheat menu.

You will typically enter this menu from the Memory Explorer when watching a specific memory address, or from the ASM Explorer when analyzing a piece of code. Once configured, you attach Breeze as a debugger, execute the watch to capture data while the game runs, and then detach to examine the results. This cycle allows you to iteratively refine your understanding and pinpoint the exact code responsible for the behavior you want to change.

### Workflow

1.  **Watch Memory Access**: Start by watching a memory address to see what code accesses it.
2.  **Choose a Code**: Select a code from the captured data that you suspect is related to the action you want to modify.
3.  **Verify Uniqueness**: Check if the chosen code's access is unique to the target. If so, proceed to the next step. Otherwise, test other codes from the list to find a unique one. If none are unique, additional filtering methods will be needed.
4.  **Create Cheat**: Once a uniquely accessing code is identified, you can create a cheat to modify its behavior.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Return slot/count | (none) | This shared Gen2 value sets how many plausible return addresses the next watch captures by scanning upward from SP. |
| Call-site source | L + ZL | Choose what dmnt.gen2 stores and later compares as the call-site discriminator: the live X30 offset, a return address read from a selected stack slot, a captured register match, or one of the specialist search modes. |
| Stack slot | (none) | Set the stack slot used when Call-site source is STACK. dmnt.gen2 reads a 64-bit value at SP plus this value times 8; the label shows both the slot number and byte offset. |
| Read | ZL + Up | Toggle the read flag. |
| Write | ZL + Down | Toggle the write flag. |
| SearchSetup | Y | Go to search setup to change data type. |
| Gen2Attach | + | Attach dmnt.gen2 to the game and change the data display mode. This no longer detaches dmnt: the cheat VM, your toggles and your frozen addresses are left alone. |
| Execute Watch | R | Start the data capture, go back to game to let it do the work. |
| Break and Trace | R + ZL + ZR | Arms Break and Trace on the selected address: the game stops when the instruction or memory access is hit. See the Break and Trace Guide. |
| Break filter | Y + ZL | Restricts Break and Trace to hits from a chosen instruction address or call context, so that it stops only on the event you want. |
| Break and Trace view | L + ZL + ZR | Opens the ASM Explorer at the address where Break and Trace last stopped. |
| Name and Execute | ZL + Plus | Name the watch and then execute it. |
| Rename+Save | (none) | Renames the current capture and saves it. |
| Gen2Detach | - | Stop the capture to perform action on the results. Leaves dmnt's cheat VM untouched; use `Reset CheatVM` in the cheat menu if you actually want it reset. |
| Select | X | Go to selected address or instruction. |
| goto call | X + ZL | Go to the caller address. |
| X30_match | R + ZL | Check the value of X30 current or stored on stack and only capture if match. |
| Capture [A] | ZL + Right | Toggle capture of extra values beginning at the memory address stored in search value A. dmnt.gen2 appends these values after the captured return-address slots; A must be a readable address. |
| Capture register | (none) | Toggle capture of the ARM64 register selected by the R= control. The value is stored after the return-address slots and can later be used to configure a register-value match. |
| R | (none) | Set the register to grab. |
| Match captured register | (none) | Use the selected capture row's saved register value as a filter for the next Gen2 watch. |
| Range Check | ZL + Left | Only capture when value falls in the range between A and B. |
| More | ZR + Down | Configure the button panel for stack watch data. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Back | B | Go back to the previous menu. |
| Save as candidates | L | Save the list of address and value for use with search manager. |
| Next results | ZL + Right Stick Right | Navigate data recorded from previous capture. |
| Pre results | ZL + Right Stick Left | Navigate data recorded from previous capture. |
| LastLoad | ZL + Right Stick Up | Jump to record that was used to start a new run. |
| Erase old results | (none) | Erase all the recorded data. |
| Set Max trigger | (none) | The run stops when total number of trigger reach this number. |
| Look | ZR + Plus | Look at the game screen. |
| Class field | Y + ZR | Opens the class field view of the object the selected capture address lies in. |
| Add method label | Left Stick Click + ZL | Puts the method name on every captured instruction row. |
| View caller | Left Stick Click + ZR | Opens the caller of the selected captured instruction. |
| Write info to file | ZL + Minus | Write data on the left panel to a file. |
| Increment Offset | ZR + Right | Increment the offset. |
| Decrement Offset | ZR + Left | Decrement the offset. |
| Set Offset | L + Up | Set the offset. |
| Refresh | Right Stick Click + ZL | Reads the capture results again. |

## Gen2 Extra Menu

The Gen2 Extra Menu provides a suite of tools to process and analyze the data captured by the Gen2 Menu, with the ultimate goal of automating the creation of Assembly (ASM) cheats. After capturing a set of memory access events, you can use this menu to sort the data, find unique code paths (X30 values), and perform exclusive searches to eliminate irrelevant code. Its most powerful features can automatically generate ASM scripts (`make match all`, `make match 1`) based on the captured data, allowing you to quickly create complex cheats that replicate or modify game logic with high precision.

The `x30` register, or Link Register (LR), is central to understanding program flow, as it holds the return address for function calls. The `BL` (Branch with Link) instruction automatically updates `x30` with the address of the next instruction, but its value is volatile and must be explicitly saved to the stack by software to survive nested function calls.

The Gen2 menu’s hardware watchpoints can capture both the current `x30` value and several values from the top of the stack. By analyzing these captured stack entries, you can often find saved `x30` values from earlier in the call chain. This provides invaluable context for low-level memory accesses, helping you trace them back to higher-level game logic—such as identifying whether an action affects an ally or an enemy.

- **`ASM match selected return`** (was `make match 1`): Creates a cheat that triggers if *either* the current `x30` or one of the selected stack values matches the captured data. This is useful for finding a single, reliable hook point.
- **`ASM match all returns`** (was `make match all`): Creates a more restrictive cheat that triggers only when *both* the current `x30` and *all* selected stack values match the captured state, ensuring maximum precision.

A successful cheat is achieved when these conditions isolate a memory access to only the desired target.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Sort | ZR + Down | Sort the captured data by address. |
| Find unique | ZR + Left | Search for unique x30 (watch or stack) value for the address selected. |
| Sort by count | L + Up | Sorts the captures by how many times each was hit. |
| Return slot/count | ZR + Right | This shared Gen2 value sets how many plausible return addresses the next watch captures by scanning upward from SP. |
| ASM match all returns | B + ZR | Generate an ASM hook template that checks the live X30 call site and every captured stack return position. |
| ASM match selected return | Y + ZR | Generate an ASM hook template that checks only the return position selected with Cursor Left/Right. It uses either live X30 or the chosen stack slot and matches the captured return address's restart-invariant low address portion. |
| Make GM cheat | Right Stick Click + ZR | Builds a GameMaker cheat from the selected capture row, using a hook shared by every variable of the game. |
| Exclusive Search (WIP) | X + ZR | Work in progress. It uses captured call-site fingerprints to retain the selected target's path while eliminating data lines whose fingerprint also permits other captured addresses. |
| DeleteEntry | (none) | Remove the data line selected, so the next line can be tested in ExclusiveSearch. |
| Expand menu | ZL + ZR + Plus | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Write info to file | ZR + Plus | Write data on the left panel to a file. |
| Pre results | ZL + Right Stick Left | Navigate data recorded from previous capture. |
| Next results | ZL + Right Stick Right | Navigate data recorded from previous capture. |
| Cursor Left | Right Stick Left | Selects the previous captured return slot. |
| Cursor Right | Right Stick Right | Selects the next captured return slot. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Select | X | Go to selected address or instruction. |
| goto call | X + ZL | Go to the caller address. |
| Execute Watch | R | Start the data capture, go back to game to let it do the work. |
| Break and Trace | (none) | Arms Break and Trace on the selected address. |
| Gen2Detach | - | Stop the capture to perform action on the results. Leaves dmnt's cheat VM untouched; use `Reset CheatVM` in the cheat menu if you actually want it reset. |
| Gen2Attach | + | Attach dmnt.gen2 to the game and change the data display mode. This no longer detaches dmnt: the cheat VM, your toggles and your frozen addresses are left alone. |
| X30_match | R + ZL | Check the value of X30 current or stored on stack and only capture if match. |
| Show capture fields | (none) | Open a diagnostic dialog showing the selected Gen2 record's raw packed i, j, k, and offset fields. This is a developer inspection aid; it displays decoding inputs and does not perform validation or repair. |
| View caller | Left Stick Click + ZR | Opens the caller of the selected captured instruction. |

## Search Items Editor (Advance Search)

Opened with **Advance search** in the Search Manager. It builds a search for several values that sit near each other in memory, one item per row, with a gap allowance between them.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Start Search | X | Start a new search from the currently configured conditions. Save any useful existing search, then verify region, type, comparison mode, and input values. |
| Continue search | Right Stick Click | Refine the active candidates after changing or observing the value in the game. Ensure the new comparison or value describes what happened since the previous search. |
| Set Target | L | Set the selected search item as the target used by the advanced search sequence. Confirm its address or condition before starting the sequence. |
| Normal search | B | Returns to the Search Manager. |
| Ptr | R | The item must be a valid address within the game's memory. |
| NotPtr | B + ZL | The item must not be a valid address within the game's memory. |
| Gap | ZL + Right | Adds a gap item: anything can be in the gap. |
| Gap allowance | ZL + Left | Allows one or more gaps, up to the given count. |
| Add Below | + | Adds a search item below the cursor. |
| Add Above | ZL + Right Stick Left | Adds a search item above the cursor. |
| Cut item | - | Remove the selected item and place it on the context-specific clipboard so it can be pasted elsewhere. |
| Edit A | Right Stick Left | Edit value A for the selected search condition. A is usually the primary known value or lower bound; its exact role depends on the displayed comparison mode. |
| Edit B | Right Stick Right | Edit value B for the selected search condition. B is used by range and two-value conditions; it may be ignored by single-value modes. |
| ExpandMenu | ZL + ZR + Plus | Shows more actions. |
| Copy item | Y | Copy the selected item to Breeze's context-specific clipboard without removing it. |
| Search Setup | Left Stick Click | Open detailed search-condition setup. Choose memory region, value type, comparison mode, and A/B values before starting or continuing. |
| Toggle Skip | ZL + Up | Include or skip the selected advanced-search step. Skipped steps remain in the sequence but are not applied during the search. |
| Integer type | Y + ZL | Cycle through integer widths and signed interpretations. Choose a type matching how the game stores the value; changing type changes search and edit width. |
| Float type | Left Stick Click + ZL | Cycle through floating-point types, normally f32 and f64. Most game decimals are f32, but verify by observing stable candidate behavior. |
| RANGE type | ZL + Plus | Cycle the range comparison applied to A and B. Ensure the bounds are ordered and match the selected numeric type. |
| EQ cycle | L + ZL | Cycle equality-related comparison modes for the selected condition. The displayed mode determines whether A, B, or prior values are compared. |
| Expand screen | R + ZR | Expand or restore the data panel/screen layout to provide more room for long values or disassembly. |
| Moon Jump preset | Right Stick Click + ZL | Apply Breeze's preset search conditions for locating a jump or vertical-motion value. It accelerates setup but still requires repeated in-game testing and validation. |
| Invert value | R + ZL | Invert the selected condition or value representation as defined by this search preset. Review the displayed result before running the search. |
| Inc A | Right Stick Up | Increases value A. |
| Dec A | Right Stick Down | Decreases value A. |
| Inc B | ZL + Right Stick Up | Increases value B. |
| Dec B | ZL + Right Stick Down | Decreases value B. |

## Pointer Search Menu

Opened with **Pointer Search** in the Search Manager. It searches forward from the main module to the target, and holds the code searches (branch, ADRP, LDR). See the **[Pointer Search Guide](pointer_search_guide.md)**.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Start forward Search | X | Start a forward pointer/reference search from the selected target. This finds instructions or addresses that lead toward it; preserve the target and current search before replacing the result set. |
| Continue forward Search | Y | Continue refining the existing forward search using its current target and conditions. Use this only after a compatible forward search has produced results. |
| Branch Search | Y + ZL | Search the current forward-search results for branch relationships. This is intended for executable-code analysis; confirm that candidates belong to a code segment. |
| Back to SearchManager | B | Returns to the Search Manager. |
| ADRP Search | (none) | Find ARM64 ADRP-based references that construct the selected target's page address. Pair results with the following ADD or load instruction and verify the complete address calculation. |
| LDR X Search | (none) | Find ARM64 64-bit load references related to the selected target. Inspect the base register and offset because an LDR match alone does not prove ownership of the value. |
| EOR Search | (none) | Find ARM64 exclusive-OR instruction relationships in the current analysis workflow. Use disassembly context to determine whether the result is relevant. |
| Show Candidates | L | Open the remaining search results. Inspect and test individual candidates carefully; a matching value is not proof that the address controls the gameplay feature. |
| search_depth | L + ZL | Set the maximum pointer or reference-chain depth. Greater depth finds more chains but costs substantially more time and memory. |
| num_offsets | R | Set how many offsets or branches may be considered per pointer-search node. Higher values broaden results and resource use. |
| search_range | + | Set the offset range examined around each pointer-search node. Keep it as small as the target structure permits. |
| bit mask | ZL + Minus | Sets the bit mask applied to values when deciding whether they are pointers. |
| Defaults | ZL + Plus | Puts the search parameters back to their defaults. |
| search_target_area | R + ZR | Chooses the memory area the search looks for targets in. |
| Select Target | X + ZL | Choose the file or result that the pointer/forward search will use as its target. Picking a different target changes the meaning of later results. |
| Delete file | - | Delete the selected item or saved file from this workflow. Save a backup first when the item cannot be recreated easily. |
| Exit | B + ZL | Leaves the Pointer Search Menu. |

## Game Information

Shows the running game's title, version, Title ID, Build ID and modules. From beta123.03 it also reports what the game is built with: the engine and its version, IL2CPP or Mono, the scripting language, the middleware, the renderer and the Nintendo SDK version, with the Breeze tools that fit. That engine scan runs once per game when Breeze attaches and is kept as `engine_scan.txt` in the game folder.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Write Gameinfo to file | + | Export the running game's displayed title, version, Title ID, Build ID, modules, and memory information to a file for reference or troubleshooting. |
| Expand Data Screen | R + ZR | Expand or restore the data panel so download logs, game information, or other long records have more display space. |
| Segment Map | X | Opens the Segment Map. |
| Code Cave Map | R | Opens the Code Cave Map. |
| add dummy cheat | Y | Add a harmless placeholder cheat entry for the current game. This is mainly useful for initializing or testing cheat-list workflows when no ordinary cheat is present. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |

## Segment Map

Lists every memory region of the game with its start, end, size, permission and type.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Select | X | Selects the segment under the cursor. |
| MemoryExplorer | Y | Opens the Memory Explorer at the start of the segment under the cursor. |
| Write map to file | + | Export the displayed process segment map to a file. This records addresses, sizes, permissions, and region types for offline analysis. |
| Expand screen | R + ZR | Expand or restore the data panel/screen layout to provide more room for long values or disassembly. |
| Page Up | Right Stick Up | Move the data list upward by one page without changing its contents. |
| Page Down | Right Stick Down | Move the data list downward by one page without changing its contents. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |
| ScreenModule | L | Limits the list to segments that belong to a module. |
| ScreenCode | R | Limits the list to code segments. |

## Code Cave Map

Opened from Game Information. Shows the free space at the end of every code segment, where the next code cave would go and which cheats have claimed what. See **[Code Caves and ASM Cheats](code%20caves.md)**.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Select | X | Shows the details of the region the cursor is on. |
| Scan nops here | Y | Count the 8-byte aligned nop pairs in the selected region. Each pair is a place a trampoline can be planted, which is what lets a cave beyond the range of a single branch still be used. |
| Scan all nops | Y + ZL | Run the nop pair scan over every module code region. Slower than scanning one region, and only worth it when comparing regions against each other. |
| Refresh | R | Reads the map again. |
| Write map to file | + | Export the displayed process segment map to a file. This records addresses, sizes, permissions, and region types for offline analysis. |
| Expand screen | R + ZR | Expand or restore the data panel/screen layout to provide more room for long values or disassembly. |
| Page Up | Right Stick Up | Move the data list upward by one page without changing its contents. |
| Page Down | Right Stick Down | Move the data list downward by one page without changing its contents. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |

## Download Menu

Checks for and installs updates. A check button turns into its install button when something newer is found.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Check for cheat database update | + | Contact the configured Breeze cheat-database source and compare its available version with the installed database. This only checks availability; use Install cheat database update afterward to download and replace it. |
| Check for app update | R | Check the configured Breeze release source for an application version newer than the one currently running. This does not install anything. |
| Expand Data Screen | R + ZR | Expand or restore the data panel so download logs, game information, or other long records have more display space. |
| Get Cheat from url list | X | Download game-specific cheats from Breeze's configured URL list. The running game's Title ID and Build ID determine the destination and applicable entry; review the downloaded file before enabling cheats. |
| Get Latest Cheat from TomVita | Left Stick Click | Download the latest available cheat package for the running game from TomVita's repository. Availability is Build-ID dependent; review the resulting entries before enabling them. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |
| Install / Update SwitchU fork | Right Stick Click | Downloads and installs the newest release of tomvita's SwitchU fork. |
| Install / Update Sphaira | (none) | Downloads and installs the sphaira homebrew menu. |
| Redownload | (none) | Repeat the selected download even when Breeze would normally consider the local copy current. Use this to replace an incomplete or damaged download. |
| Write info to file | Y | Export the current screen's results or diagnostic information to an SD-card file for later review. Existing destination behavior depends on this tool. |

## Unity Menu

Opened with **Unity** on the Main Menu. Build the two maps once with **IL2CPP map**, then find values by name instead of by searching memory. See the **[Unity Guide](UnityGuide.md)** and the **[Unity menu walkthrough](unity_menu_walkthrough.md)**.

| Button Name | Default Shortcut | Action |
|---|---|---|
| IL2CPP map | X | Opens the IL2CPP map screen to build the function map and the field map. Build both once per game build. |
| Usual suspects | Y | Lists the classes, fields and methods whose names match a list of likely targets: hp, money, energy, exp and so on. |
| Search maps | R | Searches every class, field and method name in the maps. Several words narrow the search. |
| Singletons | L | Lists the game's singleton classes, which are the usual roots of a pointer chain. |
| Edit suspects | + | Edits the list of words Usual suspects looks for, on the keyboard. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |

### Unity result lists

**Usual suspects**, **Search maps** and **Singletons** open the same kind of list: classes, fields and methods found in the maps. The field view's **Class Link**, **Descendent** and **Dump.cs** buttons open it too.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Open | X | Opens the row: a class or field opens the class view, a method opens the ASM Explorer. |
| Bookmark static | Y | Bookmarks the selected static field as `[main + class slot] -> static block -> field`. No pointer search is needed. |
| Bookmark all statics | Y + ZR | Does the same for every static in the list. |
| Instances | R | Lists the live objects of the selected class, including its subclasses, with a pointer chain to each. |
| Make cheat | L | Makes a cheat for the selected static field. |
| Hook template | X + ZR | On a method, adds a cheat on the method's first instruction and a starter `asm` script beside it. Open the cheat in Edit Cheat and press Add ASM. |
| Edit list | + | Edits the list of words on the keyboard. Enabled on the Usual suspects list. |
| Page Up | Right Stick Up | Move the data list upward by one page without changing its contents. |
| Page Down | Right Stick Down | Move the data list downward by one page without changing its contents. |
| Back | B | Return to the previous Breeze screen. Unsaved edits in the current tool may not be written automatically. |

## Unreal Menu

Opened with **Unreal** on the Main Menu. Its screens are described in the **[Unreal Support Guide](unreal.md)** and **[Unreal Field View and Object Browser](unreal_field_view_and_object_browser.md)**.

## Lua Menu

Opened with **Lua** on the Main Menu, for games that keep their data in a Lua state. See **[Lua Tools](lua.md)**.

## Rebase Menu

Opened with **Rebase** in the Extended Cheat Menu. See **[Rebase](rebase.md)**.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Build record / Abort | X + ZL | Records what every line of the loaded cheats means for this build, in `<build id>.rebase`. |
| Rebase / Abort | X | Rebuilds the cheats from the newest record of another build and writes `<build id>_rebased.txt`. |
| Add rebased cheats | Y | Adds the rebased cheats to the cheat list, turned off. |
| Back | B | Returns to the Extended Cheat Menu. |

## Trace Cheat

Opened with **Trace cheat** in the Edit Cheat Menu. It runs the cheat as a dry run and lists every pointer hop, read, compare and write, one row each. Nothing is written to the game.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Go to | X | Opens the address of the row under the cursor. |
| Save trace to file | L | Writes the list to a file in the game folder. |
| Back | B | Returns to the Edit Cheat Menu. |

## Sysmodule Manager

Opened from Settings. Each button shows a sysmodule and whether it is on; press it to turn it on or off. See the **[Sysmodule Manager Guide](sysmodules.md)**.

## Setting Menu

The settings menu allows users to configure various aspects of Breeze's behavior and appearance.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Sysmodule Manager | X | Opens the Sysmodule Manager, which lists the custom sysmodules and turns them on or off. Some changes need a console restart. |
| Profile shortcut | Y | With 1, selecting the Profile icon on the HOME menu launches Breeze. With 0, Profile opens the normal user page. |
| Jump to Last Menu | R | Toggles whether Breeze starts at the Main Menu or at the last menu visited. |
| Combo keys | (none) | Sets the number of key presses expected for a combo key definition. The same key can be pressed more than once. |
| Use titleid | Right Stick Up | Toggles whether the Breeze cheat directory of a game is named by its title ID or by its name. |
| Custom short cuts | Right Stick Left | Toggles between your own shortcuts and the default shortcuts. |
| Use starfield as background | + | Toggles between a starfield and the game screen as the background. |
| Use Dpad for Left panel item select | (none) | Toggles whether the D-pad controls the left panel and the left stick the right panel, or the other way round. |
| ShortcutProgrameKey | (none) | Defines the key combination that programs a custom shortcut. |
| ShortcutEraseKey | (none) | Defines the key combination that removes a custom shortcut. |
| alpha_toggleKey | (none) | Defines the key that adjusts transparency, showing more or less of the background. |
| RemoveFocused_key | (none) | Defines the key that removes the selected action from Focused Actions. |
| FocusedActions_key | (none) | Defines the key that opens Focused Actions management from any menu. |
| radial_modeKey | (none) | Defines the key that enters radial selection with the left stick. This key can no longer be part of a shortcut. |
| Theme | (none) | Selects the light or dark theme. |
| Use alt color | (none) | Replaces Breeze's text colour with the one in `/switch/Breeze/alt_color.ini`. |
| Prerelease updates | R | Lets update checks offer prerelease builds of Breeze. |
| PC connect | (none) | Turns PC connect on or off. When on, the label shows the address and the code a PC needs. See the Breeze PC App Guide. |
| Save setting | B | Saves the changes and leaves this menu. |
| Reinstall gen2 fork | - | Installs or updates the dmnt.gen2 sysmodule that captures data for ASM cheats, to the version bundled with Breeze. Reads **Install gen2 fork** when it is not installed. |
| Uninstall gen2 fork | (none) | Removes the dmnt.gen2 fork and restores Atmosphere's default dmnt settings. |
| Install Noexes | (none) | Installs the custom sysmodule for JNoexs and PointerSearchSE. |
| Search Code Segment | (none) | Toggles whether searches include the code segment. |
| Search Main only | (none) | Toggles whether searches cover only the main segment. |
| HOME daemon | (none) | Turns the HOME daemon on or off from the next restart. Reads **Install HOME daemon** or **Update HOME daemon** when one is needed; press twice to confirm. See HOME Toggle and Overlay Mode. |
| Home toggle | (none) | Chooses what HOME does while Breeze and a game are open: Off, No restart, Fast restart or Overlay. |
| Overlay pauses game | (none) | In Overlay mode, pauses the game while Breeze is shown. |
| Breeze first | (none) | The console starts in Breeze, and HOME from a game returns to Breeze instead of the SwitchU menu. |
| Export B8 only | (none) | Exports as text only the bookmarks that have B8 as their second offset. |
| use_titlename2 | (none) | Uses the second title name for games that have one. |
| enable_two_register | (none) | Toggles whether gen2 captures the data of one register, or the register-indirect address of code that uses two registers. |
| replace_space | (none) | Replaces spaces with `_` in a game name used as a folder name. |
| Log button press | (none) | Logs your button presses to a file. |
| visible_only | (none) | With 0, every button's shortcut works whether the layout shows the button or not. With 1, only buttons on screen answer their keys. |
| Reset general settings | (none) | Resets general settings to their defaults. Custom shortcuts and focus layouts are kept. |
| Backup custom shortcuts | (none) | Saves all custom shortcuts to `/switch/Breeze/custom_shortcuts.dat`. |
| Restore custom shortcuts | (none) | Restores custom shortcuts from `/switch/Breeze/custom_shortcuts.dat`. |
| use_module_id | (none) | Toggles whether cheats for a loadable module are filed under the module instead of main. |
| module_loaded_cheats_only | (none) | Toggles whether only cheats for modules that are loaded are shown. |
