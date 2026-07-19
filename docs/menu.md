# Menu Documentation

Welcome to the comprehensive guide for all button functionalities within Breeze. This document is designed to help you understand and master the controls across various menus, from basic navigation to advanced cheat implementation.
The menus are designed to be intuitive, but the extensive features mean there are many buttons and shortcuts available. This guide breaks down each menu, detailing what every button does, along with its default shortcut.
Whether you're a new user getting acquainted with the application or an experienced user looking for a specific function, this documentation will serve as your go-to reference for all controls.

## Table of Contents
- [Focused Actions / All Actions](#focused-actions--all-actions)
- [Context-Sensitive Help](#context-sensitive-help)
- [Extra buttons](#extra-buttons)
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
- [Jump Back Menu](#jump-back-menu)
- [Gen2 Menu](#gen2-menu)
- [Gen2 Extra Menu](#gen2-extra-menu)
- [Setting Menu](#setting-menu)

## Context-Sensitive Help

Hold **ZR first**, then press **A** to open help for the current menu. Use the D-Pad and A for topics, Left/Right for pages, X for the selected action's help, and B to return or close. Help blocks the underlying menu and saves its state per menu. See the [Help System Guide](help%20system.md).

## Focused Actions / All Actions

Focused Actions shows a smaller set of frequently used actions. All Actions shows every action available in the current menu. Open **Focused Actions** management with the configured key (default `L + ZR`) and choose **Switch action view** to change between them.

Choose **Customize actions** to edit the focused set. Breeze opens the action panel full screen in four columns and hides the left panel while editing. Press `A` to include or remove any action, `-` to cut an included action to the stack, and `+` to pop the last cut action into the position at the cursor. Press `B` or choose **Finish customizing** to save the changes and return to Focused Actions. The Focused Actions menu shortcut is ignored while customization is active. If a menu's usual selected action is not included, selection starts on the lower-right page button instead.

Status and other menu information remain below the panel title. Help for the selected action is always shown separately in the footer below the action buttons. The same footer shows customization key hints and the shortcut for the lower-right page button when applicable.

**Training mode=1** provides the learn-by-use workflow. Turning it on leaves the existing focused set and action view unchanged, then adds actions to Focused Actions as you use them. Set it back to `0` to stop learning new actions.

For a complete walkthrough, see the **[Focused Actions Guide](focus%20mode.md)**.

## Global Navigation Buttons

The following buttons are available across various menus to assist with navigation and Focused Actions.

| Button Name | Default Shortcut | Action |
|---|---|---|

| Focused X/Y → Z/Y / All X/Y → Z/Y | (none) | Shows the current action view and page. Press to advance to the indicated next page. When selected, the footer shows the configured Focused Actions menu shortcut. |
| default shortcuts | (none) | Resets all custom shortcuts for the current menu back to their default values. |
| Manage layouts | (none) | Opens Focused Actions management directly. |
| Customize actions / Finish customizing | L | Starts or finishes four-column, full-screen customization. Use `A` to toggle, `-` to cut, `+` to paste at the cursor, and `B` to finish. |

## Focused Actions Menu

This menu manages the actions shown in Focused Actions and lets you save or load named layouts. The manager itself is never filtered, so every management button remains visible. **Switch action view** is the top-left button and is selected when the menu opens. Help appears at the top for better visibility.

> [!NOTE]
> Loading a layout will restart the application to apply it.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Switch action view | L + ZR | Switches the previous menu between Focused and All Actions. The configured key opens this menu from elsewhere. |
| Load layout | Y | Loads a previously saved action layout. The application will restart to apply the changes. |
| Customize actions / Finish customizing | L | Opens All Actions for editing, or finishes editing and returns to Focused Actions. |
| Training mode=0/1 | (none) | `1` learns actions as you use them without clearing or changing the current focus state. `0` stops learning new actions. |
| Save layout | X | Updates only the menu you were working on in the selected layout. Other menu layouts in the file remain unchanged. |
| Rename layout | (none) | Renames the selected layout file. |
| New layout | + | Creates a named layout from the current configuration. |
| Delete layout | - | Deletes the selected layout file. |
| Reset all shortcuts | Left Stick Click | Restores factory shortcuts, including the Focused Actions manager and Search Manager shortcuts that share the same internal menu. |
| Clear all shortcuts | Right Stick Click | Removes all custom shortcuts. |
| Clear focus for this menu | (none) | Clears Focused Actions only for the menu you were working on and shows All Actions there. Other menus are unchanged. |
| Back | B | Returns to the previous menu. |

## Main Menu

The main entry point of the application, providing access to all major features.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Cheats | Y + ZL | Opens the Simple Cheat Menu. |
| Cheat Menu | R | Opens the Advance Cheat Menu. |
| SearchManager | L | Opens the Search Manager Menu. |
| Bookmarks | Right Stick Up | Opens the Bookmark Menu. |
| Help | (none) | Opens the Main Menu tutorial topic screen. |
| Download | - | Opens the Download Menu. |
| Exit | B | Exits the application. |
| Settings | + | Opens the Settings Menu. |
| Game Information | Y | Opens the Game Information screen. |
| Gen2 Action | Right Stick | Review break point data and generate ASM script. |
| ARM64 only/ARM32 enable | Left Stick | Toggles between ARM64 and ARM32 assembly support. |
| Launch ftpsrv | X | Launches an FTP server to access save data. |
| JumpBack Menu | Y + ZR | Opens the JumpBack Menu. |
| Memory Explorer | (none) | Opens the Memory Explorer at the last saved address. |
| Segment Map | X + ZL | Opens the Segment Map. |
| Pointer Search | (none) | Opens the Pointer Search menu. |

## Simple Cheat Menu

This is the default, simplified view of the cheat menu.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Cheat | X | A solid square indicates the cheat is on, a hollow square indicates it is off. |
| Back | B | Go to the previous menu. |
| Change size | R | Toggles the width of the left panel. |
| Left-Right swap | L | Swaps the left and right panels. |
| Advance Cheatmenu | ZL | Opens the Advance Cheat Menu. |

## Advance Cheat Menu

This menu provides more advanced cheating functionalities.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Cheat | X | A solid square indicates the cheat is on, a hollow square indicates it is off. |
| Add to bookmark | + | Create a bookmark from a static or pointer cheat. |
| Add conditional key | Right Stick | Setup a conditional key combo, up to the number defined in options. |
| Remove conditional key | Left Stick | Remove the key combo condition required to execute the cheat. |
| Edit Cheat | L | Edit a cheat or assemble an ASM hack. |
| Cut Cheat | - | Pushes the selected cheat into a stack. |
| Paste/Duplicate Cheat | Right Stick Left | Pops a cheat from the stack or duplicates the current cheat if the stack is empty. |
| Write Cheat to atm | (none) | Write from cheatVM to atmosphere's content directory. |
| Load Cheats from atm | Right Stick Up | Load cheats from the atmosphere's content directory. |
| Add freeze game code | (none) | Freeze / Unfreeze the game. |
| Bookmark | R | Go to the bookmark menu. |
| Back | B | Go to the previous menu. |
| Write Cheat to file | Right Stick Down | Write from the cheatVM to Breeze's cheat directory. |
| Load Cheats from file | Y | Load cheats from Breeze's cheat directory. |
| Load from DB | Right Stick Right | Load a cheat from the database. |
| More | ZR + ZL | Opens the Extended Cheat Menu. |
| key hint to file | (none) | Save conditional key combo in cheat name. |
| Assemble all ASM | L + ZL | Clear all ASM in memory and re-assemble them. |
| Type0 map toggle | + + ZR | Map type 0 address to cheats. |
| Expand Screen | R + ZR | Toggle the left panel width between half and full. |
| Clear clipboard | Right Stick Left + ZR | Clears the clipboard, which is useful for duplicating cheats. |
| Watch ASM | B + ZR | Apply and watch line 1 of the selected cheat. |
| Module loaded cheats only | Y + ZL | Toggle to only show cheats for the currently loaded module. |
| Get Latest Cheat from TomVita | Right Stick Down + ZR | Download the latest cheats from TomVita's repository. |

## Extended Cheat Menu (More Menu)

This menu provides extended functionalities for cheat management.

Accessed by pressing `ZR + ZL` in the Advance Cheat Menu.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Turn off all Cheats | X | Turns off all active cheats. |
| Make off Cheat | Y + ZR | Create an "off" cheat by gathering the revert code from all cheats. |
| Make AOB | D-Pad Right + ZR | Create a cheat file that can be used for an AOB search. |
| Load AOB | D-Pad Left + ZR | Use a cheat for an AOB search. |
| Remove atm cheats | (none) | Remove cheat file from atmosphere's content directory. |
| Delete all Cheats | - | Remove all cheats from the cheatVM. |
| Create Group | Right Stick | Create a grouping to organize cheats. |
| Turn on all Cheats | Y | Turns on all cheats. |
| Expand Data Screen | + | Toggle the left panel width between half and full. |
| any cheats from Breeze's TID directory | L | Load any file from Breeze's TID directory, ignoring the BID. |
| signature= | R | Set a signature to save with cheats. |
| any cheats from Atm's TID directory | ZL | Load any file from atmosphere's cheat directory, ignoring the BID. |
| Choose individual cheats from breeze/cheats | ZL + ZR | Lets you pick which cheats from a large cheat file you want to add to the current list. |
| Add R2=main | Left Stick + ZR | Create a cheat that will result in R2 having the address of main. |
| Back | B | Go back to the previous menu. |
| Watch ASM | B + ZR | Apply and watch line 1 of the selected cheat. |
| Create Cheat | X + ZR | Create a dummy cheat. |
| Clear clipboard | Right Stick Left + ZR | Clears the clipboard, which is useful for duplicating cheats. |

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
| ASM/keycombo edit | Right Stick | Edit ASM or a key combo. |
| Save | B | Upload changes to the cheatVM and return to the previous menu. |
| Save to file | Right Stick Right | Save the left panel text to a file. |
| Expand Menu | ZR + ZL | Show more buttons. |
| Add loop | + + ZL | Assistant to create loop code. |
| Add ASM | D-Pad Up + ZL | Assemble ARM code into a cheat. |
| Extract ASM | StickRDown + ZL | Extracts embedded assembly code from a cheat, generating labels for memory addresses and saving it to `{cheat_name}_extract.txt`. |
| Load register | D-Pad Down + ZL | Insert cheat code to load a register. |
| Alt ASM | Right Stick + ZL | Toggle where to place the code cave. |
| Add utility codes | D-Pad Left + ZL | Create utility cheat codes. |
| ASM Group | Left Stick + ZL | Place utility cheat codes in a group. |
| Expand Screen | R + ZR | Toggle the width of the left panel. |
| Get original values | Left Stick | Create recovery code from the original values. |
| Jump to target | D-Pad Right + ZL | Go to the target of a static or pointer code in the Memory Explorer. |
| Clear ASM space | - + ZL | Fill the code cave with 00s. |
| Asm Composer | Y + ZL | Go to the assembly code editor. |
| Jump to ASM | X + ZL | Go to the ASM explorer to examine code in memory. |
| Nop | Right Stick Up + ZL | Replace the selected code with a NOP instruction. |
| ,lsl# | Right Stick Right + ZL | Modify code by appending a logical shift left. |
| Transform1 | Right Stick Left + ZR | Toggle between assign/match, keyheld/keydown, or load/write register. |
| Transform2 | Right Stick Left + ZL | Increment load register, toggle between load/begin condition, or convert store static to load. |
| Adj=Addr-Adj | Left Stick Up + ZR | Utility to port code to a new offset. |
| Addr=Addr-Adj | Left Stick Down + ZR | Utility to port code to a new offset. |
| Search code | Left Stick Right + ZR | Search the code space for the code written by the cheat code. |
| Line 2 Cheat | Left Stick Left + ZR | Make a cheat code from the selected line of code. |
| R1=... | Left Stick Down + ZL + ZR | Display the base address of the module. |
| 4,6 to 0 | Left Stick Down + ZL | Convert type 4 and type 6 cheats into type 0 cheats. |
| type0 expand | (none) | Sorts type 0 codes by address and expands them to width 4 for better ASM visibility. |
| type0 condense | (none) | Condenses type 0 codes to width 8 for a more compact representation. |

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
| A= | X | Set value of A for comparison. |
| B= | Y | Set value of B for comparison. |
| C= | ZL + Y | Set value of C for comparison. |
| ==A | L | Perform an 'equal to A' memory search. |
| ==*A | ZL + L | Perform an 'equal to A' memory search for type u32, f32, f64. |
| [A..B] | ZL + R | Search memory for values within the range [A..B], inclusive of both A and B. |
| u32 | R | Search for unsigned 32-bit integers. |
| f32 | Right Stick | Search for single-precision floating-point numbers. |
| f64 | Left Stick | Search for double-precision floating-point numbers. |
| Same | Right Stick Up | Search for values identical to previous values. |
| Diff | Right Stick Down | Search for values differing from previous values. |
| ++ | Right Stick Right | Search for values that have incremented from previous values. |
| -- | Right Stick Left | Search for values that have decremented from previous values. |
| <A..B> | - | Search memory for values within the range (A..B), excluding both A and B. |
| More | ZR | Show more choices. |
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
| Continue search | Right Stick | Continue the previous search. |
| Show Candidates | L | Examine the search results. |
| memory dump | Left Stick | Make a full RW memory dump, preparation for unknown search. |
| Copy condition | (none) | Copy the search condition of the selected file. |
| Rename | (none) | Rename the selected file. |
| Delete file | - | Delete the selected file. |
| Look | + + ZR | Look at the game screen. |
| CapturedScreen | + | Choose between captured screen or current screen. |
| MJ preset | Right Stick + ZL | Set to search float between 0.1 and 3000. |
| Invert | R + ZL | Flip the sign of the current search. |
| [A..B]f.0 | Right Stick Left + ZL | Search for floating point value without decimal. |
| ExpandMenu | ZR + ZL | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Select B | X + ZL | Choose the file to use for previous value. |
| GetB | B + ZR | Make a new file with previous value retrived from B file. |
| GetB==A | (none) | Make a new file with previous value==A retrived from B file. |
| Advance search | R | Setup advance search. |
| Pointer Search | Y + ZR | Experimental exploration on forward search of pointers, not ready for daily use. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Edit String | Right Stick Left + ZR | Setup a string search. |
| Make64Bpair/Toggle Hex mode | Right Stick Right + ZR | When the string is taking up 128bit space with trailing zero/Toggle between hex and decimal display modes. |
| Main only | X + ZR | Save time, if you know it is in main then only search main. |
| A,,B distance | (none) | Set the maximum distance (in elements) between A and the other value(s) for proximity searches [A,,B] and [A.B.C]. The window extends this many elements on both sides of A. |
| AutoContinue | (none) | Automatic naming based on the filename of the previous file. |
| AutoStart | (none) | Choose the smallest available number when you start a new search. |
| ConfirmDelete | (none) | Whether ask for comfiramtion before deleting file. |
| VisibleOnly | (none) | Choose whether you can use short cut to buttons not visible. |
| Edit A | Right Stick Left | Set value of A for comparison. |
| Edit B | Right Stick Right | Set value of B for comparison. |
| Inc A | Right Stick Up | Increment value A. |
| Dec A | Right Stick Down | Decrement value A. |
| Express Search Setup | (none) | Perhaps a faster way to setup search. |
| EQ cycle | L + ZL | Cycle through equality search modes. |
| SAME cycle | D-Pad Up + ZL | Cycle through same value search modes. |
| DIFF cycle | D-Pad Down + ZL | Cycle through different value search modes. |
| LESS cycle | D-Pad Left + ZL | Cycle through less than search modes. |
| MORE cycle | D-Pad Right + ZL | Cycle through greater than search modes. |
| uint type | Y + ZL | Cycle through unsigned integer types. |
| Float type | Left Stick + ZL | Cycle through float types. |
| RANGE type | + + ZL | Cycle through range search modes. |
| Edit C | Right Stick Right + ZL | Set value of C for comparison. |
| Rebase | L + ZR | Rebase search results from previous game session when posible. |
| Inc B | Right Stick Up + ZL | Increment value B. |
| Dec B | Right Stick Down + ZL | Decrement value B. |

## Candidate Menu

The Candidate Menu is where you can view and interact with the results of a memory search. After performing a search in the Search Manager, the addresses that match your criteria are listed here as "candidates." This menu provides a powerful set of tools to inspect, modify, and analyze these candidates, helping you pinpoint the exact memory addresses you need for your cheats.

If you have a large list of candidates, there are two primary methods for narrowing them down:

1.  **Refine the Search**: Return to the **Search Manager Menu** and perform a **Continue Search** with more specific criteria (e.g., searching for values that have changed, increased, or decreased). This iterative process is key to isolating the exact address you are looking for.
2.  **Batch-Test Candidates**: The Candidate Menu also includes powerful tools to test changes on many candidates at once. Functions like `Freeze100`, `Set1000`, and `Inc1000` allow you to apply a change to hundreds or thousands of candidates simultaneously. By observing the effect in-game, you can quickly determine if any of the modified candidates control the desired behavior, providing another method for rapidly narrowing down a large result set.

    > **Warning:** Be cautious when batch-modifying integer values. An integer candidate may actually be part of a pointer or other critical data structure. Modifying it can easily lead to crashes or other unexpected behavior. Batch-testing is generally safer with floating-point values, which are less likely to be integral parts of the game's core structure.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Toggle Freeze Memory | X | Freezes or unfreezes the value at the selected memory address, preventing it from changing. |
| Edit Memory | Y | Opens an editor to modify the value at the selected memory address. |
| Add Bookmark | + | Saves the selected memory address to your bookmarks for easy access later. |
| Mode toggle | Left Stick | Cycles through different display modes for memory values: `smart` (context-aware), `base` (decimal), and `hex` (hexadecimal). |
| Memory Explorer | Right Stick | Opens the Memory Explorer at the selected address for a more detailed view of the surrounding memory. |
| Goto Disassembly / Bookmark | L | Depending on the search mode, this button either opens the ASM Explorer to view the disassembly of the code at the address or opens the Bookmark Menu. |
| Page Up | Right Stick Up | Navigates to the previous page of candidates. |
| Page Down | Right Stick Down | Navigates to the next page of candidates. |
| First Page | Right Stick Left | Jumps to the first page of the candidate list. |
| Last Page | - | Jumps to the last page of the candidate list. |
| Change Type -> | R | Cycles forward through the available data types (e.g., u8, s16, f32) for interpreting the memory value. |
| Change Type <- | R + ZL | Cycles backward through the available data types. |
| Revert | L + ZL | Reverts the value at the selected address to its original value from the search. |
| Write info to file | (none) | Exports the current list of candidates to a text file for external analysis. |
| Expand screen | R + ZR | Toggles the width of the left panel to show more or less information. |
| Back | B | Returns to the previous menu. |
| Freeze100 | (none) | Freezes the next 100 candidate values starting from the cursor. |
| Unfreeze100 | (none) | Unfreezes the next 100 candidate values starting from the cursor. |
| Inc1000 | (none) | Incrementally adds a specified value to the next 1000 candidates. |
| Set1000 | (none) | Sets the next 1000 candidates to a specified value. |
| Revert1000 | (none) | Reverts the next 1000 candidates to their original values. |
| First Target | - + ZL | In pointer search mode, this jumps to the first target in the list. |
| GotoSource | StickR + ZL | In pointer search mode, this jumps to the source of the pointer. |

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
| Perform Clean up | - + ZL | Remove entries marked for delete or that have bad pointers that cannot be resolved. |
| Memory Explorer | Right Stick | Open the Memory Explorer at the bookmarked address. |
| Pointer Search | X + ZL | Search for pointers to this memory address. |
| JumpBackMatch | B + ZL | Use the pointer in this bookmark to assist with a pointer search. |
| ChangeType | R + ZL | Change the data type of the bookmark. |
| Page Up | Right Stick Up | Go to the previous page of bookmarks. |
| Page Down | Right Stick Down | Go to the next page of bookmarks. |
| ExpandMenu | ZR + ZL | Show more buttons. |
| Back | B | Go back to the previous menu. |
| AppPtrSearch | (none) | Change the target to this bookmark or setup an application pointer search. |
| Delete All Bookmark | (none) | Deletes all bookmarks in the current file. |
| FileSelection | R | Select a different bookmark file to use. |
| RememberLast | (none) | Toggle whether to remember the last bookmark file used. |
| Expand screen | R + ZR | Toggle the width of the left panel. |
| Import Bookmarks | + + ZL | Import bookmarks from Pointersearcher SE. |
| Toggle Absolute Address | L | Toggle between relative and absolute addresses. |
| Mode Toggle | Left Stick | Toggle between smart, base, and hex display modes. |
| Last Page | Right Stick Right | Go to the last page of bookmarks. |
| First Page | Right Stick Left | Go to the first page of bookmarks. |
| MiscPointers | (none) | Add some useful bookmarks. |
| Export text | Right Stick Down + ZL | Export bookmarks to a text file. |

## Memory Explorer Menu

Directly view and edit memory, and navigate pointer chains.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Jump Forward | Y | Go to pointer target address. |
| MoveLeft | B + ZL | Move left on the pointer chain (jumpback). |
| MoveRight | Y + ZL | Move right on the pointer chain (jumpforward). |
| Edit Memory | X | Edit memory according to the displayed type. |
| Add Bookmark | + | Add cursor address to bookmark. |
| Change Type -> | R + ZL | Cycle to the next data type. |
| Mode Toggle | Left Stick | Toggle between smart, base, and hex display modes. |
| Expand menu | ZR + ZL | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Expand screen | R + ZR | Toggle the width of the left panel. |
| JumpBack | Y + ZR | Go to jumpback menu for pointer search. |
| Align address | R | Make current address the center of the page. |
| Page Up | Right Stick Up | Go to the previous page. |
| Page Down | Right Stick Down | Go to the next page. |
| Last Page | Right Stick Right | Go to last page of segment. |
| First Page | Right Stick Left | Go to first page of segment. |
| Toggle ValueBookMark | Right Stick Up + ZR | Toggle display between showing pointer or showing value in different datatypes. |
| SetBreakPoint | D-Pad Up + ZL | Set break point on address. |
| ASM Explorer | X + ZL | Go to ASM explorer. |
| Save to file | (none) | Write data on left panel to file. |
| Copy | D-Pad Left + ZL | Copy value. |
| Paste | D-Pad Right + ZL | Paste value. |
| Address to A | D-Pad Down + ZL | Put cursor address as A value for search. |
| Move to A | (none) | Move to address A. |
| Extra_menu | D-Pad Up + ZR | Switch to button arrangement for temdem display. |
| Value to A | D-Pad Down + ZR | Copy cursor value to A value for search. |
| Look | + + ZR | Look at game screen. |
| Left= | D-Pad Left + ZR | Set and move left by set amount. |
| Right= | D-Pad Right + ZR | Set and move right by set amount. |
| =0 | Left Stick Left + ZR | Clear Set, also get offset align to gen2 offset. |
| A=0 | Right Stick Left + L | Enter a value for search. |
| Find next | Right Stick Down + L | Search forward for address that has value A. |
| Find previous | Right Stick Up + L | Search barkward for address that has value A. |
| Freeze_setting=0 | B + L | Disable smart setting and save current setting as default. |
| Dump_Segment | Y + L | Dump current segment to file for search manager use. |
| Dump_area | X + L | Dump area around current address for search manager use. |
| Toggle_align | Left Stick + ZR | Toggle between aligned column or simple display line with no alignment. |
| Change Type <- | L + ZL | Cycle to the previous data type. |
| Set tandem | X + ZR | Push current address to tandem list. |
| Clear tandem | B + ZR | Clear tandem list. |
| Save tandem list | L + Right Stick Down + ZR | Save tandem list. |
| Load tandem list | L + Y + ZR | Load saved tandem list. |
| Append tandem list | L + X + ZR | Append current address to saved tandem list. |
| Edit String | Right Stick Left + ZR | Edit current address as c string, also make a copy. |
| Paste String | Right Stick Right + ZR | Paste string form Edit String to address. |
| CopyPasteQty | (none) | Set copy paste quantity. |
| PasteMultiple | Right Stick + ZR | Paste multiple values from the clipboard. |
| EditOffset | Left Stick Left + Right Stick Right + ZR | Edit the offset of the bookmark. |

## ASM Explorer Menu

The ASM Explorer allows for in-depth analysis of disassembled code directly from memory. It is an essential tool for reverse engineering and understanding how a game functions at a low level. You can set breakpoints, edit instructions on the fly, and navigate through code to identify key logic for cheat development.

| Button Name | Default Shortcut | Action |
|---|---|---|
| ASMedit | X | Directly edit game code (not recommended). |
| Copy instruction | Y | Push code to the paste stack of cheat editor and asm composer. |
| Watch instruction | L | Place a watch on this instruction and go to the Gen2 Menu for dynamic analysis. |
| Follow branch | R | Go to the target of this branch instruction. |
| Add to Cheat | Y + ZL | Make a cheat with this ASM as the hook. |
| Expand screen | R + ZR | Toggle the width of the disassembly panel. |
| MemoryExplorer | StickR + ZL | View this address in memory explorer. |
| Goto Source | StickR | Jump to the caller or base pointer of this instruction. |
| Branch_to above | StickRUp + ZL | Perform a scan for and move to the branch target above the current address. |
| Branch_to below | StickRDown + ZL | Perform a scan for and move to the branch target below the current address. |
| AutoSave = 0/1 | StickRDown + ZL | Toggle whether to automatically save the cheat list to file after using "Add to Cheat". |
| Line Up | StickRLeft | Scroll up one line. |
| Line Down | StickRRight | Scroll down one line. |
| Page Up | StickRUp | Go to the previous page of disassembly. |
| Page Down | StickRDown | Go to the next page of disassembly. |
| Write info to file | + | Write information on the left panel to a file. |
| Back | B | Return to the previous menu. |

## Jump Back Menu

The Jump Back Menu is designed for multi-level pointer searching, a powerful technique for finding stable pointers to dynamic memory addresses.

### What is Pointer Searching?
In game hacking, the memory address for a value like player health can change each time the game is launched. A pointer is simply a memory address that holds the value of another memory address. Pointer searching is the process of finding a sequence of pointers—a "pointer chain"—that starts from a static, unchanging base address (usually in the game's main code) and, after applying a series of offsets, reliably leads to the desired dynamic data. This allows cheats to work across different game sessions.

### The Methodology
The Jump Back menu automates this by working backward from a target address you've identified (the "node"). It scans memory for any addresses that point to your target, building a "pointer map" of potential chains. The process is iterative:
1.  **Start**: Begins a search for pointers pointing to the initial set of target addresses (nodes).
2.  **Next Depth**: Takes the pointers found in the previous step and searches for pointers that point to *them*, effectively moving one level up the chain toward a static base address.
This continues until a stable path from a static address is found.

### Search Parameters
The search process is governed by several key parameters that help refine the results and manage performance:
- **`search_depth`**: Sets the maximum number of levels (jumps) the search will automatically perform in "Goto depth" mode.
- **`num_offsets`**: Restricts the search to using only the specified number of nearest-offset pointers for the next depth, pruning less likely candidates.
- **`search_range`**: Defines the maximum valid offset value for a pointer. This helps filter out invalid pointers and focus the search.
- **`Max per node`**: Limits how many pointers are found for each target address in a given search step, preventing the results from being flooded by a single, heavily-referenced node.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Select | X | Go to memory address of the node. |
| Analyse | Y | Details on the pointers to this node. |
| Start | L | Start search for pointers to node addresses. |
| do B8 scan | (none) | Search for base pointer with second offset being B8 pointing to node. |
| next depth | R | Recode bookmark and move search back to source by one jump. |
| get depth+1 ptr | (none) | Recode bookmark without moving to next depth. |
| Goto depth | + + ZL | Continue search until specified depth is reach or out of memory. |
| search_depth | + | Set depth to stop for auto mode. |
| num_offsets | D-Pad Left + ZL | Number of nearest offset to use for next step. |
| search_range | D-Pad Right + ZL | The maximum offset accepted by the search. |
| Name= | X + ZL | Name the search, bookmark recorded will bear this name. |
| Max per node | D-Pad Down + ZL | Set max pointer per node. |
| Bookmark menu | R + ZL | Bring you to bookmark menu. |
| Save_Map | Right Stick Down + ZL | Save the current progress. |
| Load_Map | Right Stick Up + ZL | Load from save to try a different parameter. |
| Delete Offset | - | You can delete an offset if you know it is not the right one. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Back | B | Go back to the previous menu. |
| Write info to file | (none) | Write data on left panel to file. |
| Screen Map | - + ZL | Implementation incomplete, ignore this. |

## Gen2 Menu

The Gen2 Menu is a powerful dynamic analysis tool for creating advanced cheats by watching memory and capturing data about how and when it's accessed. Instead of just searching for static values, you can monitor a memory address or region to see exactly what code is reading from or writing to it. The core workflow involves setting up a watch, specifying the access type to look for (read/write), and defining what data to capture when a trigger occurs—most importantly, the return address (X30) of the function that accessed the memory. This is invaluable for understanding game logic and finding the precise code to modify.

You will typically enter this menu from the Memory Explorer when watching a specific memory address, or from the ASM Explorer when analyzing a piece of code. Once configured, you attach Breeze as a debugger, execute the watch to capture data while the game runs, and then detach to examine the results. This cycle allows you to iteratively refine your understanding and pinpoint the exact code responsible for the behavior you want to change.

### Workflow

1.  **Watch Memory Access**: Start by watching a memory address to see what code accesses it.
2.  **Choose a Code**: Select a code from the captured data that you suspect is related to the action you want to modify.
3.  **Verify Uniqueness**: Check if the chosen code's access is unique to the target. If so, proceed to the next step. Otherwise, test other codes from the list to find a unique one. If none are unique, additional filtering methods will be needed.
4.  **Create Cheat**: Once a uniquely accessing code is identified, you can create a cheat to modify its behavior.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Next stack_check | (none) | The number of stack value to capture in next run, also used for asm script generation. |
| X30_catch | L + ZL | Specify the data capture type. |
| Stack_offset | (none) | Specify the offset if X30_catch_type is stack. |
| Read= | D-Pad Up + ZL | Toggle the read flag. |
| Write= | D-Pad Down + ZL | Toggle the write flag. |
| SearchSetup | Y | Go to search setup to change data type. |
| Gen2Attach | + | Detach from dmnt and attach to dmnt.gen2 changes data display mode. |
| Execute Watch | R | Start the data capture, go back to game to let it do the work. |
| Name and Execute | + + ZL | Name the watch and then execute it. |
| Gen2Detach | - | Stop the capture to perform action on the results. |
| Select | X | Go to selected address or instruction. |
| goto call | X + ZL | Go to the caller address. |
| X30_match | R + ZL | Check the value of X30 current or stored on stack and only capture if match. |
| Grab[A] | D-Pad Right + ZL | Setup grab of memory at the address currently in A. |
| Grab_R | (none) | Setup grab of a register value. |
| R= | (none) | Set the register to grab. |
| Match_R | (none) | Match the value of the selected register. |
| Range Check | D-Pad Left + ZL | Only capture when value falls in the range between A and B. |
| More | D-Pad Down + ZR | Configure the button panel for stack watch data. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Back | B | Go back to the previous menu. |
| Save as candidates | L | Save the list of address and value for use with search manager. |
| Next results | Right Stick Right + ZL | Navigate data recorded from previous capture. |
| Pre results | Right Stick Left + ZL | Navigate data recorded from previous capture. |
| LastLoad | Right Stick Up + ZL | Jump to record that was used to start a new run. |
| Erase old results | (none) | Erase all the recorded data. |
| Set Max trigger | (none) | The run stops when total number of trigger reach this number. |
| Look | + + ZR | Look at the game screen. |
| Write info to file | - + ZL | Write data on the left panel to a file. |
| Increment Offset | D-Pad Right + ZR | Increment the offset. |
| Decrement Offset | D-Pad Left + ZR | Decrement the offset. |
| Set Offset | D-Pad Up + ZR | Set the offset. |

## Gen2 Extra Menu

The Gen2 Extra Menu provides a suite of tools to process and analyze the data captured by the Gen2 Menu, with the ultimate goal of automating the creation of Assembly (ASM) cheats. After capturing a set of memory access events, you can use this menu to sort the data, find unique code paths (X30 values), and perform exclusive searches to eliminate irrelevant code. Its most powerful features can automatically generate ASM scripts (`make match all`, `make match 1`) based on the captured data, allowing you to quickly create complex cheats that replicate or modify game logic with high precision.

The `x30` register, or Link Register (LR), is central to understanding program flow, as it holds the return address for function calls. The `BL` (Branch with Link) instruction automatically updates `x30` with the address of the next instruction, but its value is volatile and must be explicitly saved to the stack by software to survive nested function calls.

The Gen2 menu’s hardware watchpoints can capture both the current `x30` value and several values from the top of the stack. By analyzing these captured stack entries, you can often find saved `x30` values from earlier in the call chain. This provides invaluable context for low-level memory accesses, helping you trace them back to higher-level game logic—such as identifying whether an action affects an ally or an enemy.

- **`make match 1`**: Creates a cheat that triggers if *either* the current `x30` or one of the selected stack values matches the captured data. This is useful for finding a single, reliable hook point.
- **`make match all`**: Creates a more restrictive cheat that triggers only when *both* the current `x30` and *all* selected stack values match the captured state, ensuring maximum precision.

A successful cheat is achieved when these conditions isolate a memory access to only the desired target.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Sort | D-Pad Down + ZR | Sort the captured data by address. |
| Find unique | D-Pad Left + ZR | Search for unique x30 (watch or stack) value for the address selected. |
| make match all | R + ZR | Create asm script that checks all x30 values captured. |
| make match 1 | Y + ZR | Create asm script that match only one x30 values(selected by Next stack_check=). |
| ExclusiveSearch | X + ZR | Match all X30 captured and eliminate every dataline that allow address other than the address captured. |
| DeleteEntry | (none) | Remove the data line selected, so the next line can be tested in ExclusiveSearch. |
| Expand menu | ZR + ZL | Show more buttons. |
| Back | B | Go back to the previous menu. |
| Write info to file | + + ZR | Write data on the left panel to a file. |
| Pre results | Right Stick Left + ZL | Navigate data recorded from previous capture. |
| Next results | Right Stick Right + ZL | Navigate data recorded from previous capture. |
| Expand screen | R + ZR | Toggle the left panel width between half and full. |
| Select | X | Go to selected address or instruction. |
| goto call | X + ZL | Go to the caller address. |
| Execute Watch | R | Start the data capture, go back to game to let it do the work. |
| Gen2Detach | - | Stop the capture to perform action on the results. |
| Gen2Attach | + | Detach from dmnt and attach to dmnt.gen2 changes data display mode. |
| X30_match | R + ZL | Check the value of X30 current or stored on stack and only capture if match. |
| check data | (none) | View the data details. |

## Setting Menu

The settings menu allows users to configure various aspects of Breeze's behavior and appearance.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Save Setting | B | Save changes and exit this menu. |
| Gen2 Fork | - | Toggles installation of the custom sysmodule needed to capture data for ASM cheat creation. |
| Noexes Fork | (none) | Toggles installation of the custom sysmodule for JNoexs and PointerSearchSE. |
| Search Code Segment | (none) | Toggles whether to search for code in the code segment. |
| Search Main Only | (none) | Toggles whether to only search the main segment (if you already know that your target is there). |
| Dmnt Fork | (none) | Toggles installation of the custom version of CheatVM. |
| Export B8 Only | (none) | Toggles whether to only export as text the bookmarks that have B8 as the second offset (Unity often, but not always, has this). |
| ASM Type | (none) | Cycle between ARM32, ARM64, and THUMB assembly types. |
| Use Titlename2 | (none) | Toggles whether to use the second title name for games that have one. |
| Enable Two Register | (none) | Toggles whether to capture the data of one register or the register indirect address of code that makes use of two registers. |
| Replace Space | (none) | Toggles whether to replace space with '_' when the game name contains a space. |
| Log Button Press | (none) | Toggles whether to log your button presses to a file. |
| Visible Only | (none) | Toggles whether shortcuts can activate buttons that are not visible. |
| Reset Options | (none) | Reset all options to default. |
| Backup Focused Actions and Custom Shortcuts | (none) | Back up the current focused layouts and custom shortcuts. They become the defaults used by Reset Options. |
| Use Module Name | (none) | Toggles whether to use the module name for cheats. |
| Module Loaded Cheats Only | (none) | Toggles whether to only display cheats for currently loaded modules. |
| ShortcutProgrameKey | (none) | Define the key combo that lets you program a custom shortcut. |
| ShortcutEraseKey | (none) | Remove a shortcut if you are using Custom Shortcuts. |
| alpha_toggleKey | (none) | Adjust the alpha transparency of the UI. |
| RemoveFocused_key | (none) | Remove the selected action from Focused Actions. |
| FocusedActions_key | (none) | Open Focused Actions layout management. |
| radial_modeKey | (none) | Enter radial mode for the left stick. |
| Theme | (none) | Select the light or dark theme. |
| Use Alt Color | (none) | Replaces normal white/light text with RGB values from `/switch/Breeze/alt_color.ini`; light theme retains black text. |
| Prerelease updates | R | Allows update checks to offer prerelease Breeze builds. |

### Sysmodule Manager

**On** means a sysmodule is currently loaded and running; **Off** means no process was detected. Immediate modules can change state without restarting. Boot-time modules show a restart popup and retain their current On/Off display until reboot. See the [Sysmodule Manager Guide](sysmodules.md), including `sys-ftp-breeze` setup and security notes.
