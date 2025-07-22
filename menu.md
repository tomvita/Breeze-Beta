# Menu Documentation

This document outlines the button controls for the various menus in the application.

## Main Menu

The main entry point of the application, providing access to all major features.

| Button Name | Default Shortcut | Action |
|---|---|---|
| Cheats | Y + ZL | Opens the Simple Cheat Menu. |
| Cheat Menu | R | Opens the Advance Cheat Menu. |
| SearchManager | L | Opens the Search Manager Menu. |
| Bookmarks | Right Stick Up | Opens the Bookmark Menu. |
| Help | (none) | Opens the Help Screen. |
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
| [A,B] | (none) | Search for values that match A, followed by B in sequence. |
| [A,,B] | (none) | Search for A and B within a specified distance to each other. |
| ++Val | (none) | Search for values incremented by a specified amount from previous values. |
| --Val | (none) | Search for values decremented by a specified amount from previous values. |
| STRING | (none) | Search for string values. |
| SAMEB | (none) | Search for values that are identical to the previously stored values in the file marked as B. |
| DIFFB | (none) | Search for values that differ from the previously stored values in the file marked as B. |
| B++ | (none) | Search for values that have increased compared to the previously stored values in the file marked as B. |
| B-- | (none) | Search for values that have decreased compared to the previously stored values in the file marked as B. |
| NotAB | (none) | Search for values that are different from both this file and file marked as B. |
| [A.B.C] | (none) | Search for values that match A, followed by B, and then C in sequence. |
| A bflip B | (none) | Search for bit-flipping identical to bit-flipping between A and B. |
| Back | B | Go back to the previous menu. |

## Search Manager Menu

Manage search files, continue searches, and view candidates.

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
| A,,B distance | (none) | Set the distance between A and B when making search for A and B near each other. |
| Help_toggle | (none) | Toggle whether help text is displayed. |
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
| Change Type -&gt; | R + ZL | Cycle to the next data type. |
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
| Change Type &lt;- | L + ZL | Cycle to the previous data type. |
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

## Jump Back Menu

Analyze pointer chains and perform multi-level pointer searches.

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

Perform advanced data watch and capture to assist in cheat creation.

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

Provides extra tools for processing data captured with the Gen2 menu.

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
| Sysmodule Manager | X | Access and manage sysmodules.
| Profile Shortcut | Y | Toggle a shortcut to launch Breeze via a profile.
| Extra Button | (none) | Add utility buttons to assist menu navigation.
| Jump to Last Menu | R | Toggles whether to start at the main menu or the last menu visited.
| Combo Keys | (none) | Sets the number of key presses expected for a combo key definition; can press the same key more than once.
| Use Title ID | Right Stick Up | Toggles whether to use the title ID or game name for the Breeze cheat directory.
| Custom Shortcuts | Left Stick | Toggles whether to define your own shortcuts or use default shortcuts.
| Use Starfield | + | Toggles whether to use a starfield as the background or the game screen as the background.
| Use Dpad for Left Panel Item Select | (none) | Toggles whether Dpad is used for left panel control and left stick for right panel control, or to flip the choice.
| Shortcut Program Key | (none) | Define the key combo that lets you program a custom shortcut (number of keys in the combo is defined by "Combo keys").
| Shortcut Erase Key | (none) | Remove a shortcut if you are using Custom Shortcuts.
| Alpha Toggle Key | (none) | This key allows you to adjust the alpha transparency, revealing more or less of the background.
| Focus Mode Erase Key | (none) | This key allows you to remove the button in easy mode.
| Focus Mode Toggle Key | (none) | This key allows you to toggle between focus and normal mode.
| Radial Mode Key | (none) | This key allows you to enter radial mode for the left stick; this key can no longer be used with any shortcut.
| Theme | (none) | Select the light or dark theme of Breeze.
| Use Alt Color | (none) | Toggles whether to use an alternate color for Breeze's font.
| Save Setting | B | Save changes and exit this menu.
| Gen2 Fork | - | Toggles installation of the custom sysmodule needed to capture data for ASM cheat creation.
| Noexes Fork | (none) | Toggles installation of the custom sysmodule for JNoexs and PointerSearchSE.
| Search Code Segment | (none) | Toggles whether to search for code in the code segment.
| Search Main Only | (none) | Toggles whether to only search the main segment (if you already know that your target is there).
| Dmnt Fork | (none) | Toggles installation of the custom version of CheatVM.
| Export B8 Only | (none) | Toggles whether to only export as text the bookmarks that have B8 as the second offset (Unity often, but not always, has this).
| ASM Type | (none) | Cycle between ARM32, ARM64, and THUMB assembly types.
| Use Titlename2 | (none) | Toggles whether to use the second title name for games that have one.
| Enable Two Register | (none) | Toggles whether to capture the data of one register or the register indirect address of code that makes use of two registers.
| Replace Space | (none) | Toggles whether to replace space with '_' when the game name contains a space.
| Log Button Press | (none) | Toggles whether to log your button presses to a file.
| Visible Only | (none) | Toggles whether shortcuts can activate buttons that are not visible.
| Reset Options | (none) | Reset all options to default.
| Backup Easy Mode and Custom Shortcuts | (none) | Backup easy mode and custom shortcuts to a file. Your current custom keys and easy menu will become the new defaults when you use the reset options button.
| Use Module Name | (none) | Toggles whether to use the module name for cheats.
| Module Loaded Cheats Only | (none) | Toggles whether to only display cheats for currently loaded modules.