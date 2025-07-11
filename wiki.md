Welcome to the Breeze-Beta wiki!

# Installing / Updating
1. This app support in app updating. Use "Download" "Check for app update" and if there is an update available then "Install app update" will be enabled, use it to update the app. If you just want to reinstall the app use "Redownload" to enable the "Install app update" button. 
2. You can manually install/update by downloading Breeze.zip and place the contents from this zip file on the root of your sd card, go ahead to overwrite existing file if present.

# Launching the app
1. This is a designed to run as an applet. It is not an overlay. Can only be launched via the home screen. 
2. For faster access in addition to launching via the hbmenu a forwarder hooked to profile is available. To enable profile to launch Breeze enable it with "Setting" "Profile shortcut =" buttons. Once enabled press "Home" "up" "A" to launch Breeze from your game. To return to game press "Home" "Home".
3. For reason not yet clear to me this does not work for some older version of atmosphere "Switch to HBM on Breeze directory" button can be use to enable profile to launch hbmenu made to focus on the breeze directory (so it is the only app for quicker launch). Once enabled press "Home" "up" "A" "A" to launch Breeze from game. To return to game press "Home" "Home". 
 

# Navigating the UI 
1. This app has two type of panels. Data panel and button panel. Buttons on button panel is use to activate actions and data panel present data and allow users to pick which data to be act on by the buttons. When there is two panel shown, data panel is on the left and button panel is on the right.
2. When data panel is shown either lstick or dpad is used for choosing items on this panel. (Configurable in setting). Up and down move the cursor one step and left and right move the cursor 10 steps.  
3. The unused lstick or dpad is used to navigate the button panel. Use this control to choose the buttons and press A to activate it. 
4. Short cut keys may be assigned to the buttons. Pressing these also will activate the buttons.
5. This app support full touch control. Use touch and scroll to select data and touch the button to activate the associated actions. 

# Getting / loading cheats

## Cheat Url
1. Breeze will look through a list of url to find cheats if there are no cheats already loaded in a fixed order.
2. When cheat is found or the list is exhausted the process stops. 
3. If you goto download and ask it to fetch cheat each press of the button will go down the list of urls successively until one is found or the list is exhausted. It will continue from the last url with each press of the button. This way you can fetch a different cheat file if more than one exist.

## Cheat database
1. Breeze will make use of a database of cheats and automatically load it for you when you launch Breeze if there isn't any cheat that is already loaded. You can also ask it to fetch cheat from the database which will overwrite the existing one with the one from the cheat database.
2. To get the database you can use the in app download feature. Activate these buttons "Download" "Check for cheat database update" "Install Cheat database update". 
3. Alternatively you can get it from https://github.com/tomvita/NXCheatCode/releases/latest. Put "titles.zip" in "sdmc:/switch/breeze/cheats".

## Manual placement of cheat files
1. "sdmc:/atmosphere/contents/(titleid)/cheats/(buildid).txt". This is where cheatVM will automatically load from and the file will be use by every other apps. Will be already loaded for you when the game launch but you can use "Load Cheats from atm" to reload it (if you have put or made changes to the file after you launch the game).  
2. "sdmc:/switch/breeze/cheats/(titleid)/(buildid).txt" or "sdmc:/switch/breeze/cheats/<title name>/(buildid).txt" depending on "setting" "Use titleid =?". Use "Load Cheats from file" button to load it. 
3. If the above two option is too hard, any file name you like as long as you can remember it and place it in "sdmc:/switch/breeze/cheats/(any filename)". Use "More" "any cheats from breeze/cheats" and pick the file. See notes below about BID. No check on BID match will be made on this option.

## Picking individual cheats from file (Advance option, make sure you understand what is BID, you are responsible to check that BID match)
1. You may already have a cheat file that you are using when you saw there are some nice new cheats available that you want to add to this file.
2. You don't need to manually edit your favorite cheat file to get the new cheats. You can pick cheats and add it to existing cheat file with Breeze. 
3. Use "More" "Choose individual cheats from breeze/cheats" pick the file, pick the cheats, use "Back" to pick another file or "Return to cheat menu" to return and remember to save your change.

## Combining cheats from different files
1. If there is a file you want all the cheats then Load this file using one of the method described above. 
2. Use "Picking individual cheats from file" described above to pick the cheats you want to add. 
3. Proceed to "Customizing cheats for everyone" steps below. Remember to save your work. 

## A note about code compatibility
1. It is only possible for cheat code author to do their best to ensure compatibility to the exact same copy of the game that they develop the cheat code on. 
2. To know if the game is the same copy there is what is call build id (BID). BID is a hash of the game code. Only when this match then we know the code is exactly the same.
3. Only when BID is matching would cheatVM load the code for you when the game starts. 
4. Sometime game has a different BID for different region due to some localization being done. These localization may or may not affect the compatibility of the cheat code. There is a fairly good chance that same game version with different BID has compatibility. 
5. In rare occasions some cheat code even have compatibility when the change between versions are minor.
6. To check the BID of the game installation you have when the game is running launch Breeze and use "Game information" button. 

## Loading cheat code for a BID different from the copy installed on your Switch
1. Firstly know that it is risky to use cheat code in the first place. Cheat code hack the game's memory space and can have unintended consequences.
2. If you use code written for a different BID the risk is increased exponentially. 
3. I highly recommend that you make a backup of your save and immediately press "HOME" and "X" to quit the game should some of the code don't work.
4. If you can't find cheat codes that is written for the BID of the game installation you have and you are desperate enough to want to try your luck you can load any cheat file. See point 3 of ## Manual placement of cheat files. 

# Customizing cheats for everyone
1. Basic customization of cheats can be made without any knowledge of making cheats. You only need to read the follow instructions. 
## Saving the change you made
1. There are two buttons for this. 
2. "Write Cheat to atm" will make the change to the file that atmosphere's cheatVM load cheats from. This option will change the cheat that you get from all other cheat management app.  
3. "Write Cheat to file" will write the code to cheat directory only used by Breeze. This cheat will not be loaded until you launch Breeze and request for it by activating the "Load Cheats from file" button. 

## Change cheat name
1. Don't like the name the author gave and prefer something else? You can easily change it to what ever you like.
2. Activate "Edit Cheat" button. 
3. The first line is the cheat name. 
4. Activate "Edit" button.
5. If you are happy with the edit activate the "Save" button.

## Change cheat value
1. Most cheat change a value in the game. For example Gold, HP, EXP etc etc.
2. Sometimes you just want a little help at some stage of the game and don't want to remove the challenge and fun of earning them yourself and the cheat is simply giving too much. 
3. Sometimes the cheat is giving too little in quantity of what you want and you want much more.
4. To edit the value activate "Edit Cheat" button.
5. The value is change by code type 0, 3, 6. There is a button that you bring you to these code or you can navigate to the correct entry.
6. The next thing is to guess the datatype. There is three buttons for you to use: "Edit u32" "Edit f32" "Edit f64". 
7. Normally you can tell if you select the wrong button if the number does not look right. 
8. Change the value and test the cheat. Repeat if you don't get what you want. 

## Changing / Adding conditional key / key combo
1. Some cheats has conditional key / key combo. The cheat only activates when you press the conditional key / key combo.  
2. Breeze will display the key / key combo in front of cheat name. 
3. Some times you may find that you didn't like the key / key combo that was chosen by the author.
4. Some times you don't want to have conditional key / key combo and prefer the cheat to be active all the time.
5. Some times you want to have conditional key when the author didn't include one.
6. Activate "Remove conditional key" button to achieve the stated purpose.
7. Activate "Add conditional key" to add or modify the conditional key / key combo. 
8. (The number of keys you can use in a key combo is defined in settings menu. Use "Combo keys =" button to cycle from 1 to 6.)
9. Press the keys you want to use in the key combo one at a time. The keys you press until the count down reach 0 will be in the combo. You can press the same key more than once. 

## Changing a moon jump into a hover
1. There are many use for a hover in addition to a moon jump. 
2. Activate "Paste/Duplicate Cheat" button. (If you have previously activated "Cut Cheat" button you need to activate "Clear clipboard" button first)
3. Edit the cheat name.
4. Edit the value to a smaller one (most moon jumps are f32). 
5. Change the key combo.
6. Check if the new value make the player rise or fall. Adjust the value until the character hovers. 
7. Save the cheats. 

# CheatVM operation
CheatVM runs at a fixed frequency. Each time doing the follow:
### Clears the cheat registers
The 15 registers that are used by cheat code are set to zero
### Assemble opcodes to be executed
#### Take the master code
Take the opcode with the master code label and add them one by one in order of appearance
#### Check if the next section is to be added
Go to the next label and if this label is mark to be on add the opcodes between this label and the next label one by one in order of appearance
#### Repeat the last step until there is no more labels. 
### Execute the opcodes assembled

# Syntax of cheat code file
{} or [] are use to create label. 

{} marks start of master code, opcode that follows this until [] or end of file will always be included for execution. 

[] marks start of optional code, code that follows this until the next [] or end of file can be activated (included for execution) or not activated (not included for execution) 

Only group of 8 hex digits separated by optional whitespace characters are allowed outside of {} or []

# How cheat code works

### The desired game behavior is modified by changing memory content at locations that game fetch data from 
These memory addresses used by the game may not be the same in all stages of the game. Quite often they change on major transition(when you see the loading screen, your player died, you restart a stage etc). 

### Memory hack works by using cheatVM to hack memory periodically
The data used by the game will be updated by the game code. The cheat can work only if the content is being modified by the cheatVM between game code read and write. i.e. game write, cheatVM write, game read(what cheatVM wrote). The period between write by cheatVM needs to be shorter than the time between game write and game read to be 100% successful. 
  
### ASM hack works by hacking game code to write desired content to memory
CheatVM is used to modify game code. The modified game code is the one changing the game memory.
Since game code is only loaded once, all ASM hack only need to be turn on once and it is permanent until the game is reloaded.
A off code is needed to turn off an ASM hack. The hack runs as often as the code that is hooked to run it. For example if the code hooked is written to update the life bar, when the life bar refresh the memory hacking take place. 

### Some data hack only need to be successful some of the time and some need to be so all the time
For example money, one time get 1M and you are rich for the rest of the game. 
For example HP, miss once and you can die.
Some hack that needs to be 100% successful can only be ASM hack due to short time between game write and read.
 
### Pointer chain
A pointer is an address placed in memory. A pointer points to an address that together with an offset gives you either another pointer or the memory that you want to hack. A pointer chain is a list of offsets. It's like a treasure hunt, one clue leads to the next clue and the next clue ... until the last clue leads to the treasure. 
Cheat code can make use of pointer chain that originate from main base address. The chain's validity is always time dependent. A good one is the one that is valid when you want the memory hacked. 

### The When and How
Cheat codes works at certain time and when certain action is taken. 
For example some code works when you are in battle, some code works when you are hit, some code works when you buy, some code when you sell, some code seems to work all the time because you are not able to notice when it didn't. When pointer chain is not valid or when code that was hooked don't run the cheat code won't work.

# Customizing cheats for adventurous users

## Format of cheatVM instruction
1. An opcode is 8 hex digit. An instruction consists of one to four opcodes. The first opcode specify the action of the instruction and the following opcodes provide address or data for the action.
2. Please refer https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md for more details.

## What is a master code
A master code is a code with the label that is inside {} instead of []
Any cheat file can only have one.
This will be always on.
This will be executed first.
What you do with it is entirely up to you.
Put code that you want always executed and always executed first there.
### Common use for master code
#### Set up ASM code cave
Some author likes to setup code cave in a master code. The code setup here may or may not be use by more than one cheat. Ideally this can be just done once per game session but current format don't support it.
#### Set up register content that may be use by more than one cheat code
Many pointer cheats may have pointer chain that start with a common section, this is one way to reduce cheat code size. 
#### Enable ASM cheat to be turn off
When a ASM cheat is turn off, cheatVM stop writing the ASM code to memory. This don't change what is already written. So there is the need to write the original code back to memory.

## Disassembler and Assembler
1. Use "Cheats" "Edit Cheat" "Toggle Disassembly" to look at the code with a disassembler I wrote to make the cheat code more readable. 
2. Use "Assemble" button to explore code change with the interactive assembler I wrote to make code change/composition easier. First line on left panel shows the code type. When the cursor is on this line "Increment" and "Decrement" button change the code type. 
3. The lines below shows the fields that correspond to the code type selected and some fields also changes with the options selected by other field. Move the cursor to the line and use "Increment" and "Decrement" button to change the field. 

Code works by modifying memory. Hacking the right memory address with the right value gives the desired change in game behavior
# ASLR, dynamic memory and reacquiring the addresses found previously by memory search
Address space layout randomization is performed every time a game starts. This means the game addresses are never the same when you restart a game. The game memory address that was found in search needs to be reacquired every time the game starts. Dynamic memory means memory is allocated when needed from a pool (heap) when needed and released back into the pool when no longer needed. This means target addresses also quite often don't stay the same even in the same gaming session. Luckily the second time around it is easier. Here are some of the method to reacquire those memory address
## Base address + offset
Some memory addresses has a constant offset from main base address or heap base address. Every bookmark in Breeze always have this information and the current physical address. When the current physical address is not accessible, base + offset address is then used to resolve the memory address. If a bookmark is still good after you restart the game there is a very good chance that this may be the case every time you restart the game, to be very sure check a few restarts. To make cheat code is as simple as using the bookmark to cheat button in bookmark menu. 
## Pointer chain
Pointers that originated from main data segment sometimes lead to a chain of pointers that eventually lead to the desired memory addresses. What is needed is a series of offsets. To find these offsets is call pointer search. A bookmark in Breeze may also have a pointer chain attached to it. If a bookmark is derived from another that has pointer chain then it will also have pointer chain attached. If not pointer search needs to be performed. Just like the previous case you want to check that the bookmark is good when the game restarts, when there is enough confidence that it is good make a cheat code using the bookmark to cheat button in bookmark menu.
## Pointer Search
Coming in a future update
## Register content of game code
Game code is given the memory addresses of interest. By hooking game code and using the register content when the code execute we can have access to the memory address that we wish to acquire. 
# Hacking the game memory
## CheatVM directly writing to game memory
CheatVM is executed at a fix frequency. On every cycle that it execute desired memory writes are performed. The timing is not in sync with game process.
## CheatVM injecting ASM instruction that do the change 
The act of hacking can only be performed when the hooked code has a chance to execute. The frequency of execution is not fixed. The timing is sync with game process.
### Finding the code to hook
To hook a game code is to hack the game code to branch off to a code cave (a series of unused bytes in a process's memory that has capacity for injecting custom instructions). 
#### Perform a watch on a memory address to find code that access it
#### Check the list of codes to find one that is suitable
### Writing the ASM code
#### Direct code replacement
#### Code cave

Breeze search is file based. Each search will result in a file being created with a list of address value pair. When you continue a search it will search the address stored in the file that the cursor is on. With this system you have unlimited redo at any stage of the search, just point the cursor at the desired file.
# If you see a number on game screen and want to change it
## Mind the game state
It is not very common for a memory address to be valid for the whole duration of the gaming session. Quite often when there is a major state change the addresses where your targets are at will change. If you need more than one search to narrow down the list of candidates bear this in mind. If you see "loading" most of the time it is back to square one.
## Data types
Data types is how the bits in memory are representing numbers
### u8, u16, u32, s8, s16, s32
Integer of 8, 16 and 32 bit respectively. u8, u16, u32 are unsigned integer and s8, s16, s32 are signed integers. u32 is the most common, u16 is used by 16 bit games, u8 is sometimes used by game that combine two attribute into one variable. The signed variant is when the most significant bit is the sign bit. 
### f32, f64
f32 is single precision floating point, f64 is double precision floating point. 
## What you see is what you search
The most commonly used types are u32, f32, f64. "=*" will perform a search for these two types that equal to the value you enter. Just enter the value and perform the search. Go play the game and see that the value changed then come back and repeat the search. Do this for some iteration until the number of candidates is small enough. 
## Test the candidates to see which one is the right one
You modify the value and see if you get the desired effect. 
![2023022812511400-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/221757376-0a924d43-199d-4426-b98c-a34534a08e99.jpg)
### Edit, ToggleFreeze
If the list is small just do it individually
### Freeze100, Unfreeze100, Set1000
If the list is fairly large you may want to try this to know if the list even has the right target to avoid wasting time. Bear in mind that change many targets at once also increase the risk of crashing the game. The action is only from the cursor down and does not affect items above the cursor. You can move the cursor to select any range that is smaller than the number of candidates the button will act on. For example Freeze100 from index 1 then Unfreeze100 form index 4 will means only index 1,2,3 are frozen. Same apply for Inc1000 and Revert1000
### Inc1000
Increment the value so it becomes easy for you to identify the right one
### Revert1000
Remember to restore the value and this can save you from a crash some of the time
### Display value is same as effective value
Change the value and see the update on screen, found the one, job done
### Display value is not same as effective value
Sometimes the display value and the effective value are not the same. The effective value is updated on screen only when the game change it, when you change it the update don't happen on screen. The update only comes when the game update the value.
## Didn't find any good candidate?
Try a different datatype and repeat the search. Usually u16 is the next one, then u8
## Still didn't find any good candidate?
Try unknown value search
## Unknown value search
When you can't see a number on screen you need to either do a range search or do a full dump as a first search. Then you need to make a guess of the datatype and follow up with Change from previous value search.
## Change from previous value search
### ++
The value has increased from previous value on file
### ++Val
The value has increased from previous value on file by val. (sometimes the game will let you know this number)
### --
The value has decreased from previous value on file
### --Val
The value has decreased from previous value on file by val. (sometimes the game will let you know this number)
### same
The value is same as previous value on file
### sameB
Search the address on file but use the value stored in file mark with a B. This is useful when you can be sure the value is the same. For example you can expect full bar of health to be the same value.
### diff
The value is different from the previous value on file.

# These are the defined sizes
*   constexpr static size_t MaximumProgramOpcodeCount = 0x400;
*   constexpr static size_t NumRegisters = 0x10;
*   constexpr static size_t NumReadableStaticRegisters = 0x80;
*   constexpr static size_t NumWritableStaticRegisters = 0x80;
*   constexpr static size_t NumStaticRegisters = NumReadableStaticRegisters + NumWritableStaticRegisters;
*   constexpr size_t MaxCheatCount = 0x80;
*   constexpr size_t MaxFrozenAddressCount = 0x80;
*   constexpr size_t          CheatMaxSessions = 2;

# Each cheat has this data structure
*   char readable_name[0x40]; The cheat label is limited to 64 characters
*   uint32_t num_opcodes; 
*   uint32_t opcodes[0x100]; You can only have 256 opcodes in each cheat

# Setting menu
![2023022810294300-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/221738544-3ef95f03-9f57-49b7-b355-1753a40e7d1b.jpg)

## Sysmodule manager
![2023022810353900-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/221738864-d49e0cd9-9ba3-46ca-8c7b-87dd24707603.jpg)
Optional sysmodules can be enable here.
### Tesla
Tesla is a sysmodule required to enable overlay. Tesla consume a large amount of memory and is known to have problem with EdiZon and some games (for example MHR). I would recommend turning it off at the first sign of trouble. Tesla is not part of Breeze.
### 010000000000d609
You will see this if gen2 fork is installed. You can't disable it here. Delete the directory /atmosphere/contents/010000000000d609 to use the original
### sys-ftpd-10k
This is a ftp sysmodule. My fork enlarge the buffer to slightly increase the transfer speed. This is bundled with Breeze but turn off by default. I have it on all the time so I can easily transfer cheat code into the Switch
### NoExes
My fork is bundled with Breeze but turn off by default. This is required to enable pointer searcher se to communicate with Switch. This is backward compatible with JNoexs. If you have the original you need to remove it for this to work as it listen to the same port (for backward compatibility).
## Profile shortcut
Enable this will make profile short cut launch Breeze. Toggle it off the make it launch profile again. You can also launch profile when this is on by holding R
## Combo keys =
This is the number of keys you can have when you customize a cheat with activation key press. If you want to have a cheat that activate by pressing say ZL+ZR+L+R then you need the number to be 4. Default is 2. You don't have to reduce this to use a smaller number of keys as you can repeat the same keys. Breeze only record unique key press
## Use titleid =
Default 1. Set this to 0 to use title name, there are some games that has title name that isn't compatible with PC file system and cannot be seen by ftp. I prefer title name as they are easily recognized compared with titleid
## Use starfield as background =
Set this to 0 to see the screen of the game
## Install gen2 fork
Only support 1.4 and above. You need gen2 fork to use any gen2 features of Breeze.

As per official atmosphere, you also need these two lines in atmosphere/config/system_settings.ini to enable gen2

[atmosphere]

enable_standalone_gdbstub = u8!0x1

## Use Dpad for Left panel item select =
0 use left stick
## Search Code Segment =
1 to search for code
## Search Main only =
This will limit search to main so if you already know what you want to find is in main this will make the search faster
## Install dmnt fork
My fork make some code type extension. https://github.com/tomvita/Breeze-Beta/blob/master/cheats.md
## VisibleOnly
1 is default. Only buttons that are visible can be activated with the corresponding short cut. 0 will allow short cut keys to be used when the button is not visible. This setting is found in Search Manager but it is global and affects all menu 
![2023022811230400-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/221745391-071ce427-3e8d-4098-9cb3-450a03199436.jpg)


# Breeze: File Management and Game State Handling

Breeze is a powerful tool for tracking changes in game memory across different states. Its unique approach requires a bit of adaptation but offers greater flexibility and accuracy compared to other tools like EdiZon. Below is a detailed explanation of how Breeze works.

---

## Search Process in Breeze

Breeze creates files that store **address-value pairs**, which represent the search criteria. These files help track changes in game memory across different states. The process involves the following steps:

1. **Dump to File 1**: Capture a full memory dump of **Game State A** (data for every address in game memory).
2. **Play the game and make changes**: Transition from **Game State A** to **Game State B**.
3. **Diff from File 1 to File 1(00)**: Identify addresses with values that changed between **Game State A** and **Game State B**. Store the values from **Game State A** in **File 1(00)**.
4. **Diff from File 1(00) to File 1(01)**: Identify the same addresses but store the values from **Game State B** in **File 1(01)**.
5. **Play the game and make further changes**: Transition from **Game State B** to **Game State C**.
6. **Diff from File 1(01) to File 1(02)**: Identify addresses with values that changed between **Game State B** and **Game State C**. Store the values from **Game State C** in **File 1(02)**.

In summary, the Breeze search process follows this sequence:  
**Dump → Play → Diff → Diff → Play → Diff**

---

## File Management

To simplify the process:
- The first file is automatically named **File 1** if it doesn’t already exist.
- Subsequent files are named sequentially, such as **File 1(00)**, **File 1(01)**, **File 1(02)**, etc., to maintain an organized structure.

Each file stores:
- **Address-value pairs**: The values represent what was in memory at the time of the search.
- **Screenshots**: A screenshot of the game is saved with each file, allowing you to visualize the game state at the time of the dump.

---

## Key Behavior of Diff

- When performed on a dump result, the **Diff** operation stores data from the **dump** (not the current memory).
- To capture the current memory state, a second dump must be performed sequentially.

---

## Comparison with EdiZon

- **EdiZon** uses a single file, and each operation overwrites the previous result. Its process is:  
  **Dump → Play → Diff → Play → Diff**

- **Breeze** requires one additional search step when starting with a dump:  
  **Dump → Play → Diff → Diff → Play → Diff**

This extra step in Breeze ensures that changes are tracked more comprehensively, with separate files for each state and diff operation.

---

## Game State Explanation

- **Game State A**: The initial state where you dump the game’s memory (stored in **File 1**).
- **Game State B**: The state after making changes (stored in **File 1(01)**), with a diff performed between **Game State A** and **Game State B**.
- **Game State C**: The state after further changes (stored in **File 1(02)**), with a diff performed between **Game State B** and **Game State C**.

This progression helps track changes in the game’s memory and provides a clear view of how values evolve over time.

---

## Why Breeze?

Breeze’s approach provides a more detailed and organized way to track memory changes across game states. By creating separate files for each step and storing values from both the dump and current memory, Breeze offers greater flexibility and accuracy in analyzing game memory.

---

Let me know if you have any questions or need further clarification!

After you found a memory location you want to hack the next step is to hook a code that will lead you that change

# Watch the memory location with Gen2 menu and get a list of candidates
In memory explorer point the cursor at the memory you want to hack press "SetBreakPoint" which will bring you to Gen2 menu. "Gen2Attach" followed by "Execute Watch" will start the watch. Go back to the game and play it a bit. Then come back to see if some candidates had been captured. If the list is empty it means you did not play the game until that memory had been access. (by default both Read and Write will be captured, you can customize that with the "Read=" and "Write=" buttons before you execute watch)  
If you are satisfied with the amount captured then "Gen2Detach"

# Check what the candidates do
The next step is to [put a watch on the instructions to see what memory the code access](https://github.com/tomvita/Breeze-Beta/wiki/How-to-watch-what-an-instruction-reads-or-writes)
## Most of the time you want a code that access your target and only your target
Make sure you play the game enough. Check back and see that there is only one memory target this code access and that it is the memory that you want to hack. You are now done and can proceed to write the code to do the hack
## Some times you want code that access a list of target, for example if you were looking at the quantity value of an inventory item maybe this code access all the items in that list. Hooking this code will let you hack the whole list at one go.
Check the targets of this code to identify what they are. You can use the "Save as candidates" button then goto Search Manager menu and use "Show Candidates" button and play with those candidates with the tools available in Candidates menu.
Once you are happy that it is the code you want to hook you can proceed to write the code to do the hack
## Some times the code access both Friends and Foe
First make sure that the code only access the correct property that you want to hack. For example HP, then the memory needs to be only HP for your hero, friends and foe.
* If you like you can make a code that hack all HP. Such code can be selectively activated by conditional key and sometime that is already perfect (game play dependent)

If you can only find this kind of code you need to [find a way to identify friend from foe](https://github.com/tomvita/Breeze-Beta/wiki/How-to-tell-friend-from-foe) and potentially make also a one hit kill for foes. 

### Install my fork of dmnt gen2
![2023080114312600-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/328ebef6-34f8-4d93-a13b-ed8a91bf6b23)
### Enable gen2 fork in your system_settings.ini
you need these lines in the file /atmosphere/config/system_settings.ini 
* [atmosphere]
* enable_standalone_gdbstub = u8!0x1
* enable_htc = u8!0x0
### If you have no clue how to edit files on Switch
You can have my system_settings.ini. Bear in mind that then any customization done to that file by some others for you will be lost 
![2023080114345500-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/d748ff32-1a6d-4b9e-a648-8074e2eb0ffe)

### Reboot Switch for change to take effect

## It is quite common for a game code to access a group of items
* This can be a list of inventory items
* This can also be a number of stats that is display on screen
## Find a value
Say the qty value. Do the search, reduce value, search again, hack and validate the memory address is the correct one
## Find the code that access the value
Set a watch on the value address
## See what the code access
Set a watch on the code
## Play the game
## Look at what has been captured
## Save the list
## Use candidate view to hack the values

* Quite often code reuse cause the code that targets Friend to also targets Foe.
* When you can't find an alternative that only target one or the other a method to tell friend or foe is needed
# Look at the value of X30
Some times the X30 is distinct between friend or foe.
First enable X30 match to see if the access is now distinct between friend or foe.
If it is then job done and can proceed to [make ASM hack with X30 match](https://github.com/tomvita/Breeze-Beta/wiki/make-ASM-hack-with-X30-match)
# Look at return address on the stack
WIP
# Look at the pattern around the data value
There isn't a generic way, the guess may turn out to be no good at some stage of the game

# Introduction
With every update most of the time the game code would have shifted and quite often the code itself wasn't changed.
AOB method search for binary sequence of bytes to located the new position of the unchanged or moderately changed code.

Breeze's tools for AOB are not polished enough for it's use to be intuitive. If you are ready to bear with that here is a write up on how to use it.

![2023070709451800-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/8ec5d802-de68-43dd-ac83-f4f1d8aaa3a7)

# "Make AOB"
This method requires AOB pattern from the game code to be been recorded.
Breeze's ASM creation tool will leave the original code above the branch to code cave. Make AOB will look for this pattern.
The follow two screen illustrate this, if "Add ASM" is used to create the cheat there will be these lines that write to the same address, the first write the original code and the second the branch to code cave. 
![2023070709511500-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/5ba30d6c-aba8-4571-93e2-7c793fa8403a)
![2023070709535000-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/4d109ef9-3c18-4814-bec6-33f8f094debe)
This works only for ASM code created with "Add ASM"
To use this button on code that wasn't created this way all you have to do is to make a code that has this pattern.
The only thing that is important is the code is writing to the start of the AOB pattern you want to capture.
The button creates a file with code that writes the eight instructions of the original code at that address.
When you press this button a file with aob appended to the title id would be created.
![2023070710130000-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/b2445664-41fc-4a45-b3ec-0b1f9eeec68f)
The list of cheats in this aob file is writing the first 8 instruction found in the game code
![2023070710131300-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/6383deea-9ca3-4349-9781-ca7409e7e36a)


# "Load AOB"
This button loads the AOB pattern into advance search and start the search.
![2023070710230400-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/197885dc-275b-4b6a-b657-1f11847798db)
In this case I apply it to the same game version so there is only one result, sometimes you are lucky and there is only one also with the new version and sometimes there are more than one and sometimes non and you may want to revise the advance search criteria.
![2023070710231300-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/032f96ef-5a95-4199-9e47-386fe94b7343)
You can delete lines that may have higher chance of change, for example that bl #0xcd920 would only be unchanged if there isn't any code added between here and there that is 0xcd920 bytes away.
![2023070710452400-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/54629042-d609-4689-a0c1-88c02b9db18e)
![2023070710454500-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/tomvita/Breeze-Beta/assets/68505331/39c0077f-3063-418d-a1b3-71a2c1b671b8)
Load AOB would automatically insert a gap for the search criteria. The more you delete the higher chance of having more than one result but some results(hopefully not too many) is better than no results. 

# Getting to ASM explorer
## From a cheat code
If the cheat code is patching game code you can use "Jump to ASM" button
![2023040512243900-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229980780-e74a480d-ed40-480e-9310-af1b6bd87a0b.jpg)
## From memory explorer
Use "ASM explorer" button
![2023040512284600-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229981179-67962c8c-1795-4199-946a-c1ff7df82a81.jpg)

# Set a watch on an instruction
![2023040512305700-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229981532-e4eca29d-9f37-4adb-9061-437efd20426d.jpg)

# Attach Gen2
![2023040512310700-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229981547-7af2e2fb-5e7b-4d5d-a9af-aaa1ba7dd0bc.jpg)

# Execute Watch
![2023040512311300-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229981569-395bb2a1-0c56-46ba-9c2d-dae51b0ce945.jpg)

# Play the game

# Detach Gen2
![2023040512370300-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229982391-33b018a7-5b90-4ef3-b58b-c03f718c4190.jpg)

# Examine the results
Press select will bring you to memory explorer of the data so you can look at surrounding values 
![2023040512463000-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229983519-324e6a6c-097b-4130-b784-35839b7819eb.jpg)
You can go back to asm explorer with your cursor is at the address of the code
![2023040512463700-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/229983835-d8a4f407-fd44-4ff6-953d-fe478fc6b479.jpg)

Goto ASM composer then load "x30.txt" then use "X30_cmp" to insert the last X30 number captured by gen2 menu.

# Here is a sample:
* stp x25, x26, [sp,#-0x90]	
* ldr w25,e
* lsl w26,w30,16
* cmp w25, w26
* b.ne original
* ( put you hack here, you may also want to put something here to watch to check that the code did the correct screening )
* original: {original}	
* ldp x25, x26, [sp,#-0x90]
* return: b code1+4
* e:.word 0x2e780000


Goto ASM composer then load "x30.txt" then use "X30_cmp" to insert the last X30 number captured by gen2 menu.

# Here is a sample:
* stp x25, x26, [sp,#-0x90]	
* ldr w25,e
* lsl w26,w30,16
* cmp w25, w26
* b.ne original
* ( put you hack here, you may also want to put something here to watch to check that the code did the correct screening )
* original: {original}	
* ldp x25, x26, [sp,#-0x90]
* return: b code1+4
* e:.word 0x2e780000


## What is BID
Build ID is a [hash](https://en.wikipedia.org/wiki/Hash_function) of the game code. CheatVM uses this to identify the game code being the intended target. The way cheat code works requires the game being hacked to be exact binary image of what the hack was made for, no deviation even for a single bit can be allowed. Only on very rare occasion would a game with a different BID have cheat code compatibility. 

## Why you should not use cheat code of unknown quality
Cheat code makes hack to game and the ill it made may not be immediately apparent. All cheat code have the possibility to damage your game in a unrecoverable(other than to delete the save and restart the game from the beginning) way. Cheat code makers may not do that much of testing but thanks to channel of feedback(if they exist) there may be reasonable amount of quality assurance. Pick your cheats with that in mind. 

## Why it's not a good idea to rename cheat code file to match your game's BID
This will fool the CheatVM into executing code that wasn't intended for your game. This is like changing the label of medicine, it is just as senseless or full of malice. If you are changing the label and eating the medicine check in to a hospital first before doing so (make a backup of your game save and restore it immediately if nothing happens, bear in mind that if you didn't die it does not mean you are out of the woods). If you hate the game this much just delete it already!

## What can be done when BID don't match
A lot of fundamentals of a game don't change with updates. In fact most of the time only a very small percentage of the game code is changed. The way cheat code works is by using offsets and these offsets do change which of course will make cheat code invalid. To make the code work again the change in offset needs to be found and corrected. Most of the time pointer code only have the first offset changed. This can be easily corrected by trying every starting point in main.(This is performed by Breeze when you try to add a invalid pointer code to bookmark and the results are added to bookmark, you can then look at them to see if some of them are good. Even if search needs to be performed again looking into the code will give ideas how they were made in the first place and if the original is still available learning from the existing code will make creating them again very easy. 

## How does multiplier cheat works and how to customize it
Most of the time multiplier cheats are ASM code and generally it fall onto two types
### mov Rd or fmov Rd ,#imm
If the immediate value match the described multiplier, assume it is the multiplier, change it and profit
### add Rd, Rn, Rm, lsl#
Add can be modified into multiply when a left shift is performed but only with multiple that is power of 2
lsl#2 means 2^2=4, lsl#3 means 2^3=8 etc

## Be careful if you use BL or the stack
On ARM the CPU don't update SP and X30 automatically when a call it made, it is up to the code to do something with SP and X30, if a subroutine is not going to call another there is no need to update SP nor save X30 so it won't. 

If your hook is inside this kind of subroutine it is inherently unsafe to just use the stack if you don't know how much of it this subroutine uses. If you do a BL to code cave you will be corrupting X30 and that means crashing the game.

In the course of the search you may need to launch Breeze frequently. Making it easier is the goal of this step. 

When you go home screen if you press up your cursor will be ready to launch profile when you press A

![2023042119372000-57B4628D2267231D57E0FC1078C0596D](https://user-images.githubusercontent.com/68505331/233627936-ec878748-9f73-4a76-a032-9f05aef448e9.jpg)

If you like you can take over profile and have Breeze instead when you press A

Goto "Settings" then press Y to toggle this option.

![2023042119473600-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/233628277-f84467e7-46d3-4df3-b78a-9216d560f020.jpg)
![2023042119474600-CCFA659F4857F96DDA29AFEDB2E166E6](https://user-images.githubusercontent.com/68505331/233628298-c992a98f-d54b-4d99-ad00-d9878074fe91.jpg)

After you did this, when you press A you will be launching the first app that hbmenu sees. Make it Breeze by "Staring" Breeze if it isn't the first one.
![2023042120020100-DB1426D1DFD034027CECDE9C2DD914B8](https://user-images.githubusercontent.com/68505331/233631198-795d580b-369a-47d6-be55-19db27781d98.jpg)

Now you can launch Breeze quickly by pressing "Home", "up", "A"



  















