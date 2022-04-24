# Breeze
A Nintendo Switch game cheating tool designed to work with Atmosphere's cheatVM.

This will start as a rewrite of the features I put into EdiZon SE. As I added features to EdiZon SE the code has become increasing hard to maintain and the UI is probably confusing for many users.

I have three objectives: 

1. To improve the UI so more users are able to enjoy the features. 
2. To make the code easier to built on.
3. Apply what I have learn in developing SE tools to build a better foundation for further development. 

# Features 
1. Manage cheat codes for atmosphere cheat VM. Toggling code on/off, easy adding/removing of conditional key, loading cheats from cheat database, picking cheats from multiple cheat file, editing cheats in app.
2. (Not yet implemented) Search memory, edit memory, freeze memory, search for pointer chain to locate dynamic memory location. Creat memory and pointer chain bookmark. Generate cheat code from bookmark. Generate bookmark from cheat code.
3. Auto update of app and database. 
4. Consistant and easy to use UI.

# Search concepts
1. Memory locations use for storing data of interest can remain static for a window of time. The objective of search is to locate these location while it is still valid.
2. Game state where such memory locations remain static can vary between games. For most game many location of interest stay between loading screen. Some location only stay for a certain mode, for example in a specific screen and is lost upon exiting the screen. It is for the user to guess the condition (where memory address of the data of interest stay static) and hope that the search converge within the window of opportunity.
3. The data type is the format how data is stored in memory. Commonly use data types are u32, f32, f64, u16, u8, obfuscate type, packed integer (in my opinion try your search in this order). 
4. What you see is what you search(first). Normally you will start with a known(you think you know the data format and value) search. Guess the data type and make search for the number that you see on screen. 
5. Fast unknown(fuzzy) search. Sometimes the value is not directly represented. For example a heart may be not 1 in data representation but is 4 or 5 or 10 ... or you may see a bar on screen. Guess the datatype and try range search first, for example you see three hearts, search for number between 3 and 300(make the range too big it will take longer time to converge, make the range too small and you risk excluding the data and the whole search exercise in vain), play until you loose heart, search for less(current value < previous value), continue to search for less or more(in case you have potion to recover heart) until you have a smaller list of candidates.
6. Full unknown search. When 4 and 5 above fail to give you the results that you seek first examine you assumption on point 2 above and decide if you want to repeat 4 and 5. When you are sure you want to do full unknow search then continue as full unknown search is time consuming. First do a dump on memory. See that the item you want to search has changed, now you have another decision to make, if you think you know that the number is increasing or decreasing do "increasing" or "decreasing" search, if you have no idea do "different" search.

# Game hacking concept
1. There are two way to hack a game, you can either change game data directly or you can change the game code that modify the data.
2. Searching memory help you find memory address that are changing in tandem with the game value you want to hack. The only way to know which one is effective in changing the game prpoerty is by hacking the value. Some changes the effective value and some changes the display value. Most of them will appear to have no effect to the game. 
3. The most valuable memory address is of course the one that store the effective value but sometimes the game don't fetch this and update the display regularly and instead only update the display when the game code make the change to the value. So you may miss it and think that the address isn't the right one, instead you may think that the display value is the one, only to be disappointed later when you found out that you have been fooled. Display value and those other value that only change in tandem are useful in code tracing that leads to effective value.
4. ASLR cause memory address of a Switch game to be always different when you start a game. What is call "static" address are those that are static relative to the start of game code(main) or relative to the start of dynamic storage(heap). For static address once you have found it you are done as main and heap are both easy to locate and will be automatically supplied by (probably)all hacking tools. Unfortunately not all memory of interest are "static", for these either a game code hack(often referred to as ASM hack) is needed or a pointer chain is needed(to find this chain is often referred to as pointer search). 

# Breeze search manager
1. There are four search commands: "memory dump", "dump compare", "start search", "continue search".
2. Each search command produce a file with the extension of ".dat" in "sdmc:\switch\Breeze\". These files are valid only while in the window of opportunity to find the target(please read search concept above). While in the current game session Breeze can't tell if you are still in the window of opportunity, it's a matter for you to decide if you want to keep any of the file produced. If you enter search manager in a different gaming session Breeze will delete the useless files(before you do this the files will be taking up space and you may want to delete them manually, some of these file can be very large in size). 
3. There are two type of search file in Breeze, memory dump and address data pair of candidates found. "memory dump" is the only command that produces memory dump, the rest of the commands produce address data pair.
4. There is two way to start a search. "memory dump"(then "dump compare" followed by as many "continue search" as desired) or "start search"(follow by as many "continue search" as desired). 
5. "dump compare" and "continue search" can only be follow up action upon a prior search file. "dump compare" requires a prior memory dump file and "continue search" requires a prior address data pair file. 
6. This system allows as many undo and as many search missions as your storage can support and you can continue or start any search any time within the windows of time where the memory state is valid. Name the file according to your preference to help you identify them. You can delete any file to free space. 
7. All search can be paused with the "Pause Search" command. The search will resume with any search command("memory dump", "dump compare", "start search", "continue search"). To issue a new search command use "End Search" to end the current search. When "End Search" is issued the file is closed and can be use for follow on search even if the search wasn't 100% complete.  

# How to install
Copy the contents of Breeze.zip to the root of your SD card.

# How to use
https://github.com/tomvita/Breeze-Beta/wiki

# Acknowledgement
The UI framework is derived from daybreak.
The knowledge on game hacking is gain from making edizon se and many thanks to Werwolv for showing the way both in the work he did and the advise he gave. 
Thanks to the many people who share their knowledge in coding and game hacking. A big thanks to the Atmosphere team, without atmosphere there can be no breeze. 
