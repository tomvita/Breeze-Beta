# Context-Sensitive Help System

Breeze includes an in-application help overlay that follows the current menu and selected action.

## Controls

- Hold **ZR first**, then press **A** to open or close help for the current menu.
- Use the **D-Pad** to select a topic and **A** to open it.
- Use **Left/Right** to change lesson pages. A also advances to the next page.
- Press **X** on the topic list for Action Help about the action selected behind the overlay.
- Press **B** in Action Help or a lesson to return to the topic list. Press B on the topic list to close help.
- The Main Menu **Help** button opens the Main Menu tutorial directly.

Help blocks input to the underlying menu, preventing accidental action activation. Breeze saves the selected topic, page, detail state, and Action Help state per menu in `/switch/Breeze/tutorial_state.ini` and restores them after restart.

## Coverage

The Main Menu includes Introduction, UI and controls, Settings and customization, Using cheats, and Making cheats. Contextual lessons cover Cheat menus, Focused Actions, searches, candidates, bookmarks, pointers, JumpBack, CheatVM, ASM Composer, ASM Explorer, Gen2, Unity/IL2CPP, Unreal, GameMaker, downloads, Settings, and Sysmodules.

## Focused Actions

The generated **Focused/All** button opens the Focused Actions overview. In the Focused Actions manager, each management button has its own Action Help. The manager has separate tutorial state from Search Manager even though they share an internal menu ID.

## Safety

The overlay explains controls but does not make an unsafe memory edit safe. Verify the running game, Build ID, address, data type, and destination before closing help and executing an advanced action.
