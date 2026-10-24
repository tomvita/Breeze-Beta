# Break on a Game's Start-up

Some code runs only once, while a game starts: its own set-up, the first reads of its data files, the code that builds the objects you later want to cheat. gen2 normally attaches to a game that is already running, so by then that code has finished. **Launch for gen2** starts the game with gen2 already on it, held before it has run a single instruction.

Needs Breeze beta128.02 or later and the **v0.21 gen2 fork** (Settings > Install gen2 fork, then reboot).

## Start the game held

1. Close the game if it is running.
2. Main > **Games** (ZR+X on Main). Put the cursor on the game.
3. Press **ZR+Y** (**Launch for gen2**). Breeze closes and the game starts.
4. The screen stays on the Switch logo and "Licensed by Nintendo". That is expected: the game is held and has not drawn anything yet. It waits as long as needed.
5. Press **HOME**. Breeze comes back and opens the **Break and Trace** view on the game's first instruction.

The first instruction is in rtld, the loader that runs before the game's own code. It sits just below the game's main module, so its lines show a plain address (for example `0B96600000:`), while lines inside main read `M+...` as usual.

## Place breaks and run

- Move to the code you want to stop at and press **Break point** (ZL+X). **Temp break point** (Minus) is one that goes away when it is hit.
- Press **Continue** (ZL+Plus). The game runs until it reaches one of your breaks, and the Break and Trace view shows where it stopped, with the registers.
- **Step into** (R+ZL) and **Step over** (L+ZL) work from the very first instruction too.

A good first break is the game's `nnMain`, its main function: everything the game itself does at start-up comes after it.

## Things to know

- The game stays held until you press Continue or step. Hiding Breeze, showing it again, or restarting Breeze does not let it run.
- Use the Break and Trace view (or PC connect `dbg`) on a held game. The gen2 menu's **Execute** and PC connect `gen2 break` detach and re-attach first, which lets the game run.
- Cheats load as usual: the cheat engine attaches to the held game too.
- Only the game's main module and the system modules exist this early. Modules a game loads later (nn::ro) are not there yet.
- If no game is started, the request lapses after 60 seconds, so a later game started from HOME is not caught by surprise.

## From the PC

With PC connect:

```
gamestart <title id> held     start the game held; Breeze closes
                              (press HOME on the Switch to bring Breeze back)
dbg                           "launch":"held" while the game is held
dbg bp M+<offset>             a break point in main
dbg cont                      run to it
```

GDB clients (IDA, gdb) can use `monitor wait application` on port 22225, then `attach 0x<pid>` once the game starts. The v0.21 fork fixes that command, but it has not been tried on a console yet. See [PC connect](pcconnect.md).
