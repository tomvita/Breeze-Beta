# Code Caves and ASM Cheats

An ASM cheat replaces one instruction of the game with a branch to new code. That new code needs somewhere to live: a **code cave**, a stretch of unused memory inside a code segment. This page explains how Breeze picks caves, how to see what is free, and how ASM cheats are run and switched off.

## How a cave is chosen

When you use **Add ASM** in Edit Cheats, Breeze places the cave for you. It looks at every executable segment of the game and ranks them. A region is used only when:

- the code fits,
- a plain branch (`B`) from the hook reaches it, which means within about 127 MB,
- it can be addressed by a cheat.

The free space is the padding the linker leaves at the end of each segment, so it is different in every game and every build.

### Cheats claim their space

Breeze reads the cheats themselves to know which addresses are taken. Every assembled ASM cheat lists the addresses it writes, so two cheats are never given the same cave, even when neither has been turned on yet.

### The cave floor

Where free space starts can only be measured in a game that no cheat has written to. Breeze measures it once per game build, when it attaches to the game, and keeps it in `cave_floor.txt` in the game folder. It refuses to measure while a cheat is applied, because what the cheat wrote would be taken for part of the game.

### Caves below main

`nnrtld` sits just below the main module and usually has free space within reach of every hook. Breeze uses it when main is full, or first when **Alt ASM = 1** in Edit Cheats. A cave there is written through register R1:

```
40010000 FFFFFF00 00000000      R1 = 0xFFFFFF0000000000
040100FF FFFFC2C0 F9421408      writes below main
...
40010000 00000000 00000000      R1 = 0
```

**Jump to target**, **Jump to ASM** and the disassembly in Edit Cheats follow these lines to the real address.

## Code Cave Map

**Game Information > Code Cave Map** (`R`) shows what the allocator is working with. For every executable segment it lists:

- the free space at its end,
- the recorded empty-cave floor,
- where the next cave would go,
- which cheats have claimed what,
- whether a plain branch reaches it.

| Button | Shortcut | Action |
|---|---|---|
| Select | X | Show the details of the region the cursor is on. |
| Scan nops here | Y | Count the aligned `nop` pairs in this region. |
| Scan all nops | Y + ZL | Count them in every region. |
| Refresh | R | Read the map again. |
| Write map to file | Plus | Save the map to a text file in the game folder. |
| Expand screen | R + ZR | Use the full width for the list. |
| Back | B | Return to Game Information. |

A cave whose cheat has no script is marked `NO SOURCE, cannot be moved`. Breeze never removes it; everything else is packed around it.

## Assemble all ASM

Assembling cheats one at a time cannot pack their caves, because each one only knows about itself. **Assemble all ASM** on the Cheats screen (`L + ZL`) rebuilds every cheat that has a script in one pass and packs the caves together.

- A cheat is included once it has a script: saved from Asm Composer, or assembled with Add ASM from its own `.txt`. The list is kept in `<build id>.ini` in the game folder, one line of `<cheat name>=<script file>`.
- A cave cheat with no script is left alone and packed around.
- A cheat hooked inside another cheat's cave moves with its owner.
- The original instructions are put back before the rebuild, so no branch points at a cave that has moved.

**Relocate Code Cave** on the Cheats screen (`R + ZL`) moves the cave of the cheat at the cursor.

## How an ASM cheat is run

An ASM cheat is stored as three parts: the original instruction, the branch over it, and the cave.

The game keeps running while the cheat VM writes. So Breeze hands the cheat to the VM in a safer order: the cave first, the branch last, with the original instruction kept as data that is never executed. The branch is never live before the cave it leads to.

Nothing changes in the cheat file, in Edit Cheats or in how a cheat is shared. Cheats that Atmosphere loads by itself at game start run in the stored order, as before.

## Three stages of Toggle Cheat

**Toggle Cheat** on an ASM cheat steps through three stages:

1. **On.**
2. **Off, hook left in the game.** The cheat VM stops writing, but the branch and the cave are still there, so the cheat keeps working at no cost to the VM. The row is drawn as a green line with a solid square.
3. **Off, original instruction back.**

**Turn off all Cheats** (More menu) puts the original instruction back for every cheat. **Make off Cheat** builds a cheat that does the same and can be used with other cheat loaders.

## Checking a cheat without running it

- **Jump to target** (`ZL + Right` in Edit Cheats) runs the cheat as a dry run and opens the address it reads or writes. Nothing is written to the game.
- **Trace cheat** (`ZR + Right`) lists every pointer hop, read, compare and write the cheat makes, with the result of each condition. Use it to see why a cheat does nothing.

## Generated files

In the game folder, `/switch/breeze/cheats/<game>/`:

| File | Holds |
|---|---|
| `cave_floor.txt` | Where free space starts in each code segment of this build. |
| `<build id>.ini` | The cheats Assemble all ASM rebuilds, with their script files. |
