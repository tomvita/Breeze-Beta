# AOB (Array of Bytes) Feature Guide

## Overview

The AOB system lets you create version-resilient cheat hooks. When a game updates, instead of manually finding the hook address again, the AOB file stores a byte pattern that can automatically locate the correct address in the new version.

## How It Works

There are two parts:

1. **make_AOB** -- automatically creates a `.aob` file when you use "Add ASM"
2. **AOB 2 cheat** -- uses a `.aob` file to recreate the cheat after a game update

---

## Part 1: Creating an AOB File

This happens automatically. When you press **Add ASM** in the Edit Cheat menu, Breeze saves a `.aob` file alongside your cheat. No extra steps needed.

The file is saved to your game's cheat directory:

```
sdmc:/switch/breeze/cheats/<TitleID>/<cheat name>.aob
```

### What gets saved

- The cheat name
- The hook address (offset from main)
- The original ARM instruction at the hook point
- 32 bytes of surrounding code as a search pattern
- A mask for each instruction that wildcards version-dependent parts (branch offsets, PC-relative addresses) while keeping version-stable parts (opcodes, registers)

### When a file is skipped

If a `.aob` file already exists with the same offset, it is not overwritten. This means the file stays valid as long as you are on the same game version. After a game update the offset will differ, and a new `.aob` file will be created on the next "Add ASM" use.

---

## Part 2: Rebuilding a Cheat After a Game Update

1. Open the **Cheat menu** (Advanced mode)
2. Press the **AOB 2 cheat** button
3. A file picker opens showing your game's cheat directory
4. Select the `.aob` file for the cheat you want to rebuild
5. Breeze will:
   - Check if the stored offset is still valid for the current game version
   - If not, scan the game's code for the byte pattern using masked matching
   - Create a new cheat with the original instruction written to the found address
6. The new cheat appears in your cheat list
7. You can now use **Edit Cheat > Add ASM** on that cheat to rebuild the full ASM hook

### If it fails

If the scan does not find the pattern, it means the code around the hook changed significantly in the update. In that case you will need to find the hook address manually.

---

## Example Workflow

### First time (original game version)

1. Find your hook address in the ASM explorer
2. Create a cheat with the original instruction at that address (e.g. via Add2Cheat)
3. Edit the cheat, write your ASM file, press **Add ASM**
4. Breeze auto-creates `Speed Hack.aob` in your game directory

### After a game update

1. Load the game with the new version
2. Go to the Cheat menu
3. Press **AOB 2 cheat**
4. Pick `Speed Hack.aob`
5. A cheat named "Speed Hack" is created with the correct new address
6. Edit that cheat and press **Add ASM** to apply your assembly code

---

## Technical Details

### ARM64 Instruction Masking

The AOB pattern uses intelligent masking based on ARM64 instruction encoding. Instructions with relocatable immediates (values that change when code moves) are partially wildcarded:

| Instruction Type | What is kept | What is wildcarded |
|---|---|---|
| B / BL | Opcode | 26-bit branch offset |
| B.cond | Opcode + condition | 19-bit offset |
| CBZ / CBNZ | Opcode + register | 19-bit offset |
| TBZ / TBNZ | Opcode + bit index + register | 14-bit offset |
| ADR / ADRP | Opcode + destination register | PC-relative immediate |
| LDR (literal) | Opcode + register | 19-bit offset |
| All others | Entire instruction (exact match) | Nothing |

This means the pattern survives recompilation because branch targets and address calculations change between versions, but the opcode structure and register allocation remain stable.

### .aob File Format

The file is plain text in INI style:

```
[AOB]
name=Speed Hack
offset=00123456
instruction=D65F03C0
offset_register=0
hook_position=0
pattern=D65F03C0 A9BF7BFD 910003FD F9400108 B9400900 7100001F 54000005 F9400508
mask=FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FF00001F FFFFFFFF
```

| Field | Description |
|---|---|
| `name` | Cheat display name |
| `offset` | Hook address as hex offset from main module base |
| `instruction` | Original 32-bit ARM instruction at the hook (hex) |
| `offset_register` | 0 = main module relative, 1 = dynamic module relative (R1) |
| `hook_position` | Byte offset of the hook within the pattern (usually 0) |
| `pattern` | 8 space-separated 32-bit hex words |
| `mask` | 8 space-separated 32-bit hex masks (FFFFFFFF = exact, partial = wildcarded) |
