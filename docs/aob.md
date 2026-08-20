# AOB (Array of Bytes) Feature Guide

## Overview

The AOB system lets you create version-resilient cheat hooks. When a game updates, instead of manually finding the hook address again, the AOB file stores a byte pattern that can automatically locate the correct address in the new version.

## How It Works

There are four entry points:

1. **Make AOB** -- creates version-3 `.aob` files for eligible paired ASM hooks
2. **Make AOB M** -- handles cheats skipped by Make AOB and creates one indexed file per eligible type-0 line
3. **AOB 2 cheat** -- selects and converts one `.aob` file
4. **Load AOB** -- converts every `.aob` file in the current game directory

---

## Part 1: Creating an AOB File

After creating your ASM cheats, open the **Extended Cheat Menu** and press **Make AOB**. Breeze examines every eligible ASM cheat and creates or retains its version-3 `.aob` file. **Add ASM no longer creates AOB files automatically.**

The file is saved to your game's cheat directory:

```
sdmc:/switch/breeze/cheats/<TitleID>/<cheat name>.aob
```

### What gets saved

- The cheat name
- The hook address (offset from main)
- The original ARM instruction at the hook point
- Between 6 and 16 ARM64 instructions (24–64 bytes) around the hook
- A mask for each instruction that wildcards version-dependent parts (branch offsets, PC-relative addresses) while keeping version-stable parts (opcodes, registers)

### When a file is skipped

If a version-3 `.aob` already records multiple occurrences and its hook metadata is unchanged, it is retained without repeating the uniqueness scan. A unique existing signature is retained when either its complete signature matches live memory or its surrounding signature matches while the hook word contains an active patch. Changed hook metadata, invalid files, and stale unique signatures are regenerated.

### Make AOB M

**Make AOB M** processes only cheats that the normal paired-hook **Make AOB** test skips. It decodes actual cheat opcode lines, selects 32-bit type-0 writes targeting executable code outside the mapped code segment's final 4 KiB, and excludes writes in that final code-cave page. Each selected line produces:

```text
<cheat label>.<zero-based line index>.aob
```

The indexed name prevents multiple hook lines from the same cheat from overwriting one another.

---

## Part 2: Rebuilding a Cheat After a Game Update

1. Open the **Cheat menu** (Advanced mode)
2. Press the **AOB 2 cheat** button
3. A file picker opens showing your game's cheat directory
4. Select the `.aob` file for the cheat you want to rebuild
5. Breeze will:
   - Scan the game's code for every occurrence of the byte pattern using masked matching
   - Create one cheat containing an original-instruction write line for every address found
6. The new cheat appears in your cheat list
7. You can now use **Edit Cheat > Add ASM** on that cheat to rebuild the full ASM hook

### If it fails

If conversion fails, inspect `aob.log`. Possible causes include an invalid file, no matching pattern after recompilation, unreadable code memory, or more occurrences than a single cheat can hold.

### Processing every AOB file

Use **Load AOB** in the Extended Cheat Menu to process all `.aob` files in the current game directory. Breeze creates one cheat for each file that succeeds, and each cheat contains one write line per occurrence. The completion message reports successful and failed file counts. Use **AOB 2 cheat** when you only want to select and process one file.

---

## Example Workflow

### First time (original game version)

1. Find your hook address in the ASM explorer
2. Create a cheat with the original instruction at that address (e.g. via Add2Cheat)
3. Edit the cheat, write your ASM file, press **Add ASM**
4. Return to the Extended Cheat Menu and press **Make AOB**
5. Breeze creates `Speed Hack.aob` in your game directory

### After a game update

1. Load the game with the new version
2. Go to the Cheat menu
3. Press **AOB 2 cheat**
4. Pick `Speed Hack.aob`
5. A cheat named "Speed Hack" is created with one write line for each matching address
6. Edit that cheat and press **Add ASM** to apply your assembly code

---

## Technical Details

### ARM64 Instruction Masking

The AOB generator examines executable modules and tries to select the shortest unique ARM64 signature between 6 and 16 instructions. It uses instructions before and after the hook and records the hook's position inside the signature. If no unique candidate exists, Breeze saves the longest readable candidate, records every occurrence, and records the original target's zero-based index instead of discarding the file. Instructions with relocatable immediates are partially wildcarded:

| Instruction Type | What is kept | What is wildcarded |
|---|---|---|
| B / BL | Opcode | 26-bit branch offset |
| B.cond | Opcode + condition | 19-bit offset |
| CBZ / CBNZ | Opcode + register | 19-bit offset |
| TBZ / TBNZ | Opcode + bit index + register | 14-bit offset |
| ADR / ADRP | Opcode + destination register | PC-relative immediate |
| LDR (literal) | Opcode + register | 19-bit offset |
| ADD / SUB (immediate) | Operation, shift, and registers | 12-bit immediate |
| LDR / STR (immediate) | Operation and registers | Address offset |
| LDP / STP | Operation and registers | Pair address offset |
| All others | Entire instruction (exact match) | Nothing |

The mask improves resilience when code moves. Recompilation can still change instruction selection or register allocation. Unique patterns and every line produced from an ambiguous pattern should be verified after conversion.

### .aob File Format

The file is plain text in INI style:

```
[AOB]
format_version=3
name=Speed Hack
offset=00123456
instruction=D65F03C0
offset_register=0
hook_position=0
pattern_words=8
occurrences=1
target_index=0
pattern=D65F03C0 A9BF7BFD 910003FD F9400108 B9400900 7100001F 54000005 F9400508
mask=FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FF00001F FFFFFFFF
```

| Field | Description |
|---|---|
| `format_version` | Signature generator/file-format version; current value is `3` |
| `name` | Cheat display name |
| `offset` | Hook address as hex offset from main module base |
| `instruction` | Original 32-bit ARM instruction at the hook (hex) |
| `offset_register` | 0 = main module relative, 1 = dynamic module relative (R1) |
| `hook_position` | Byte offset of the hook within the pattern (usually 0) |
| `pattern_words` | Number of valid words in `pattern` and `mask` (6–16 for new files) |
| `occurrences` | Executable-code matches found during generation; `1` is unique and larger values are ambiguous |
| `target_index` | Zero-based position of the original hook in the occurrence list; this maps to the same generated cheat line |
| `pattern` | Variable-length sequence of 32-bit ARM64 instruction words |
| `mask` | One mask per pattern word (`FFFFFFFF` = exact, partial = wildcarded) |

Older files without `format_version`, `pattern_words`, or `target_index` remain loadable. Breeze infers legacy pattern lengths from the `pattern` line, while a missing target index defaults to the first occurrence. Running **Make AOB** regenerates an older definition in version-3 format.

Generation diagnostics are appended to `aob.log` in the same game directory. The log records whether an existing file was retained, why generation failed, and the pattern length and occurrence count when a file was written.
