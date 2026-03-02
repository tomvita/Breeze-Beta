# Base Pointer Illustration

## Jump 9 ASM Cheat

```txt
[jump 9]
04000000 01DA16BC B9408E68
04000000 01DA16BC 14BA42EF
04000000 04C32278 D0010868
04000000 04C3227C F907E113
04000000 04C32280 52800128
04000000 04C32284 B9008E68
04000000 04C32288 1745BD0E
```

## Source Logic

```txt
data_save = 0x06D40FC0
adrp x8, (data_save & 0xFFFFFFFF000)
str x19, [x8, (data_save & 0xFFF)]
mov w8, 9
str w8, [x19, #0x8c]
return:
b code1+4
```

## What It Does

- Piggy-backs on the `jump 9` cheat.
- Saves a runtime pointer (`x19`) into `main` at `0x06D40FC0`.
- Forces jump value to `9` with `str w8, [x19, #0x8c]`.

## Pointer Cleanup Cheat

```txt
[Clear pointer from jump 9]
04010000 06D40FC0 00000000
```

## Why Clear Pointer

- Prevents stale pointer reuse.
- This clear cheat should be placed last in the CheatVM sequence.
- Flow:
  1. ASM cheat sets pointer when game code reaches the hook.
  2. Other cheats can use that pointer during the same execution round.
  3. Final clear cheat zeros `0x06D40FC0`.
  4. Next CheatVM round waits for game code to fill pointer again.

## Link Base Pointer To Field View Save

1. Go to the base-pointer target location in Memory Explorer.
2. With the pointer cleanup cheat active, use Jump to Target to follow the saved pointer link.
3. You should land on the live memory region for the fields.
4. Place the cursor on the field you want to track.
5. Load a saved Field View.
6. Pin the target field.
7. Save this Field View.

Result:
- The saved Field View is now base-pointer linked.
- Next time you load this Field View, it resolves to the current instance even if the game moved it in memory.
