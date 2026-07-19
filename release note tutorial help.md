# Context-Sensitive Help System Release Note

This release adds an interactive, context-sensitive help overlay to Breeze. Hold **ZR**, then press **A** to open it. The overlay supplies menu topics, selected-button Action Help, input blocking, and persistent per-menu state. The Main Menu Help button now opens the tutorial directly.

See the [Help System Guide](docs/help%20system.md) and [Sysmodule Guide](docs/sysmodules.md) for full instructions.

## Changed action labels

| Area | Old label | New label |
|---|---|---|
| Gen2 | `Next stack_check` | `Return slot/count` |
| Gen2 | `X30_catch` | `Call-site source` |
| Gen2 | `Stack_offset` | `Stack slot` |
| Gen2 | `Grab[A]` | `Capture [A]` |
| Gen2 | `Grab_R` | `Capture register` |
| Gen2 | `Match_R` | `Match captured register` |
| Gen2 | `make match all` | `ASM match all returns` |
| Gen2 | `make match 1` | `ASM match selected return` |
| Gen2 | `ExclusiveSearch` | `Exclusive Search (WIP)` |
| Gen2 | `check data` | `Show capture fields` |
| JumpBack | `do B8 scan` | `Unity B8 pointer scan` |
| JumpBack | `get depth+1 ptr` | `Add pointers at current depth` |
| JumpBack | `last_range` | `Final offset range` |
| ASM Composer | `ldr_str` | `LDR/STR helper` |
| ASM Composer | `mov_fmov` | `MOV/FMOV toggle` |
| ASM Composer | `X30_cmp` | `Insert X30 match` |
| ASM Composer | `paste A` | `Insert value A` |
| ASM Composer | `button_save` | `Insert button gate` |
| Cheat Editor | `Transform1` | `Transform opcode 1` |
| Settings | `Prelease` | `Prerelease updates` |

The prerelease option moved from the legacy Help screen to Settings. The Gen2 fork is excluded from the general Sysmodule Manager, and Sysmodule On/Off labels now consistently describe current runtime state.
