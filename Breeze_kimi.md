# Breeze – Nintendo Switch Cheat Toolkit  
> Modern successor to EdiZon SE • Built for Atmosphere CheatVM

---

## One-Minute Install
1. Download latest **Breeze.zip** → extract to SD root.  
2. Launch:
   - **Home ▲ + A** (profile shortcut)  
   - or hbmenu → Breeze.  
3. Update in-app: **Download ▸ Check ▸ Install**.

---

## Why Breeze?
| Pain in EdiZon SE | Breeze Fix |
|---|---|
| Spaghetti code | Clean C++17 rewrite |
| Cluttered UI | Touch / stick / shortcuts |
| Slow searches | 2-pass diff + bookmarks |
| Needs PC | 100 % on-Switch workflow |

---

## Core Features
| Area | What You Get |
|---|---|
| **Cheat Mgmt** | Toggle, key-combos, DB sync, drag-and-drop files |
| **Memory** | Search, freeze, bookmark, pointer chains, heap/main offsets |
| **Debugger** | Memory & code breakpoints, register capture, IDA-link |
| **Editor** | Live ARM64 disassembler + assembler, loop-code wizard |
| **Updater** | One-button app & cheat DB refresh |

---

## Memory Search – 30 s Guide
| Data Types | Operators |
|---|---|
| `u8 … u64`, `f32/f64`, `ptr` | `== != > < range ++ -- DIFF SAME` |

**Typical Flow**  
`Dump A → Play → Diff A→B → Play → Diff B→C`  
Files auto-named `File1`, `File1(00)`, `File1(01)` … = unlimited undo.

---

## File Paths Cheat-Sheet
| Purpose | Where |
|---|---|
| Atmosphere auto-load | `/atmosphere/contents/<titleid>/cheats/<buildid>.txt` |
| Breeze private stash | `/switch/breeze/cheats/<titleid>/<buildid>.txt` |
| Search snapshots | `/switch/Breeze/*.dat` |

---

## Customizing Cheats (Zero Code)
1. **Load** any cheat file.  
2. **Edit name / value / keys** in two clicks.  
3. **Save** to Atmosphere (global) **or** Breeze (local).

---

## Build-ID (BID) – The Rule
- **BID = game hash**. If it doesn’t match → expect crashes.  
- Check in **Breeze ▸ Game Information**.  
- **Never** rename a cheat file to force a match — back-up saves instead.

---

## Gen2 Debug Loop
1. **Memory Explorer** → cursor on value → **SetBreakPoint**.  
2. **Gen2 Attach ▸ Execute Watch** → play → **Gen2 Detach**.  
3. Inspect results, **Jump to ASM**, craft patch.

---

## AOB Patching (Version-Proof Cheats)
| Button | What It Does |
|---|---|
| **Make AOB** | Records 8-instruction signature from current ASM cheat. |
| **Load AOB** | Searches new game build for the same bytes. |

---

## Settings Quick-Look
| Setting | Default | Purpose |
|---|---|---|
| **Profile Shortcut** | Off | **Home ▲ + A** launches Breeze |
| **Combo Keys** | 2 | Max keys in activation combo (1-6) |
| **Use TitleID** | 1 | 0 = human-readable folder names |
| **Starfield BG** | 1 | 0 = transparent overlay (see game) |
| **Gen2 Fork** | Off | Enables advanced debugger (needs Atm ≥ 1.4) |

---

## Data Types Reference
| Type | Bits | Signed |
|---|---|---|
| `u8 / s8` | 8 | ✗ / ✓ |
| `u16 / s16` | 16 | ✗ / ✓ |
| `u32 / s64` | 32 / 64 | ✗ / ✓ |
| `f32 / f64` | 32 / 64 | IEEE float |
| `pointer` | 64 | address |

---

## CheatVM 5-Line Primer
- `{}` = master code (always runs)  
- `[]` = optional code (toggleable)  
- Opcode = 8-digit hex, 1-4 per instruction  
- 15 registers, 256 opcodes max per cheat  
- Refresh rate fixed; timing critical for data hacks.

---

## Resources & Disclaimers
- [📚 Wiki](https://github.com/tomvita/Breeze-Beta/wiki) •
  [💾 Cheat DB](https://github.com/tomvita/NXCheatCode) •
  [🛠️ Source](https://github.com/tomvita/Breeze-Beta)

> Cheats can corrupt saves or get you banned.  
> **Back-up saves** before use — developers assume **zero liability**.