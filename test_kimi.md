# Breeze – Nintendo Switch Cheat Toolkit
> A modern replacement for EdiZon SE, purpose-built for Atmosphere’s CheatVM.

- **Faster, cleaner, stronger** – rewritten from scratch to eliminate SE’s technical debt.  
- **All-in-one** – create, manage, debug, and update cheats **entirely on-Switch**.  
- **Beginner-friendly UI** – touch, gamepad, or shortcuts.

---

## Quick Start
| Step | Action |
|---|---|
| 1 | Copy `Breeze.zip` to SD root (overwrite if prompted). |
| 2 | Launch via **Home ▲ + A** (profile-shortcut) or hbmenu. |
| 3 | In-app updater: **Download ▸ Check ▸ Install**. |

---

## Core Features
| Category | Highlights |
|---|---|
| **Cheat Codes** | Toggle, batch-edit, conditional keys, live DB. |
| **Memory** | Search, freeze, bookmark, pointer chains, diff dumps. |
| **Debugger** | Memory & instruction breakpoints, ASM hook finder. |
| **Editor** | Dis/assemble ARM64, loop-code generator, ASM composer. |
| **Auto-Update** | App + cheat DB via one button. |

---

## Memory Search Cheat-Sheet
| Data Types | Search Modes |
|---|---|
| `u8, u16, u32, u64, s8 … f64, pointer` | `== != > < >= <= range ++ -- DIFF SAME` |

**Typical Flow**  
`Dump → Play → Diff → Diff → Play → Diff`  
Files auto-named `File1`, `File1(00)`, `File1(01)` … keep full history.

---

## File Paths
| Purpose | Location |
|---|---|
| Atmosphere auto-load | `sdmc:/atmosphere/contents/<titleid>/cheats/<buildid>.txt` |
| Breeze private stash | `sdmc:/switch/breeze/cheats/<titleid or name>/<buildid>.txt` |
| Search snapshots | `sdmc:/switch/Breeze/*.dat` |

---

## Customizing Cheats (No Coding)
1. **Load** a cheat file.  
2. **Edit** name, value, or activation keys.  
3. **Save** to Atmosphere (global) **or** Breeze (local).  

---

## Build-ID (BID) Safety
- **Never rename** a cheat file to match your BID → high crash risk.  
- Check your game’s BID in **Breeze ▸ Game Information**.  
- Pointer cheats often need only the **first offset** updated after patches.

---

## Gen2 Debug Workflow
1. Memory Explorer → **SetBreakPoint** → **Gen2 Attach** → **Execute Watch**  
2. Play → **Gen2 Detach** → Inspect captured instructions.  
3. **Jump to ASM** → compose & test your patch.

---

## AOB (Array-of-Bytes) Patching
| Button | Purpose |
|---|---|
| **Make AOB** | Record 8-instruction signature from current ASM cheat. |
| **Load AOB** | Search new game version for the same signature. |

---

## Settings at a Glance
| Key | Default | Effect |
|---|---|---|
| **Profile shortcut** | Off | Launch Breeze with **Home ▲ + A**. |
| **Combo keys** | 2 | Max keys in activation combo (1-6). |
| **Use titleid** | 1 | 0 = folder uses human-readable game name. |

---

## Need Help?
- Full wiki: [Breeze Wiki](https://github.com/tomvita/Breeze-Beta/wiki)  
- Cheat DB: [NXCheatCode](https://github.com/tomvita/NXCheatCode)

---

> Happy hacking – but **back up your saves** first!