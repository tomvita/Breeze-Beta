# Break and Trace Guide

This guide covers **Break and Trace**, Breeze's integrated ARM64 interactive debugger powered by `dmnt.gen2`. It allows you to halt a running Nintendo Switch game at any instruction or memory write, step instruction-by-instruction, inspect and modify CPU registers, dereference operand addresses, and create cheats directly on-device without requiring a PC or GDB cable.

---

## 1. Overview: What Is Break & Trace?

In traditional Switch cheat development, finding the code that modifies a value (e.g. Player HP, Money, Coordinates) involves watching memory writes:
- **Execute Watch (standard Gen2 watch)**: Logs every write to an address into a list of rows while the game keeps running. This is great for high-frequency writes to observe data patterns.
- **Break & Trace**: Instead of simply recording hits in the background, **Break & Trace halts the game thread the moment the watch condition or breakpoint is hit**.

When the game stops:
1. Breeze immediately opens the **Break & Trace** view (integrated natively into the **ASM Explorer**).
2. The Program Counter (`PC`) points to the exact instruction that triggered the stop.
3. You can inspect all 31 general-purpose registers (`X0`–`X30`), stack pointer (`SP`), program status (`PSTATE`), and 32 vector registers (`V0`–`V31`).
4. You can single-step (`Step into` / `Step over`), dereference memory operands, edit registers, or patch the instruction in memory (`ASMedit`) and immediately test the result.
5. In **SwitchU Overlay mode**, Breeze automatically pops onto the screen over the live game when a breakpoint hits and hides itself when you press `Continue`.

```
               [ Game Running ]
                      │
           (Breakpoint or Watch Hit)
                      ▼
               [ Game Paused ]
                      │
     ┌────────────────┴────────────────┐
     ▼                                 ▼
[SwitchU Interface 3]          [Breeze Standalone]
Auto-pops Breeze overlay       HUD alerts: "HOME to view"
     │                                 │
     └────────────────┬────────────────┘
                      ▼
          [ Unified ASM Explorer ]
  • Disassembly centered at stopped PC
  • Step into / Step over / Continue
  • Live Register & Stack inspection
  • "Memory at operand" dereferencing
  • In-place ASM editing & cheat creation
```

---

## 2. Prerequisites & Setup

1. **Atmosphere 1.7+ with dmnt.gen2 Installed**:
   - Open Breeze -> **Settings** -> **Full Menu**.
   - If the button says **"Install gen2 fork"**, click it (`-` Minus) to install `dmnt.gen2`.
   - If it says **"Reinstall gen2 fork"**, it is already installed.
   - Restart your console to load the custom sysmodule.
2. **SwitchU Fork (Optional, Highly Recommended)**:
   - For seamless overlay debugging where Breeze appears automatically when a breakpoint hits, install Tomvita's **SwitchU fork** (`v1.2.0g+`).
   - Open Breeze -> **Download** -> **"Install / Update SwitchU fork"** (`R-Stick`).
   - In **Settings**, set **Home toggle** to `Overlay`.

---

## 3. Two Ways to Trigger Break & Trace

### Method A: Break on Memory Access / Write (via Gen2 Menu)

Use this method when you know a memory address (e.g. your character's current HP or Gold) and want to find the exact code that alters it.

1. **Find Target Address**:
   - Locate the target address using the **Search Menu** or **Memory Explorer**.
   - Note down the address or save it as a bookmark.
2. **Configure Gen2 Watch**:
   - In the Main Menu, open **Gen2 Action** (`R-Stick`).
   - Set **Next address** to your target address.
   - Set the data type to match your variable (e.g. `u32`, `f32`).
   - Ensure `Write = 1` (or `Read = 1` if searching for code that reads the value).
3. **Arm Break & Trace**:
   - **Unfiltered Break**: Press **Break and Trace** (`+ + ZL + ZR` or button). The game will halt on the very next write to that address.
   - **Filtered Break (Recommended for shared code)**:
     - First run **Execute Watch** (`+`). Go back to the game and perform an action (take damage, heal, spend money).
     - Return to Gen2 Menu. You will see captured lines showing which instructions wrote to the address.
     - Move the cursor to the specific line that corresponds to your action.
     - Press **Break and Trace**. Breeze arms a **Break Filter**: it will break *only* when that specific instruction and call context matches, ignoring irrelevant background writes!
4. **Game Halts**:
   - Return to the game and trigger the action.
   - Execution immediately halts, and Breeze displays the Break & Trace view.

---

### Method B: Break on Code Execution (via ASM Explorer)

Use this method when you are already inspecting code in ASM Explorer and want to halt when a function or branch is executed.

1. Navigate to the desired instruction in **ASM Explorer**.
2. Press **Break point** (`X + ZL`):
   - Sets a persistent breakpoint. A `*BP` indicator appears next to the instruction.
3. *Alternatively*, press **Temp break point** (`-` Minus):
   - Sets a one-shot breakpoint. A `*bp` indicator appears. This breakpoint automatically clears itself once hit.
4. Return to the game (`Continue` or resume). When execution reaches that address, the game halts immediately.

---

## 4. The Break & Trace View (Unified ASM Explorer)

When the game is stopped at a breakpoint, the ASM Explorer title changes to **"Break and Trace"**, and the debugger controls are dynamically enabled.

The screen is organized into two primary panels matching Breeze's 1280x720 layout:
- **Left Panel**: Disassembly listing centered around the stopped `PC`, with active breakpoint indicators.
- **Right Panel**: Two columns of 9 action buttons (18 primary actions on Page 1).

| Disassembly (Left Panel) | Action Buttons (Column 1) | Action Buttons (Column 2) |
|:---|:---|:---|
| `PC> 710234A120: STR  W0, [X1, #0x28]` | **Step into** &nbsp; `R + ZL` | **Stop Break & Trace** &nbsp; `- + ZL` |
| `    710234A124: LDR  W2, [X1, #0x30]` | **Step over** &nbsp; `L + ZL` | **Goto PC** &nbsp; `R-Stick Up + ZR` |
| `    710234A128: ADD  W0, W0, W2`     | **Continue** &nbsp; `+ + ZL`  | **Threads** &nbsp; `R-Stick Down + ZR` |
| `*BP 710234A12C: BL   0x7102350000`   | **Break point** &nbsp; `X + ZL` | **Follow branch** &nbsp; `R` |
| `    710234A130: MOV  W0, #0x1`       | **Temp break point** &nbsp; `-` | **Detail** &nbsp; `X + ZR` |
| `    710234A134: RET`                 | **Breakpoints** &nbsp; `R-Stick Left + ZL` | **ASMedit** &nbsp; `X` |
| `    710234A138: NOP`                 | **Memory at operand** &nbsp; `R-Stick Right + ZL` | **MemoryExplorer** &nbsp; `R-Stick + ZL` |
| `    710234A13C: LDR  X0, [SP, #0x10]` | **Registers** &nbsp; `+ + ZR` | **Add to Cheat** &nbsp; `Y + ZL` |
| `    710234A140: LDP  X29, X30, [SP], #0x20` | **Stack** &nbsp; `L-Stick + ZR` | **Back** &nbsp; `B` |

> **Header**: `Break and Trace` &bull; `Breeze beta121.02`  
> **Status Bar**: `PC: 0x000000710234A120 (main+0x0024A120) [Stopped]` &bull; `ARM64`


### Visual Disassembly Indicators

| Indicator | Meaning |
|:---:|---|
| `PC>` | The current Program Counter where the game thread is halted. |
| `*BP` | An active, persistent breakpoint set at this address. |
| `-BP` | A registered breakpoint that is currently disabled / disarmed. |
| `*bp` | A temporary (one-shot) breakpoint that will disarm after the first hit. |
| `*W`  | Watched instruction address (`BreakOnWrite` / watchpoint). |

---

### Primary Debugger Controls

| Action | Shortcut | Description |
|---|:---:|---|
| **Step into** | `R + ZL` | Executes the single instruction at `PC`. If the instruction is a branch or subroutine call (`B`, `BL`, `BLR`), execution enters the function. |
| **Step over** | `L + ZL` | Executes the instruction at `PC`. If the instruction is a subroutine call (`BL`/`BLR`), it runs the entire subroutine and stops at the subsequent return address. |
| **Continue** | `+ + ZL` | Resumes game execution until the next breakpoint or watchpoint is hit. In overlay mode, Breeze hides itself. |
| **Stop Break and Trace** | `- + ZL` | Disarms all breakpoints, clears active watches, and lets the game run freely. |
| **Goto PC** | `R-Stick Up + ZR` | Re-centers the disassembly listing back to the stopped `PC`. |
| **Break point** | `X + ZL` | Toggles a persistent breakpoint (`*BP`) on the instruction under the cursor. |
| **Temp break point** | `-` (Minus) | Toggles a one-shot temporary breakpoint (`*bp`) on the instruction under the cursor. |
| **Breakpoints** | `R-Stick Left + ZL` | Opens the **Breakpoint List** menu to view, toggle, or delete all set breakpoints. |

---

## 5. Advanced Inspection Tools

### 5.1 Live Register Inspection & Editing (`Registers`)
- **Shortcut**: `+ + ZR`
- Displays the complete ARM64 architectural state at the time of the stop:
  - **General-Purpose Registers**: `X0` through `X28`.
  - **Frame Pointer**: `X29` (`FP`).
  - **Link Register**: `X30` (`LR`) — shows the return address to the caller.
  - **Stack Pointer**: `SP`.
  - **Program Counter**: `PC`.
  - **Status**: `PSTATE`, `FPCR`, `FPSR`.
  - **Vector / SIMD Registers**: `V0` through `V31` (low 64 bits and high 64 bits displayed).
- **Live Register Modification**:
  - Select any register and press **A** to edit its value live.
  - Test cheat hypotheses immediately! For example: if `W0` contains damage to subtract, change `W0` to `0` and press **Continue** to verify if damage is cancelled before writing a permanent cheat!

---

### 5.2 Memory at Operand Dereferencing (`Memory at operand`)
- **Shortcut**: `R-Stick Right + ZL`
- **Dynamic Calculation**: When stopped at an instruction that references memory (e.g. `LDR W0, [X1, #0x28]`, `STR X2, [X19, X8]`, or `LDRB W3, [X0]`), Breeze automatically computes the effective target address using the live register values:
  $$\text{Effective Address} = X_n + \text{offset}$$
- **Instant Memory Explorer**: Clicking **"Memory at operand"** immediately opens `MemoryExplorer` focused directly at that address with the inferred data type (`u8`, `u16`, `u32`, `u64`, `f32`, `f64`).
- No manual hexadecimal math required!

---

### 5.3 Stack Inspection (`Stack`)
- **Shortcut**: `L-Stick + ZR`
- Displays memory starting at the current `SP` (Stack Pointer).
- Useful for inspecting stack parameters, local variables, saved caller registers, and verifying return address chains.

---

### 5.4 Thread Management (`Threads`)
- **Shortcut**: `R-Stick Down + ZR`
- Lists all threads in the active game process with their Thread ID, name, PC, LR, and whether their PC resides inside `main`.
- Allows switching the debugger focus to inspect other threads in multi-threaded games.

---

## 6. Practical Workflow: Creating Cheats from Break & Trace

Here is a step-by-step example of developing an "Infinite Health" cheat using Break & Trace:

1. **Locate Health Address**: Search for HP in the Search Menu; say it is found at `0x7120ABC028`.
2. **Arm Break Filter**:
   - Open Gen2 Menu (`R-Stick`).
   - Set `Next address = 0x7120ABC028`, `Write = 1`, `size = 4`.
   - Run `Execute Watch` (`+`). Return to game and take 1 hit of damage.
   - Return to Gen2 Menu. Highlight the captured write row and press **Break and Trace**.
3. **Trigger Break**:
   - Return to game and take damage again. The game halts immediately!
4. **Analyze Instruction**:
   - Breeze shows the stopped instruction:
     ```arm
     PC> 710045A100: SUB W0, W0, W1    ; New HP = Current HP - Damage
         710045A104: STR W0, [X19, #0x28] ; Store new HP back to player struct
     ```
5. **Inspect Operands**:
   - Press **Registers** (`+ + ZR`): Verify `X0` is previous HP, `X1` is damage received.
   - Highlight line `710045A104` and press **Memory at operand** (`R-Stick Right + ZL`). `MemoryExplorer` opens directly on `X19 + 0x28`, confirming it is indeed your HP address!
6. **Test the Patch**:
   - Select line `710045A100` (`SUB W0, W0, W1`).
   - Press **ASMedit** (`X`). Replace `SUB W0, W0, W1` with `NOP` (or `ADD W0, W0, #0`).
   - Press **Continue** (`+ + ZL`).
   - In game, take damage: health no longer decreases!
7. **Export as Cheat Code**:
   - Return to ASM Explorer, highlight the modified instruction, and press **Add to Cheat** (`Y + ZL`).
   - Breeze automatically generates the cheat code and saves it to your cheat file!

---

## 7. Safety & Best Practices

1. **Always Disarm Before Exiting**:
   - Never exit Breeze or restart the console while a game thread is frozen at a breakpoint.
   - Use **Stop Break and Trace** (`- + ZL`) to disarm all breakpoints and let the game resume before closing Breeze.
2. **Narrow Down Watch Targets**:
   - Setting a raw watchpoint on a memory address that is read or written thousands of times per frame (like a global timer or camera matrix) can cause performance drops.
   - Always prefer **Break Filter** on a specific captured hit to ensure the break only fires on the relevant event.
3. **Use Temp Breakpoints for Loops**:
   - When stepping through loops, place a **Temp break point** on the instruction immediately after the loop and press **Continue** to skip iterating manually.

---

## 8. Summary of Controller Shortcuts

| Key Combination | Function |
|---|---|
| `R + ZL` | Step into |
| `L + ZL` | Step over |
| `+ + ZL` | Continue (resume game) |
| `- + ZL` | Stop Break and Trace (disarm & resume) |
| `R-Stick Up + ZR` | Goto PC |
| `X + ZL` | Toggle persistent breakpoint |
| `-` (Minus) | Toggle temporary (one-shot) breakpoint |
| `R-Stick Left + ZL` | Open Breakpoints list |
| `+ + ZR` | Open Register view (inspect & edit) |
| `L-Stick + ZR` | Open Stack view |
| `R-Stick Down + ZR` | Open Threads view |
| `R-Stick Right + ZL` | Memory at operand (dereference address) |
| `X` | ASMedit (in-place instruction assembly) |
| `Y + ZL` | Add to Cheat (export instruction to cheat) |
| `B` | Back |
