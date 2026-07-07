# Break and Trace Guide

The **Break and Trace** feature, introduced in Breeze beta108+ (using `dmnt.gen2` fork v0.15+) and Breezehand-Overlay v0.10.0+, is an advanced debugging tool for Nintendo Switch memory hacking. It allows users to set hardware watchpoints on memory addresses or instructions, trace execution in real-time, inspect call stacks, and view/modify CPU registers.

---

## 🚀 The Advantage of Breezehand-Overlay over the Breeze App

While the main Breeze homebrew application is ideal for deep memory searching, pointer scanning, and configuring settings, it runs as a foreground applet or application. This imposes a significant limitation during active debugging:
* **Breeze App (Foreground):** Opening Breeze requires suspending the active game (e.g., by pressing the Home button). This **pauses a large part of the game's execution**, making it impossible to capture real-time program flow or trace code while the game is running.
* **Breezehand-Overlay (Background / Tesla Overlay):** The overlay runs concurrently on top of the running game. 
  * It allows for **real-time updates** on watches/bookmarks.
  * You can perform a **live trace** because the game continues to execute in the background. Tracing occurs as watchpoints are triggered naturally during gameplay.

---

## 🛠️ Requirements & Sysmodule Setup

To use Break and Trace, you must update both the system files (sysmodule) and the overlay:

1. **Breeze Beta 108.7+**
2. **Breezehand-Overlay v0.10.3a+** 
   * Includes `Breezehand_watch.ovl` and `Breezehand_light.ovl` (a low-memory version footprinted at 4 MB for improved stability).
3. **Updated `dmnt.gen2` Fork (v0.15+):**
   > [!IMPORTANT]
   > You must reinstall the sysmodule to get the break and trace upgrades:
   > 1. Go to the Breeze **Settings Menu**.
   > 2. Press the button to **uninstall the old gen2 fork**.
   > 3. Press **Install gen2 fork** to install the new version (v0.15+).
4. **EdiZon SE Compatibility (Optional):**
   * If you use EdiZon SE, you must download and install [EdiZon_alt.zip (v3.8.37a)](https://github.com/tomvita/EdiZon-SE/releases/download/3.8.37a/EdiZon_alt.zip) to ensure compatibility with `dmnt.gen2` fork v0.14 or newer.

---

## 📖 How to Use Break and Trace

### 1. Set up a Watchpoint in Breeze
1. Open the **Breeze** homebrew application.
2. Navigate to the memory address or instruction you wish to monitor (e.g., in the Memory Explorer or instruction list).
3. Place a hardware watchpoint on the target to initiate the watch session via the `dmnt.gen2` debugger.

### 2. Launch the Watch Overlay (`breezehand_watch.ovl`)
1. Return to the game (so it is running).
2. Open the Tesla menu and select the **Breezehand Watch** overlay (`breezehand_watch.ovl`) to monitor the active watchpoint in real-time.

### 3. Enter the Trace Menu
1. In the overlay watch screen, Press **`L3 + Y`** to open the **Trace Menu**.
2. Select the path you want to trace and press A

### 4. Trace Instructions and Edit Registers
Inside the Trace Menu, you can:
* **Disassemble Instructions:** See the exact instruction accessing the watchpoint (formatted as `[M+Offset] <instruction> n=<count>`).
* **Inspect Registers:** View CPU registers (`X0`–`X28`, `FP`, `LR`, `SP`, `PC`).
* **Modify Register State:** Highlight any register value and edit it directly to modify the CPU state in real-time.
* **Toggle Register Mode:** Switch the display between integer registers and FPU (floating-point) registers.
* **FPU Precision:** Toggle FPU views between single-precision float and double-precision float values.

---

## 🎮 Overlay Controls & Shortcuts (Breezehand v0.10.3a+)

* **`L3 + Y`**: Open the **Trace Menu** from the Watch screen.
* **`L3 + B`**: Return to the previous menu (replaces standard `B` to avoid closing the entire overlay).
* **`L3 + D-Pad Left` / `L3 + D-Pad Right`**: Dynamically change the overlay font color.
