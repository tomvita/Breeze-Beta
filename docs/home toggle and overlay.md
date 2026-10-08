# HOME Toggle and Overlay Mode

With the HOME daemon installed, the HOME button switches between Breeze and the game you are playing. In **Overlay** mode Breeze is drawn on top of the running game, so the game keeps running while you use Breeze.

This replaces the older "qlaunch takeover" (`qlaunch=0/1`, `HomeRestart Off`, `Home2Profile`), which no longer exists.

## What you need

- Breeze beta122.01 or later.
- The **HOME daemon** from tomvita's SwitchU fork. Breeze installs it from Settings. Fork **1.2.0i** or newer is needed for Breeze first and for running without the SwitchU menu; **1.2.0l** is needed for Start game on some games.

The HOME daemon is the part of the SwitchU fork that replaces the Nintendo HOME menu. It can be installed with or without the SwitchU menu itself.

## Installing

1. Open **Settings** in Breeze.
2. Press **Install HOME daemon** twice (the second press confirms). If the button reads **Update HOME daemon**, an older fork is installed; press it twice to update.
3. Restart the console.

After the restart the button reads **HOME daemon=on**. Press it twice to switch between the daemon and the Nintendo HOME menu; the change applies after the next restart. If the daemon was off before an install or update, it stays off.

Breeze installs from `/switch/Breeze/home_daemon.zip` when that file is there. Without it, the button downloads the full SwitchU fork.

## Settings

These appear in Settings once a compatible daemon is installed.

| Setting | What it does |
|---|---|
| **HOME daemon=on/off** | Uses the daemon or the Nintendo HOME menu, from the next restart. |
| **Home toggle** | How HOME behaves while Breeze and a game are both open. See below. |
| **Overlay pauses game=Yes/No** | In Overlay mode, pauses the game while Breeze is shown. |
| **Breeze first=on/off** | The console starts in Breeze, and HOME from a game returns to Breeze. Shown only when the SwitchU menu is installed; without it Breeze is HOME anyway. |

### Home toggle

Press the button to step through the modes.

| Mode | What HOME does |
|---|---|
| **Off** | Opens the SwitchU menu. Off lasts for the session: Breeze goes back to No restart the next time it starts. |
| **No restart** | Breeze stays open behind the game. HOME returns to exactly where you left it. |
| **Fast restart** | HOME closes Breeze, and the next HOME opens a new one. Needs Breeze started from Profile. |
| **Overlay** | Breeze is shown over the running game and hidden again with HOME. |

## Using Overlay mode

1. Set **Home toggle** to **Overlay**.
2. Start a game and open Breeze.
3. Press HOME. The game comes back.
4. Press HOME again. Breeze appears over the running game and takes the controller, so the game ignores your presses.
5. Press HOME to hide Breeze and hand the controller back.

Things to know:

- **Text entry.** Anything that asks for text first brings Breeze to the front as full-screen Breeze, because the on-screen keyboard cannot be used over the game. After typing, HOME returns to the game and the next HOME shows the overlay again.
- **Other overlays.** While Breeze is shown, Tesla / Ultrahand overlays and Nintendo's long-press HOME overlay do not answer their buttons. Press HOME to hide Breeze first and both work as usual.
- **Screenshots.** A screenshot taken while the overlay is shown includes it.
- **Cost.** A frame is drawn only when the menu changes, so an idle overlay costs the game almost nothing.

## Reaching the SwitchU menu and hbmenu

- **SwitchU** on Breeze's main menu (left stick click) exits to hbmenu; the next HOME closes it and opens the SwitchU menu. The button is hidden when the SwitchU menu is not installed.
- **hbmenu** on the main menu (`ZR + B`) leaves Breeze for hbmenu. Plain `B` on the main menu no longer leaves Breeze.
- **Restart Breeze** in the Focused Actions manager (`L + ZR`, then `ZR + B`) restarts Breeze in place.

## Limits

- After leaving Breeze for hbmenu, HOME from hbmenu switches to the game like No restart. Start Breeze again to use the overlay.
- A game opening its own keyboard or an error dialog closes Breeze while it is held behind the game. So does the console going to sleep, so that the game wakes up on its own.
- HOME cannot be blocked during a download or install. Do not press it while a progress window is up.

## Working from a PC

Because Breeze keeps running behind the game in No restart and Overlay modes, PC connect keeps answering while you play. See the **[Breeze PC App Guide](pc%20connect%20app.md)**.
