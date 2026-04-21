# Qlaunch Takeover

## What it is

Breeze can take over the Switch's **Home button** so that pressing Home brings
up Breeze (or resumes it if it's already running) instead of the normal Home
menu. This lets you flip between your game and Breeze with a single button
press, just like switching between a game and the system Home menu.

The takeover works by installing a small replacement for the system's qlaunch
process (provided by the SwitchU daemon). Without the takeover, Breeze still
works normally — it just has to cold-start every time through Album / hbmenu.

## Installing the takeover

1. Open **Settings** inside Breeze.
2. Find the button labelled **`qlaunch=0`** and press it.
   - The button becomes `qlaunch=1` once installed.
   - If the button is greyed out, `qlaunch.zip` is missing from
     `sd:/switch/Breeze/`.
3. Reboot your console. A message will remind you.

To uninstall, press the same button when it reads `qlaunch=1` and reboot again.

## The two controls you care about

Once the takeover is installed, two switches decide what the Home button does:

### `HomeRestart Off` — in the Main menu

This button switches Breeze into **suspend-resume** mode. Pressing it arms
the mode; to turn it off again, exit Breeze normally with **B** from the Main
menu.

Breeze has two ways of dealing with the Home button:

- **Restart mode** (the default, and the way Breeze has worked for a long
  time). Pressing Home exits Breeze cleanly. On the next launch, Breeze saves
  and restores *some* state to disk. This is the familiar
  behavior existing users will recognize.
- **Suspend-resume mode** (enabled by pressing **HomeRestart Off**). Breeze
  stays suspended in the background when you press Home, and the next Home
  press brings it back exactly as you left it — attached process, search
  results, cheats, scroll positions, everything. It's an instant toggle with
  nothing lost.

Use suspend-resume mode when you want a smooth game ↔ Breeze toggle; use the
default restart mode if you prefer the classic workflow or want each session
to start fresh.

The HomeRestart button only appears when a game is attached and the qlaunch
takeover is installed.

### `Home2Profile=0 / 1` — in Settings

Controls what the Home button does **when Breeze is not the current target**
(i.e. you've exited Breeze, or you haven't opened it yet this session).

- **Home2Profile=1** — Home opens the **Profile** applet. *This is the
  default, and the recommended setting for normal use.*
- **Home2Profile=0** — Home opens the **SwitchU home menu** if you have
  installed the SwitchU fork by Tomvita. If you haven't, Home will open
  **hbmenu** instead — which is not a normal use case, so leave this at `1`
  unless you know you want it.

Press the button to flip between the two states.

## Typical flow

After installing the takeover and rebooting, **Breeze appears automatically on
cold boot** — it replaces the normal Home menu as the first thing you see.

### Getting to a game

How you launch a game depends on whether you also use the SwitchU fork (by
Tomvita):

- **With SwitchU installed** — in Breeze's Settings, set **`Home2Profile=0`**
  once. From now on, pressing **Home** brings up the SwitchU home menu, and
  you launch the game from there as normal.
- **Without SwitchU** — press **B** from Breeze's Main menu to exit. You'll
  land in **hbmenu**, so use any homebrew game-launcher (forwarder / title
  launcher) to start the game. SwitchU is optional — any homebrew that can
  launch a game works.

### While playing

1. Press **Home** → Album → hbmenu → Breeze.
2. In Breeze's Main menu, press **HomeRestart Off** to arm suspend-resume
   mode.
3. Press **Goto Game**. The game resumes; Breeze stays alive in the
   background.
4. From now on, Home toggles between the game and Breeze instantly, with all
   Breeze state preserved.
5. When you're done, press **B** (Exit) in the Main menu. This leaves
   suspend-resume mode and returns Home to whatever `Home2Profile` selects
   (Profile if `=1` — the default; SwitchU home menu if `=0` and the SwitchU
   fork is installed; otherwise hbmenu).

Rebooting always returns you to a clean state — the takeover forgets any active
Breeze session on startup.

## Optional: other Home destinations

Advanced users can place empty marker files on the SD card to send Home to a
different applet when Breeze isn't the target. Priority is highest first:

| File on SD card                               | Home opens              |
| --------------------------------------------- | ----------------------- |
| `sd:/config/SwitchU/launch_profile`           | Profile (My Page)       |
| `sd:/config/SwitchU/launch_cabinet`           | Amiibo Cabinet          |
| `sd:/config/SwitchU/launch_eshop`             | eShop (broken on firmware 22.1+) |
| *(none of the above)*                         | Album (→ hbmenu)        |

The `Home2Profile` button in Settings simply creates or deletes the first one
(`launch_profile`) for you. If you're on firmware 22.1 or newer and want a
non-Album fallback, use `launch_cabinet` instead of `launch_eshop`.

## Troubleshooting

- **Home does nothing / takes me back to the system menu** — the takeover
  isn't installed, or you rebooted without it. Check that Settings shows
  `qlaunch=1`.
- **Breeze cold-starts every time I press Home** — you're in the default
  restart mode. Press **HomeRestart Off** in the Main menu to switch to
  suspend-resume.
- **Home opens hbmenu / Album when I wanted Profile** — set
  `Home2Profile=1` in Settings (this is the default).
- **Something is stuck in a weird state** — reboot. The takeover clears its
  session flags on every boot, so you always start fresh.
