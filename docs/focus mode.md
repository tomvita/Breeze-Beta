# Focused Actions Guide

Breeze has many buttons on every screen. Three views decide which of them are drawn:

- **All Actions** shows every action of the current menu.
- **Focused Actions** shows a smaller, per-menu set that you choose or load from a layout.
- **Dynamic view** shows the buttons that belong to the shift keys you are holding.

A view only decides what is drawn. With the default setting (`visible_only=0`), every button's shortcut works whether the button is shown or not.

## Opening the Focused Actions manager

Press `L + ZR` by default. The shortcut can be changed with `FocusedActions_key` in Settings.

The manager always shows all of its controls. Its title names the menu you came from, and the left panel lists the layout files.

| Button | Default shortcut | Action |
|---|---|---|
| Switch view | L + ZR | Changes the menu you came from between Focused and All. |
| Dynamic=ON/OFF | | Turns Dynamic view on or off for that menu. |
| Load layout | Y | Applies the selected layout at once. |
| Customize actions | L | Chooses which actions are focused. |
| Training mode: ON/OFF | | Adds actions to the focused set as you use them. |
| Save layout | X | Saves the current focus of every menu into the selected file. |
| Rename layout | | Renames the selected file. |
| New layout | + | Saves the current focus under a new name. |
| Delete layout | - | Deletes the selected file. |
| Reset all shortcuts | Left Stick Click | Restores the factory shortcuts. |
| Clear all shortcuts | Right Stick Click | Removes custom shortcuts. |
| Clear focus for this menu | | Clears the focused set of the menu you came from only. |
| Restart Breeze | ZR + B | Saves the settings and restarts Breeze. |
| Back | B | Returns to the menu you came from. |

## Built-in layouts

Breeze comes with six layouts. On first run it asks which one to start with; `B` keeps every button.

| Layout | For |
|---|---|
| **Player** | Using ready-made cheats: turning cheats on and off, conditional keys, loading cheats from the database, writing them to Atmosphere. |
| **Beginner maker** | Player plus simple search, candidates, bookmarks, basic memory editing and the cheat editor. |
| **Advanced maker** | Beginner plus pointer chains, Gen2 with Break and Trace, and ASM. |
| **Engine tools** | Advanced plus the Unity, Unreal and Lua menus. |
| **All** | Every button on every screen. |
| **Dynamic** | Every screen in All view with Dynamic view on. |

Load one with **Load layout**. Built-in layouts are shown in green in the list.

Breeze writes the built-in layouts again at every start, so they follow Breeze's buttons as these change. For that reason **Save layout**, **Rename layout** and **Delete layout** refuse on a green layout, and **New layout** refuses one of their names. To change a built-in layout, load it, make your changes and save the result under your own name.

## Dynamic view

Dynamic view needs no layout. It sorts the buttons by the shift keys in their shortcut:

- **Hold nothing:** the buttons whose shortcut has no ZL or ZR in it, and the buttons with no shortcut.
- **Hold ZL, ZR or ZL + ZR:** the buttons of that key. `ZL + ZR + Plus` is a ZL + ZR button, not a ZL one.

Things to know:

- It filters whatever the screen shows. On a Focused screen only the focused buttons are split; on an All screen every button is.
- The lower-right button reads `Dynamic`, then each shift key's glyph with the number of buttons on it. Green means Focused, olive means All. With more than one page it reads `Dyn 1/2`.
- A shift key with no buttons on the screen keeps the normal view up, and the label says `(none)`.
- Each layer keeps its own cursor and page.
- The keys must be held for a few frames before the panel changes, so a quick `ZL + Y` does not flash a layer.
- `A` on the highlighted button works with a shift key held, so a layer can be used with the cursor too.
- With custom shortcuts on, a button is sorted by its custom key.

## Customizing a menu

1. Open the Focused Actions manager from the menu you want to change.
2. Choose **Customize actions**.
3. The action panel expands to four columns and the left panel is hidden.
4. Use the following controls:
   - `A`: include or remove the action at the cursor.
   - `-`: cut an included action and push it onto the temporary stack.
   - `+`: pop the last cut action and insert it at the cursor, pushing later actions down.
   - `B`: finish customization and return to Focused Actions.

The cursor stays at the same grid position after `A`, cut, and paste. The Focused Actions shortcut is ignored during customization.

A menu's Back button is always shown in Focused view, so no layout can leave a screen without a way back. A Focused screen with nothing focused shows every button.

## Training mode

Turn **Training mode** on to add actions to Focused Actions as you use them. It does not clear the existing focused set and does not change the current view. Turn it off to stop learning new actions.

## Layout files

Layouts are `.focus` files in `/switch/Breeze/`.

- **Load layout** applies the selected layout at once, to every screen, without a restart.
- **Save layout** overwrites the selected file with the current focus of every menu.
- **New layout** saves the current focus as a new named layout.
- **Clear focus for this menu** clears only the menu you are managing.

### The layout in effect

Breeze remembers which layout you last loaded or saved. Opening the manager puts the cursor on that file, and its row is marked `(in effect)`, or `(in effect, changed)` when your focus has drifted from it.

The status line on the left panel shows the menu and the layout state, for example `Cheat [Focused]  Layout: default changed: Cheat, Main`:

- `unchanged` (green): your focus matches the file.
- `changed:` (yellow): followed by the menus that differ.
- `file missing` (red): the file was deleted or renamed outside Breeze.

When it has changed you can **Save layout** to overwrite the file, **New layout** to keep the file and save your focus under a new name, or **Load layout** to get the old focus back.

## Shortcuts

- **Reset all shortcuts** restores factory shortcuts and gives every screen its own keys.
- **Clear all shortcuts** removes custom action shortcuts.
- Settings has **Backup custom shortcuts** and **Restore custom shortcuts**, which use `/switch/Breeze/custom_shortcuts.dat`.
- `ZL`, `ZR` and `A` on their own are never shortcuts: they are the shift keys and the confirm key.

## Finding a missing action

Open the manager and choose **Switch view** to show All Actions, hold `ZL` or `ZR` if Dynamic view is on, or choose **Clear focus for this menu**.
