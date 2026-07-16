# Focused Actions Guide

Focused Actions reduces visual clutter by showing a smaller, per-menu set of frequently used actions. **All Actions** shows every action available in the current menu.

## Opening the Focused Actions manager

Press `L + ZR` by default. The shortcut can be changed with `FocusedActions_key` in Settings.

The manager always shows all of its controls; it does not have its own Focused/All state. **Switch action view** is its top-left and initially selected button. Contextual help appears at the top of this screen.

Choose **Switch action view** to change the menu you came from between Focused Actions and All Actions.

## Customizing a menu

1. Open the Focused Actions manager from the menu you want to change.
2. Choose **Customize actions**.
3. The action panel expands to four columns and the left panel is hidden.
4. Use the following controls:
   - `A`: include or remove the action at the cursor.
   - `-`: cut an included action and push it onto the temporary stack.
   - `+`: pop the last cut action and insert it at the cursor, pushing later actions down.
   - `B`: finish customization and return to Focused Actions.

The cursor stays at the same grid position after `A`, cut, and paste. The Focused Actions shortcut is ignored during customization, preventing accidental re-entry into the manager.

Any normal action can be removed, including a menu's usual default or Back action. If the configured initial action is not present, selection safely starts on the lower-right page button.

## Training mode

Set **Training mode=1** to add actions to Focused Actions as you use them. Enabling training does not clear the existing focused set and does not change the current Focused/All view. Set it to `0` to stop learning new actions.

## Layout files

- **Save layout** updates only the menu you are currently managing. Other menu layouts in the same file are preserved.
- **New layout** saves the current configuration as a new named layout.
- **Load layout** loads a saved layout and restarts Breeze to apply it.
- **Clear focus for this menu** clears only the menu you are currently managing and leaves every other menu unchanged.

## Shortcuts

- **Reset all shortcuts** restores factory shortcuts, including both the Focused Actions manager and Search Manager controls that share the same internal menu ID.
- **Clear all shortcuts** removes custom action shortcuts.
- The lower-right page button footer shows the configured Focused Actions shortcut.

## Status and help text

For normal action menus, status or search information remains below the panel title while contextual help appears separately below the action buttons. Help is always enabled, so there is no Help toggle. Customization hints and lower-right page-button hints take priority in the footer when applicable.

## Finding a missing action

Open the manager and choose **Switch action view** to show All Actions, or choose **Clear focus for this menu** to rebuild only the current menu's focused set.
