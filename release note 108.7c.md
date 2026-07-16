# Breeze beta108.7c

This release redesigns Focus Mode as **Focused Actions**, with clearer navigation, safer customization, and less hidden state.

## Focused Actions and All Actions

- **Focused Actions** shows the smaller action set chosen for each menu.
- **All Actions** shows everything available in that menu.
- The lower-right button identifies the current view and page, for example `Focused 1/3 → 2/3`.
- Selecting that button shows the configured Focused Actions shortcut in the footer.

## A simpler manager

- The Focused Actions manager no longer has a focused state of its own; all management buttons are always visible.
- **Switch action view** is the top-left and initially selected button.
- Manager help is shown at the top where it is easier to notice.
- **Reset all shortcuts** restores both the manager defaults and the Search Manager defaults that share its internal menu.

## Full-screen customization

Choose **Customize actions** to open a four-column action panel with the left panel hidden.

- `A` includes or removes the action at the cursor.
- `-` cuts an included action and pushes it onto a temporary stack.
- `+` pops the last cut action and inserts it at the cursor, pushing later actions down.
- `B` finishes customization and returns to Focused Actions.
- The cursor remains at the same grid position after `A`, cut, or paste.
- The Focused Actions shortcut is ignored while customization is active, preventing accidental re-entry and a crash.

Any normal action can now be removed, including the usual initial or Back action. When the configured initial action is not available, Breeze safely selects the lower-right page button.

## Training and layouts

- Set **Training mode=1** to add actions to Focused Actions as you use them.
- Enabling Training mode does not clear the focused set or change the current Focused/All view.
- **Save layout** updates only the menu currently being managed; other menus in the layout file remain unchanged.
- **Clear focus for this menu** clears only the current menu.

## Status, help, and shortcuts

- Menu status or search information remains at the top.
- Contextual action help is always available below the buttons.
- Customization and lower-right button hints use the same footer when applicable.
- The obsolete Help toggle has been removed.
- Lower-right labels now use the arrow symbol and consistent `X/Y` page counts.

See the [Focused Actions Guide](docs/focus%20mode.md) and [UI reference](docs/menu.md#focused-actions-menu) for complete instructions.
