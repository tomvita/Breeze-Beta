# Make cheat (Cheats menu): cheats from a recipe and a table

**Make cheat** on the Cheats menu (default key R+ZL) builds cheats from two files
in the game's Breeze folder (`sdmc:/switch/breeze/cheats/<game>/`):

- `make_cheat.ini`: the recipes, one section each.
- a table of data, usually a `.tsv` file the recipe names.

The screen lists the table's rows. You search, filter and mark them, and make a
cheat from the row under the cursor or one per marked row. A made cheat is
added switched on, replaces a loaded cheat of the same name, and the cheat file
is saved.

| Key | Action |
|---|---|
| X | Make cheat from the row under the cursor |
| Y | Search: every typed word must appear (empty shows everything) |
| R / L | Filter: one value of the recipe's filter column, or all |
| Minus | Mark / unmark the row |
| ZL+X | Make marked: one cheat per marked row |
| ZL+Minus | Clear marks |
| Plus | Next recipe |
| B | Back |

## The recipe

```ini
[Give item]
name            = Give {count} {name} ({key})
data            = items.tsv
show            = {name}   {cat:names}   {sell}G
search          = name
filter          = cat
exclude         = cat 23-35
ask             = count 1-999 default 99
key             = ZL+ZR+X
key_mode        = down
requires        = Give item hook (needed by Give cheats)
requires_script = Give item hook (needed by Give cheats).txt
requires_hook   = M+2DDCED0
requires_stock  = F9401400
code            = {keycond}
                  04000000 075D8FF4 {count}
                  04000000 075D8FF0 {id}
                  20000000

[cat names]
1  = Seeds
10 = Crops
```

A section with both `data` and `code` is a recipe. Other sections are lookups.

| Key | Meaning |
|---|---|
| `name` | The cheat's label (text template). |
| `data` | The table: a file in the game's folder, or `[Section]` for rows written in this ini (first row is the header). |
| `show` | How a row is shown in the list (text template). |
| `search` | Columns the search looks in, comma separated (default: all). |
| `filter` | The column Filter R / L steps through. |
| `exclude` | Rows never offered: `column range[, range]`, several separated by `;` (e.g. `cat 23-35; cat 0`). |
| `ask` | Values asked when making: `var lo-hi default d`, several separated by `;`. Asked once for a batch. |
| `key` | The default key combo, changeable when making: `ZL+ZR+X` (A B X Y L R ZL ZR LS RS PLUS MINUS UP DOWN LEFT RIGHT). |
| `key_mode` | `down` (default): once per press. `held`: every pass while held. |
| `requires` | A cheat that has to be loaded (and is switched on) for these cheats to work. |
| `requires_script`, `requires_hook`, `requires_stock` | When the required cheat is missing, install it: the script in the game's folder, the hook address and the game's word expected there. It is built through Add ASM's cave planner and registered for Assemble all ASM. If the word at the hook is not `requires_stock` it refuses (another cheat hooks there, or the game is another build). |
| `code` | The cheat, as a template. Lines go on indented continuation lines. |

**Templates.** `{column}` is the row's value, `{var}` an asked value, `{key}`
the key combo text, `{column:names}` the value's name from the `[column names]`
section. In `code`, every value becomes 8 hex digits, and `{keycond}` becomes the
key condition (`C4000000 hi lo`, or `C4100000` for `held`). In `name` and
`show` values stay as text.

## The table

Tab separated, the first non-comment line names the columns, `#` lines are
comments. Numbers are decimal, or hex with `0x`.

```
id	cat	kind	sell	name
50136	1	50	5	Turnip Seeds
```

## First use: Harvest Moon The Winds of Anthos

`items.tsv` has the game's 1,987 items (from its item table and texts).
`exclude = cat 23-35` hides the tools and the key and event items. The give
cheats write a request (count, then item id) that the `Give item hook` cheat
hands to the game's own `ItemInfo::AddHaveItem`: the call harvesting makes, so
the item goes to the right bag group and stacks. Only give items from the
table: an id the game does not know may make that call fail.
