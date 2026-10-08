# Rebase: Carrying Cheats to a New Game Version

A game update moves addresses even when the data a cheat changes stayed the same. **Rebase** (beta120.00) records what every line of every cheat means, and rebuilds the cheats against the new version of the game.

It works on Unity (IL2CPP) games.

## Why cheats break on an update

- **Pointer cheats** start from a slot in the main module. The slot moves with every build, and every offset of a class that gained or lost a field moves too.
- **ASM cheats** hook an instruction. An `.aob` file finds the hook again only while the bytes around it stay the same; a recompiled function defeats it.
- **Code caves** sit at the end of a segment, and that end moves when the size changes.

Rebase stores the meaning instead: which class a pointer starts from, which field each offset is, which method a hook is in.

## How to use it

Open the Cheats screen, then **More** (`ZL + ZR + Plus`), then **Rebase** (`ZR + Down`).

| Button | Shortcut | Action |
|---|---|---|
| Build record | ZL + X | Name every line of the loaded cheats for this build. |
| Rebase | X | Rebuild the cheats from the newest record of another build. |
| Add | Y | Add the rebased cheats to the cheat list, turned off. |
| Back | B | Return. |

1. **Before updating the game:** load your cheats, be in the game at a point where their pointer chains lead somewhere, and press **Build record**. Breeze writes `<build id>.rebase` in the game folder. The first run may build the IL2CPP maps, which takes a while.
2. Install the update and start the game.
3. Open the Rebase screen and press **Rebase**. Breeze writes `<build id>_rebased.txt`.
4. Press **Add**, or load the file with **any cheats from Breeze's Game directory**.

Every cheat is listed as OK or FAIL with the reason. `rebase.log` shows how each line was resolved.

Both jobs can be stopped with the button that started them.

## What Rebase checks

- Each offset is looked up again by field name in the running game.
- Each pointer step reads the class of the object it lands on.
- Each hook is found by its AOB and by its method name. When the two disagree, the cheat fails instead of guessing.
- Caves are placed by the same rules as Assemble all ASM, and branches into and out of them are encoded again.

## Limits

- Unity (IL2CPP) games only.
- **Recording is manual.** Nothing is recorded unless you pressed Build record before the update.
- Cave code that uses ADR, ADRP or literal loads is refused rather than moved.
- A cheat with more than one cave, or with opcodes the recorder does not size (such as `C0` conditionals), is recorded as UNRESOLVED.
- Conditions and writes on fixed main addresses, and main slots that hold something other than a class, are UNRESOLVED.

For a cheat Rebase cannot carry, see the **[AOB Guide](aob.md)**.

## Generated files

In the game folder:

| File | Holds |
|---|---|
| `<build id>.rebase` | The record of what each cheat line means. |
| `<build id>_rebased.txt` | The rebuilt cheats for the new build. |
| `rebase.log` | How each line was resolved. |
