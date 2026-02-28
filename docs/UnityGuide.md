Unity metadata support and class-exploration workflow.

## Feature guide

- `dump.cs` view to inspect C# class definitions directly in Breeze.
- `Class Field View` to inspect fields from a live class instance, including pinning resolved addresses for live tracking.
- Class navigation tools:
  - `View class` to follow field types.
  - `Class Link` to find parent/up links.
- Enhanced class-link resolution so discovering one instance can lead to many related instances for exploration.
- Save/load for class views, including instance links when the address is still valid.
- Cheat generation support when linked addresses start from `main`-region.

## Preparation

### Get il2cpp Breeze helper

You need to generate required files with helper for new Unity-specific features to work.

Get from here: <https://github.com/tomvita/Il2CppDumper/releases/latest>

## Views guide

### ASM Explorer

- `Function Up` (`StickRLeft`): jump to the nearest function above the current cursor line.
- `Function Down` (`StickRRight`): jump to the nearest function below the current cursor line.
- `Detail` (`X + ZR`): open `dump.cs` details for the current function.

### dump.cs View

- `Search` (`+`): text search inside `dump.cs`.
- `Add bookmark` (`A + ZL`): bookmark current `dump.cs` line/offset.
- `Bookmarks` (`R`): open `dump.cs` bookmark list.
- `Find definition` (`X`): jump to class/field/type definition.
- `Field view` (`X + ZR`): open Field View for the selected class/field context.
- `Goto Namespace` (`L`): jump to namespace block.
- `Goto RVA` (`Y`): jump to function/class area by RVA.
- `Page Up/Down` and `Line Up/Down`: fast/precise navigation in `dump.cs`.

### Field View

- `Pin selected offset` (`X`): pin the selected field using the active source address/bookmark.
- `Pin gen2 offset` (`ZR`): pin using gen2 offset flow when applicable.
- `Memory Explorer` (`R`): jump to live memory at current field context.
- `Dump.cs` (`L`): jump back to `dump.cs` context.
- `View class` (`R + ZL`): open field-type class details.
- `Class Link` (`Y`): find classes/fields that link to the current class.
- `Descendent` (`Y + ZL`): find direct child classes.
- `Jump Back` (`StickL + ZR`): open jump-back style source navigation.
- `Make cheat` (`+ + ZR`): generate cheat from valid linked field context.
- `Save field view` (`StickR + ZR`): save current field view state for reload.

### Related Main / Memory Explorer Buttons

- Main Menu: `Load field view`
- Purpose: open saved Field View entries and resume previous class-analysis sessions.
- Main Menu: `Launch dumptool`
- Purpose: launch `nxdumptool` to extract `main` and `global-metadata.dat` into `sdmc:/switch/breeze/cheats/<TITLE_ID>/`.
- Memory Explorer: `Load field view` (`StickLUp + ZR`)
- Purpose: use current cursor context as source input for Field View pinning workflow.
- Memory Explorer: `SetBreakPoint` (`Up + ZL`)
- Purpose: set watch/breakpoint on validated address to capture code that accesses it.

## Memory Explorer to Field Pin Workflow

1. In Memory Explorer, move cursor to the address you want to use as the live source instance.
2. Press `Load field view` (`StickLUp + ZR`) to use current memory context as the source and enter Field View flow.
3. In Field View, highlight the target field and press `Pin selected offset` (`X`).
4. Breeze computes pinned base from source and field offset, then shows live values for that class instance.
5. Optional: use `Save field view` for later restore or `Make cheat` when target resolves from a valid `main` region.

## Start from Scratch Workflow

1. Search for a target memory value/address with Breeze search workflow until you have stable candidate addresses.
2. Validate the candidate address in Memory Explorer by checking that it changes with in-game behavior as expected.
3. From Memory Explorer, use `SetBreakPoint` (`Up + ZL`) on the validated address to capture code access.
4. Review the captured result and move into ASM Explorer for code analysis.
5. Review captured access points, then use `Function Up` and `Function Down` to move to nearby method boundaries and find promising functions.
6. For a promising function, press `Detail` (`X + ZR`) to open its `dump.cs` context.
7. In `dump.cs` view, navigate to the relevant class/field and open `Field view` (`X + ZR`).
8. Save the field view (`Save field view`, `StickR + ZR`) so it can be reused in the next phase.
9. Continue with the Memory Explorer to Field Pin Workflow to pin live instance addresses and finalize cheat/validation work.
