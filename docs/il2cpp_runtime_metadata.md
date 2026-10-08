# Runtime IL2CPP Metadata

Breeze beta109.01 can browse Unity IL2CPP methods and build ASM Explorer function names directly from live game memory. `dump.cs` is not needed. From beta124.00 the buttons that used to ask for it (**Class Link**, **Descendent**, **Dump.cs** and **Load field view**) answer from Breeze's own maps, and the **Il2Cpp** and **Launch dumptool** buttons that produced it are gone from the Main Menu. A `dump.cs` made on a PC is still used when it is in the game folder.

## Quick Start

1. Open a class Field View and select **Methods** (`L + ZR`) to inspect that class. Breeze runs a lightweight Klass scan automatically if needed.
2. To name functions across the executable, open **Unity > IL2CPP map** from the Main Menu (or **IL2CPP map**, `Y + ZR`, in ASM Explorer) and press **X** to build the function map. Press **Y** to build the field map.
3. Return to ASM Explorer. Function names and **Function Up** / **Function Down** are available immediately.

## Runtime Method List

Rows show a method's static (`S`), virtual (`V`), and abstract (`A`) flags; name; parameters; return type; and live address. `<no code>` means the method was inlined or stripped and cannot be opened as a standalone function.

| Action | Shortcut | Result |
|---|---|---|
| ASM Explorer | X | Open the selected method's live address. |
| Class field | R | Open the current class's Field View. |
| Visit type | Y | List classes and structs in the selected signature. |
| Resolve type names | L + ZR | Resolve runtime type placeholders to class names. |
| Build function map | Y + ZR | Open the IL2CPP function-map builder. |
| Write to file | Minus + ZR | Append methods and layout diagnostics to `runtime_methods.log`. |

In the Visit Type menu, press **X** for the selected type's Field View or **Y** for its methods.

## Generated Files

Files are written to `/switch/breeze/cheats/<TitleID>/`:

- `il2cpp_function_map.txt` supplies ASM Explorer function names.
- `il2cpp_field_map.txt` holds every field of every class with its offset and type.
- `runtime_methods.log` records method listings and detected layout details.

## Limitations and Diagnostics

- Runtime coverage follows `Klass.dat`. Rebuild the map when additional classes have loaded.
- `Klass.dat` stores process addresses; Breeze automatically refreshes missing or stale data when a runtime feature needs it.
- Parameter names appear only on IL2CPP builds that retain them; parameter types and counts remain available.
- Type-name resolution is a separate action because it has a one-time performance cost.
- When reporting incorrect decoding, include the `# layout` and `# datamap` lines from `runtime_methods.log`.

## Field Map and the Unity Menu

From beta123.00 Breeze also builds an **IL2CPP field map**: every field of every class with its offset and type, including each class's slot in the main module and its static block. Build it with **Y** on the IL2CPP map screen.

With both maps built, the **Unity** menu on the Main Menu finds values by name instead of by searching memory:

- **Usual suspects** lists classes, fields and methods with likely names: hp, money, energy, exp and so on.
- **Search maps** searches every class, field and method name.
- **Singletons** lists the classes that are the usual roots of a pointer chain.
- **Instances** lists the live objects of a class, with a pointer chain to each.
- **Find chain** searches for a chain from a static root to an object, through lists, arrays, dictionaries and interface fields.

Build the maps again after a game update. On a large game, pause the game while the maps build.

See the **[Unity Guide](UnityGuide.md)** and the **[Unity menu walkthrough](unity_menu_walkthrough.md)**.
