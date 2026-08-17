# Runtime IL2CPP Metadata

Breeze beta109.01 can browse Unity IL2CPP methods and build ASM Explorer function names directly from live game memory. `dump.cs` is optional: it remains supported and may contain richer metadata, but it is no longer required for method discovery and navigation.

## Quick Start

1. Open a class Field View and select **Methods** (`L + ZR`) to inspect that class. Breeze runs a lightweight Klass scan automatically if needed.
2. To name functions across the executable, open ASM Explorer, select **IL2CPP map** (`Y + ZR`), and press **X** to build.
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
- `runtime_methods.log` records method listings and detected layout details.

## Limitations and Diagnostics

- Runtime coverage follows `Klass.dat`. Rebuild the map when additional classes have loaded.
- `Klass.dat` stores process addresses; Breeze automatically refreshes missing or stale data when a runtime feature needs it.
- Parameter names appear only on IL2CPP builds that retain them; parameter types and counts remain available.
- Type-name resolution is a separate action because it has a one-time performance cost.
- When reporting incorrect decoding, include the `# layout` and `# datamap` lines from `runtime_methods.log`.
