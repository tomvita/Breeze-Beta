# Breeze beta109.01 Release Note

## Automatic Klass Search

Breeze now creates the live Unity IL2CPP class data needed by runtime method browsing and function-map generation automatically. You no longer need to run **Search → Klass** before using these features.

### Changes

- Building `il2cpp_function_map.txt` now runs the lightweight Klass scan automatically when `Klass.dat` is missing, empty, or from an earlier game session.
- Opening runtime class fields, resolving signature types, and navigating from an ASM Explorer runtime function now trigger the same automatic scan when needed.
- The automatic path creates only the class data these features require and skips the slower Klass instance scan.
- Updated status and error messages to describe automatic recovery and distinguish missing live classes from an outdated function map.
- Existing valid `Klass.dat` data is reused, so no extra scan is performed during normal navigation.

### Updated Workflow

1. Open a class Field View and select **Methods** (`L + ZR`) to browse its runtime methods, or open ASM Explorer and select **IL2CPP map** (`Y + ZR`).
2. Press **X** to build the function map. Breeze runs the Klass scan automatically if required.
3. Return to ASM Explorer to use runtime function names and **Function Up** / **Function Down**.

### Notes

- `Klass.dat` contains process addresses and is refreshed automatically after a game restart when one of these runtime features needs it.
- Rebuild the function map if it belongs to an older run or if additional classes have loaded since it was created.
- The full **Search → Klass** action remains available when you need the separate Klass instance-search results.
