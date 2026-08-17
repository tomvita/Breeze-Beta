# Breeze beta109.00 Release Note

## Unity Without `dump.cs`

Breeze can now read Unity IL2CPP method metadata directly from a running game. Method names, live addresses, signatures, and function navigation no longer require Il2CppDumper or a `dump.cs` file. Existing `dump.cs` workflows remain supported and provide additional detail when available.

### Highlights

- Added a runtime method list for each class, including method names, live addresses, flags, return types, and parameters.
- Added on-device `il2cpp_function_map.txt` generation for ASM Explorer function names and Function Up/Down navigation.
- Added parameter and return-type navigation to runtime class field and method views.
- Updated ASM Explorer Detail to open the owning runtime class when a name came from the runtime map.
- Fixed an empty Klass name-cache latch and improved cache performance.
- Fixed automatic cheat-download validation and database fallback.
- Fixed opening Focused Actions from the Candidate menu.

### Workflow

1. Run **Search → Klass**.
2. In ASM Explorer, select **IL2CPP map** (`Y + ZR`) and press **X** to build.
3. Return to ASM Explorer to use generated names and Function Up/Down.

For a single class, use **Methods** (`L + ZR`) in its Field View. See the [Runtime IL2CPP Metadata guide](docs/il2cpp_runtime_metadata.md) for actions, generated files, limitations, and diagnostics.
