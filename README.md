# Breeze
A Nintendo Switch game cheating tool designed to work seamlessly with Atmosphere's cheatVM.

This project started as a rewrite of the features implemented in EdiZon SE. Over time, the code for EdiZon SE became increasingly difficult to maintain, and its UI posed challenges for many users. Over time, numerous features were added, along with significant optimizations, making Breeze much faster and far more powerful than EdiZon SE.

## Objectives
1.  **Improve the User Interface**: Ensure more users can access and enjoy the tool’s features.
2.  **Streamline Codebase**: Make the code easier to develop and extend.
3.  **Leverage Experience**: Apply lessons learned from SE tools to create a robust foundation for future development.
4.  **All in one tool**: Every task involved in cheat creations can be perform with Breeze alone on Switch.

---

## Features
-   **Cheat Code Management**: Toggle, edit, and manage cheats from multiple sources.
-   **Cheat Code Editor**: Integrated disassembler, assembler, and loop creator. Extract ASM from existing cheats, edit in the integrated ASM Composer.
-   **ARM64 Instruction Support**: Assemble and disassemble ARM64 instructions.
-   **Memory Tools**: Search, edit, freeze, and bookmark memory with static offsets or pointer chains.
-   **Advanced Debugging**: Set memory breakpoints and watch instructions.
-   **ASM Composer**: Build ASM cheats efficiently. One-click templates for common hacks.
-   **Unity (IL2CPP) Analysis Workflow**: Inspect live classes, fields, methods, and signatures; build ASM Explorer function maps directly from game memory; or use `dump.cs` for additional detail.
-   **Class Field View & Persistence**: Inspect Unity, Unreal, and native C++ objects; pin live offsets, navigate class relationships, and cache inferred layouts.
-   **Native Function Discovery**: Recover function boundaries, calling-convention signatures, and script binding names in stripped C++ games.
-   **Unreal (UE4/UE5) Runtime Tooling**: Scan UE profiles, resolve root chains (`UWorld` flow), export native `UFunction` maps, browse every object, and read Gameplay Ability System attributes. UE 4.16 and later.
-   **Unity Menu**: Find values by name from Breeze's own IL2CPP maps, list live objects and get a pointer chain to them. No `dump.cs` needed.
-   **Lua, GameMaker and Godot Support**: Browse a Lua state by name, build GameMaker cheats from a shared hook, and find chains through a Godot object graph.
-   **Engine Detection**: Game Information reports the engine, scripting language and middleware of the running game.
-   **Rebase**: Carry cheats to a new version of the same game.
-   **Overlay Mode**: Show Breeze on top of the running game and switch with the HOME button.
-   **PC Connect and PC App**: See and drive Breeze from a PC, take save snapshots, and copy files, while the game runs.
-   **Auto-Update**: Keep the app and database up to date automatically.
-   **Consistent UI**: A user-friendly interface designed for seamless navigation. Includes **Radial Selection** (hold ZL and use stick) for quick action activation.

---

## Documentation

For detailed information, please refer to our comprehensive documentation:

-   **[Quick Start Guide](quick_start.md)**: For new users who want to get started with basic cheat usage right away.
-   **[User Manual (Breeze.md)](Breeze.md)**: The main guide for installation, usage, and all features.
-   **[Unity Guide](docs/UnityGuide.md)**: Unity-specific workflow: the Unity menu, IL2CPP maps, Find chain, Field View, and class-link based cheat building.
-   **[Unity Menu Walkthrough](docs/unity_menu_walkthrough.md)**: A money cheat and an HP cheat, step by step.
-   **[Make Cheat](docs/make%20cheat.md)**: Turn the pointer chain in Memory Explorer into a cheat for one value or for every element of an array (all enemies), with screenshots.
-   **[Runtime IL2CPP Metadata](docs/il2cpp_runtime_metadata.md)**: Browse methods and generate function maps without `dump.cs`.
-   **[Unreal Support Guide](docs/unreal.md)**: Unreal workflow for UE profile scan, root-chain resolution, function map export, and explorer tools.
-   **[Unreal Primer](docs/unreal_primer.md)**: Core UE runtime concepts (`UObject`, `UClass`, `UFunction`, NamePool, and `OuterPrivate`) used by Breeze.
-   **[AOB Guide](docs/aob.md)**: Create version-3 signatures with Make AOB or Make AOB M and rebuild hooks after a game update.
-   **[Lua Tools](docs/lua.md)**: Browse and cheat games that keep their data in a Lua state.
-   **[Rebase](docs/rebase.md)**: Carry cheats to a new version of the same game.
-   **[Code Caves and ASM Cheats](docs/code%20caves.md)**: How caves are placed, the Code Cave Map, Assemble all ASM, and the three stages of Toggle Cheat.
-   **[Beta 124.00 Release Note](release%20note%20124.00.md)**: Game files, Unity without `dump.cs`, save snapshots, and the PC app's file manager. See also the shorter **[user note](release%20note%20124.00%20user%20note.md)**.
-   **[Basic Cheat Making Tutorial](basic_cheat_making_tutorial.md)**: A step-by-step guide to creating your first cheat.
-   **[Advance Cheat Making Tutorial](docs/advance_cheat_making_tutorial.md)**: A step-by-step guide to creating advanced ASM cheat.
-   **[UI Reference (menu.md)](docs/menu.md)**: A complete reference for every button and menu in the UI.
-   **[Focused Actions Guide](docs/focus%20mode.md)**: Configure Focused/All Actions views, training, layouts, customization, and shortcuts.
-   **[Context-Sensitive Help Guide](docs/help%20system.md)**: Open and navigate the in-application tutorial and selected-button Action Help.
-   **[Sysmodule Manager Guide](docs/sysmodules.md)**: Runtime status, restart-required modules, and `sys-ftp-breeze` configuration.
-   **[HOME Toggle and Overlay Mode](docs/home%20toggle%20and%20overlay.md)**: The HOME daemon, the Home toggle modes, Overlay mode and Breeze first.
-   **[Breeze PC App Guide](docs/pc%20connect%20app.md)**: See and drive Breeze from a PC over Wi-Fi: install, key and mouse mapping, save snapshots, Stop / Start game, and the file manager.
-   **[PC Connect](docs/pcconnect.md)**: The protocol behind the PC app, for scripts: commands, the Python client, and recipes.
-   **[Save Snapshots and Game Files](docs/save%20snapshots%20and%20game%20files.md)**: What save redirect does, where the files are, and how a game's own files are reached.
-   **[Break and Trace Tutorial](docs/break_and_trace_guide.md)**: Visual step-by-step guide to Break and Trace in Breeze's ASM Explorer.
-   **[Break and Trace with Breezehand-Overlay](docs/break%20and%20trace.md)**: The same feature driven from the overlay.
-   **[Technical Cheat Details (cheats.md)](docs/cheats.md)**: Advanced documentation on the cheat code format and CheatVM instructions.
-   **[Dynamic Modules](docs/dynamic_module.md)**: An explanation of how dynamic modules work.
-   **[Pointer Search Guide](docs/pointer_search_guide.md)**: Using the Jump Back Menu to find stable pointer chains.
-   **[Pointer Search Method](docs/pointer%20search.md)**: Detailed explanation of the pointer search algorithm.
-   **[x30 Match](docs/x30%20match.md)**: The theory of x30 match.
-   **[x30 Match Example](docs/x30%20match%20example.md)**: A practical example of using x30 match.
-   **[Changelog](CHANGELOG.md)**: A history of recent changes and milestones.
-   **[Community Wiki](https://github.com/tomvita/Breeze-Beta/wiki)**: For other tutorials and community-contributed guides.

---

## Acknowledgments
This project builds on the UI framework from Daybreak. The knowledge gained from developing EdiZon SE and insights from contributors like Werwolv have been invaluable. Special thanks to the Atmosphere team and the broader hacking community for their support and inspiration.
