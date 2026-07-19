# Changelog

## Tutorial Help System

### Added

- Added context-sensitive topic tutorials and selected-button Action Help throughout Breeze.
- Added ZR then A as the ordered global help toggle, with underlying input blocked while help is open.
- Added persistent per-menu tutorial state and a separate Focused Actions tutorial context.
- Added dedicated Sysmodule help, including runtime On/Off semantics and `sys-ftp-breeze` configuration guidance.

### Changed

- Main Menu Help now opens the Main Menu tutorial.
- Moved Prerelease updates from the legacy Help screen to Settings.
- Renamed unclear Gen2, JumpBack, ASM Composer, and Cheat Editor actions; see [release note tutorial help.md](release%20note%20tutorial%20help.md).
- Excluded the Gen2 fork Title ID `010000000000D609` from Sysmodule Manager.

## [Beta 108.7c] - 2026-07-16

### Changed

- Renamed the simplified and complete action views to **Focused Actions** and **All Actions**.
- Reworked the Focused Actions manager so all management controls are always visible. **Switch action view** is now the top-left and initially selected control.
- Added four-column, full-screen customization with `A` toggle, `-` cut, `+` paste, and `B` finish controls.
- Added optional Training mode for learning actions as they are used without clearing or switching the current view.
- Made layout saving and focus clearing operate on only the menu currently being managed.
- Split top status information from bottom contextual help and removed the obsolete Help toggle.

### Fixed

- Menus now fall back to the lower-right page button when their configured initial action is absent from Focused Actions.
- Any normal action can be removed without causing menu initialization crashes.
- Reset All Shortcuts now restores the Focused Actions manager defaults as well as Search Manager defaults.
- The Focused Actions shortcut is ignored during customization, preventing a crash caused by re-entering the manager.

## [Beta 99s] - 2026-01-25
### Added
- **Radial Selection**: Hold `ZL` and use the stick to quickly select buttons in the right panel.
- **Dynamic Module Support**: Enhanced support for Unity/Unreal Engine games with automatic `R1` register setup for module offsets.
- **Pointer Search Improvements**: Integrated `JumpBackMatch` concepts for higher quality and faster pointer search results.
- **Assemble GUI Enhancements**:
  - Tandem scrolling for code and data views.
  - Visual error highlighting for assembly lines with errors.
  - Click on error log to scroll to the corresponding error line.
- **New Documentation**:
  - [Dynamic Modules Guide](docs/dynamic_module.md)
  - [Pointer Search Method Primer](docs/pointer search.md)
  - [x30 Match Examples](docs/x30 match example.md)
- **Updated Manual**: Comprehensive updates to `README.md` and `Breeze.md`.

### Fixed
- Various bug fixes and stability improvements in the ASM Composer.
- Improved master code generation for dynamic modules.

## [Beta 99m] - 2025-08-27
- Readme update to 99m level.
- Initial preparation for major documentation overhaul.
