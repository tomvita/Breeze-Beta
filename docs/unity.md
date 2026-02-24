# Unity / IL2CPP Support in Breeze

This document describes what Breeze currently supports for Unity IL2CPP targets and how each feature operates.

## Scope
- Target source: IL2CPP metadata from `dump.cs`.
- Main workflows: class/field discovery, live memory inspection, pointer-chain-based restoration, and cheat generation.

## Core Data Source
- `dump.cs` is indexed and used for:
  - class and namespace navigation
  - RVA lookup
  - definition lookup
  - text search
  - inheritance and field-type link search

## Field View
- Field View opens parsed instance fields for a selected class.
- Each row includes field offset, field name, type, and live value when a base address is pinned.
- Supported synthetic expansions include:
  - array/list-like structures
  - string handling
  - struct component expansion
- Enum type recognition is supported.

## Pinning Model
- `Pin selected offset` computes base as:
  - `base = selected_source_address - selected_field_offset`
- The physical live source address at pin-time is authoritative.
- Pointer chain metadata can be attached, but it does not replace a mismatched live source.

## Pointer Chain Support
- Field View records can store pointer chain metadata used for restore and automation.
- Saved chain data includes root/main-relative anchor and chain hop information.
- On load, chain-based resolution is used to restore usable addresses across restarts when valid.
- Chain validation requires resolved source to match expected addressing context.

## Class Relationship Navigation
- `Class Link`:
  - one-pass search for fields whose type links to the current class
  - selection jumps to the owner class and positions cursor on the linking field
- `Descendent`:
  - one-level search for classes declared as `child : current`

## Memory Explorer Integration
- Field View can jump to Memory Explorer while preserving context.
- When pointer-chain context exists, handoff keeps chain state so navigation depth and source tracking stay consistent.
- Bookmark handoff from memory workflows is supported.

## Save / Load Field View
- Field View entries can be saved, loaded, and deleted.
- Saved entries retain enough addressing metadata to reapply context after restart when chain resolution is valid.
- After save/load, the Field View title uses the saved entry name.

## Cheat Creation from Field View
- `Make cheat` is available from Field View when a valid pointer chain context exists.
- Cheat-name prefill uses:
  - saved Field View entry name (if present)
  - plus current field name
- Chain emission avoids incorrect extra dereference on terminal additive offset.

## Dump.cs Navigation Tools
- Jump to `dump.cs` from related views.
- Go to RVA.
- Namespace jump.
- Find definition.
- Text search.
- Bookmark support and right-panel match/status helpers.

## Notes
- `Pin pointer offset` was removed.
- Pointer chain is treated as supplemental restore data, not a blind override of live source.
