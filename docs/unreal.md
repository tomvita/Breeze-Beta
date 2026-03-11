# Unreal Support in Breeze

This document describes what Breeze's Unreal module does today and how it is used.

## What Breeze does

Breeze's Unreal workflow is a runtime scanner/exporter for UE4/UE5 targets on Nintendo Switch.

At a high level it:
1. Attaches to the active game process through `dmntcht`.
2. Scans target memory ranges for likely UE objects.
3. Identifies `UFunction` objects and their native pointers.
4. Resolves names through NamePool + Outer chain.
5. Writes `ue_function_map.txt` (and timing info) for later exploration.

Primary output:
- `ue_function_map.txt`
- `ue_function_map_timing.log`

## Main Unreal menu actions

From the Unreal menu, Breeze currently exposes:
- `Scan UE Profile`: scans and writes UE profile offsets/config.
- `UE Root Chain (profile)`: resolves chain from profile and enables Explorer.
- `Export UE Func Map`: fast function map export.
- `Export UE Func Map (Extended)`: slower fallback scan path for more coverage.
- `Function Explorer`: reads `ue_function_map.txt` and browses function rows.
- `UWorld Explorer`: browses resolved runtime chain state.

## Function map export pipeline

The exporter (`run_ue_export_function_map`) does roughly this:
1. Build readable/executable scan ranges.
2. Enumerate candidate UObject-like entries.
3. Filter candidates whose class-name looks function-like.
4. Probe candidate object slots for a native pointer in `RX` memory.
5. Build fully qualified names using name + outer-chain resolution.
6. Deduplicate and sort rows.
7. Emit text rows with both relative and absolute code addresses.

Example row shape:
```text
Package.Class.Function=main+0x123456 | abs=0x4XXXXXXXXX class=Function obj_abs=0x... slot=0x..
```

## Key Unreal concepts used in Breeze

Breeze relies on UE runtime semantics directly:
- `OuterPrivate` walk: reconstructs ownership path (Package -> Class -> Function).
- `NamePrivate` decode: converts object `FName` to readable string.
- Function class heuristics: `Function` / `DelegateFunction` / `SparseDelegateFunction`.
- Native function pointer extraction: finds callable target in executable memory.

## UWorld chain workflow

`UE Root Chain (profile)` uses profile offsets (`ue_profile.ini`) to resolve runtime anchors like:
- `UWorld`
- `GameInstance`
- `LocalPlayers`
- `PlayerController`
- Pawn / movement-related objects

When resolution succeeds, `UWorld Explorer` can inspect these objects and related fields.

## Function Explorer workflow

`Function Explorer` loads `ue_function_map.txt` and provides:
- row browsing/search/filtering,
- jump to ASM Explorer by selected function RVA,
- function detail view with parsed argument/return info where available.

## Practical use cases

- Build a function name -> code offset catalog for a specific game build.
- Quickly locate native implementations of gameplay functions.
- Cross-check class/function ownership via outer-chain names.
- Prepare stable targets for ASM analysis, hooks, or cheat actions.

## Notes and limits

- Results depend on runtime memory layout and detected offsets.
- NamePool/offset mismatch can reduce name quality.
- Extended export mode may be much slower but can recover missed rows.
- Exported offsets are build-specific; regenerate after game updates.
