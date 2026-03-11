# Unreal Primer

This primer explains the Unreal Engine concepts used by Breeze's Unreal tooling.

## Scope
- Focus: runtime object model in UE4/UE5 (`UObject`, `UClass`, `UFunction`, `FNamePool`).
- Context: reverse engineering a live game process, not compiling UE source.

## Core runtime objects

### `UObject`
Base runtime type for most reflected UE objects. Important fields (conceptual names):
- `ClassPrivate`: points to the object's `UClass` descriptor.
- `NamePrivate`: `FName` identity (index/number into NamePool-based naming).
- `OuterPrivate`: ownership parent in the object tree.

### `UClass`
Runtime class descriptor. It describes fields, functions, and inheritance for a type.

Mental model:
- C++ class metadata + runtime reflection descriptor.
- `UClass` objects are also `UObject` instances.

### `UFunction`
Runtime function descriptor object owned by a class.

A `UFunction` typically gives you:
- Short function name (`NamePrivate`).
- Owning object/class via `OuterPrivate` chain.
- Native function pointer (for native functions), which points into executable code (`RX` memory).

## Ownership: `OuterPrivate`

`OuterPrivate` defines containment/ownership hierarchy, not inheritance.

Example hierarchy:
1. Package: `/Game/Maps/MyLevel`
2. Class object: `Actor` (outer = Package)
3. Function object: `GetVelocity` (outer = `Actor`)

Walking `OuterPrivate` repeatedly gives a qualified path like:
- `Package.Class.Function`

Terminology note:
- Unreal has explicit `Outer`.
- "Inner" is informal shorthand for "object contained by an outer".

## Names: `FName`, `NamePrivate`, and NamePool

UE stores names in a global pool (`FNamePool`). Objects usually store compact `FName` references instead of full strings.

Practical implication:
- To show readable names, tools must decode `NamePrivate` through the NamePool.
- If NamePool offsets are wrong, names decode as garbage or fail.

## Function-class naming

When inspecting arbitrary heap objects, function descriptors are commonly identified by class names like:
- `Function`
- `DelegateFunction`
- `SparseDelegateFunction`

These class names are useful heuristics when filtering candidates.

## Native function pointer concept

For native `UFunction`s, a field inside the function object points to executable machine code.

Reverse engineering use:
- Read this native pointer.
- Convert to main-module-relative offset (`main+0x...`) when possible.
- Build a stable name-to-code map for analysis/patching.

## Pawn chain in Breeze

### What is the Pawn?

In Unreal, a Pawn (`APawn`) is the actor currently possessed by a player or AI. It is the physical in-world entity being controlled (character body, vehicle, etc.). A common subclass is `ACharacter`, which adds character-specific movement/collision systems.

In Breeze logic (`source/unreal.cpp`), pawn candidates are scored with positive/negative heuristics (for example, class-name signals like `"character"`/`"pawn"` vs obvious non-pawn signals).

### Pointer chain to reach Pawn

The Pawn is resolved by walking a pointer chain from a static world pointer:

```text
GWorld pointer (static slot in .bss)
  -> UWorld object
      -> [+OwningGameInstance] UGameInstance
          -> [+LocalPlayers] TArray<ULocalPlayer*>
              -> [0] ULocalPlayer
                  -> [+PlayerController] APlayerController
                      -> [+AcknowledgedPawn] APawn
```

Each `+offset` is build-dependent and discovered/stored by profile workflow (`ue_profile.ini`).

### Why AcknowledgedPawn

Breeze uses `APlayerController -> AcknowledgedPawn` as the primary controlled-pawn target. The exact offset varies by engine/game build, so it scans a candidate offset list (defined in `source/unreal.cpp`) rather than assuming a single hardcoded value.

Example definition used by the scanner:

```cpp
static constexpr u32 kAcknowledgedPawnOffsets[] = {
    0x2E0, 0x2E8, 0x2F0, 0x2F8, 0x300, 0x308, 0x310,
    0x318, 0x320, 0x328, 0x330, 0x338, 0x340, 0x348, 0x350
};
```

### Validation heuristics (conceptual)

Pawn candidates are scored using multiple signals, including:

| Check | Score trend |
|---|---|
| Class name contains `pawn` or `character` | positive |
| Object name contains `pawn` / `character` / `player` | positive |
| Back-reference to owning `PlayerController` | positive |
| Valid movement-component-like pointer | positive |
| Class/name indicates non-pawn type (`texture`, `material`, `world`, etc.) | negative |

### After chain resolution

Once resolved, Breeze stores chain outputs (including pawn pointer) in the live UE chain state and exposes Explorer actions (such as Pawn bookmark shortcut and object-row scanning) for follow-up analysis.

## Terms at a glance
- `UObject`: base reflected object.
- `UClass`: reflected class descriptor.
- `UFunction`: reflected function descriptor (method metadata + native target pointer).
- `OuterPrivate`: ownership parent pointer.
- `NamePrivate`: object's `FName` identity.
- `FNamePool`: global name string storage/lookup backing `FName`.
- `RX region`: readable+executable memory, where native code lives.

## Why this matters for reverse engineering

These concepts let you move from anonymous pointers to meaningful symbols:
- Raw heap pointer -> object identity
- Object identity -> class/function name
- Function object -> native code address
- Address map -> practical hooks, breakpoints, and cheat workflows
