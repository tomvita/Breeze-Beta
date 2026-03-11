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
