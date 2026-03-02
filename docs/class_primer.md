# Class Primer

## What is a class?
A **class** is a blueprint for creating objects.

- It defines **data** (what the object stores).
- It defines **behavior** (what the object can do).

In C#/Unity terms, a class is a type like `Player`, `Inventory`, or `EnemyAI`.

## Properties vs fields vs methods

### Fields
Fields are raw storage inside an object.

```csharp
public int health;
```

### Properties
Properties are controlled accessors around data.

```csharp
public int Health { get; private set; }
```

They can validate, compute, or trigger side effects.

### Methods
Methods are functions attached to a class.

```csharp
public void TakeDamage(int amount) { ... }
```

They operate on the object state.

## What is an instance of a class?
An **instance** is one concrete object created from a class.

- Class: `Player`
- Instances: `player1`, `player2`, etc.

Each instance has its own per-object data (instance fields), while static data is shared by all instances.

## Theory and practice

### Theory
Object-oriented design uses classes to model domain concepts and to keep related data/logic together.

Goals:
- Encapsulation (hide internals behind APIs)
- Reuse (base classes, composition)
- Maintainability (clear boundaries)

### Practice
Real codebases are messy:
- Legacy code remains after features change.
- Generated code adds boilerplate.
- Reflection/serialization requires members that look unused.
- Platform/build variants keep code only used in some targets.

So production projects often have far more definitions than the currently active path uses.

## Why are many things defined but never used?
Common reasons:

1. Feature flags: code is only used when a runtime/config flag is enabled.
2. Future or deprecated features: old definitions left in place for compatibility.
3. Generated bindings/models: tools emit classes broadly; only some are used.
4. Reflection/DI/serialization: usage is indirect, so static analysis marks as unused.
5. Inheritance contracts: overrides/placeholders required by a base type or interface.
6. Build differences: used on other platforms, game versions, or debug-only flows.

In reverse-engineered dumps, this effect is amplified: you see *everything* the metadata declares, not just hot runtime paths.

## Why are there so many empty fields?
“Empty field” usually means a field exists in layout/metadata but has no meaningful value in the current object.

Typical causes:

1. Default values: references default to `null`, numbers to `0`, bool to `false`.
2. Optional feature state: field is populated only in specific game modes/events.
3. Sparse containers: arrays/lists with capacity larger than active element count.
4. Base-class baggage: derived classes inherit fields they may never use.
5. Alignment/padding/reserved slots: memory layout includes gaps for alignment/versioning.
6. Static vs instance confusion: static fields are not per-instance data.
7. Uninitialized at capture time: object observed before setup or after partial teardown.

## Quick mental model when inspecting dumps

1. Treat class definition as **possible structure**, not guaranteed live usage.
2. Distinguish **declared fields** from **currently populated fields**.
3. Validate with runtime evidence:
- non-null pointers
- changing values over time
- references from active objects
4. Prefer “used now” over “exists in metadata.”

## Practical approach (game hacking / reverse engineering)

Use this loop when you want to find real, useful instances:

1. Start from what you can see in-game.
- HP changing
- ammo count
- menu selection
- cooldown timers

2. Search memory for that visible value/state.
- Do repeated scans while the value changes in-game.
- Narrow candidates until you get a small set.

3. Watch instructions that read/write the target value.
- Find the method/function touching that address.
- This often leads you to the owning class context.

4. Follow pointers/owners back to class instances.
- Identify which object base holds the field.
- Confirm by checking nearby fields for expected patterns.

5. Navigate outward from that class to discover more.
- Look at referenced objects (inventory, stats, weapon, controller, etc.).
- Map relationships between classes and instances.

6. Prioritize specific promising instances.
- Stable across scenes/reloads
- Clearly tied to player-owned state
- Writable without immediate crash/desync

7. Validate before trusting.
- Freeze/test a value and observe game behavior.
- Reopen/restart and check whether the same path still resolves.

## Minimal example

```csharp
class Player {
    public string Name;               // often set
    public Inventory Inventory;       // may stay null early
    public QuestState[] QuestSlots;   // many empty entries
    public int DebugBuildOnlyFlag;    // present, maybe never used in release
}
```

All four fields can be valid to define, even if only one is populated in your current run.
