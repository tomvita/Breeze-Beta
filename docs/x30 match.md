# AArch64: Matching Return Addresses with X30

## The Role of the Link Register (X30)

When a function is called with the `BL` (Branch and Link) instruction, the CPU stores the **return address** in the `X30` register (also known as the Link Register). When the function completes, the `RET` instruction jumps to the address in `X30`, returning control to the caller.

However, if a function calls another function (a "non-leaf" function), it must first save `X30` to the stack. This is because the nested `BL` call will overwrite `X30` with a new return address.

## Where the Return Address Lives

- **Leaf Function** (does not call other functions): The return address stays in `X30`.
- **Non-Leaf Function** (calls other functions): The function prologue saves `X30` to the stack.
  ```arm
  STP X29, X30, [SP, #-16]!  // Save frame pointer (X29) and link register (X30)
  ```

> **Key Rule:** A function's return address is always in one of two places: `X30` or on the stack.

## Practical Use: Identifying Callers and Tracing Deep Code

Imagine a game where a single `updateHealth()` method is used by both `Hero` and `Enemy` objects. Setting a breakpoint on this method triggers for everyone. But what if you only want to find the code that updates the *hero's* health bar?

By inspecting the return address in `X30` (or on the stack), you can identify **who called** `updateHealth()`:
- If the return address points back to `updateHeroHealthBar()`, you've found the hero's call chain.
- If it points back to `updateEnemyHealthBar()`, it belongs to an enemy.

This allows you to "match" a generic function call to a specific context.

However, the call chain is often not direct. There may be many intermediate functions:
`updateHeroHealthBar()` → `animateBar()` → `calculatePercentage()` → `updateHealth()`

Furthermore, the function that *writes the value* might be even deeper. `updateHealth()` could call another function, like `setUnitPropertyValue()`, which is where the memory write actually happens. By repeatedly examining the call stack (`X30` and the stack itself) at each step, you can trace the execution flow from a high-level event (the health bar changing) all the way down to the specific instruction that modifies the value. This enables a far more precise hack or analysis.

## Why the Call Chain Gets Complicated and this method don't always work (optional reading if you are curious)

In a perfect world, the stack would give you a clean backtrace. But compiler optimizations can muddy the waters.

### Tail Call Optimization
If `foo()` calls `bar()` as its very last action, the compiler can use a `B` (Branch) instead of `BL`. `foo()` is removed from the call stack, and `bar()` returns directly to `foo()`'s caller. The backtrace appears as `main` → `bar`, completely hiding `foo()`.

### Inlining
The compiler may copy `bar()`'s code directly into `foo()` instead of making a call. `bar()` ceases to exist as a separate function, so it never appears in the backtrace.

### Hubs and Trampolines
Sometimes a function returns to a central "hub" or "trampoline" instead of its direct caller. This is common in event systems. The backtrace might show `main` → `library_function` → `event_hub`, which may not be the direct sequence you expected.

## Summary

- **`X30`** holds the return address for the current function.
- The **stack** stores the return addresses for previous functions in the call chain.
- The call chain can be broken or altered by:
  - **Tail Call Optimization:** Skips a stack frame.
  - **Inlining:** Removes a function call entirely.
  - **Hubs/Trampolines:** Add extra, indirect frames to the stack.

## Analogy: A Trail of Breadcrumbs

- **`X30`:** The breadcrumb that takes you one step back.
- **The Stack:** The full trail of breadcrumbs showing where you've been.
- **Tail Call:** A bird snatches your breadcrumb before you can drop it.
- **Inlining:** You decide not to drop a breadcrumb because you're just taking one small step.
- **Hub/Trampoline:** Following a different trail of breadcrumbs that leads back to your original path eventually.

