# Dynamic Modules

Dynamic modules are blocks of code and data that are loaded into memory by the game's own code, rather than by the operating system's loader. This is common in games that use engines like Unity or Unreal Engine.

## Key Characteristics

- **Runtime Loading:** They are loaded dynamically while the game is running.
- **Variable Address:** Because they are not loaded by the OS, their base address in memory can change each time they are loaded, or even during gameplay. This makes creating stable cheats a challenge.
- **Pointer Access:** To access code or data within a dynamic module, you must use pointers. You cannot rely on static addresses.

## Handling Dynamic Modules in Breeze

To create cheats that work reliably with dynamic modules, Breeze and the Atmosphere CheatVM use a shared mechanism involving the `R1` register.

The core solution is to place cheat code that sets up the `R1` register inside the **master code** section (`{}`). A type 0 code, which has the format `main+R1`, is used for this purpose. By default, `R1` is 0, making the address equivalent to `main`.

When code to calculate and set `R1` is placed in the master code, two things happen:
1.  **CheatVM** executes this code, correctly setting up `R1` with the offset of the dynamic module. This ensures that subsequent cheat codes that rely on `R1` will point to the correct memory locations.
2.  **Breeze** recognizes this `R1` setup in the master code. This allows it to correctly interpret and display addresses for cheats targeting the dynamic module, and enables other features like the memory explorer to function correctly.

This cooperation is essential: the code that sets up `R1` must be in the master code for both systems to work together seamlessly.

### Automated Cheat Creation

Breeze further simplifies this process. When you are in the **ASM Explorer** and use the **Add to Cheat** button on game code that resides in a dynamic module, Breeze automatically generates the necessary master code for you.

This generated master code sets up the `R1` register to hold the offset of the dynamic module. The relationship is as follows:

`Main + R1 = module Main`

This means that `R1` stores the difference between the game's main static base address and the dynamic module's base address. By doing this, all subsequent cheat codes can use `R1` to reliably calculate the correct memory addresses within the dynamic module, making cheat creation seamless.