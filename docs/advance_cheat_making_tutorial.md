# Making ASM Cheats: A Tutorial

This guide provides a comprehensive tutorial on creating Assembly (ASM) cheats in Breeze. It covers the fundamental workflow of finding a hook, writing code, and testing your cheat. It also introduces powerful automated tools for advanced and complex scenarios.

> **Note**: This tutorial covers advanced ASM cheat creation. If you are new to cheat making, it is highly recommended to start with the [**Basic Cheat Making Tutorial**](../basic_cheat_making_tutorial.md) first.

## Part 1: The Basic Workflow

ASM cheats modify the game's own code to achieve results, making them incredibly powerful. The basic process involves finding an instruction to change and then writing your own ASM code to replace it.

### Step 1: Finding a Unique Hook

The first and most critical part of making an ASM cheat is finding a "unique hook"—a piece of code that *only* affects your target and nothing else. This is an iterative process.

1.  **Capture Potential Hooks**: The first step is to get a list of all code that accesses the value you want to modify.
    *   Use the [**Search Manager Menu**](menu.md#search-manager-menu) to find the memory address of your target value (e.g., a character's health).
    *   From the [**Memory Explorer Menu**](menu.md#memory-explorer-menu), set a hardware watchpoint on that address, which will take you to the [**Gen2 Menu**](menu.md#gen2-menu).
    *   Perform an action in-game that changes the value. The Gen2 Menu will now display a list of all code locations that accessed the address. Use the `Save as candidates` button to save this list. This file contains all your potential hooks.

2.  **Verify the Hook's Uniqueness**: A non-unique hook will cause unintended side effects (e.g., making enemies invincible along with the player). The verification process is iterative: you must test potential hooks from your list until you find one that is unique.
    *   **The Iterative Method**: From your list of potential hooks, select one and set a new watchpoint directly on that *instruction's address*. Return to the game and perform various actions. If the instruction is only executed when your target is affected, it is unique. If not, you must test the next instruction in the list.
    *   **Accelerating the Process**: If you have a very long list of hooks, the one-by-one method can be slow. To accelerate it, you can use the [**Search Manager Menu**](menu.md#search-manager-menu) to compare your saved list of hooks against a new list captured from a non-target (e.g., an enemy). This allows you to quickly filter out a large number of common, non-unique instructions.

3.  **The Two Paths**:
    *   **If a unique hook is found**: You can proceed with a simple cheat. Continue to Step 2.
    *   **If no unique hook can be found**: A simple cheat is not possible. You must use the advanced conditional logic techniques described in Part 2.

### Step 2: Writing the Cheat

Once you have a unique hook, you can write the code to modify the game's behavior.

1.  **Analyze the Hook**: From the [**Gen2 Menu**](menu.md#gen2-menu), go to the [**ASM Explorer Menu**](menu.md#asm-explorer-menu) to examine the unique instruction you found. It is crucial to understand what the code does before you attempt to modify it.

2.  **Create the Cheat**: Once you have decided on the exact instruction to hook, press the `Add ASM` button directly from the [**Edit Cheat Menu**](menu.md#edit-cheat-menu). This creates a new cheat pre-configured with the necessary hook information.

3.  **Write Your Code in the Asm Composer**:
    *   Navigate to your new cheat in the [**Advance Cheat Menu**](menu.md#advance-cheat-menu) and open it in the [**Asm Composer Menu**](menu.md#asm-composer-menu).
    *   Use the `Original` button to insert the original game code. This is essential for reference.
    *   The Asm Composer has many tools to help, including the powerful `data_value` button, which acts as a multi-purpose templating tool.

4.  **Using the `data_value` Template**:
    *   If you use `data_value` on a blank line in an empty file, it will generate a full, basic script for you, providing an excellent starting point.
    *   If you want to load a value from a nearby memory address (e.g., a "max health" value) and write it to your target, you can first use the `Original` button, then press `data_value` to generate a template for that specific action.
    *   Pressing `data_value` repeatedly will add stack-push/restore code to preserve registers if they are needed.

#### Example: Handling Hazards with `data_value`

A frequent challenge is dealing with instructions that modify the registers they use (a "hazard"). The `data_value` template intelligently handles these situations.

*   **Hazardous Hook**: `ldr w0, [x0, #0x38]`
    This instruction corrupts the `x0` register. The template generates safe code using a temporary register (`s0`) to prevent a crash:
    ```asm
    ldr s0, a
    str s0, [x0, #0x38]
    ldr w0, [x0, #0x38]
    return:
    b code1+4
    a:.word 100
    ```

*   **Non-Hazardous Hook**: `ldr w2, [x0, #0x38]`
    Here, the template generates simpler, more direct code:
    ```asm
    ldr w2, a
    str w2, [x0, #0x38]
    return:
    b code1+4
    a:.word 100
    ```

5.  **Save and Assemble**: Use the `Save & Back` button from the Asm Composer. Back in the [**Edit Cheat Menu**](menu.md#edit-cheat-menu), use the `Add ASM` button to generate the final cheat code, then `Save` to return to the cheat list.

### Step 3: Testing

With the cheat active, go back to the game and test if your changes have the desired effect. Debugging may involve returning to the Asm Composer to tweak your code.

## Part 2: Advanced Technique - Automated Cheat Generation

When you cannot find a simple unique hook, you must use conditional logic. The [**Gen2 Extra Menu**](menu.md#gen2-extra-menu) offers powerful tools to automate this process.

### Theory

Instead of relying on a single instruction, you can create a cheat that only activates when a specific *sequence* of code calls occurs. This is done by watching not just the `x30` register (the return address), but also a snapshot of the call stack. The `make match 1` and `make match all` buttons will then generate a script that checks these conditions before running your code.

### Step-by-step Flow

1.  **Watch Memory**: Start a watch on a memory address from the **Memory Explorer**.
2.  **Configure and Capture Data**: In the **Gen2 Menu**, set the `Next stack_check` value. A value of `0` captures only the `x30` register, while `1` to `5` also captures that many values from the top of the stack. Execute the watch, perform the target action in-game, and detach.
3.  **Analyze and Generate**: In the **Gen2 Extra Menu**, analyze the captured data to find a reliable pattern. Once you select a promising data line, press `make match 1` or `make match all` to automatically generate the complete ASM cheat script.
4.  **Test The Cheat**: Test the newly generated conditional cheat in-game. This automated process can create highly precise cheats that would be very tedious to write manually.
