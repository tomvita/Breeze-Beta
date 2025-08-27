# Advanced Cheat Making Tutorial

This guide provides a comprehensive tutorial on creating advanced cheats in Breeze, covering two primary techniques: creating powerful **Assembly (ASM) Cheats** to modify game logic directly, and robust **Pointer Cheats** to handle dynamic memory addresses.

> **Note**: This tutorial covers advanced ASM cheat creation. If you are new to cheat making, it is highly recommended to start with the [**Basic Cheat Making Tutorial**](../basic_cheat_making_tutorial.md) first.

## Quick Navigation
- [Part 1: Making ASM Cheats](#part-1-making-asm-cheats)
- [Part 2: Creating Pointer Cheats](#part-2-creating-pointer-cheats)

## Part 1: Making ASM Cheats

ASM cheats modify the game's own code to achieve results, making them incredibly powerful. The basic process involves finding an instruction to change and then writing your own ASM code to replace it.

### The Basic Workflow

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
    *   **If no unique hook can be found**: A simple cheat is not possible. You must use the advanced conditional logic techniques described in the "Advanced Technique - Automated Cheat Generation" section.

### Step 2: Writing the Cheat

Once you have a unique hook, you can write the code to modify the game's behavior.

1.  **Analyze the Hook**: From the [**Gen2 Menu**](menu.md#gen2-menu), go to the [**ASM Explorer Menu**](menu.md#asm-explorer-menu) to examine the unique instruction you found. It is crucial to understand what the code does before you attempt to modify it.

2.  **Create the Cheat**: Once you have decided on the exact instruction to hook, press the `Add ASM` button directly from the [**ASM Explorer Menu**](menu.md#asm-explorer-menu). This creates a new cheat pre-configured with the necessary hook information.

3.  **Write Your Code in the Asm Composer**:
    *   Navigate to your new cheat in the [**Advance Cheat Menu**](menu.md#advance-cheat-menu) and open it in the [**Asm Composer Menu**](menu.md#asm-composer-menu) by `Edit Cheat` then `Asm Composer`.
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

6.  **Using the "Easy Template"**: For any simple `ld` (load) or `st` (store) instruction, you can use the "Easy Template" in the **Asm Composer Menu** to automatically generate a complete hack. This is a quick way to create cheats without manually writing the assembly.

### Step 3: Testing

With the cheat active, go back to the game and test if your changes have the desired effect. You can place watch on instruction in the cheat to debug it.

### Automated Cheat Generation

When you cannot find a simple unique hook, you must use conditional logic. The [**Gen2 Extra Menu**](menu.md#gen2-extra-menu) offers powerful tools to automate this process.

### Theory

Instead of relying on a single instruction, you can create a cheat that only activates when a specific *sequence* of code calls occurs. This is done by watching not just the `x30` register (the return address), but also a snapshot of the call stack.

Before generating a full script, you can quickly test a potential hook using the [`X30_match`](menu.md#gen2-menu) button in the Gen2 Menu. This provides a less robust but fast way to check if a particular `x30` value is unique enough for your needs. If it works, it's a good indicator that a more complex script generated by `make match 1` will also be successful.

The `make match 1` and `make match all` buttons will then generate a script that checks these conditions before running your code.

### Step-by-step Flow

1.  **Watch Memory**: Start a watch on a memory address from the **Memory Explorer**.
2.  **Configure and Capture Data**: In the **Gen2 Menu**, set the `Next stack_check` value. A value of `0` captures only the `x30` register, while `1` to `5` also captures that many values from the top of the stack. Execute the watch, perform the target action in-game, and detach.
3.  **Analyze and Generate**: In the **Gen2 Extra Menu**, analyze the captured data to find a reliable pattern. Once you select a promising data line, press `make match 1` or `make match all` to automatically generate the complete ASM cheat script.
    *   It is best to start with **`make match all`**. If it successfully isolates the target, you can then check if the less restrictive **`make match 1`** is sufficient.
    *   If `make match all` cannot isolate the target, then `make match 1` will also fail.
    *   Note that `make match all` can sometimes fail to get a hit if one of the captured values is not consistent between game runs.
4.  **Test The Cheat**: Test the newly generated conditional cheat in-game. This automated process can create highly precise cheats that would be very tedious to write manually.

## Part 2: Creating Pointer Cheats

When a value's memory address changes every time you restart the game or even during gameplay, a simple static cheat won't work. This is where pointer cheats are essential. A pointer is a memory address that stores another memory address. By finding a stable "pointer chain," you can reliably locate a dynamic value.

### Step 1: Find the Initial Address

First, you need to find the memory address of the value you want to modify, just like in the [**Basic Cheat Making Tutorial**](../basic_cheat_making_tutorial.md).

1.  Use the [**Search Manager Menu**](menu.md#search-manager-menu) to find the address of your target value.
2.  Once you have a single candidate, add it to your bookmarks from the [**Candidate Menu**](menu.md#candidate-menu).

### Step 2: Use the Jump Back Menu to Find Pointers

The [**Jump Back Menu**](menu.md#jump-back-menu) is Breeze's powerful tool for discovering pointer chains. It works by building a map of "nodes," where each node represents a potential step in the pointer chain.

> **Understanding Nodes and Pointer Chains**
> *   **Depth 0**: The process starts with your initial bookmarked address. This is the first node, with an empty offset chain.
> *   **Increasing Depth**: When you perform a `Start` or `next depth` search, Breeze looks for pointers pointing to the previous set of nodes. Each pointer it finds creates a *new* node at the next depth.
> *   **Offset Chains**: Each new node contains the address of the pointer itself, plus the chain of offsets required to get from that pointer back to your original target address. The goal is to find a node whose address is in a static memory region (like `main`), giving you a complete, stable pointer chain.

1.  Go to the [**Bookmark Menu**](menu.md#bookmark-menu) and highlight the bookmark you just created.
2.  Press `X + ZL` to start a **Pointer Search** for that address. This will take you to the **Jump Back Menu**.
3.  Press `L` to **Start** the search. Breeze will scan the memory for any addresses that point to your bookmarked address.
4.  The results will be displayed as a list of potential pointers, showing the offset from the base address.

> **Pro-Tip: Finding the First Offset**: Often, the first offset in a pointer chain is visible in the instruction that accesses your target value. Before starting a blind pointer search, use the [**Gen2 Menu**](menu.md#gen2-menu) to watch the memory address. The instruction that reads/writes the value (e.g., `LDR W8, [X0, #0x40]`) will show you the base register (`X0`) and the immediate offset (`0x40`). This tells you that the value is at `[address in X0] + 0x40`. The address in `X0` is your next target, and `0x40` is your first offset. This can significantly speed up finding the pointer chain.
5.  To find a multi-level pointer chain, press `R` for **next depth**. This takes the pointers found in the previous step and searches for pointers that point to *them*, effectively moving one level up the chain.
6.  Repeat the **next depth** search until you find a stable pointer path that originates from a static part of the game's memory (usually `main`). When a candidate is found that originates from `main`, a bookmark with the complete pointer chain is automatically created.

> **Pointer Search Strategy & Key Controls**
> The `Jump Back Menu` has many options, but a successful search primarily relies on a few key controls:
> *   **Core Actions**: `Start` and `next depth` are the main buttons you will use to initiate and build your pointer chain.
> *   **Essential Parameters**: To manage memory usage and refine results, focus on `num_offsets=` (limits candidates for the next depth) and `search_range=` (defines the maximum valid offset). The `search_depth=` and `goto depth` buttons are optional for more automated searching.
> *   **Validation is Key**: Remember that every pointer found is only a *candidate*. It was valid at the moment it was found but may become invalid later. You must test the final pointer chain by restarting the game to ensure it is stable.

For a detailed explanation of all the options and parameters in the Jump Back Menu, please refer to the [**Jump Back Menu**](menu.md#jump-back-menu) section in the menu documentation.

### Step 3: Evaluate and Choose a bookmark with reliable Pointer Chains

After running the `next depth` search, the bookmarks generated in the [**Bookmark Menu**](menu.md#bookmark-menu) represent potential pointer chains. When viewing the bookmarks in the Bookmark Menu, Breeze constantly evaluates *only the visible* pointer chains, attempting to resolve them, read the resulting memory address, and display its current value. This real-time feedback helps you identify which visible bookmarks are still valid.

To refine your bookmark list and eliminate bookmarks with unreliable pointer chains, the following methods operate on *all* bookmarks within the currently loaded bookmark file:

1.  **Examine Bookmarks**: Go to the [**Bookmark Menu**](menu.md#bookmark-menu). Observe the values displayed for each bookmark. A working pointer chain should consistently show the expected value of your target (e.g., your character's health). If a chain cannot be resolved, it may show an error or an unexpected value.

2.  **Eliminate Bad Bookmarks**:
    *   **By Value (`SearchBookmark`)**: If you know the exact value your target should have, you can use the `SearchBookmark` button (`Y + ZR` in the Bookmark Menu). This will scan the current bookmark file, filter it, and save *only* those bookmarks whose resolved address currently holds the desired value to a designated bookmark file.
    *   **By Validity (`Perform Clean up`)**: The `Perform Clean up` button (`- + ZL` in the Bookmark Menu) will remove all bookmarks whose pointer chains cannot be fully resolved or lead to invalid memory addresses. This is crucial for removing broken or unstable pointers that consume memory without providing useful results.

### Step 4: Create and Test the Pointer Cheat

Once you have identified a stable and reliable pointer chain (or a small set of highly probable ones), you can create a cheat from it.

1.  In the **Bookmark Menu**, select the promising pointer bookmark.
2.  Press `Y + ZL` to **Bookmark to Cheat**.
3.  The new cheat will appear in the [**Advance Cheat Menu**](menu.md#advance-cheat-menu).

4.  **Test the Cheat**: Restart your game and test the newly created cheat. A stable pointer cheat should consistently work across game sessions and reloads. If it doesn't, return to the Jump Back Menu or Bookmark Menu to continue refining your search.
