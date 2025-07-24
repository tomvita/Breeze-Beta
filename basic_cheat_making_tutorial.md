# Basic Cheat Making Tutorial

Welcome to Breeze! This tutorial will walk you through the fundamental process of creating a simple cheat. We'll find a value in a game, like health or currency, and create a cheat to modify it.

## The Goal

Our goal is to find a specific value in the game's memory and create a cheat to change it. This process involves:
1.  Searching for the value.
2.  Changing the value in-game.
3.  Searching again to narrow down the results.
4.  Identifying the correct memory address.
5.  Creating a cheat to write our desired value to that address.

## Step 1: Getting Started - The Search Manager

The heart of cheat creation in Breeze is the **Search Manager**.

1.  Launch your game.
2.  Launch Breeze.
3.  From the **Main Menu**, navigate to the **Search Manager** by pressing `L`.

The `Search Manager` is where you'll initiate and refine your memory searches.

## Step 2: The First Search - Finding Initial Candidates

Let's say we want to find our character's health, which is currently 100.

1.  In the `Search Manager`, press the **Simple Search** button.
2.  An on-screen keyboard will appear. Enter the value `100` and confirm.

Breeze will automatically search for `100` across common data types (integers and floats) and save the results into a new "candidate file". By default, this first file will be named `1`. You'll see this file appear in the `Search Manager`.

## Step 3: Refining the Search - Narrowing the List

A single search will likely return thousands of results. To find the *correct* address, we need to change the value in the game and search again.

1.  Go back to your game and take some damage. Let's say your health is now 80.
2.  Return to Breeze and the `Search Manager`.
3.  Press `Edit A` (`Right Stick Left`) and enter the new value, `80`.
4.  Now, with the previous candidate file highlighted, press `Continue search` (`Right Stick`).

Breeze will now filter the previous list of candidates, keeping only the addresses that *were* 100 and are *now* 80. A new file, named `1(00)`, will be created with these refined results. Each subsequent search will create a new file (e.g., `1(01)`, `1(02)`). You can rename these files at any time, and Breeze will continue the naming sequence from your new name (e.g., `MyHealthSearch(00)`).

Repeat this process:
*   Change the value in-game.
*   Return to Breeze and **Continue search** with the new value.

Do this until you have a small number of candidates. An ideal result is a list with fewer than 10 candidates. A list of 50-100 is still manageable, but will require more effort to narrow down.

**Pro Tip:** If your candidate list is still long, you can try to isolate the data type. Go to **Search Setup** (`Y`) and perform a **Continue Search** for a specific type, like `u32` or `f32`. This can quickly eliminate many incorrect candidates.

## Step 4: Identifying the Correct Address

Once you have a manageable list of candidates, it's time to pinpoint the exact address.

1.  In the `Search Manager`, press `L` to **Show Candidates**.
2.  This will take you to the **Candidate Menu**, showing the list of memory addresses that match your search.

From here, you have two main strategies:

### Strategy 1: Test Candidates One-by-One (For Short Lists)

This is the most straightforward method when you have only a handful of candidates.

1.  Select a candidate and press `Y` to **Edit Memory**. Change the value to something obvious, like `999`.
2.  Go back to the game. If your health is now 999, you've found the correct address!
3.  If not, return to Breeze, change the value back (or use the `Revert` button), and try the next candidate.

### Strategy 2: Batch-Testing (For Longer Lists)

If your list is in the 50-100 range, testing them one-by-one is impractical. For very large lists in the hundreds or thousands, this method should only be used as a last resort when you cannot refine the search further. In these cases, you can use the Candidate Menu's powerful batch tools to test many addresses at once.

1.  In the **Candidate Menu**, you can use buttons like `Freeze100`, `Set1000`, or `Inc1000`. For example, pressing `Set1000` will let you change the value of the next 1000 candidates simultaneously.
2.  Change them to a new value and return to the game. If you see the effect (e.g., your health changes), you know the correct address is within that batch.
3.  You can then undo the change (`Revert1000`) and test smaller batches to zero in on the correct address.

> **Warning: Use Batch-Testing with Caution!**
> Be very careful when batch-modifying **integer** values (`u8`, `s16`, `u32`, etc.). An integer candidate might actually be part of a pointer or another critical data structure. Hacking it can easily crash your game.
>
> It is generally much safer to batch-test **floating-point** values (`f32`, `f64`), as they are less likely to be critical to game stability.

Once you've found the correct address using either method, you're ready to create a cheat.

## Step 5: Creating a Cheat

Once you've confirmed the correct memory address, you can create a cheat for it.

1.  With the correct address highlighted in the candidate list, press `+` to **Add Bookmark**. Give it a descriptive name like "Player Health".
2.  Go to the **Bookmark Menu** (`Right Stick Up` from the `Main Menu`).
3.  Find your new "Player Health" bookmark.
4.  Press `Y + ZL` to **Bookmark to Cheat**.

This will automatically create a new cheat that writes a value to the health address. You can now go to the **Advance Cheat Menu** (`R` from `Main Menu`), find your new cheat, and edit it further if you wish (e.g., change the value it writes).

## What's Next? Pointers and ASM Cheats

You've created a basic cheat! **Be aware: this type of cheat is often very unstable.** The memory address you found is likely to change not just when you restart the game, but even after a loading screen or other major in-game event. This will cause your cheat to stop working or, in a worst-case scenario, crash the game.

To create reliable cheats that work consistently, you need to use more advanced techniques:

*   **Pointer Searching**: If a value's address changes, it's often pointed to by a more stable, static address. The **Jump Back Menu** helps you find these "pointer chains" to create cheats that work across game sessions. You can start a pointer search from the **Bookmark Menu**.
*   **ASM Cheats**: Instead of just changing a value, you can modify the game's actual code (in Assembly) to, for example, prevent health from ever decreasing. The **Asm Composer Menu** and the **Gen2 Menu** are powerful tools for this.

This tutorial covers the basics, but Breeze is a very powerful tool. Explore the menus, experiment, and check out the other documentation files to learn more!