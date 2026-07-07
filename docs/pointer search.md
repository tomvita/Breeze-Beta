# Pointer Search Method in Breeze

This document provides a primer for the pointer search method employed by Breeze.

## Jump Back Node

A jump back node consists of an address. For nodes with a depth greater than 0, this address will be a pointer with a list of offsets. This forms a pointer chain that leads to the target address.

## Jump Back

Jump back is the process of searching for a pointer that points to a node within a defined range. The distance between the pointer and the node is the offset. When this process is complete, we have the next level of nodes, and we have "jumped back" one level.

This process continues until a memory region called `main` is reached. The `main` region is invariant, so a good pointer chain can be established from `main` to the target.

## JumpBackMatch

`JumpBackMatch` is used when we have a previously found pointer chain that we believe may share nodes with a new chain leading to a new target.

Using this existing pointer chain, we create a forward chain originating from `main`. While the nodes in the jump back process are lost when the game state changes, the nodes in the forward chain will always be valid. On each node, we create a list of offsets that will lead back to `main`.

`JumpBackMatch` attempts to find forward nodes that are within range of the jump back nodes. By linking them, we create a full pointer chain from `main` to the target. Using `JumpBackMatch` shortens the search process and can produce higher quality results.

## Workflow Overview: Step-by-Step

Here is the complete workflow to perform a pointer search in Breeze, starting from finding a target address:

1. **Initiate from Memory Explorer**: Find the target memory address (e.g., Player HP or dynamic value). Inside the **Memory Explorer**, press the **JumpBack** button (`ZR + Y`) to start the pointer search.
2. **Name the Search**: Enter a name/label for the search when prompted (e.g., `Energy`). This name acts as the label for any bookmarks created and added by this process.
3. **Configure Search Parameters**: Setup parameters (such as `search_range`, `last_range`, and `num_offsets`) based on the game's architecture.
4. **Run the JumpBack Search**:
   - Use the **Start** (`L`) button and the **next depth** (`R`) button to climb back through pointer levels.
   - **Start is optional**: You can skip pressing `Start` directly, as pressing `next depth` will automatically perform the start operation if it has not been done yet.
   - **Advantage of manual Start**: Running `Start` manually allows you to use the **Analyse** (`Y`) button to look at intermediate results (such as offset candidates) before advancing.
   - **Analysing Depth 0**: Using `Analyse` at depth 0 is extremely useful. If you have already examined the assembly instructions accessing that memory in a debugger or from ASM Explorer (e.g., `[x0, #offset]`), you might already know what the correct offset is. The intermediate results analysis lets you inspect the candidate list at depth 0 to see if your expected offset is present.
   - **Delete Offset**: When analysing a node, you can use the **Delete Offset** (`-` button) to manually delete any offsets that you know are incorrect or not good, allowing you to prune the search space early and focus on valid paths.
5. **View and Resume**:
   - Continue using `next depth` until you are satisfied with the number of bookmarks added.
   - At any time, you can go to the **Bookmark Menu** to inspect the found pointer chains, and then come back to the **JumpBack Menu** to continue the search.
6. **Testing and Verification**:
   > [!IMPORTANT]
   > Discovered pointer chains are only **candidates** until further verification. You must play the game and restart it a few times to be certain these pointer chains remain valid, reliable, and point to the correct values across game sessions.
   - **Alternative verification**: You can manually walk the chain and inspect the managed objects at each level using the **Class field** button (`Y + ZR + ZL`) in the Memory Explorer.

## Search Settings & Parameters

When configuring a pointer search (climbing up the chain from a dynamic target address to the static `main` module), three key settings dictate the search limits, resource usage, and result filtering:

### `search_range`
* **What it does**: The maximum offset allowed between a node address and a candidate source pointer on each hop up the chain.
* **Tuning**: Checked on every depth step. If any struct or class along the path is larger than `search_range`, the chain will break. For Unity (IL2CPP) and Unreal Engine games, a wider range of `0x2000` to `0x10000` (or more) is recommended to prevent chains from breaking on large objects.

### `last_range`
* **What it does**: The maximum offset allowed for the final hop from the static address in `main` into the first heap node.
* **Tuning**: This is checked only when a candidate source pointer is found in the `main` module. If the offset is within `last_range`, the pointer chain is recorded as a bookmark; otherwise, it is discarded. On Unity (IL2CPP) games, this should typically not be set below `0xC0` to account for static-fields offsets (e.g., `0xA8`, `0xB8`, `0xC0`).

### `num_offsets`
* **What it does**: The number of candidate source pointers per node that are kept when moving to the next search depth.
* **Unity & Unreal Engine Recommendation**: Setting `num_offsets=1` is particularly effective when dealing with managed fields inside managed objects, which are highly prevalent in Unity and Unreal Engine games. Because managed object references usually point directly to the start of the object, the closest candidate (offset 0 or very small) is almost always the correct path. Setting `num_offsets=1` keeps candidate growth linear rather than exponential, allowing you to use a wide `search_range` without running out of memory.

