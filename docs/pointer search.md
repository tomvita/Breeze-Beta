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
