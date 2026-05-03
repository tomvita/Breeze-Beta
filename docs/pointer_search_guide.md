# Pointer Search Guide

This guide walks you through using the **Jump Back Menu** in Breeze to find stable pointer chains for dynamic memory addresses, and how to confirm those chains survive a game restart.

For background on what a pointer chain is and what `main`, "node", and `JumpBackMatch` mean, read [pointer search.md](pointer%20search.md) first.

---

## 1. Setting Up the Search

Before opening the Jump Back Menu you need a **target bookmark** — a bookmark on the dynamic address you want to track (Player HP, Gold, etc.).

1. Use a normal value search to find the address of the value you care about.
2. Add the address to a bookmark file (from the search results, or via `+` in the Memory Explorer).
3. Confirm the bookmark resolves to the right value (Field View / Edit Memory).
4. With the bookmark selected, press **Pointer Search** (`X + ZL`) in the Bookmark Menu. This seeds the Jump Back search with that bookmark as the initial target node.

You can also enter directly from the Memory Explorer with **JumpBack** (`Y + ZR`) for the address under the cursor.

> Tip: To find a shared parent for several related values (e.g. HP, MP, Stamina that live in the same struct), bookmark all of them in the same file before pressing **Pointer Search**. They will all be seeded as initial nodes and the search will look for pointers reaching the group.

---

## 2. Entering the Jump Back Menu

Three entry points:

| From | Button | Use when |
|---|---|---|
| Bookmark Menu | **Pointer Search** (`X + ZL`) | Most common — start a fresh search from a target bookmark. |
| Memory Explorer | **JumpBack** (`Y + ZR`) | Start a search for the address under the cursor. |
| Bookmark Menu | **JumpBackMatch** (`B + ZL`) | Reuse a previously discovered pointer chain to assist a new search. |

Once inside, the left panel shows the current node list. The first time you arrive nothing has been computed — press **Start** (`L`) to begin.

---

## 3. Search Parameters

Five parameters control the search:

| Parameter | Default | What it does |
|---|---|---|
| `search_range`   | `0x800`  | Maximum offset between a node and a candidate source pointer during the climb up the chain. |
| `last_range`     | `0x100`  | Maximum offset of the final hop **into `main`**. A chain only becomes a recorded bookmark if the offset from the static slot in `main` to the heap node it points at is within this value. |
| `num_offsets`    | `2`      | How many candidate source pointers per node are kept when stepping to the next depth. |
| `Max per node`   | `10000`  | Caps how many sources any single node can spawn — the default is effectively "no cap"; lower it if one heavily-referenced node is flooding the result set. |
| `search_depth`   | `4`      | Maximum depth that **Goto depth** will iterate to automatically. |

---

## 4. Picking Ranges

The two range parameters do **different jobs** at different points in the chain. Getting them mixed up is the most common reason a search produces no useful bookmarks.

### `search_range` — the per-hop range during the climb

`search_range` is checked on **every** `next depth` step. As the search climbs from your dynamic target up toward `main`, each hop must satisfy `node_addr - source_ptr <= search_range`. If any struct along the chain is larger than `search_range`, the chain breaks at that hop and you never reach `main`.

Because the chain is built bottom-up you don't yet know which depth the largest struct sits at, so `search_range` has to bracket the worst case across all hops.

| Game type | Recommended `search_range` |
|---|---|
| Small game with simple struct layout | `0x800` (default) – `0x2000` |
| Unity (IL2CPP) games | `0x2000`–`0x10000` |
| Unreal Engine | `0x2000`–`0x10000` |
| Open-world / large monolithic structs / ECS arrays | `0x10000`–`0x40000`+ |

Rule of thumb: start at `0x2000`. If `next depth` finds no candidates for some node, raise the range. If candidates explode, lower `num_offsets` first (to `1`) before lowering the range.

### Pairing `search_range` with `num_offsets`

A wide `search_range` only blows up the search when `num_offsets` is also high. The two are designed to be tuned together:

- Wide `search_range` + `num_offsets = 1` -> **safe**. You scan a wide window but keep only the single closest source per node, so the candidate list grows roughly 1x per depth.
- Wide `search_range` + `num_offsets = 3` (or more) -> N^depth growth, runs out of memory after a few hops.

This is why a large range is affordable on Unity / IL2CPP games: managed object references always point to the very start of the target object, so the closest candidate that `num_offsets = 1` keeps is almost always the correct one. The wide range just makes sure you don't miss a chain that happens to pass through a large class struct or static-fields block at some unknown depth.

### `last_range` — the hop from `main` into the heap

`last_range` is checked **only** when a candidate source pointer is found inside the `main` module. At that moment, Breeze decides whether to record a bookmark by checking the offset from the static slot in `main` to the heap node it points at: if that offset is within `last_range`, the bookmark is written; otherwise it is silently dropped even though the chain successfully reached `main`.

So `last_range` is **not** about the bottom of the chain near your dynamic target — it is about the **top**, the single hop from a static address into the first heap node.

#### Sizing `last_range` on Unity (IL2CPP)

On Unity, the chain almost always lands in `main` at the `Il2CppClass -> static_fields` slot, whose offset depends on the IL2CPP metadata version of the game:

| IL2CPP metadata version | `static_fields` offset |
|---|---|
| 1–24  | `0xA8` |
| 25–28 | `0xB8` |
| 29+   | `0xC0` |

Adjacent class-level slots at `0xA0`, `0xB0`, `0xC8` and similar also appear in real games. The default `last_range = 0x100` is chosen to sit just above `0xC0` so it covers every known static-fields offset with a small margin.

> Do **not** drop `last_range` below `0xC0` on a Unity game. The static-fields hop will be skipped and you will get zero bookmarks even though the chain visibly reaches `main`.

For locking onto the static-fields hop specifically, use the **do B8 scan** button in the Jump Back menu — it probes `0xA8`, `0xB8`, and `0xC0` directly.

#### Sizing `last_range` on other engines

| Situation | `last_range` |
|---|---|
| Default — works for IL2CPP and most native games | `0x100` (default) |
| Native code where the static slot in `main` points at a struct base | `0x10`–`0x100` |
| Unreal Engine or custom engines where the main slot may point further into a struct | `0x400`–`0x2000` |
| Last resort — chain reaches `main` but produces no bookmarks | raise until bookmarks appear |

When in doubt, leave `last_range` at the default `0x100`. The win from making it smaller is small; the cost of making it too small is "the search finds nothing."

---

## 5. Running the Search

Typical workflow:

1. **Start** (`L`) — performs the depth-0 scan: finds every memory address that points at one of your seed nodes within `search_range`. The result populates the node list.
2. **Analyse** (`Y`) — inspect the source pointers found for the highlighted node. Are the offsets clustered (good — likely a real struct), or random-looking (bad — likely noise)?
3. **next depth** (`R`) — steps the search one level *up* the chain (toward `main`). Records any source that already lies inside `main` as a bookmark, then re-scans memory for sources of the new node set. Press repeatedly to climb manually.
4. **Goto depth** (`+ + ZL`) — automatic loop: keeps calling `next depth` until either the depth reaches `search_depth`, the search runs out of memory, or all surviving nodes have landed inside `main`.
5. **get depth+1 ptr** — record the would-be next-depth bookmark *without* advancing the search. Use this to capture intermediate progress without committing to another scan.
6. **Save_Map** / **Load_Map** — checkpoint the node graph before trying riskier parameters; reload to retry without re-scanning from scratch.

### When to use `next depth` (manual)

- You want to inspect candidates with **Analyse** between depths.
- You suspect the chain is short (2–3 hops) and want to stop as soon as it lands in `main`.
- You want to change `search_range` or `num_offsets` between depths.

### When to use `Goto depth` (auto)

- You have a working `search_range` / `num_offsets` config and just want results.
- You expect a long chain (5+ hops, common in Unreal pawn lookups).
- The candidate set is small enough that growth is contained — typically `num_offsets = 1`.

The default `search_depth = 4` is a sane bound for most chains. Raise it (`5`–`8`) if you expect a long chain — common in Unreal pawn lookups. If `Goto depth` runs out of memory before reaching a static address, drop `num_offsets` to `1` first, then lower `search_range` if needed.

### Use of `Delete Offset`

If **Analyse** shows one offset is clearly bogus (e.g. `0x7E0` when every other candidate is `0x10`–`0x40`), press **Delete Offset** (`-`) to remove it before the next step. This prevents that false branch from contaminating later depths.

---

## 6. Validating Bookmarks Against a Game Restart

A pointer chain that resolves correctly *right now* is not necessarily a stable chain. To confirm a chain survives a fresh process launch:

1. **Name** your search (`Name=`, `X + ZL`) before recording so the bookmarks it produces are easy to identify.
2. After `next depth` / `Goto depth` finishes, return to the **Bookmark Menu** (`Bookmark menu`, `R + ZL`). New bookmarks will be present, ideally with addresses inside the `main` module.
3. Use **Toggle Absolute Address** (`L`) to switch between absolute and `main`-relative form. Bookmarks shown in `main`-relative form are the static, restart-safe ones.
4. Verify each chain resolves now: open **Memory Explorer** (`Right Stick`) on the bookmark and use **Jump Forward** (`Y`) to walk the chain. Confirm it lands on the expected dynamic value.
5. **Save** the bookmark file.
6. **Fully close the game** (close software, not suspend) and **relaunch** it.
7. Reload Breeze and reopen the bookmark file.
8. For each candidate static bookmark:
   - Open Memory Explorer at its address and step through the chain with **Jump Forward** (`Y`).
   - Confirm the final dereferenced value matches what you expect for the new game session.
9. From the Bookmark Menu run **Perform Clean up** (`- + ZL`). This removes bookmarks whose chain no longer resolves — anything left is restart-stable.
10. Optional: repeat the close-and-relaunch test 1–2 more times. Some chains hold across one restart but break across scene or save changes; chains that survive multiple cold launches are the most reliable.

> If **all** candidates die after restart, the chain depth was too shallow — you stopped before reaching `main`. Reload your saved map (**Load_Map**) and run more **next depth** iterations.
>
> If **most** die but a few survive, those survivors are your real chains. Use **Mark To Delete** + **Perform Clean up** to drop the dead ones.

---

## 7. Quick Reference

| Goal | Action |
|---|---|
| Seed a search | Bookmark target -> **Pointer Search** (`X + ZL`) |
| Start scan | **Start** (`L`) in Jump Back menu |
| Inspect candidates | **Analyse** (`Y`) |
| One step toward static | **next depth** (`R`) |
| Auto-run to `search_depth` | **Goto depth** (`+ + ZL`) |
| Tune the per-hop range | `search_range` (`Right + ZL`) |
| Tune the main-to-heap range | `last_range` (`Right + ZR`) |
| Restrict candidates per node | `num_offsets` (`Left + ZL`) |
| Cap auto-mode depth | `search_depth` (`+`) |
| Snapshot before retry | **Save_Map** (`RStick Down + ZL`) |
| Restore snapshot | **Load_Map** (`RStick Up + ZL`) |
| Drop a known-bad offset | **Delete Offset** (`-`) |
| Probe the IL2CPP static-fields hop | **do B8 scan** |
| Validate after restart | **Perform Clean up** in Bookmark menu (`- + ZL`) |

---

## See Also

- [pointer search.md](pointer%20search.md) — primer on jump back nodes, `main`, and `JumpBackMatch`.
- [base pointer illustration.md](base%20pointer%20illustration.md) — what a captured base-pointer cheat looks like in practice.
- [unity.md](unity.md), [UnityGuide.md](UnityGuide.md) — Unity / IL2CPP workflow.
- [unreal.md](unreal.md), [unreal_primer.md](unreal_primer.md) — Unreal Engine workflow.
- [menu.md](menu.md) — full Jump Back menu button reference.
