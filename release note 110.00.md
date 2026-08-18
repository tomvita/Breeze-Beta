# Breeze beta110.00 Release Note

## Unreal Field View and Object Browser Overhaul

Breeze's Unreal Engine tools now recover reflected fields more reliably and can browse objects beyond those referenced directly by static memory. The new object graph walk follows reflected object references, groups results by class, and can create restart-safe pointer-chain bookmarks for reachable objects.

### Highlights

- Reworked field discovery around `UStruct::PropertyLink`, providing own and inherited properties without confusing function frame locals with object fields.
- Added runtime detection for packed and expanded `FFieldVariant` layouts, field names and offsets, `FNamePool` layout, and Unreal version tags across read-only main-NSO segments.
- Saved `NamePoolData` is now validated before use, allowing stale profiles to recover automatically.
- Restored **Browse UE Objects** with class filtering, paging, class summaries, graph rescans, deep heap scans, and pointer-chain bookmarks.
- Added graph traversal through reflected object, array, map, set, interface, class, and weak-object references.
- Added `ue_field_map.txt` with nested struct expansion and inherited-property ownership.
- Added validated object and class-summary caches for quick reuse while the same game process remains active.
- Simplified the Unreal entry menu so **UWorld Explorer** performs profile scanning and root resolution on demand.

### Object Browser Controls

| Action | Shortcut |
|---|---|
| Open UClass view / show summary class | X |
| Filter by class | R |
| Rescan object graph | Y |
| Class summary | L |
| Bookmark chain | L + ZL |
| Deep scan | A + ZL |
| Previous/next page | Right stick up/down |

The UObject field view also supports right-stick up/down paging.

### Generated Files

Files are written under `/switch/breeze/cheats/<TitleID>/`:

- `ue_field_map.txt` — reflected fields, nested structs, and inheritance.
- `ue_class_summary.txt` — class counts, sizes, and reflected coverage.
- `ue_class_summary.bin` and `ue_object_cache.bin` — validated caches.
- `ue_fproperty_raw_dump.txt` and `ue_field_chain_dump.txt` — field diagnostics and rendered rows.

Delete `ue_class_summary.bin` to force regeneration of the field map.

### Notes

- Only Unreal-reflected members can be named; unreflected members remain visible as gaps for manual annotation.
- Map and set traversal is approximate because container element layouts vary by build.
- Objects found only by walking upward through `Outer` cannot be bookmarked unless also reached through a forward reflected reference.
- Nested structs are expanded in the field map, but their object references are not yet followed by the graph walk.
- Cache validation rejects data from a different game process.
