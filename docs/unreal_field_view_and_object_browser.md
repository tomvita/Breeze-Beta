# Unreal field view & object browser — overhaul notes

Working notes for the Unreal Engine subsystem rework (`source/ue_*.cpp`,
`source/unreal.cpp`). Everything marked **verified** was confirmed by reading a
live game process over the Atmosphère GDB stub, not inferred from engine source.

Reference title throughout: **SWD7** (*Sword and Fairy 7*), UE **4.25**, Switch
retail build.

---

## 1. What started it

> "the class field routine for unreal engine is a lot less robust compared to
> unity, quite often no field name retrieved"

The asymmetry is real and partly structural:

| | Unity | Unreal |
|---|---|---|
| Name source | `dump.cs` from Il2CppDumper — an offline text file (`asmdisp.cpp:get_fields_for_type`) | live memory reconstruction |
| Failure modes | file missing | ~6 chained lookups, any of which can fail |
| Coverage | every field is in the metadata | only `UPROPERTY()`-marked members exist |

Unity names come from a file seek. Unreal names come from
`FName index → FNamePool → block → entry`, with every structural offset
brute-forced at runtime. That part was fixable and was fixed. The coverage
difference is not fixable — see §8.

---

## 2. Bugs found and fixed

### 2.1 The version layout table encoded the *editor* FField layout

`ue_internal.hpp` — every row of `kUeVersionLayouts` carried
`fnext=0x20, fname=0x28, foffint=0x4C`, which is the `WITH_EDITORONLY_DATA`
variant where `FFieldVariant` holds a separate `bool bIsUObject` (16 bytes).
Shipping builds pack that flag into the owner pointer's low bit (8 bytes),
putting those three fields 8 bytes earlier.

Both variants exist in the wild, so a fixed table can only ever be right about
one of them. The table now stores the **packed/shipping base**, and the +8 delta
is detected at runtime by `detect_ffield_variant_shift()` from the owner tag bit
and applied by `resolve_ue_layout()`.

**Verified** on SWD7: `Owner` at `+0x10` is a clean pointer with `bIsUObject = 1`
stored separately at `+0x18` → `fv=8`. Predicted `0x20 / 0x28 / 0x4C`, and the
consensus detectors independently arrived at the same triple.

### 2.2 `FField::NamePrivate` offset was guessed per node

`fill_field_chain_node_names()` walked a candidate list per node and took the
first offset that decoded to anything. The name offset is a single constant for
the whole build, so a wrong-but-decodable offset could win by being earlier in
the list, and different nodes in one view could resolve at different offsets.

Replaced with `detect_best_name_offset()` — scores every candidate across up to
32 nodes (`hits × 10 + distinct names × 5`, penalising offsets that keep yielding
one repeated string), commits to one winner, decodes everything there. Same
approach `detect_best_offset_slot()` already used for `Offset_Internal`. If the
winner explains under 25% of sampled nodes it returns −1 and the legacy probing
runs, so it cannot be worse than before.

### 2.3 FName pool layout re-probed on every decode

`decode_fname_from_pool()` tried 6 block-shifts × 3 strides *per name* — up to 18
IPC reads each, and once the correct layout legitimately missed, a wrong one
could still land on a printable string.

`detect_fname_pool_layout()` now pins `(header_shift, block_shift, stride)` once
by scoring pool anchors 0–12 (entry 0 is `NAME_None` in every build; `*Property`
names are strong confirmation).

**Verified**: `shift=16, stride=2` decoded all three known FNames correctly, and
`stride=4` produced `'LevelScale'` for `QueryForLocation` — a wrong-but-plausible
name, exactly the failure this prevents.

**Caveat, documented in code**: indices 0–12 land in block 0 under *every*
`FNameBlockOffsetBits`, so this pins `header_shift` and `stride` but not
`block_shift`. Probing on a miss is retained for builds that override it.

### 2.4 Version detection only inspected one segment

`try_detect_ue_version()` queried the segment immediately after `.text` and gave
up unless it was `Perm_R`. The `++UE4+Release-X.YY` tag lives in `.rodata`, which
is not reliably that segment — `diag_game1_field_chain4.txt` shows
`g_ue_major=0`, i.e. every structural prior disabled.

Now sweeps all read-only segments inside the main NSO, accepts both UTF-16 and
ASCII, and keeps scanning past a near-miss. SWD7 now reports `ue=4.25`.

### 2.5 Properties were deleted when their class name would not decode

A node whose `FFieldClass` name failed to resolve got `node_class = ""`, which
forced `prop_offset = -1`, which removed the field from the view entirely — even
when its *name* had decoded fine.

Added `is_ffield` to `ue_field_chain_node_t`, set from the structural test
(`ClassPrivate` at a fixed `+0x08` pointing into main-NSO static data).
`node_is_property()` accepts `is_ffield || node_class resolved` — a strict
superset of the old check, so it can only add fields.

### 2.6 The SuperStruct walk climbed into a `UFunction` — *the big one*

`kSuperStructOffsets` contained `0x48`, which in the very layout the table
encodes is `UStruct::Children` — the head of the class's **UFunction list**. From
`Object`, offset `0x40` (the real SuperStruct) is null because UObject is the
root, so the probe fell through to `0x48` and adopted `ExecuteUbergraph` as a
parent class. A UFunction passes every structural test there; it *is* a UStruct
with a valid vtable and `ClassPrivate`.

**Verified** on `PlayerSystem`:

```
--- class chain (4 levels) ---
  [0] PlayerSystem
  [1] BaseGameSystem
  [2] Object
  [3] ExecuteUbergraph          <- a UFunction, in the class chain
--- contributing levels (4) ---
  slot=cls+0x50   nodes=2       <- correct ChildProperties
  slot=cls+0x10   nodes=2       <- UObject::ClassPrivate
  slot=cls+0x48   nodes=2       <- UStruct::Children (function list)
  slot=cls+0x130  nodes=8       <- ExecuteUbergraph's frame locals
```

Eight of the ten reported "properties" were function frame locals
(`TimeBias`, `TimeScale`, `Op`, `EntryCount`, …) at offsets `4, 4, 8, 24…28` —
offsets into a call frame, not an object. Correctly named, entirely wrong.

`CharacterData` was contaminated the same way: its pre-fix `props=14` was
6 real + the same 8 ubergraph locals, invisible only because the `offset < 0x28`
guard filtered them.

Fixes:
- `is_ufunction_like()` rejects a SuperStruct candidate whose meta-class resolves
  to `Function`/`DelegateFunction`. Conservative — an unresolvable name returns
  `false`, so nothing changes when the name pool is unavailable.
- Chains must consist of FFields, gated on `hierarchy_has_ffield` so pre-4.25
  UProperty titles are unaffected.
- `+4000` bonus for the layout's `ChildProperties` slot so a coincidental match
  elsewhere cannot outbid it.

### 2.7 Self-inflicted: `/`-prefixed FNames rejected

While tightening `is_likely_ue_identifier()` I added a first-character anchor
that rejected every UE **package path** (`/Script/Engine/...`, `/Game/Art/...`) —
those are FNames too. Caught from `ue_namepool_diag.txt`, where all 26 decode
failures started with `/`. Fixed by allowing `/` as a leading character.

### 2.8 A stale `ue_profile.ini` permanently suppressed name-pool detection

Any non-zero saved `NamePoolData` was trusted outright *and* set
`g_ue_namepool_tried_autodetect`, so a profile written by a scan that guessed
wrong meant blank names forever, with deleting the file as the only cure.

`adopt_saved_namepool()` now validates with `looks_like_namepool_at()` first.
The profile is a pure optimisation: right → skip the scan, wrong → scan anyway.

---

## 3. `UStruct::PropertyLink` — the structural fix

`PropertyLink` (`cls+0x70`, chained through `PropertyLinkNext`) is the
**flattened** property list, including inherited properties. One walk from the
most-derived class replaces the entire "ChildProperties at each SuperStruct
level" traversal.

**Verified** equal on three hierarchies:

| class | ChildProperties + SuperStruct walk | PropertyLink |
|---|---|---|
| PlayerSystem | 2 | 2 |
| CharacterData | 6 | 6 |
| EnvQuery → DataAsset → Object | 3 | 3 |

`EnvQuery` is the proof of inheritance coverage: its PropertyLink yields
`QueryName`(0x30), `Options`(0x38) **and `NativeClass`(0x28), declared by
`DataAsset`**.

This is now the primary path (`try_property_link_chain()`), with the old walk as
automatic fallback. It removes both bug sources in §2.6 structurally — no
SuperStruct climb to wander into a UFunction, no slot probing to grab
`ClassPrivate` or `Children`. The view note shows `[PropertyLink]` when used.

---

## 4. Verified memory layout reference

UE 4.25+ shipping, `USTRUCT_FAST_ISCHILDOF_IMPL == STRUCTARRAY` (engine default).

### UStruct

```
UObject                0x00 .. 0x28
UField::Next          +0x28
FStructBaseChain      +0x30 .. 0x40    (16 bytes; why SuperStruct is at 0x40, not 0x30)
SuperStruct           +0x40
Children              +0x48            (UFunction list — NOT properties)
ChildProperties       +0x50            (FField list, this class only)
PropertiesSize        +0x58
MinAlignment          +0x5C
PropertyLink          +0x70            (flattened, incl. inherited)
```

### FField / FProperty

`FFieldVariant` is 8 bytes in shipping builds (tag packed into the owner
pointer's low bit) and 16 bytes otherwise, which shifts everything after `Owner`:

```
                    packed (fv=0)   expanded (fv=8)
vtable                    +0x00           +0x00
ClassPrivate              +0x08           +0x08     <- always 0x08, no variance
Owner                     +0x10           +0x10     <- declaring UStruct
Next                      +0x18           +0x20
NamePrivate               +0x20           +0x28
Offset_Internal           +0x44           +0x4C
```

**Invariants relative to `Offset_Internal` (OI)** — these hold in *both* variants
and are what let the code avoid variant-specific branching:

```
NamePrivate            = OI - 0x24
ElementSize            = OI - 0x14
PropertyLinkNext       = OI + 0x0C
FStructProperty::Struct= OI + 0x2C
```

`FField::Owner` at `+0x10` (mask the low bit) names the `UStruct` that
**declares** the property — the only reliable way to tell an inherited field from
an own one, since `PropertyLink` is flattened. **Verified**:

```
EnvQuery : DataAsset : Object
  QueryName    owner -> EnvQuery    (own)
  NativeClass  owner -> DataAsset   (inherited)
```

A `UScriptStruct` is itself a `UStruct`, so it carries `PropertyLink` at `+0x70`
and the identical walk recurses into nested struct fields.

### FNamePool (SWD7 values)

```
FNameEntryAllocator: Lock, CurrentBlock(+0x20), CurrentByteCursor(+0x24), Blocks[](+0x28)
FNameEntryHeader:    bit0 = bIsWide; shipping = probe-hash(5) + Len(10) -> shift 6
                                      case-preserving = Len(15)        -> shift 1
index -> block = idx >> 16, offset = idx & 0xFFFF, entry = Blocks[block] + offset*2
```

---

## 5. New capability

### 5.1 Object browser (`Browse UE Objects`)

`Ue_pointer_search_menu` was commented out of the entry menu. It is the closest
thing to a GUObjectArray browser and was simply hidden. Re-enabled, plus:

- **Class-name filter** (`R`) — space-separated terms matched in order.
  `build_ue_candidate_rows()` honours `g_ue_candidate_filter_query`;
  `g_ue_candidate_filtered_indices` maps visible rows back to real candidates.
- **Paging** (`StickR` up/down). `fill_window_rows()` only hands the menu
  `kUeWindowRows = 160` rows at a time, and `PrevPage`/`NextPage` had handlers
  bound to no button — everything past row 160 was unreachable. This is what hid
  most of the class summary.
- Fixed navigation: `case 1000` (per-tick) was calling the menu factory, which
  re-ran init + `reload()` + `fill_window_rows()` every frame, resetting the
  highlight and the expand state continuously.

### 5.2 Graph walk (`run_ue_object_graph_walk`)

The original scan only ever found objects a **static** variable points at
(`source_scan` = main-NSO `Perm_Rw`). Anything owned by a heap container was
invisible — which is most gameplay state.

Instead of sweeping the heap, follow references:

1. Seed from the fast static scan (its globals are the roots).
2. Climb `Outer` up to 8 levels (reaches the application/engine/package objects).
3. BFS through reflected references: `ObjectProperty`/`ClassProperty`/
   `InterfaceProperty`/`WeakObjectProperty` (single pointer), `ArrayProperty`
   (`TArray{Data,Num,Max}`), `MapProperty`/`SetProperty` (sparse-array buffer,
   swept — see §8).

**Verified**: from `GameEngine` alone — 1768 objects, 188 classes, 7454 edges,
reaching all 42 game systems plus `AISystem` and `ParticleSystem`.

`Deep scan (heap, slow)` (`A+ZL`) remains as the brute-force fallback.
`mapped_target_ranges()` intersects the reserved heap/alias extents (8 GB / 64 GB
on this title) with mapped `Perm_Rw` segments so it walks real memory only.

### 5.3 Class summary (`L`)

Per-class inventory sorted by **coverage**, not raw property count:

```
cov%  props  size    count  class            sample object
 62   17     0x2D8   1      CriAudioSystem   33010D0E60
  9   6      0x4D0   1      SaveLoadSystem   3380ACBAA0
```

`cov%` = share of `PropertiesSize` covered by reflected properties, summing each
`ElementSize`. Property count alone is misleading — 17 properties across 728
bytes still leaves the object mostly undescribed, and the field view looks like a
wall of gaps. Coverage predicts a useful field view; count does not.

Rows are selectable: `X` on a class sets the filter to it and returns to the
object list.

### 5.4 Field map (`ue_field_map.txt`)

Written during summary generation — the `PropertyLink` walk happens anyway for
the counts, so only the I/O is new (64 KB `setvbuf`).

```
=== BPC_Mob_Robber_C : SWD7Character : Character : Pawn : Actor : Object  psize=0x...  props=N ===
  0x0800  size=0x8   UObject*  CharacterData    inherited from SWD7Character
=== CharacterData  psize=0x550  props=6 ===
  0x0028  size=0x278 UStruct   DataInfo
    0x0028  size=0x2C  UStruct       BaseData
      0x0038  size=0x4   int32       Hp
      0x003C  size=0x4   float       Mp
```

- **Recurses into `StructProperty`** via `FStructProperty::Struct` (OI + 0x2C),
  emitting nested fields at **absolute** offsets. Without this `CharacterData`
  showed 6 struct headers instead of the ~60 real fields inside them.
- Cycle guard is **per-path**, not global — `AttrBonus` legitimately appears three
  times in `CharacterData`; a global visited-set would expand only the first.
- **Inheritance chain** in the header and `inherited from X` per property, from
  `FField::Owner`. This answers why the same field appears at the same offset
  across many classes: it is declared once on a shared base.

### 5.5 Pointer-chain bookmarks (`L+ZL`)

The walk records, per object, the static slot it was reached from plus the
dereference hops (`ue_obj_path_t`). `build_ue_object_chain_bookmark()` replays
that as a Breeze pointer chain, so it survives ASLR and restarts.

**Verified** end to end:

```
CharacterData at 3380C32550
  chain: [GEngine static slot] -> 0xDD0 -> 0x1F8 -> 0x40 -> 0x88 -> 0x10 -> 0x0
  hops = 6 (MAX_POINTER_DEPTH = 15)
  resolves to 3380C32550  -> MATCH
```

### 5.6 Caching

Breeze is an NRO: exiting unloads all in-memory state, but the game keeps running
and its object addresses stay valid. Both caches therefore persist to disk.

| file | holds | invalidated by |
|---|---|---|
| `ue_object_cache.bin` | candidates + recorded pointer paths | header mismatch or spot-check failure |
| `ue_class_summary.bin` | summary rows + per-row class | same header check |

Validation is two-stage: **header** (title id + main/heap/alias base *and* size —
these change on a fresh game launch) and **spot-check** (up to 64 objects spread
across the set must still have their recorded `class_ptr` at `+0x10`; 75%
required, since a level unload can free some legitimately).

Lookup order on entry: memory → disk → walk. `g_ue_candidates_generation` gates
the in-memory summary cache. `reset_ue_scan_state()` clears candidates so a
different process cannot serve stale addresses.

---

## 6. Menus

**Unreal entry** — was 6 actions, now 4. `Scan UE Profile` and `UE Root Chain`
were always used in that order, and getting it wrong left the Explorer greyed out
with no hint; they are folded into `UWorld Explorer`, which now scans and
resolves on demand.

| | |
|---|---|
| X | Browse UE Objects (runs/loads the graph walk, then opens) |
| L | UWorld Explorer |
| R | Function Explorer |
| + | Export UE Func Map (prompts for the slow extended scan) |

**Object browser**

| | |
|---|---|
| X | Open UClass view — "Show this class" while the summary is up |
| R | Filter by class |
| Y | Rescan objects (graph walk) |
| L | Class summary |
| L+ZL | Bookmark chain |
| A+ZL | Deep scan (heap, slow) |
| StickR ↑/↓ | Page up / down |

> `A+ZR` is unusable: `ui.cpp:111` defines `TutorialKeyCombo = ZR | A`, so that
> chord toggles the tutorial overlay globally. Use `A+ZL` (as `script_list.cpp`
> does).

**UObject view** — added `StickR` ↑/↓ paging alongside the existing `ZL+L` /
`ZL+R`.

---

## 7. Runtime files (in `sdmc:/switch/breeze/cheats/<TitleID>/`)

| file | written by | contents |
|---|---|---|
| `ue_field_map.txt` | class summary | every reflected field, all classes, struct-expanded, with parentage |
| `ue_class_summary.txt` | class summary | the coverage table |
| `ue_class_summary.bin` | class summary | cache — **delete to force regeneration of the map** |
| `ue_object_cache.bin` | graph/deep scan | object + path cache |
| `ue_fproperty_raw_dump.txt` | UObject view, Write To File | per-node diagnostics with `SHOWN`/`NO-OFFSET`/`BELOW-HEADER`/… status |
| `ue_field_chain_dump.txt` | UObject view, Write To File | the rendered field rows |

### Reading the UObject view header

```
nodes=2 (props=2 named=2 funcs=0) next=0x18 name=0x28 off=0x4C
depth=3 levels=1 ue=4.25 fv=8 np=52DA6E5940 [PropertyLink]
```

- `named` vs `props` — the number to watch when names come back blank
- `ue=0.0` — version detection failed, all priors disabled
- `np=0000000000` — name pool never found; every name will be `field_0x....`
- `fv` — 0 packed / 8 expanded `FFieldVariant`
- a large `props` on a class that should not have one, plus a high `funcs`, is
  the signature of the §2.6 bug returning

---

## 8. Known limitations

- **Unreflected members are unrecoverable.** Only `UPROPERTY()`-marked members
  exist in reflection data. `PlayerSystem` reflects 2 of its 952 bytes; the money
  at `+0x2A0` has no `FProperty` and no tool — Breeze, UE4SS, any dumper — can
  name it. Gap rows plus annotations (`L` in the UObject view, keyed by class
  name + offset, persisted) are the answer there.
- **Container sweep is approximate.** `TMap`/`TSet` element stride depends on the
  key/value layout, so the sparse-array buffer is swept at 8-byte granularity
  rather than decoding `FScriptMapLayout`. It can pick up neighbours past the
  live elements — observed: `SaveGameBuffer` with `Num=1` returning four unrelated
  objects. Mitigated by stopping after `2*Num` accepted objects. Bookmarks
  through such a slot still resolve correctly (the chain is literally that
  address).
- **Objects reached by climbing `Outer` have no bookmark chain** — that direction
  is upward, so there is no forward pointer path. Most are also reachable forward
  and BFS finds that route.
- **Struct-nested object references are not followed** by the graph walk (the
  field *map* does expand them). `MapProperty` values are covered only via the
  sweep.
- `block_shift` is not pinned by name-pool detection (§2.3).

---

## 9. Case study: SWD7

Useful as a calibration point for how little a shipping UE title may reflect.

- `BP_SWD7Application_C::ArrayOfGameSystem` is a registry of **42 named singleton
  systems** (`PlayerSystem`, `InventorySystem`, `StoreSystem`, …). Median
  reflected-property count across them: **1**. `ItemSystem`, `InventorySystem`,
  `StoreSystem`, `RefineSystem`, `TalentSystem`, `AchievementSystem` have **zero**.
- The live money is `PlayerSystem+0x2A0` — a plain C++ member, unreflected.
  Confirmed three ways that `PlayerSystem` has exactly 2 properties
  (`ChildProperties` walk, `PropertyLink` walk, `PropertyLinkNext` terminating).
- `SWD7SaveGame` is the opposite: **79 properties over `psize=0xE00`**, including
  `Money` as an `IntProperty` at **`0x5C4`** and `Essence` at `0x5C8`. The 18
  instances are save slots held in `SaveLoadSystem::SaveGameMap` (`Num=18`), all
  real; `LastSavedGame` points at the live one.
- `0x5A0` is **inside** `TeamMemberParticipations` (a `MapProperty` at `0x570`,
  size `0x50`) — the `0xFFFFFFFF` there is a sparse-array sentinel, not a field.
- The name pool contains `Money`, `SetMoney`, `InMoney`, `RewardMoney`,
  `HandleMoneyChanged`, `MoneyChangedEvent__DelegateSignature` — the classic
  private-member-plus-BlueprintCallable-accessor pattern. `SetMoney` is a real
  UFunction, so the function map can locate it and its disassembly would give an
  AOB-stable anchor for the offset.
- `CharacterData` is the class that shows the field view working properly: 6
  top-level properties expanding to ~60 named fields
  (`DataInfo::BaseData::Hp` at `0x38`, `Mp` at `0x3C`, …).

---

## 10. How this was verified

A minimal read-only GDB Remote Serial Protocol client (`qSupported`, `vAttach`,
`m`, `D` only) against the Atmosphère stub, used to read the live game and check
every structural claim before writing code. Worth keeping in mind if this is
revisited:

- `vAttach` halts the target; `D` resumes it. Reads run ~150 KB/s, so a full heap
  sweep is impractical over the wire but targeted navigation is fast.
- The stub reports a **fixed** thread on attach whose PC never moves if that
  thread is parked in a wait — this looks exactly like a frozen process and led
  me to wrongly conclude the game was hung. Diff a **large, active** heap region
  across two attaches instead; sampling a single static object proves nothing.
- `qXfer:osdata:read:processes` lists processes without attaching — the game
  appears by name (`SWD7`), not as `Application`.
