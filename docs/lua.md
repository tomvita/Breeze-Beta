# Lua Tools

Breeze's Lua subsystem does for PUC-Rio Lua games what the IL2CPP and Unreal
tools do for theirs: it finds the runtime's own description of the game's data
and lets you work by name instead of by address.

It targets Lua 5.1 - 5.4. LuaJIT is a different runtime -- NaN-boxed values,
32-bit GC references -- and is not handled.

## Why a Lua game needs its own tool

Unity and Unreal ship a type system: metadata files, `UClass` graphs, named
fields at fixed struct offsets. Find a class, read a field offset, write a
chain, and the offsets hold for the life of the build.

A Lua game has no struct offsets to find. Gameplay state lives in Lua tables
keyed by strings on a garbage-collected heap. That is a bigger opportunity and a
harder target at the same time.

The opportunity is that the game names its own data. On Victor Vran the money is
not "a field at +0x38 of some object", it is
`_G.AllCharactersStorage.1.Gold`, written by `PlayerAddGold` at
`@FVH/Lua/PlayerProfile.lua:1272` -- all of that readable from the running
process.

The difficulty is that byte search barely works. That build packs `TValue` to
**9 bytes** and a hash `Node` to **22**, where stock Lua 5.3 uses 16 and 32. Lua
values therefore land on arbitrary even addresses, while Breeze's search steps by
the type width (`dataTypeinc` in `search.cpp`). A 64-bit search steps by 8 and can
never land on an address that is 2 mod 8. That is the whole reason a gold value
of 4,295,033,224 could only be found as its own bit pattern shifted left by 16 --
the search had landed two bytes below the real slot.

So the subsystem does not search memory. It walks the object graph and compares
typed values.

## Detection: measure, never assume

`Detect Lua state` finds the `lua_State*` static and then measures the layout.
Nothing is hardcoded, because the packed build above proves stock offsets
produce confident garbage.

- **Find the state.** Look for the *object*, not for pointers to it. A
  `lua_State` has tag `8` at `+8`, and `[+24]` is a `global_State` whose first
  field is a code pointer back into the module. The main thread and the global
  state are allocated together as one `LG` struct, so `g - L` is a small
  constant -- and because both of those facts live inside the first `0x28`
  bytes, a block that has been read once answers the whole test in the buffer.
  Every writable range is read exactly once, the heap included.
- **Find the global that points at it.** Only then, and only across the main
  module's writable segments, comparing words against the state just confirmed.
  That comparison is what produces the restart-stable offset the profile stores.
- **TValue stride.** In the registry's array part, slot 1 is the main thread --
  a pointer already in hand. Find it, then find the next valid tag byte; the
  delta is `sizeof(TValue)`.
- **Node stride.** Score candidates on tag legality, with `lastfree - node`
  divisibility as a pre-filter. On Victor Vran that filter alone eliminates every
  wrong candidate and 22 scores 128/128.
- **Sanity gate.** Resolve `registry[2]` and require a table. If that fails the
  detection reports failure rather than guessing a layout.

The order matters, and it is the opposite of the obvious one. Testing every
pointer-shaped word in module data costs one process read per candidate: Another
Eden Begins Demo has 1,006,969 of them, so that is a million IPC round trips and
minutes of frozen screen -- and it can only ever find a state that a module
global points at. Games whose binding keeps the state in a managed C# field, as
xLua and its relatives do, were reported as not being Lua games at all. Reading
every writable page once instead swept that game's 1949 MB in 9.0 seconds and
found the one real `lua_State` among 2,523,650 thread-tagged words and 22,837
`LG` pairs.

Because the sweep can take that long, `Detect Lua state` runs on a progress
screen rather than inside the button press: megabytes scanned, elapsed, an
estimate for the rest, Pause and Restart, and the counters above so a failure is
diagnosable. When nothing is found the message says which of three things
happened -- no thread-tagged object paired with a `global_State` at all, which
means no PUC-Rio Lua 5.2-5.4 in the process; states that confirmed but whose
registry would not measure; or objects shaped like Lua 5.1, which is a real Lua
this tool cannot read.

Results go to `lua_profile.ini`, which holds build-constant facts only -- offset,
strides, `g - L`, bucket counts. Deliberately no addresses: a stale address that
still looks plausible is worse than none. A state that no module global points
at is still fully usable for the session -- it just cannot be profiled, so
Detect runs again every launch, and the two master-cheat buttons, which bake
`Main+offset` into what they generate, are greyed out.

## What survives a game restart

This table is what the whole design rests on. Everything in it was measured
across three separate launches of the same save.

| Fact | Survives | Why |
| --- | --- | --- |
| Module offset of the `lua_State*` static | yes | An ordinary module global |
| `l_G` / registry / array offsets | yes | Struct offsets in the Lua build |
| TValue and Node strides | yes | Compile-time, but must be detected |
| Array indices `t[1] t[2]` | yes | Positional |
| String *contents* and lengths | yes | The runtime handhold |
| A function's source, line, constants | yes | Baked into the Proto |
| Heap addresses | no | Fresh allocations every run |
| Hash bucket of a key | no | See below |
| Node array base | no | Reallocated on every `luaH_resize` |

`g->seed` feeds every short-string hash and is randomised per launch:
`0xD24239B8`, `0xBBF61AC7`, `0xAC0539EC` on three runs. Collision displacement is
run-dependent too, so `Gold` sat at node offsets `0x2AA`, `0x23C` and `0xF2`.
A fixed-offset chain would have missed all three.

## Restart-proof cheats

A cheat is emitted as a fixed-offset prefix down to `_G`:

```
[Main+static] -> +0x18 -> +0x40 -> +0x10 -> +tv
 lua_State      global_   registry array    registry[2] == _G
                State
```

and then one step per path element. An array step is positional -- `array +
(i-1)*stride`, guarded against a shrunken array, about 15 dwords. A hash step is
a runtime scan of the node array matching the key's interned bytes: tag, then
`shrlen`, then the first eight characters, about 40 dwords. The write is guarded
twice, on the scan having resolved and on the value still carrying the expected
tag, so a failure is inert rather than destructive.

This was hand-assembled and verified before the generator existed: enabled cold
after a reboot, it resolved the right node and wrote the right value.

### The opcode budget

A cheat holds `0x100` dwords, but `LoadProgram` concatenates every *enabled*
cheat into one `0x400`-dword program and, on overflow, returns false so that **no
cheats run at all**. It is a silent total failure, not a truncation.

`Make Lua master cheat` resolves the prefix *tree* once -- each distinct edge
emitted once, each path starting from its longest already-published ancestor --
and publishes the resolved tables in registers R0-R7, handed out from R7 down
because ordinary cheats use the low registers. Dependents then read a register
and do only their final step.

This works because the VM clears registers once per pass, not per cheat, and runs
the whole concatenated program top to bottom: the master's writes land before the
dependents read them, in the same cycle. A clobbered register makes a scan
resolve nothing, the tag guard fails, and nothing is written.

The master is split across as many cheats as it needs, on recorded opcode
boundaries. All parts must be enabled, in order.

## The ASM master

The opcode budget above is a hard ceiling, and two things a Lua cheat really
wants cost more than it can spare: reading a table's live bucket count, and
re-resolving often enough to survive a rehash. Both are one instruction in
native code. **Make ASM master** takes that route.

It writes `asm_master.txt` into the game's Breeze directory and adds one
consumer cheat per enabled bookmark. You then find an instruction that runs
often, name the cheat `asm_master`, and press **Add ASM** -- Add ASM looks for
`<cheat name>.txt` in the game directory, which is what pairs the two.

The cave resolves **one path per 16384 hook hits**, round robin, and parks what
it found in a data area. The consumers are two opcodes: read the parked node,
write the value. So the resolving happens in native code at a cost that rounds
to nothing, and the cheats that depend on it stop competing for the `0x400`
dwords.

The descriptor is the **path text itself** -- `PlayerControlObjects/[1]/items/
[5]/stack` -- with a four-byte offset table in front of it. A parser in the cave
walks a segment at a time, deriving the three comparison windows straight out of
the text. That is why another bookmark costs its path string and nothing else:
the resolver is a fixed ~760 bytes however many paths there are.

It replaced a fixed-stride hop table, where every path was padded to the deepest
path in the set. On seven paths for Victor Vran the cave went from 1596 bytes to
984, the descriptor from 1008 bytes to 220, and the dead space in the cave from
34.6% to 0.8% -- two zero words out of 247, both of them deliberate slack. In
cheat words that is 1203 down to 744, which also puts it **under** the 1024-dword
global budget, so the cave parts no longer have to be applied and then disabled.

Measured on the running game: 4,472,870 hits produced 273 resolves, which is
exactly `hits / 16384`, with all paths reporting fail code 0. That ratio is the
integrity check -- if it does not come out exact, the counter and the resolve
path disagree and no reading from the area means anything.

Two limits are worth knowing. A **path segment may be at most 24 bytes**, which
is what three eight-byte windows cover; a longer one is refused by name when you
press the button rather than assembled into something that can never match. And
the data area is **pinned**, not placed by Add ASM: the consumers are generated
before the cave exists, and `findfree()` is a high-water mark, so letting it
choose would move the area on every re-assembly and leave the consumers reading
the previous run's pointers. That failure is silent and it is the reason for the
pin -- writing through a stale parked pointer reaches a node Lua may have freed.

## Working with it

**Dump all values** writes every reachable Lua slot to a candidate file, so the
normal search pipeline owns it from there -- narrowing, grouping, freezing,
labels. Because those are exact slot addresses, later passes re-read them
directly and the 22-byte stride stops mattering. This is also the route for an
unknown-value search: dump, make the thing happen, then narrow on changed and
unchanged.

**Find value** matches integers exactly, floats within one (so `1000` finds
`1000.4`), strings by content, and `true`/`false` against booleans -- one query,
every representation, because the tag says which comparison applies. **Find
name** matches key names at every level.

**Browse _G** walks the tables by name. **Class field** in the candidate or
bookmark list opens the table owning an address. **Lua bookmark** saves a value
by path.

Bookmarks store the **path**, never the address, and resolve fresh each session.
That is also exactly what the cheat generator consumes, which is why the bookmark
list and the "which cheats to build" list are one file.

## Things that will surprise you

**A nil field does not exist.** Lua stores no slot for it, so a stat that has
never been assigned is genuinely absent from its table -- not a broken path. The
bookmark list distinguishes `<not set yet>` from a named broken step, and a cheat
for such a field is built anyway: its scan finds the key the moment the game
creates it.

**Booleans are four bytes.** `Value` holds them in a C `int b`, and `setbvalue`
writes only those bytes, leaving the other four as whatever the slot held before.
Measured on Victor Vran: 100 of 222 boolean slots carried non-zero leftovers, so
reading one as eight bytes reports `false` as `true` about half the time. Every
read normalises; every write uses four bytes. Do not search booleans by value --
they are 1 and 0, which matches every integer flag in the game.

**A table's bucket count is not a build constant.** Lua reallocates a table's node
array whenever it outgrows itself, so a count captured when a cheat was generated
goes stale. The same path generated twice on Victor Vran gave 256 buckets and then
128, and the 128-bucket cheat silently missed every key in the upper half of a
table that had grown -- the scan ends early and reports the key absent. Generated
scans read `lsizenode` from the table each cycle and stop at the array's real end.

**A number's subtype is a one-way door.** Lua 5.3 has integer (tag `0x13`) and
float (`0x03`) numbers, and a value that ever takes a fractional increment stays a
float. A cheat guarded on the subtype it saw when it was generated therefore stops
matching the moment the game does that, and goes quiet -- no failed write, no
error, just a value that never changes again. Generated cheats guard on the subtype
seen at generation time, so a value that has since turned into a float needs the
cheat regenerated. Writing the wrong form is not an option either: integer bits in
a slot the game reads as a float come back as a denormal near zero.

If a cheat stops working, check the bookmark first: `Get value` resolves the path
by reading memory and ignores tags entirely. Bookmark good and cheat dead means
the path is fine and the emitted program is at fault.

**There is no `u8`.** A game-side byte or short is a full 64-bit `lua_Integer`,
so there is no width or overflow to worry about.

**Engines anchor objects by pointer.** A table reached through an
`objects[obj_ptr]` map is keyed by light userdata -- a raw C pointer, different
every run -- so a path through one is not durable. The walk prefers a nameable
route over the first one found, which is usually the difference between a value
you can turn into a cheat and one you can only look at.

## Generated Files

All in the game's Breeze directory.

- `lua_profile.ini` -- detected layout: static offset, strides, `g - L`, bucket
  counts, and the pinned offset the masters publish at. Build-constant only.
- `lua_map.dat` -- the address map: every table's array and node blocks plus the
  parent relation. Keyed on the `lua_State` address and a walk version, so it
  survives a Breeze restart but never a game restart or a change to the walk.
  Victor Vran: 85,965 tables, 109,149 blocks, 842,730 values, 16 MB read, 12.7 s.
- `lua_bookmarks.txt` -- enabled flag, name, tag, value, path. Paths, not
  addresses.
- `asm_master.txt` -- the ASM master resolver, written by Make ASM master for
  you to assemble onto a hook. Regenerated every time the button is pressed.
- `lua_info.txt` -- the resolved layout, written on request.
- `lua_debug.log` -- a timing line for every table opened (rows, buckets, and
  the cost of each phase), plus a line for anything on the Lua screens that
  outlasts 200 ms. Written only when there is something to say.
- `lua_search.dat` -- the candidate file written by Dump all values and the
  searches, in `BREEZE_DIR`.
