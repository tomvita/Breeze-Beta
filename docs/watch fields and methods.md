# Watch fields, watch methods, break on one object

Tools that answer questions about a class while the game plays, all built on the gen2 fork (run Settings > Install gen2 fork and reboot after updating Breeze):

- **Watch fields**: of all the fields in this object, which does the game read or write?
- **Watch methods**: of all the methods of this class, which are ever called, and by whom?
- **Break on one object**: stop the game when a method runs for *this* object, and not for the others of its class.
- **Code watch** (gen2 v0.19): of all the functions in the game, which ran when I did this? For finding the class before any of the above.

Each runs while you play, with Breeze closed. A box at the top left of the game shows what is found as it happens, and the gen2 menu shows the full result when you come back.

The same tools are PC connect commands (`fieldwatch`, `methodwatch`, `gen2 break`, `codewatch`); see `pcconnect.md`.

---

## 1. Watch fields

**Where:** a field view with an instance pinned (or the Unreal UObject view). Press **Watch fields**: ZL + left stick click.

gen2 watches every byte of the object. The Field watch screen opens and the watch starts; go back to the game and play. Each field appears the first time it is touched.

| Button | Key | What it does |
|---|---|---|
| Start / Stop | R | run or end the watch |
| Sweep unseen | ZL+R | go on with only the fields not found yet, at full game speed |
| Clear | Minus | forget the list and start again |
| Read= / Write= | ZL+Up / ZL+Down | count reads, writes or both; applies at the next Start |
| Mark seen | Y | from now on only newly found fields are marked `new` |
| View | ZL+Y | by offset > newest first > new only |
| Select | X | back to the field view, on that field |
| Memory Explorer | L | open the field's address |
| Watch this field | ZL+X | set the ordinary gen2 watch up on that one field, to find the code |
| Close field watch | ZL+Plus | stop and get the ordinary gen2 menu back |
| Pre results / Next results | ZL + right stick left / right | step through the saved runs (section 5) |
| Expand screen | ZR+R | the list over the whole width |

**To find what one action touches** (taking a hit, using an item): Clear, do only that in the game, look at the list.

**Write only** is light. **Read and write** finds far more and slows the game: some fields are read hundreds of times a second. When the list has stopped growing, **Sweep unseen** keeps looking at only what has not shown up, a few pieces at a time in turn; the game runs at full speed, and the price is that a field touched once can be missed.

Lines called `(unnamed)` are bytes the game used that no field in the list covers.

## 2. Watch methods

**Where:** a field view > **Methods** (ZR+R) > **Watch methods** (ZL + left stick click).

The Methods list needs the class, not an instance: a field view titled `[runtime]` has it. gen2 puts a break on the first instruction of every method in the list. A method is marked `called` at its first call and never stops the game again, so the whole run costs one short stop per live method.

A name in a class is no proof the code runs. Before putting time into hooking `get_Health`, see whether it is ever called.

| Button | Key | What it does |
|---|---|---|
| Start / Stop | R | run or end the watch (Stop takes every break off) |
| Clear | Minus | start again with every method waiting |
| View | ZL+Y | all > called, newest first > not called |
| ASM Explorer | X | the method's code |
| Go to caller | ZL+X | the code that made its first call |
| Field view of object | Y | the object it was first called on, in a field view |
| Break on object | ZL+R | break on this method for that object (section 3) |
| Close method watch | ZL+Plus | stop and get the ordinary gen2 menu back |
| Pre results / Next results | ZL + right stick left / right | step through the saved runs (section 5) |
| Expand screen | ZR+R | the list over the whole width |

Each line reads `called`, `-` (not called so far), `overwritten` or `not set`, then the method, the object it was called on, and its first caller.

- **Clear, then one action** in the game: the called methods are what that action ran. Often the shortest way to the function that applies damage or spends ammo.
- **The object** on a called line is a live instance of the class, found with no search. Static methods have none.
- **`-` is about the call only.** Small getters are often built into their callers, so the value is read with no call. Watch fields answers whether the data is used.
- **`overwritten`** means something else rewrote the method's first instruction during the run, which an enabled cheat hooking that method does. Whether it was called is then not known.
- A run holds 384 methods.
- The breaks are real changes to the game's code until the watch is stopped. Stop it (or Close) before doing anything else with a debugger.

## 3. Break on one object

A class is shared: `ReceiveDamage` runs for the hero and for every enemy. To trace it at work on the hero only:

1. Open the field view with the hero's object pinned.
2. **Methods** (ZR+R), cursor on the method.
3. **Break on pinned object** (ZL+X).
4. Go back to the game. It stops when that method is called on the pinned object, and the Break and Trace view opens with the registers and stepping, as for any Break and Trace.

With no instance pinned the button reads **Break on call** and stops at the next call on any object. From a method watch, **Break on object** (ZL+R) does the same for the object shown on that line.

How it works: at a method's first instruction register X0 holds the object the method was called on. The break is at that instruction, and gen2 lets every hit pass where X0 is not your object.

- Every call still reaches the breakpoint and costs a moment, matching or not. On a method called thousands of times a second the game slows while the break is set.
- A static method has no object; the break is on any call.
- One break at a time, as with Break and Trace.

## 4. Code watch: which classes ran?

**Where:** gen2 menu > **Code watch** > **Start**. It needs the game's function map (Unity menu, or it is already there if you have used the Methods list).

Watch methods needs a class. Code watch finds the class: it puts the same one-shot break on every function in the function map. The code that runs all the time is called in the first seconds, each function stopping the game once, so the game stutters for a few seconds and then plays at full speed.

1. **Start**, go back to the game, and wait until the box at the top left stops counting.
2. Open Breeze and press **Mark** (Y).
3. Do one thing in the game: take a hit, fire, open a chest.
4. Open Breeze. The list shows the classes with a function called for the first time since the mark, the most first.
5. **Select** (X) a class to see its functions and who called each. **Watch methods** (ZL + left stick click) stops the code watch and starts a method watch on that class, which gives you the live objects.

| Button | Key | What it does |
|---|---|---|
| Start / Stop | R | run or end the watch (Stop takes every break off) |
| Mark | Y | from now on `new` counts only functions first called after this |
| Clear | Minus | every function waiting again |
| View | ZL+Y | new since the mark > called |
| Select | X | a class: its functions; a function: its code |
| Go to caller | ZL+X | the code that made the function's first call |
| Watch methods | ZL + left stick click | stop, and method-watch this class |
| Watch | ZL+Up | the game's own code > everything in the map; applies at the next Start |
| Close code watch | ZL+Plus | stop and get the ordinary gen2 menu back |
| Expand screen | ZR+R | the list over the whole width |

- **The game's own code** leaves out the runtime and the engine (`System`, `UnityEngine`, `Unity` and the like): fewer functions, less stutter, and the classes you are after.
- A function that ran before the mark is not new. If the action has already happened once, **Clear**, wait for the count to settle, **Mark**, and do it again.
- Stop writes `code_watch.txt` in the game's Breeze folder: every called function in the order of the first calls.
- The list on screen is kept until Breeze is restarted; the file stays.

## 5. Getting back, and saved runs

While a watch runs, the gen2 menu button opens that watch's screen. Once it is stopped the gen2 menu is the gen2 menu again, and two buttons there lead back: **Field watch** and **Method watch**.

Every watch is kept when it is stopped, as the gen2 menu keeps its captures. On either screen **Pre results** steps back through the saved runs and **Next results** forward; past the newest, Next results returns to the current watch. The title shows which run is on screen (`Method watch 3/4: ...`) and the status line reads `[Saved run]`.

- Opening a screen when gen2 has since been used for something else shows the newest saved run.
- A run that only added to the one before it (stop, sweep, stop again on the same object; more calls on the same method list) replaces it. A different object, a different list, or a Clear followed by one action is a run of its own.
- A saved run is a record: Clear, Mark seen, Sweep and Read / Write do nothing on it. **Start** watches it again and makes it the current run.
- A run from an earlier launch of the game reads `[Saved run, earlier launch]`. Its field list and its called methods are still right. Its addresses are not: a field watch shows no values and cannot be started again from it, and a method watch shows no objects. Its methods can be watched again, since they are places in the game's code.
- The runs are small text files in `field_watch_history` and `method_watch_history` in the game's Breeze folder.

---

## What has been tried on a console

On The Walking Dead: Streets of Survival (Unity):

- Watch fields on the player's stats: 23 of 72 fields with read and write, 4 with write only; Sweep unseen then found more at 2 stops in 31 seconds, against 350 to 480 a second for the full watch.
- Watch methods on the stats class: 6 of 61 methods called in 10 seconds standing still, each with its caller and its object (the player's for two, an enemy's for four). After Stop none of the 61 held a break.
- The Method watch screen: View, and Field view of object, which opened the enemy's object.
- Saved runs: two method watches and a field watch were stopped and kept; with gen2 holding the field watch, the Method watch button opened `Method watch 4/4`, Pre results and Next results stepped through all four, and Next results past the newest returned to the current watch. Expand screen widened the list from 550 to 1180 pixels on both screens.
- Break on one object: a break on `get_IsDead` (called for every character) with the player's stats object stopped three times out of three with that object, and never with another.

- Code watch: 39,557 functions (the game's own code) armed in 0.7 seconds; about 2,000 were called in the first ten seconds and then the count stood still. After Mark, 0 new in six seconds; the first button press after it showed 508 new functions in 165 classes (the game noticing a controller), and the next press 1. The whole map, 106,022 functions, armed in 2.1 seconds. Select on a class, and Watch methods from it, opened the method watch with its objects. After Stop no break was left in the game's code.

Driven over PC connect rather than by hand, and not yet pressed on a console: the **Watch methods** and **Break on pinned object** buttons of the Methods list, **Break on object** on the Method watch screen, and **Watch fields** in the Unreal UObject view.
