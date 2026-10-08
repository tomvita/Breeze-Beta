# Walkthrough: two cheats with the Unity menu

This walkthrough makes two cheats for a Unity game using only **Main > Unity**:
**money**, which the game keeps in a list, and **HP**, a field of the player's
object. There is no memory search to start from and no pointer search: you find
the value by its name, pick the right object, and let Breeze build the pointer
chain.

The example game is **Graveyard Keeper 2** (1.0.2). The names are that game's,
but the steps are the same in any IL2CPP game; only the class and field names
change. Every step and result below was done on a Switch.

## Before you start

- The game is running and past its loading screens, with Breeze attached (open
  Breeze from the game as usual).
- The two maps are built once per game version. **Main > Unity > IL2CPP map**:
  press **Build / Abort** (the function map), wait for Complete, then **Build
  field map** (Y). On Graveyard Keeper 2 the field map takes about 70 seconds,
  and the screen does not respond for the first 20 of them. The Unity menu
  shows "Maps ready" when both are there.

Three terms used below:

- A **class** is a kind of object (`HPComponent`); a **field** is a value in it
  (`hp`).
- **Instances** are the live objects of a class. A game can have hundreds: every
  enemy and crate with health has its own `HPComponent`.
- A **chain** is the path from a fixed place in the game's code to the object,
  which is what makes a cheat keep working after the game or console restarts.

---

## Cheat 1: Money

The coin counter at the bottom of the Character screen shows **1**. The game
stores money as a number of coppers, so 1 on screen is **100** in memory.

### 1. Find the field by name

**Unity > Usual suspects** lists number fields whose names contain words like
money, gold, hp or energy. Money in this game is not a field called "money":
it is one entry in the player's list of resources, and each entry is a
`GameResAtom` with a name (`type`) and a `value`. So search for that.

**Unity > Search maps**, type `GameResAtom::value`:

```
LazyBearTechnology.GameResAtom::value +0x18 float
```

(If you do not know the class, search for part of a likely name, like `Res`,
`Money` or `Wallet`, and open the classes that look right; the field view shows
every field with its live value.)

### 2. List the live objects

Select the row and press **Open** (X). Because `value` is not a static field,
this lists every live `GameResAtom` with its `value`. Graveyard Keeper 2 has
1,538 of them; the scan takes a few seconds.

### 3. Pick out the money one

1,538 rows are too many to read, so let the normal search narrow them:

1. **Save candidates** (+). This writes `/switch/Breeze/unity_value.dat`, one
   entry per object, with its current value.
2. Go back to Main, open **SearchManager**, select **unity_value**, and
   **Continue search** with **==** and the value you know (100, for 1 on
   screen).
3. Change your money in the game (buy or sell something) and continue again
   with the new value, or with **changed**. Repeat until one or two are left.
4. On **Show Candidates**, select the one left and press **Find chain**
   (Y+ZR) right there: it works out which object the address belongs to and
   goes straight to step 4. (Or come back to the instance list, Unity > Search
   maps > Open again, and press **Keep searched** (-) to see only the objects
   left in your search.)

Many values can be the same number, so look at the names: for a class with a
name field (`GameResAtom` has `type`), the instance list shows it after the
value, `value = 100 [money]`, and the chain screen's title shows it too. On
Graveyard Keeper 2 an `== 100` search left ten resources holding 100: nine
reputations and scores, and a `money` that belongs to something other than the
player. Only the player's own resources have a chain from a static, so *Find
chain* finding nothing is a sign you picked the wrong one.

If you already know the address (for example from Memory Explorer), **Go to
address** (L) selects that object directly.

### 4. Let Breeze find the chain

With the money object selected, press **Find chain** (R). It searches from the
game's static fields through the fields the field map describes, including
lists, and shows the shortest chains:

```
MainGame.PlayerData > res > resValues[0]
```

That reads: the game's `MainGame` holds `PlayerData`, which holds `res`, whose
list `resValues` has money at position 0. It took 2.7 seconds.

### 5. Make the cheat

**Make cheat** (X) writes the value the field has **right now**, every time the
cheat runs. To get a different amount, set it first: on the instance list,
**Field view** (X) opens the object, where you can edit `value` (for example
to 1000000, which shows as 10000 coins), then come back to the chain and press
**Make cheat**. Give it a name when asked.

Because the chain goes through a list position, Breeze adds a **name check**:
the cheat only writes if the object at `resValues[0]` is still called "mo..."
(money). In another save the list could be in a different order, and the check
makes the cheat do nothing instead of changing the wrong resource. The message
says what it checks:

```
Added cheat: Money (disabled; enable it in Cheats) - checks the name starts "mo"
```

### 6. Turn it on and keep it

The cheat is added **switched off**. Open **Cheats**, turn it on, and check
the coin counter. To keep it for next time, use **Write Cheat to file** (and
**Write Cheat to atm** if you want it without Breeze).

On the Switch: with money set to 500 by hand, turning this cheat on wrote
1,000,000 back straight away.

---

## Cheat 2: HP

The player has 100 HP (the game's full health).

### 1. Find the field

**Unity > Usual suspects** lists `hp` fields, or **Search maps** `HPComponent::hp`:

```
HPComponent::hp +0x3C int
```

### 2. List the live objects

Select it and press **Open**. There are 1,227 `HPComponent`s: every creature and
breakable object has one.

### 3. Pick out the player's

1. **Save candidates**: writes `unity_hp.dat`.
2. **SearchManager**: continue `unity_hp` with **==** 100.
3. Take a little damage in the game, then continue with **decreased** (or ==
   the new value). Repeat once or twice.
4. On **Show Candidates**, select it and press **Find chain** (Y+ZR), or go
   back to the instance list and press **Keep searched**.

### 4. Find the chain

**Find chain** on the player's object:

```
MainGame.PlayerData > hpComponent
```

### 5. Make the cheat

Heal to full first (or set `hp` in the **Field view**), then **Make cheat**.
The cheat keeps writing 100, so HP stays full. No name check this time: the
chain does not go through a list.

### 6. Turn it on

As for money: **Cheats**, turn it on, save it to file.

---

## When something does not work

| You see | What it means |
|---|---|
| "Maps ready" missing | Build both maps first (IL2CPP map). |
| "Class not loaded yet" or "has no slot yet" | The game has not used that class yet. Play a little further, then rebuild the field map. |
| **Find chain** finds nothing | First check the name in the title: it may be a different object with the same value (a price instead of your money). Otherwise the object is reached through something Breeze does not walk yet (a dictionary, or more than three objects deep); use **Bookmark field** for this session, or the normal pointer search. |
| The cheat changes nothing | Check it is switched on. For a cheat through a list, the name check may have failed: another save may order the list differently. Make the cheat again in that save. |
| The value snaps back in the game | Some values are recalculated every frame from somewhere else. Look for the field the game reads, or use a code cheat: **Search maps** the method that changes it (for example `PlayerEnergyGameResSystem::Add`) and **Hook template**. |

## Other ways in

- **From any field view**: press **Find chain** (Down+ZR) on a row. On a value
  row (an item's `count`) it chains to that object with the field ready for
  *Make cheat*; on a pointer row it chains to the object it points at. This is
  the quickest way to an inventory cheat: open the item from the bag's list,
  select `count`, *Find chain* gives `MainGame.PlayerData > inventory >
  inventoryItem > inventory[1]`, then *Make cheat*.

- **Statics**: a field marked `[static]` in the results needs no instance at
  all. Select it and press **Make cheat** or **Bookmark static** straight away.
- **Singletons** lists each class's `Instance`-style static, the usual place
  a game keeps its managers; open one to browse from there.
- **Hook template** on a method (a `[method]` row from Search maps) makes the
  starting point for a code cheat: the cheat on the method's first instruction
  plus a script to fill in with **Edit Cheat > Add ASM**.

See `UnityGuide.md` for every button, and the Graveyard Keeper 2 notes in the Breeze source repository for how
the same cheats were first made by hand.
