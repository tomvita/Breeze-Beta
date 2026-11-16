# SpongeBob SquarePants: The Cosmic Shake -- health, glide, moon jump, jelly, doubloons, abilities, speed

Made on Nov 16 2026 with the game running in Lichii, through Breeze Studio's Unreal object
reader (`studio/studio_ue.py`) and PC connect. No Switch was used.

| | |
|---|---|
| Title ID | `01009FB0172F4000` |
| Build ID | `F712547C68C66A0A` (1.0.7) |
| Engine | Unreal Engine 4.27, PhysX, Box2D, NVN |
| Nintendo SDK | 14.3.0 |
| Cheat file | `sdmc:/switch/breeze/cheats/01009FB0172F4000/F712547C68C66A0A.txt` |

All `M+` offsets are main-module offsets.

## The cheats

```
[Infinite health]
580F0000 08402A18
580F1000 00000180
580F1000 00000038
580F1000 00000000
580F1000 00000030
580F1000 000002A8
580F1000 000005A8
580F1000 00000140
580F1000 00000008
540E2F00 00000048
A4EF0200 00000038
A4EF0200 0000003C

[Infinite glide]
580F0000 08402A18
580F1000 00000180
580F1000 00000038
580F1000 00000000
580F1000 00000030
580F1000 000002A8
580F1000 000005A8
580F1000 00000140
580F1000 00000018
540E2F00 00000038
A4EF0200 00000048
A4EF0200 0000004C

[Moon jump (hold ZL+B)]
80000102
580F0000 08402A18
580F1000 00000180
580F1000 00000038
580F1000 00000000
580F1000 00000030
580F1000 000002A8
580F1000 00000290
400E0000 00000000 447A0000
A4EF0200 000000CC
400E0000 00000000 00000003
A1EF0200 00000168
20000000

[Jelly 99999]
580F0000 08402A18
580F1000 00000180
580F1000 000000F0
580E2F00 00000168
580F1000 00000170
580D2F00 00000010
C085E5D0
400E0000 00000000 0001869F
A4EF0200 00000104
20000000

[Doubloons 999]
580F0000 08402A18
580F1000 00000180
580F1000 000000F0
580E2F00 00000168
580F1000 00000170
580D2F00 00000010
C085E5D0
400E0000 00000000 000003E7
A4EF0200 00000108
20000000

[All abilities unlocked]
580F0000 08402A18
580F1000 00000180
580F1000 000000F0
580E2F00 00000168
580F1000 00000170
580D2F00 00000010
C085E5D0
400E0000 00000000 FFFFFFFF
A4EF0200 000001C8
20000000

[Run speed x1.5]
580F0000 08402A18
580F1000 00000180
580F1000 00000038
580F1000 00000000
580F1000 00000030
580F1000 000002A8
580F1000 00000290
400E0000 00000000 44A8C000
A4EF0200 0000018C
```

| Cheat | Writes | Measured in the running game |
|---|---|---|
| Infinite health | Health (base and current) = MaxHealth, float | health set to 2 by hand came back to 4 |
| Infinite glide | GlideTimeLeft (base and current) = MaxGlideTime, float | 1 came back to 5 |
| Moon jump (hold ZL+B) | Velocity.Z = 1000.0, MovementMode = 3 (Falling) | a copy without the key line raised SpongeBob 980 units in 1.2 s; he fell back and landed. The key itself was not pressed |
| Jelly 99999 | `PersistentPlayerData.JellyBeans`, int | 0 became 99999 in memory (put back to 0 after) |
| Doubloons 999 | `PersistentPlayerData.Doubloons`, int | 0 became 999 in memory (put back) |
| All abilities unlocked | `PersistentPlayerData.UnlockedAbilitiesFlags` = FFFFFFFF | the word was written (put back to 0). Not tried in play |
| Run speed x1.5 | CharacterMovement MaxWalkSpeed 900 -> 1350 | the value held for a second with the game running. Not tried in play |

Not checked in play: what the counters on screen show after the jelly and doubloon writes (the
game redraws them from its `OnItemAmountChanged` event, which a memory write does not raise),
and whether the abilities work at once or after the next level load.

## The route to the player

```
M+8402A18 (GWorld) -> +180 OwningGameInstance -> +38 LocalPlayers -> +0 [0]
  -> +30 PlayerController -> +2A8 AcknowledgedPawn (BP_SinglePlayerSpongeBob_C)
       +290 CharacterMovement (CS_CharacterMovementComponent)
              +C4  Velocity, 3 floats (Z at +CC)
              +150 GravityScale   +158 JumpZVelocity (1300)   +168 MovementMode (u8)
              +18C MaxWalkSpeed (900)
       +5A8 AbilitySystemComp -> +140 SpawnedAttributes (array of sets)
              [0] CS_PlayerAttributeSet        ammunition, slide speeds
              [1] CS_PlayerHealthAttributeSet  Health +30, MaxHealth +40
              [2] PL_MovementAttributeSet      MaxWalkSpeed +40, JumpZVelocity +60, GravityScale +A0
              [3] CS_GlideAttributeSet         MaxGlideTime +30, GlideTimeLeft +40
```

A `GameplayAttributeData` is 0x10 bytes: BaseValue (float) at +8, CurrentValue at +C. Writing
MaxWalkSpeed in the movement attribute set does not reach the movement component (it copies
the attribute only when the game's own code changes it), so the speed cheat writes the
component.

## The save data

`CS_PersistenceSystem` is a game-instance subsystem; no reflected property points at it. The
game finds it in the game instance's subsystem map (`GameInstance + E0`, the map's entries at
`+F0`, 0x18 bytes each: class, object, hash links). It is entry 15, so the object is at
`[[GameInstance + F0] + 170]` and its class at `+168`. The three save cheats compare that class
with the object's own class and write nothing when they differ.

```
CS_PersistenceSystem
  +100 PersistentPlayerData
         +104 JellyBeans (int)      +108 Doubloons (int)     +10C Tier (int, the shop's)
         +110 OwnedCostumes (array of soft class paths, 0x28 each)
         +120 MaxHealth (u8)        +1C8 UnlockedAbilitiesFlags (bit n = ability n)
         +310 Playtime (float)
  +3D8 CurrentCostume (class)
```

Ability numbers (`ECS_UnlockableAbilityTypes`): 1 SpinAttack, 2 GroundPound, 3 GrandSlam,
4 Seahorse, 5 BubbleShoot, 6 Surfboard, 7 Karate, 8 DodgeRoll, 9 Unicycle, 10 Slingshot,
11 LassoSwing, and more after it.

## The game's own cheat code

The shipped game still has its developers' cheat manager. These are the functions behind it,
for a later cheat that calls them (none does yet):

| Function | Does |
|---|---|
| `M+E70804` (x0 = persistence system) | unlocks every costume |
| `M+F2B9C0` (x0 = persistence system, w1 = flags) | sets the abilities word and raises the event; the cheat manager passes -1 |
| `M+F2B84C` (x0 = persistence system, w1 = ability number) | unlocks one ability |
| `M+F10848` | returns the persistence system |

Costumes are not a cheat here: the list is an array of asset paths, which a pointer cheat
cannot build. With the doubloon cheat on they can be bought in the shop.
