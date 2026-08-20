# Breeze beta114.00

This release makes Unity/IL2CPP object lists much easier to inspect and
substantially speeds up runtime function-map generation.

## What's new

- **Extract fields into object-list rows:** In Class Field View, highlight a
  class-pointer row and press **Extract** (`Minus + ZL`). Pick the fields that
  identify the object, then go back. Breeze will show those values inline for
  every object of that declared type. Your choices are saved automatically per
  title in `field_extract.txt`.
- **Readable managed strings:** `System.String` fields now show their text
  directly in Field View. UTF-8 output preserves Chinese, Korean, and other
  non-ASCII characters, and null strings are clearly shown as `(null)`.
- **Faster IL2CPP function maps:** Runtime layout discovery is cached and the
  scan uses batched reads and time-based pacing. Building an **IL2CPP map** now
  performs far fewer process-memory reads while keeping the UI responsive.

## Fixes

- Fixed arrays and `List<T>` backing arrays of class objects being walked with
  the size of the class instead of the size of a pointer. Object entries now
  appear at the correct eight-byte stride and open through **View class** as
  expected.
- Extracted values written with **Write to file** are now included in
  `field_view.log`.

## Using Extract

1. Open a Class Field View containing an object pointer, such as an item in a
   `List<Item>`.
2. Press **Extract** (`Minus + ZL`) on that row.
3. In the `[Extract pick]` view, press **Extract** on each field you want shown;
   selected fields are marked with `*`.
4. Press **Back**. The selected values will now appear on every row of that
   declared object type.

Press **Extract** again to change the selection. Delete `field_extract.txt`
from the title's Breeze directory to clear all saved selections.

