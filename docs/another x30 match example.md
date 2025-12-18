# Finding Caller Identification (x30) for Shared Functions

This guide explains how to find a caller's identification (the saved `x30` value) to target a specific memory address of interest. This is particularly useful when the memory is accessed by a utility function that is shared by many different entities.

### Steps

1.  **Watch the Target Code**
    First, watch the line of code that accesses the target address. Set `stack_check` to the maximum supported value (e.g., 5). This watch will capture every time this code line accesses memory. Depending on how many entities use this utility function, you may get many hits.
  
2.  **Identify the Correct Access**
    You must have a way to identify which captured access is your target. Often, the value itself is unique, making it easy to spot. If not, you'll need to check the address to find the correct one.

![2025121813583600-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/58e0172d-0f1e-4de2-8621-077e37839505)
    
![2025121814002300-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/b2b507d9-7c46-431b-b878-bb2f1c0426fb)

4.  **Analyze Captured Data**
    Press the "More" button (default: `ZR` + `D-Pad Down`). You can then use the "Sort" button (also `ZR` + `D-Pad Down`) to sort the list. This will show you how many unique combinations of `x30` and stack values were captured for the address.

6.  **Find a Unique Identifier**
    Next, use the "Find Unique" button (`ZR` + `D-Pad Left`) to find an `x30` or stack value that is unique to the lines accessing your target address.

![2025121814015700-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/d6dda77f-d3be-4058-abd3-0c4e20fea30a)

![2025121814020900-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/cf444c30-8d80-4995-92c5-89eb59201a40)

![2025121814032900-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/9c2425c8-e987-4697-a684-a2d41b7b16e3)

7.  **Select the Identifier**
    Use the "Cursor Left" and "Cursor Right" buttons to navigate to the `x30` or stack value; `[]` brackets will enclose your selection of stack value when there is no `[]` the x30 value is selected. The status line on the right panel will show "Count=", indicating how many times the selected value has occurred in the capture session. A large count generally indicates that a cheat using this condition will execute at a higher frequency. The default sort of the x30 is lower address first, use the sort by count button to sort it by count, the stack value is sorted by lower offset from SP.

8.  **Create the Assembly Match**
    Use the "Make Match 1" button to create an assembly template. This template will include the necessary condition to match the `x30` or stack entry you selected.



