# Example: Creating a "Moon Jump" Cheat with x30 Match

This guide demonstrates how to create a "moon jump" cheat for *Adventure of Samsara 0.22.19e* (TID: 010038701F412000, BID: 03802B9F8E7DC2D8) using the `x30` register matching method. This method is used to isolate and modify a specific memory address (like Y velocity) when the instruction that writes to it is too generic and is used for other purposes as well.

This example assumes you have already identified the memory address that controls the player's Y velocity.

## Steps

1.  **Set a Breakpoint:**
    In Breeze's memory explorer, navigate to the target address for the player's Y velocity. Place the cursor on it and click the **Set Breakpoint** button.
    ![setbreakpoint](https://github.com/user-attachments/assets/0dfeeb31-22d4-47fc-9ee9-1d9fc966dc8e)

2.  **Create a Memory Watch:**
    The Gen2 Menu will appear. Click **Gen2Attach**, then **Name and Execute**. Name this watch "moonjump" to identify it.
   ![watch moonjump](https://github.com/user-attachments/assets/46ae39bc-83ee-4038-9d23-8f1eaa112124)

3.  **Analyze Memory Access:**
    Return to the game and make the character jump a few times. This will trigger the breakpoint. Go back to Breeze and press the **Gen2Detach** button to see a list of instructions that accessed the address.

4.  **Identify a Hook Instruction:**
    From the list, select an instruction that accesses the address. The ideal instruction is one that *only* accesses the Y velocity and nothing else. If you find such an instruction, you can use it as a direct hook. However, often the instruction is generic and accesses many different addresses. In that case, proceed to the next step to see if x30 match can be used to make the distinction.
    ![select instruction to watch](https://github.com/user-attachments/assets/e113cf94-65ab-4c26-862e-3f0524907d8e)

5.  **Create an Instruction Watch:**
    Click **Watch Instruction** to monitor when this specific instruction is executed.
    ![watch instruction](https://github.com/user-attachments/assets/2ad8f3d3-1116-4b68-92f4-62d8c6ef03ae)

6.  **Execute the Instruction Watch:**
    Click **Gen2Attach**, then **Name and Execute**. Let's name this new watch "moonjump1".
   ![moonjump1](https://github.com/user-attachments/assets/05780a5d-a7f3-47cc-8ec4-e2dfae361fba)

7.  **Gather Instruction Hits:**
    Go back to the game and jump again. Return to Breeze. You should now see multiple hits for the "moonjump1" watch, indicating the instruction access more than the address we want to hack.
    ![15 hits](https://github.com/user-attachments/assets/5961846a-3655-4304-9796-fbe993038454)

8.  **Refine with x30 Match:**
    Since the instruction we are watching is generic, we need a way to distinguish when it's accessing our target Y velocity versus other data. We can achieve this by using the `x30` register. The `x30` register holds the return address of the function, allowing us to identify the "context" of the memory access. By matching this context, we can create a cheat that only activates when the Y velocity is being modified during a jump.

    Execute the "moonjump1" watch again, but this time with `Next stack_check=5`. This tells Breeze to inspect the call stack.

9.  **Locate the Target Address in the Stack:**
    To make the target address easier to find, you can freeze the game mid-jump. With the watch results displayed, set the offset to `44`. This specific hook loads two registers and our target is the second one so we need to adjust the offset that Breeze set automatically.
    ![2025090810100700-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/84ba5f16-cf27-440c-a396-f099c1d5e9c9)

10. **Find the Correct Value:**
    Look through the captured values to find the address you are targeting.
   ![2025090810091400-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/36b1f3c6-301b-4b0c-a1f2-f1d5a3f3f6b5)

11. **Sort and Isolate a Unique Value:**
    If there are many hits, sorting the results make it easier to find the unique x30 value that corresponds only to the jump action.
    ![2025090810112100-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/c5b92361-fb94-4145-b782-88b7880c7646)

    After sorting, it's still hard so we use find unique to screen out x30 values that also appears when other address is being accessed
   ![2025090810121000-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/1554e02e-97e0-4c04-8696-31082c93aa90)

12. **Test Different x30 match candidates:**
    Select the line and select the column using `Next stack_check` value. Generate the asm code with "make match 1". Test to see if you have the cheat that you want. 
   ![2025090810131500-CCFA659F4857F96DDA29AFEDB2E166E6](https://github.com/user-attachments/assets/035236da-3db7-4307-b466-1655763c7813)

   
