# Focus Mode Guide

Focus Mode is a powerful interface customization feature in Breeze designed to streamline your workspace and boost efficiency. 

By hiding unnecessary or advanced buttons and displaying only the actions you use most, Focus Mode reduces visual clutter so you can focus entirely on the task at hand.

---

## 🎯 Purpose of Focus Mode

As Breeze has evolved, many advanced menus have grown to include numerous buttons and options. Focus Mode lets you:
- **Reduce Cognitive Load**: Limit the buttons shown to only those relevant to your current workflow.
- **Speed Up Navigation**: Access your most frequent actions quickly without scanning through complex options.
- **Personalize Every Screen**: Customize the button layout for *each individual menu* in the application.

---

## 🛠️ The Focus Manager

The **Focus Manager** is your control center for managing, customizing, saving, and loading focus profiles.

### How to Access the Focus Manager and toggle between Focus Mode and Normal Mode
1. **Shortcut Key**: By default, press **`L + ZR`** (the **Focus Manager key**) from any menu to open the Focus Manager Menu directly.
   > [!TIP]
   > You can customize this shortcut under the **Settings Menu** by remapping the **Focus Manager key**.
2. **Mode Toggle**: You can use the **`Normal/Focus toggle`** button which has the same default keys that calls up Focus Manager switch between focus mode and normal mode. Normal mode let you see all the buttons available.

---

## ✍️ Customizing Your Buttons: The Magic of `Lock focus = 0`

Breeze makes defining your focus layout incredibly simple. Instead of selecting buttons from a tedious list, you can add them dynamically by simply using them.

> [!IMPORTANT]
> When **`Lock focus = 0`** (unlocked), using or pressing any button in **Normal Mode** will automatically add that button to your focus list for that specific menu.

### Step-by-Step Guide to Customizing Your Layout:
1. Open the Focus Manager by pressing **`L + ZR`**.
2. Set **`Lock focus = 0`** (unlocked) and **`Focus edit = 1`** (edit mode enabled).
3. Return to the menu you want to customize and switch to **Normal Mode** (so you can see all available buttons).
4. **Press/Activate the buttons** you wish to include in your Focus Mode list. Because `Lock focus` is set to `0`, simply using these buttons adds them to the list!
5. To remove any button, highlight it and press the **`FocusMode_EraseKey`** (configurable in Settings), or toggle **`Focus edit`** to delete unwanted items.
6. Once satisfied, return to the Focus Manager and set **`Lock focus = 1`** to lock your layout and prevent accidental modifications.
7. Save your layout using **`Save focus`** (to update your current profile) or **`New focus`** (to save as a new file).

---

## 🔄 Resetting to Defaults (Tutorial Troubleshooting)

If you are following a tutorial (such as the *Basic* or *Advanced Cheat Making Tutorials*) and cannot find a button mentioned in the instructions, you may have hidden it in Focus Mode or configured custom layouts.

> [!WARNING]
> To ensure all buttons are visible and match the tutorial screenshots/steps, reset your layout to the factory default.
>
> To do this, open the **Focus Manager Menu** and select **`Clear focus`**. This will clear all custom button lists and return every menu to its default configuration.
