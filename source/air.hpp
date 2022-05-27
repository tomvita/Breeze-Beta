/*
 * Copyright (c) 2021 Tomvita
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include "ui.hpp"
#include "dmntcht.h"
#include <string>
namespace air {

    static const std::vector<u32> buttonCodes = {0x80000040,
                                                 0x80000080,
                                                 0x80000100,
                                                 0x80000200,
                                                 0x80000001,
                                                 0x80000002,
                                                 0x80000004,
                                                 0x80000008,
                                                 0x80000010,
                                                 0x80000020,
                                                 0x80000400,
                                                 0x80000800,
                                                 0x80001000,
                                                 0x80002000,
                                                 0x80004000,
                                                 0x80008000,
                                                 0x80010000,
                                                 0x80020000,
                                                 0x80040000,
                                                 0x80080000,
                                                 0x80100000,
                                                 0x80200000,
                                                 0x80400000,
                                                 0x80800000};

    static const std::vector<std::string> buttonNames = {"\uE0A4 ", "\uE0A5 ", "\uE0A6 ", "\uE0A7 ", "\uE0A0 ", "\uE0A1 ", "\uE0A2 ", "\uE0A3 ", "\uE0C4 ", "\uE0C5 ", "\uE0B3 ", "\uE0B4 ", "\uE0B1 ", "\uE0AF ", "\uE0B2 ", "\uE0B0 ", "\uE091 ", "\uE092 ", "\uE090 ", "\uE093 ", "\uE145 ", "\uE143 ", "\uE146 ", "\uE144 "};
    static const std::vector<std::string> buttonNames2 = {"\uE0A0 ", "\uE0A1 ", "\uE0A2 ", "\uE0A3 ", "\uE0C4 ", "\uE0C5 ", "\uE0A4 ", "\uE0A5 ", "\uE0A6 ", "\uE0A7 ", "\uE0B3 ", "\uE0B4 ", "\uE0B1 ", "\uE0AF ", "\uE0B2 ", "\uE0B0 ", "\uE091 ", "\uE092 ", "\uE090 ", "\uE093 ", "\uE145 ", "\uE143 ", "\uE146 ", "\uE144 "};
    struct gFileEntry {
        char name[128];
        char dir[128];
        unsigned char d_type;
        // bool picked = false;
    };

    enum class Menu_id
    {
        Main,
        Cheat,
        Search,
        SearchManager,
        Setting,
        EditCheat,
        MemoryExplorer,
        Sysmodule,
        pointersearcher,
        bookmark,
        candidate,
        Download,
        Gameinfo,
    };
    struct ButtonEntry
    {
        std::string label = "";
        u32 ButtonId = 1;
        HidNpadButton keycode = HidNpadButton_Verification;
        bool enable = true;
    };
    struct DataEntry
    {
        char data[200];      
    };
    class BreezeActions;
    struct Air_menu_setting
    {
        Menu_id menuid;
        void (*action)(u32, u32);  //(u64 keycode, Button *activated_button)
        BreezeActions *_action = nullptr;
        std::shared_ptr<BreezeActions> action2 = nullptr;
        float xoffsetL = -315.0f;   // take priority over xoffset2 when there isn't enough space xoffset2 will be shifted and the right panel shrinks
        float xoffsetR = 315.0f;   // these are xoffset and xoffset2 are offsets from the center of the screen for left panel and right panel, bottom panel have zero offset and take whole screen width.
        u32 num_button_column = 1; // keep button rows less than 8 by expanding number of columns
        u32 num_data_column = 1;   // for two data columns button panel go to bottom of screen, otherwise button window is the right panel.
        float WindowWidth = 400.0f;     
        std::string left_panel_title = "";
        std::string right_panel_title = "";
        std::string left_panel_status = "";  // status text when not empty will be displayed below panel title
        bool show_left_panel_index = true;
        std::string right_panel_status = ""; // status text when not empty will be displayed below panel title
        float font_size_left_panel_status = 18.0f;
        float font_size_right_panel_status = 18.0f;
        std::vector<ButtonEntry> actions = {};
        u32 button_selected = 2;
        bool show_leftpanel_status = false;
        bool show_rightpanel_status = false;
    };

    class MessageMenu : public AlertMenu {
       private:
        static constexpr u32 ExitButtonId = 0;

       public:
        MessageMenu(std::shared_ptr<Menu> prev_menu, const char *text, const char *subtext, Result rc = 0);

        virtual void Update(u64 ns) override;
    };
    class WaitforkeyMenu : public AlertMenu {
       private:
        static constexpr u32 ExitButtonId = 0;
        u32 m_keycount = 2;
        u32 m_id;
        void (*m_action)(u32, u32);
       public:
        WaitforkeyMenu(std::shared_ptr<Menu> prev_menu, const char *text, u32 keycount, void (*action)(u32, u32), u32 id, const char *subtext = "", Result rc = 0);

        virtual void Update(u64 ns) override;
    };
    class WaitforkeyMenu2 : public AlertMenu {
       private:
        static constexpr u32 ExitButtonId = 0;
        u32 m_keycount = 2;
        u32 m_id;
        BreezeActions * m_action;
        // void (*m_action)(u32, u32);

       public:
        WaitforkeyMenu2(std::shared_ptr<Menu> prev_menu, const char *text, u32 keycount, BreezeActions * action, u32 id, const char *subtext = "", Result rc = 0);

        virtual void Update(u64 ns) override;
    };
    class WaitforcompletionMenu : public AlertMenu {
       private:
        u32 m_id;
        bool m_do_once = true;
        void (*m_action)(u32, u32);

       public:
        WaitforcompletionMenu(std::shared_ptr<Menu> prev_menu, const char *text, void (*action)(u32, u32), u32 id, const char *subtext = "", Result rc = 0);

        virtual void Update(u64 ns) override;
    };
    // class SelectMenu : public Menu {
    //    private:
    //     u32 N;
    //     static constexpr float WindowWidth = 610.0f;
    //     static constexpr float xoffset = -320.0f;
    //     static constexpr float TitleGap = 90.0f;

    //    public:
    //     SelectMenu(std::shared_ptr<Menu> prev_menu);

    //     virtual void Update(u64 ns) override;
    //     virtual void Draw(NVGcontext *vg, u64 ns) override;
    // };
    class AirMenu : public Menu
    {
    private:
        int N = 3; // total number of boxes
        static constexpr u32 ToggleCheatButtonId = 0;
        static constexpr u32 AddConditionalkeyButtonId = 1;
        static constexpr u32 RemoveConditionalkeyButtonId = 2;
        static constexpr u32 ExitButtonId = 3;
        static constexpr u32 SaveCheatsButtonId = 4;
        static constexpr u32 LoadCheatsButtonId = 5;
        static constexpr u32 EditCheatButtonId = 6;
        static constexpr u32 AddCheatToBookmarkButtonId = 7;
    private:
        static constexpr size_t MaxFileRows = 11;

        static constexpr float WindowWidth = 610.0f;
        static constexpr float WindowHeight = 680.0f;
        static constexpr float TitleGap = 90.0f;
        static constexpr float TextBackgroundOffset = 20.0f;
        static constexpr float FileRowHeight = 40.0f;
        static constexpr float FileRowGap = 10.0f;
        static constexpr float FileRowHorizontalInset = 10.0f;
        static constexpr float FileListHeight = MaxFileRows * (FileRowHeight + FileRowGap);

    private:
        char m_root[FS_MAX_PATH];
    public:
        u32 m_current_index;
        u32 m_current_column_index = 0;
        u32 m_current_column_size = 0;
    private:
        float m_scroll_offset;
        float m_touch_start_scroll_offset;
        bool m_touch_finalize_selection;
        bool IsSelectionVisible();
        bool IsEntryTouched(u32 i);
        void UpdateTouches();
        void FinalizeSelection();
    public:
        void ScrollToSelection();
        Air_menu_setting m_menu_setting;
        float xoffsetL = -315.0f;
        float xoffsetR = 315.0f;
        std::vector <DataEntry> m_data_entries;
        AirMenu(std::shared_ptr<Menu> prev_menu, Air_menu_setting menu_setting);
        void reload();
        virtual void Update(u64 ns) override;
        virtual void Draw(NVGcontext *vg, u64 ns) override;
        virtual void SetButtonLabel(u32 id, char *text) override;
    };

    class BoxMenu : public Menu {
       private:
        int N = 3;  // added number of boxes from original
        static constexpr float WindowHeight = 240.0f;
        static constexpr float TitleGap = 90.0f;

       public:
        Air_menu_setting m_menu_setting;
        BoxMenu(std::shared_ptr<Menu> prev_menu, Air_menu_setting menu_setting);
        virtual void Update(u64 ns) override;
        virtual void Draw(NVGcontext *vg, u64 ns) override;
    };
    void request_exit();
    bool requestKeyboardInput(const char *headerText, const char *subHeaderText, const char *initialText, SwkbdType type, char *out_text, size_t maxLength);
    void ReturnToPreviousMenu();
    void ChangeMenu(std::shared_ptr<Menu> menu);
    std::shared_ptr<air::Menu> get_current_menu();

    // class CheatMenu : public Menu {
    // private:
    //     int N = 3; // total number of boxes
    //     static constexpr u32 ToggleCheatButtonId = 0;
    //     static constexpr u32 AddConditionalkeyButtonId = 1;
    //     static constexpr u32 RemoveConditionalkeyButtonId = 2;
    //     static constexpr u32 ExitButtonId = 3;
    //     static constexpr u32 SaveCheatsButtonId = 4;
    //     static constexpr u32 LoadCheatsButtonId = 5;
    //     static constexpr u32 EditCheatButtonId = 6;
    //     static constexpr u32 AddCheatToBookmarkButtonId = 7;
    // private:
    //     static constexpr size_t MaxFileRows = 11;

    //     static constexpr float WindowWidth = 610.0f;
    //     static constexpr float xoffset = -320.0f;
    //     static constexpr float WindowHeight = 680.0f;
    //     static constexpr float TitleGap = 90.0f;
    //     static constexpr float TextBackgroundOffset = 20.0f;
    //     static constexpr float FileRowHeight = 40.0f;
    //     static constexpr float FileRowGap = 10.0f;
    //     static constexpr float FileRowHorizontalInset = 10.0f;
    //     static constexpr float FileListHeight = MaxFileRows * (FileRowHeight + FileRowGap);

    // private:
    //     char m_root[FS_MAX_PATH];
    //     u32 m_current_index;
    //     float m_scroll_offset;
    //     float m_touch_start_scroll_offset;
    //     bool m_touch_finalize_selection;
    //     bool m_editCheat = false;
    //     u32 keycode = 0x80000000, keycount = 0;
    //     int m_enabledcnt = 0, m_totalopcode = 0;

    //     Result PopulateCheatEntries();
    //     bool IsSelectionVisible();
    //     void ScrollToSelection();
    //     bool IsEntryTouched(u32 i);
    //     void UpdateTouches();
    //     void FinalizeSelection();
    //     void RemoveKeyfromSelection();
    //     void AddKeytoSelection();
    //     void dumpcodetofile();

    // public:
    //     CheatMenu(std::shared_ptr<Menu> prev_menu, const char *root);

    //     virtual void Update(u64 ns) override;
    //     virtual void Draw(NVGcontext *vg, u64 ns) override;

    // };

// may remove these

    // class EditCheatMenu : public Menu {
    // private:
    //     struct CheatlineEntry
    //     {
    //         char line[FS_MAX_PATH];
    //     };

    // private:
    //     int N = 3; // total number of boxes
    //     static constexpr u32 EditButtonId = 0;
    //     static constexpr u32 Editf32ButtonId = 1;
    //     static constexpr u32 Editf64ButtonId = 2;
    //     static constexpr u32 ExitButtonId = 3;
    //     static constexpr u32 DoublicateButtonId = 4;
    //     static constexpr u32 DeleteButtonId = 5;
    //     static constexpr u32 CopylineButtonId = 6;
    //     static constexpr u32 PastelineButtonId = 7;

    // private:
    //     static constexpr size_t MaxFileRows = 11;

    //     static constexpr float WindowWidth = 610.0f;
    //     static constexpr float xoffset = -320.0f;
    //     static constexpr float WindowHeight = 680.0f;
    //     static constexpr float TitleGap = 90.0f;
    //     static constexpr float TextBackgroundOffset = 20.0f;
    //     static constexpr float FileRowHeight = 40.0f;
    //     static constexpr float FileRowGap = 10.0f;
    //     static constexpr float FileRowHorizontalInset = 10.0f;
    //     static constexpr float FileListHeight = MaxFileRows * (FileRowHeight + FileRowGap);

    // private:
    //     char m_root[FS_MAX_PATH];
    //     std::vector<CheatlineEntry> m_cheat_lines;
    //     u32 m_cheat_index;
    //     u32 m_current_index;
    //     float m_scroll_offset;
    //     float m_touch_start_scroll_offset;
    //     bool m_touch_finalize_selection;
    //     bool m_editCheat = false;
    //     u32 keycode = 0x80000000, keycount = 0;
    //     int m_enabledcnt = 0, m_totalopcode = 0;

    //     // void PopulateCheatEntries(u32 i);
    //     void PopulateCheatLines(u32 i);
    //     bool IsSelectionVisible();
    //     void ScrollToSelection();
    //     bool IsEntryTouched(u32 i);
    //     void UpdateTouches();
    //     void EditSelection();

    // public:
    //     EditCheatMenu(std::shared_ptr<Menu> prev_menu, u32 cheat_index);

    //     virtual void Update(u64 ns) override;
    //     virtual void Draw(NVGcontext *vg, u64 ns) override;
    // };
//BM1 ProgressinfoMenu
    class SearchTask;
    class ProgressinfoMenu : public Menu {
       private:
        static constexpr u32 ExitButtonId = 0;
        static constexpr u32 DumptofileButtonId = 1;
        static constexpr float WindowWidth = 600.0f;
        static constexpr float WindowHeight = 600.0f;
        static constexpr float TitleGap = 120.0f;
        static constexpr float ProgressTextHeight = 20.0f;
        static constexpr float ProgressBarHeight = 30.0f;
        static constexpr float TextAreaHeight = 320.0f;

       private:
        // Result GetUpdateInformation();
       public:
        SearchTask* m_searchtask;

        Air_menu_setting m_menu_setting;
        float m_progress_percent;
        ProgressinfoMenu(std::shared_ptr<Menu> prev_menu, air::Air_menu_setting menu_setting, SearchTask* searchtask);
        virtual void Update(u64 ns) override;
        virtual void Draw(NVGcontext *vg, u64 ns) override;
    };
}
