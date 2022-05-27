/*
 * Copyright (c) 2020 Adubbz
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
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include "ui.hpp"
#include "air.hpp"
#include "action.hpp"
#include "ui_util.hpp"
#include "assert.hpp"

namespace air {
    extern gFileEntry g_FileEntry;
     bool m_HasCheatProcess;
     Options options;
     NsApplicationControlData m_appControlData;
    u8 m_screenshot_buffer[0x384000] = {0};
    bool m_capturescreen = true;
    bool m_refresh_backgroud = false;
    int m_icon = -1;
    namespace // to move to action.cpp 
    {
        // bool m_usealias = false;
        // bool m_useheap = false;
        // u64 m_heap_alias_size = 0;
        // DmntCheatProcessMetadata m_Metadata = {};
        // std::vector<MemoryInfo> m_memInfos5 = {};
        // std::vector<MemoryInfo> m_memInfosM = {};
        // std::vector<MemoryInfo> m_memInfosAll = {};
        // u64 m_heapBaseAddr = 0;
        // u64 m_heapSize = 0;
        // u64 m_heapEnd = 0;
        // u64 m_heap_total = 0;
        // u64 m_RW_total = 0;
        // u64 m_RW_size = 0;
        // u64 m_not_RW = 0;
        // std::vector<DmntCheatEntry> m_cheat_entries;
        // std::vector<char[100]> m_cheat_lines;
        // std::string m_versionString = "";
        // std::string m_titleName = "No game running";
        // char m_cheatcode_path[128];

        // u32 m_combo = 2;

        
        // std::string m_selections_title;

        // u32 m_selections_Selected_ButtonId = 0;
        // bool m_selections_Selected = false;
        // std::vector<ButtonEntry> m_actions = {{"Go home and come again", 1}, {"\uE0C5 Doublicate cheat", 2}, {"\uE0C5 Edit f32 value", 3}, {"\uE0C5 Tripple treat and good", 4}, {"\uE0C5 save and continue", 5}, {"Check for update", 6}, {"\uE0C4 check for updates tomorrow", 7}, {"\uE0C4 Remove conditional key", 8}, {"Good9", 9}, {"Good10", 10}, {"Good11", 11}, {"Good12", 12}, {"Good13", 13}, {"Good14", 14}, {"Good15", 15}, {"Good16", 16}};
    }
    namespace {

        static constexpr u32 ExosphereApiVersionConfigItem = 65000;
        static constexpr u32 ExosphereHasRcmBugPatch       = 65004;
        static constexpr u32 ExosphereEmummcType           = 65007;

        /* Insets of content within windows. */
        static constexpr float HorizontalInset       = 20.0f;
        static constexpr float BottomInset           = 20.0f;

        /* Insets of content within text areas. */
        static constexpr float TextHorizontalInset   = 8.0f;
        static constexpr float TextVerticalInset     = 8.0f;

        static constexpr float ButtonHeight          = 60.0f;
        static constexpr float ButtonHorizontalGap   = 10.0f;

        static constexpr float VerticalGap           = 10.0f;

        u32 g_screen_width;
        u32 g_screen_height;


        std::shared_ptr<Menu> g_current_menu;
        bool g_initialized = false;
        bool g_exit_requested = false;

        PadState g_pad;

        u32 g_prev_touch_count = -1;
        HidTouchScreenState g_start_touch;
        bool g_started_touching = false;
        bool g_tapping = false;
        bool g_touches_moving = false;
        bool g_finished_touching = false;

        /* Update install state. */
        // char g_update_path[FS_MAX_PATH];
        // bool g_reset_to_factory = false;
        // bool g_exfat_supported = false;
        // bool g_use_exfat = false;

        constexpr u32 MaxTapMovement = 20;

        void UpdateInput() {
            /* Scan for input and update touch state. */
            padUpdate(&g_pad);
            HidTouchScreenState current_touch;
            hidGetTouchScreenStates(&current_touch, 1);
            const u32 touch_count = current_touch.count;

            if (g_prev_touch_count == 0 && touch_count > 0) {
                hidGetTouchScreenStates(&g_start_touch, 1);
                g_started_touching = true;
                g_tapping = true;
            } else {
                g_started_touching = false;
            }

            if (g_prev_touch_count > 0 && touch_count == 0) {
                g_finished_touching = true;
                g_tapping = false;
            } else {
                g_finished_touching = false;
            }

            /* Check if currently moving. */
            if (g_prev_touch_count > 0 && touch_count > 0) {
                if ((abs(current_touch.touches[0].x - g_start_touch.touches[0].x) > MaxTapMovement || abs(current_touch.touches[0].y - g_start_touch.touches[0].y) > MaxTapMovement)) {
                    g_touches_moving = true;
                    g_tapping = false;
                } else {
                    g_touches_moving = false;
                }
            } else {
                g_touches_moving = false;
            }

            /* Update the previous touch count. */
            g_prev_touch_count = current_touch.count;
        }


        Result IsPathBottomLevel(const char *path, bool *out) {
            Result rc = 0;
            FsFileSystem *fs;
            char translated_path[FS_MAX_PATH] = {};
            DBK_ABORT_UNLESS(fsdevTranslatePath(path, &fs, translated_path) != -1);

            FsDir dir;
            if (R_FAILED(rc = fsFsOpenDirectory(fs, translated_path, FsDirOpenMode_ReadDirs, &dir))) {
                return rc;
            }

            s64 entry_count;
            if (R_FAILED(rc = fsDirGetEntryCount(&dir, &entry_count))) {
                return rc;
            }

            *out = entry_count == 0;
            fsDirClose(&dir);
            return rc;
        }
        u32 EncodeVersion(u32 major, u32 minor, u32 micro, u32 relstep = 0) {
            return ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | ((micro & 0xFF) << 8) | ((relstep & 0xFF) << 8);
        }
    } 
        void ChangeMenu(std::shared_ptr<Menu> menu) {
            g_current_menu = menu;
        }

        std::shared_ptr<air::Menu> get_current_menu() {
            return g_current_menu;
        }

        void ReturnToPreviousMenu() {
            /* Go to the previous menu if there is one. */
            if (g_current_menu->GetPrevMenu() != nullptr) {
                g_current_menu = g_current_menu->GetPrevMenu();
            }
        }

    void Menu::AddButton(u32 id, const char *text, float x, float y, float w, float h) {
        if (!(id < MaxButtons)) id = MaxButtons - 1;
        Button button = {
            .id = id,
            .selected = false,
            .enabled = true,
            .x = x,
            .y = y,
            .w = w,
            .h = h,
        };

        strncpy(button.text, text, sizeof(button.text)-1);
        m_buttons[id] = button;
    }

    void Menu::ResetButtons() {
        for (auto &button : m_buttons) {
            button.reset();
        }
    }

    void Menu::SetButtonSelected(u32 id, bool selected) {
        DBK_ABORT_UNLESS(id < MaxButtons);
        auto &button = m_buttons[id];

        if (button) {
            button->selected = selected;
        }
    }

    void Menu::SetButtonLabel(u32 id, char *text) {
        DBK_ABORT_UNLESS(id < MaxButtons);
        auto &button = m_buttons[id];

        if (button) {
            strcpy(button->text, text);
        }
    }

    void Menu::DeselectAllButtons() {
        for (auto &button : m_buttons) {
            /* Ensure button is present. */
            if (!button) {
                continue;
            }
            button->selected = false;
        }
    }

    void Menu::SetButtonEnabled(u32 id, bool enabled) {
        DBK_ABORT_UNLESS(id < MaxButtons);
        auto &button = m_buttons[id];
        button->enabled = enabled;
    }

    bool Menu::ButtonEnabled(u32 id) {
        DBK_ABORT_UNLESS(id < MaxButtons);
        auto &button = m_buttons[id];
        return button->enabled;
    }

    Button *Menu::GetButton(u32 id) {
        DBK_ABORT_UNLESS(id < MaxButtons);
        return !m_buttons[id] ? nullptr : &(*m_buttons[id]);
    }

    Button *Menu::GetSelectedButton() {
        for (auto &button : m_buttons) {
            if (button && button->enabled && button->selected) {
                return &(*button);
            }
        }

        return nullptr;
    }

    Button *Menu::GetClosestButtonToSelection(Direction direction) {
        const Button *selected_button = this->GetSelectedButton();

        if (selected_button == nullptr || direction == Direction::Invalid) {
            return nullptr;
        }

        Button *closest_button = nullptr;
        float closest_distance = 0.0f;

        for (auto &button : m_buttons) {
            /* Skip absent button. */
            if (!button || !button->enabled) {
                continue;
            }

            /* Skip buttons that are in the wrong direction. */
            if ((direction == Direction::Down && button->y <= selected_button->y)  ||
                (direction == Direction::Up && button->y >= selected_button->y)    ||
                (direction == Direction::Right && button->x <= selected_button->x) ||
                (direction == Direction::Left && button->x >= selected_button->x)) {
                continue;
            }

            const float x_dist = button->x - selected_button->x;
            const float y_dist = button->y - selected_button->y;
            const float sq_dist = x_dist * x_dist + y_dist * y_dist;

            /* If we don't already have a closest button, set it. */
            if (closest_button == nullptr) {
                closest_button = &(*button);
                closest_distance = sq_dist;
                continue;
            }

            /* Update the closest button if this one is closer. */
            if (sq_dist < closest_distance) {
                closest_button = &(*button);
                closest_distance = sq_dist;
            }
        }

        return closest_button;
    }

    Button *Menu::GetTouchedButton() {
        HidTouchScreenState current_touch;
        hidGetTouchScreenStates(&current_touch, 1);
        const u32 touch_count = current_touch.count;

        for (u32 i = 0; i < touch_count && g_started_touching; i++) {
            for (auto &button : m_buttons) {
                if (button && button->enabled && button->IsPositionInBounds(current_touch.touches[i].x, current_touch.touches[i].y)) {
                    return &(*button);
                }
            }
        }

        return nullptr;
    }

    Button *Menu::GetActivatedButton() {
        Button *selected_button = this->GetSelectedButton();

        if (selected_button == nullptr) {
            return nullptr;
        }

        const u64 k_down = padGetButtonsDown(&g_pad);

        if (k_down & HidNpadButton_A || this->GetTouchedButton() == selected_button) {
            return selected_button;
        }

        return nullptr;
    }

    void Menu::UpdateButtons() {
        const u64 k_down = padGetButtonsDown(&g_pad);
        Direction direction = Direction::Invalid;

        if (k_down & HidNpadButton_AnyDown) {
            direction = Direction::Down;
        } else if (k_down & HidNpadButton_AnyUp) {
            direction = Direction::Up;
        } else if (k_down & HidNpadButton_AnyLeft) {
            direction = Direction::Left;
        } else if (k_down & HidNpadButton_AnyRight) {
            direction = Direction::Right;
        }

        /* Select the closest button. */
        if (const Button *closest_button = this->GetClosestButtonToSelection(direction); closest_button != nullptr) {
            this->DeselectAllButtons();
            this->SetButtonSelected(closest_button->id, true);
        }

        /* Select the touched button. */
        if (const Button *touched_button = this->GetTouchedButton(); touched_button != nullptr) {
            this->DeselectAllButtons();
            this->SetButtonSelected(touched_button->id, true);
        }
    }

    void Menu::DrawButtons(NVGcontext *vg, u64 ns) {
        for (auto &button : m_buttons) {
            /* Ensure button is present. */
            if (!button) {
                continue;
            }

            /* Set the button style. */
            auto style = ButtonStyle::StandardDisabled;
            if (button->enabled) {
                style = button->selected ? ButtonStyle::StandardSelected : ButtonStyle::Standard;
            }

            DrawButton(vg, button->text, button->x, button->y, button->w, button->h, style, ns);
        }
    }

    void Menu::LogText(const char *format, ...) {
        /* Create a temporary string. */
        char tmp[0x100];
        va_list args;
        va_start(args, format);
        vsnprintf(tmp, sizeof(tmp), format, args);
        va_end(args);

        /* Append the text to the log buffer. */
        strncat(m_log_buffer, tmp, sizeof(m_log_buffer) - strlen(m_log_buffer) - 1);
    }

    std::shared_ptr<Menu> Menu::GetPrevMenu() {
        return m_prev_menu;
    }

    AlertMenu::AlertMenu(std::shared_ptr<Menu> prev_menu, const char *text, const char *subtext, Result rc) : Menu(prev_menu), m_text{}, m_subtext{}, m_result_text{}, m_rc(rc){
        /* Copy the input text. */
        strncpy(m_text, text, sizeof(m_text)-1);
        strncpy(m_subtext, subtext, sizeof(m_subtext)-1);

        /* Copy result text if there is a result. */
        if (R_FAILED(rc)) {
            snprintf(m_result_text, sizeof(m_result_text), "Result: 0x%08x", rc);
        }
    }

    void AlertMenu::Draw(NVGcontext *vg, u64 ns) {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;

        DrawWindow(vg, m_text, x, y, WindowWidth, window_height);
        DrawText(vg, x + HorizontalInset, y + TitleGap, WindowWidth - HorizontalInset * 2.0f, m_subtext);

        /* Draw the result if there is one. */
        if (R_FAILED(m_rc)) {
            DrawText(vg, x + HorizontalInset, y + TitleGap + SubTextHeight, WindowWidth - HorizontalInset * 2.0f, m_result_text);
        }

        this->DrawButtons(vg, ns);
    }

    ErrorMenu::ErrorMenu(const char *text, const char *subtext, Result rc) : AlertMenu(nullptr, text, subtext, rc)  {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;
        const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float button_width = WindowWidth - HorizontalInset * 2.0f;

        /* Add buttons. */
        this->AddButton(ExitButtonId, "Exit", x + HorizontalInset, button_y, button_width, ButtonHeight);
        this->SetButtonSelected(ExitButtonId, true);
    }

    void ErrorMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down & HidNpadButton_B) {
            g_exit_requested = true;
            return;
        }

        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case ExitButtonId:
                    g_exit_requested = true;
                    break;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the exfat button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(ExitButtonId, true);
        }
    }

    MessageMenu::MessageMenu(std::shared_ptr<Menu> prev_menu, const char *text, const char *subtext, Result rc) : AlertMenu(prev_menu, text, subtext, rc)  {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;
        const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float button_width = WindowWidth - HorizontalInset * 2.0f;

        /* Add buttons. */
        this->AddButton(ExitButtonId, "OK", x + HorizontalInset, button_y, button_width, ButtonHeight);
        this->SetButtonSelected(ExitButtonId, true);
    }

    void MessageMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down & HidNpadButton_B) {
            ReturnToPreviousMenu();
            return;
        }

        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case ExitButtonId:
                    ReturnToPreviousMenu();
                    break;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the exfat button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(ExitButtonId, true);
        }
    }

    WaitforkeyMenu::WaitforkeyMenu(std::shared_ptr<Menu> prev_menu, const char *text, u32 keycount, void (*action)(u32, u32), u32 id, const char *subtext, Result rc) : AlertMenu(prev_menu, text, subtext, rc) {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;
        const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float button_width = WindowWidth - HorizontalInset * 2.0f;
        m_keycount = keycount;
        m_id = id;
        m_action = action;
        /* Add buttons. */
        this->AddButton(ExitButtonId, "Abort", x + HorizontalInset, button_y, button_width, ButtonHeight);
        this->SetButtonSelected(30, true);
    }

    void WaitforkeyMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down) {
            m_action(m_id, k_down);
            m_keycount--;
            if (m_keycount == 0){
                ReturnToPreviousMenu();
            };
            return;
        }

        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case ExitButtonId:
                    ReturnToPreviousMenu();
                    break;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the exfat button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(ExitButtonId, true);
        }
    }
    WaitforkeyMenu2::WaitforkeyMenu2(std::shared_ptr<Menu> prev_menu, const char *text, u32 keycount, BreezeActions * action, u32 id, const char *subtext, Result rc) : AlertMenu(prev_menu, text, subtext, rc) {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;
        const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float button_width = WindowWidth - HorizontalInset * 2.0f;
        m_keycount = keycount;
        m_id = id;
        m_action = action;
        /* Add buttons. */
        this->AddButton(ExitButtonId, "Abort", x + HorizontalInset, button_y, button_width, ButtonHeight);
        this->SetButtonSelected(30, true);
    }

    void WaitforkeyMenu2::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down) {
            m_action->menu_action(m_id, k_down);
            m_keycount--;
            if (m_keycount == 0){
                ReturnToPreviousMenu();
            };
            return;
        }

        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case ExitButtonId:
                    ReturnToPreviousMenu();
                    break;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the exfat button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(ExitButtonId, true);
        }
    }

    WaitforcompletionMenu::WaitforcompletionMenu(std::shared_ptr<Menu> prev_menu, const char *text, void (*action)(u32, u32), u32 id, const char *subtext, Result rc) : AlertMenu(prev_menu, text, subtext, rc) {
        // const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        // const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        // const float y = g_screen_height / 2.0f - window_height / 2.0f;
        // const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        // const float button_width = WindowWidth - HorizontalInset * 2.0f;
        // m_keycount = keycount;
        m_id = id;
        m_action = action;
        /* Add buttons. */
        // this->AddButton(ExitButtonId, "Abort", x + HorizontalInset, button_y, button_width, ButtonHeight);
        // this->SetButtonSelected(30, true);
    }

    void WaitforcompletionMenu::Update(u64 ns) {
        if (m_do_once) {
            m_action(m_id, 0);
            m_do_once = false;
        };
        ReturnToPreviousMenu();
        return;
    }
    WarningMenu::WarningMenu(std::shared_ptr<Menu> prev_menu, std::shared_ptr<Menu> next_menu, const char *text, const char *subtext, Result rc) : AlertMenu(prev_menu, text, subtext, rc), m_next_menu(next_menu) {
        const float window_height = WindowHeight + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - window_height / 2.0f;

        const float button_y = y + TitleGap + SubTextHeight + VerticalGap * 2.0f + (R_FAILED(m_rc) ? SubTextHeight : 0.0f);
        const float button_width = (WindowWidth - HorizontalInset * 2.0f) / 2.0f - ButtonHorizontalGap;
        this->AddButton(BackButtonId, "Back", x + HorizontalInset, button_y, button_width, ButtonHeight);
        this->AddButton(ContinueButtonId, "Continue", x + HorizontalInset + button_width + ButtonHorizontalGap, button_y, button_width, ButtonHeight);
        this->SetButtonSelected(ContinueButtonId, true);
    }

    void WarningMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down & HidNpadButton_B) {
            ReturnToPreviousMenu();
            return;
        }

        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case BackButtonId:
                    ReturnToPreviousMenu();
                    return;
                case ContinueButtonId:
                    ChangeMenu(m_next_menu);
                    return;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the exfat button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(ContinueButtonId, true);
        }
    }
    // SelectMenu::SelectMenu(std::shared_ptr<Menu> prev_menu) : Menu(prev_menu) {
    //     N = (m_actions.size()+1) / 2;
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f - xoffset;
    //     const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
    //     const float button_width = (WindowWidth - HorizontalInset * 3)/2;
    //     for (u64 i = 0; i < m_actions.size(); i++)
    //     {
    //         this->AddButton(m_actions[i].ButtonId, m_actions[i].label.c_str(), x + HorizontalInset + (button_width + HorizontalInset) * (i % 2), y + TitleGap + (ButtonHeight + VerticalGap) * (i / 2), button_width, ButtonHeight);
    //     }
    //         this->SetButtonSelected(1, true);
    // // }

    // void SelectMenu::Update(u64 ns) {
    //     u64 k_down = padGetButtonsDown(&g_pad);

    //     if (k_down & HidNpadButton_B) {
    //         ReturnToPreviousMenu();
    //     }

    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
    //         switch (activated_button->id) {
    //             case 1:
    //                 ReturnToPreviousMenu();
    //                 return;
    //         }
    //     }

    //     this->UpdateButtons();

    //     /* Fallback on selecting the install button. */
    //     if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
    //         this->SetButtonSelected(1, true);
    //     }
    // }

    // void SelectMenu::Draw(NVGcontext *vg, u64 ns) {
    //     DrawWindow(vg, "SE tools", g_screen_width / 2.0f -xoffset - WindowWidth / 2.0f, g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, WindowWidth, TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N);
    //     this->DrawButtons(vg, ns);
    // }
 //BM1-1 AirMenu
    std::string button_short_cut_str(int buttoncode) {
        std::string namestr = "";
        for (u32 i = 0; i < buttonCodes.size(); i++) {
            if ((buttoncode & buttonCodes[i]) == (buttonCodes[i] & 0x7FFFFFFF))
                namestr = namestr + buttonNames[i];
        }
        return namestr;
    }
    #define MAX_BUTTON_ROWS 9
    AirMenu::AirMenu(std::shared_ptr<Menu> prev_menu, Air_menu_setting menu_setting) : Menu(prev_menu), m_current_index(0), m_scroll_offset(0), m_touch_start_scroll_offset(0), m_touch_finalize_selection(false) {
        m_menu_setting = menu_setting;
        xoffsetL = m_menu_setting.xoffsetL;
        xoffsetR = m_menu_setting.xoffsetR;
        float extension = 2 * (315 - xoffsetR);  // when xoffset is reducced from 320 can extend the windows width by this amount

        // N = (menu_setting.actions.size() + (menu_setting.num_button_column == 2)) / menu_setting.num_button_column;
        N = menu_setting.actions.size() / menu_setting.num_button_column + (menu_setting.actions.size() % menu_setting.num_button_column > 0);
        if (N > MAX_BUTTON_ROWS) N = MAX_BUTTON_ROWS;
        const float x = g_screen_width / 2.0f - (WindowWidth + extension) / 2.0f + xoffsetR;
        const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
        const float button_width = (WindowWidth + extension - HorizontalInset * (menu_setting.num_button_column+1)) / menu_setting.num_button_column;
        char boxstr[100];
        u64 max_buttons = m_menu_setting.num_button_column * MAX_BUTTON_ROWS;
        if (max_buttons > m_menu_setting.actions.size()) max_buttons = m_menu_setting.actions.size();
        for (u64 i = 0; i < max_buttons; i++) {
            // if (menu_setting.actions[i].ButtonId < 24)
                snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", button_short_cut_str(menu_setting.actions[i].keycode).c_str(), menu_setting.actions[i].label.c_str()); //programmable shortcut change
            // else
            //     snprintf(boxstr, sizeof(boxstr) - 1, "%s", menu_setting.actions[i].label.c_str());
            this->AddButton(menu_setting.actions[i].ButtonId, boxstr, x + HorizontalInset + (button_width + HorizontalInset) * (i % menu_setting.num_button_column), y + TitleGap + (ButtonHeight + VerticalGap) * (i / menu_setting.num_button_column), button_width, ButtonHeight);
            if (!menu_setting.actions[i].enable) SetButtonEnabled(menu_setting.actions[i].ButtonId, false);
        }
        this->SetButtonSelected(menu_setting.button_selected, true);

    }
    void AirMenu::reload() {
        this->ResetButtons();
        xoffsetL = m_menu_setting.xoffsetL;
        xoffsetR = m_menu_setting.xoffsetR;
        float extension = 2 * (315 - xoffsetR);  // when xoffset is reducced from 320 can extend the windows width by this amount

        // N = (menu_setting.actions.size() + (menu_setting.num_button_column == 2)) / menu_setting.num_button_column;
        N = m_menu_setting.actions.size() / m_menu_setting.num_button_column + (m_menu_setting.actions.size() % m_menu_setting.num_button_column > 0);
        if (N > MAX_BUTTON_ROWS) N = MAX_BUTTON_ROWS;
        const float x = g_screen_width / 2.0f - (WindowWidth + extension) / 2.0f + xoffsetR;
        const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
        const float button_width = (WindowWidth + extension - HorizontalInset * (m_menu_setting.num_button_column+1)) / m_menu_setting.num_button_column;
        char boxstr[100];
        u64 max_buttons = m_menu_setting.num_button_column * MAX_BUTTON_ROWS;
        if (max_buttons > m_menu_setting.actions.size()) max_buttons = m_menu_setting.actions.size();
        for (u64 i = 0; i < max_buttons; i++) {
            // if (menu_setting.actions[i].ButtonId < 24)
                snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", button_short_cut_str(m_menu_setting.actions[i].keycode).c_str(), m_menu_setting.actions[i].label.c_str()); //programmable shortcut change
            // else
            //     snprintf(boxstr, sizeof(boxstr) - 1, "%s", menu_setting.actions[i].label.c_str());
            this->AddButton(m_menu_setting.actions[i].ButtonId, boxstr, x + HorizontalInset + (button_width + HorizontalInset) * (i % m_menu_setting.num_button_column), y + TitleGap + (ButtonHeight + VerticalGap) * (i / m_menu_setting.num_button_column), button_width, ButtonHeight);
            if (!m_menu_setting.actions[i].enable) SetButtonEnabled(m_menu_setting.actions[i].ButtonId, false);
        }
        this->SetButtonSelected(m_menu_setting.button_selected, true);
    };

    void AirMenu::SetButtonLabel(u32 id, char *text) {
        for (size_t i = 0; i < m_menu_setting.actions.size(); i++) {
            if (m_menu_setting.actions[i].ButtonId == id) {
                char boxstr[100];
                snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", button_short_cut_str(m_menu_setting.actions[i].keycode).c_str(), text);  
                Menu::SetButtonLabel(id, boxstr);
                break;
            }
        };
    }

    bool AirMenu::IsSelectionVisible() {
        const float visible_start = m_scroll_offset;
        const float visible_end = visible_start + FileListHeight;
        const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
        const float entry_end = entry_start + (FileRowHeight + FileRowGap);
        return entry_start >= visible_start && entry_end <= visible_end;
    }

    void AirMenu::ScrollToSelection() {
        const float visible_start = m_scroll_offset;
        const float visible_end = visible_start + FileListHeight;
        const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
        const float entry_end = entry_start + (FileRowHeight + FileRowGap);

        if (entry_end > visible_end) {
            m_scroll_offset += entry_end - visible_end;
        } else if (entry_end < visible_end) {
            m_scroll_offset = entry_start;
        }
    }

    bool AirMenu::IsEntryTouched(u32 i) {
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f + xoffsetL;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

        HidTouchScreenState current_touch;
        hidGetTouchScreenStates(&current_touch, 1);

        /* Check if the tap is within the x bounds. */
        if (current_touch.touches[0].x >= x + TextBackgroundOffset + FileRowHorizontalInset && current_touch.touches[0].x <= WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f) {
            const float y_min = y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset;
            const float y_max = y_min + FileRowHeight;

            /* Check if the tap is within the y bounds. */
            if (current_touch.touches[0].y >= y_min && current_touch.touches[0].y <= y_max) {
                return true;
            }
        }

        return false;
    }

    void AirMenu::UpdateTouches() {
        /* Setup values on initial touch. */
        if (g_started_touching) {
            m_touch_start_scroll_offset = m_scroll_offset;

            /* We may potentially finalize the selection later if we start off touching it. */
            if (this->IsEntryTouched(m_current_index)) {
                m_touch_finalize_selection = true;
            }
        }

        /* Scroll based on touch movement. */
        if (g_touches_moving) {
            HidTouchScreenState current_touch;
            hidGetTouchScreenStates(&current_touch, 1);

            const int dist_y = current_touch.touches[0].y - g_start_touch.touches[0].y;
            float new_scroll_offset = m_touch_start_scroll_offset - static_cast<float>(dist_y);
            float max_scroll = (FileRowHeight + FileRowGap) * static_cast<float>(this->m_data_entries.size()) - FileListHeight;

            /* Don't allow scrolling if there is not enough elements. */
            if (max_scroll < 0.0f) {
                max_scroll = 0.0f;
            }

            /* Don't allow scrolling before the first element. */
            if (new_scroll_offset < 0.0f) {
                new_scroll_offset = 0.0f;
            }

            /* Don't allow scrolling past the last element. */
            if (new_scroll_offset > max_scroll) {
                new_scroll_offset = max_scroll;
            }

            m_scroll_offset = new_scroll_offset;
        }

        /* Select any tapped entries. */
        if (g_tapping) {
            for (u32 i = 0; i < m_data_entries.size(); i++) {
                if (this->IsEntryTouched(i)) {
                    /* The current index is checked later. */
                    if (i == m_current_index) {
                        continue;
                    }

                    m_current_index = i;

                    /* Don't finalize selection if we touch something else. */
                    m_touch_finalize_selection = false;
                    break;
                }
            }
        }

        /* Don't finalize selection if we aren't finished and we've either stopped tapping or are no longer touching the selection. */
        if (!g_finished_touching && (!g_tapping || !this->IsEntryTouched(m_current_index))) {
            m_touch_finalize_selection = false;
        }

        /* Finalize selection if the currently selected entry is touched for the second time. */
        if (g_finished_touching && m_touch_finalize_selection) {
            {if (m_menu_setting._action!=nullptr){ m_menu_setting._action->menu_action(0, m_current_index);} else {
                    m_menu_setting.action(0, m_current_index);}}
            // m_menu_setting.action(0, m_current_index);
            // this->FinalizeSelection();
            m_touch_finalize_selection = false;
        }
    }

    void AirMenu::FinalizeSelection(){
        // action(m_menu_setting, HidNpadButton_A, this->GetActivatedButton(), m_current_index);
    };
#define BC_add(i,x,y) x+=i; if(x>y-1) x=y-1
#define BC_sub(i,x) if (i > x) x = 0; else x -=i
    void AirMenu::Update(u64 ns) {
        auto h_inc = [&]() {
            if (options.use_row_jump) {
                /* Page down. */
                BC_add(10, m_current_index, m_data_entries.size());
            } else {
                /* Move Right. */
                BC_add(1, m_current_column_index, m_current_column_size);
            }
        };
        auto h_dec = [&]() {
            if (options.use_row_jump) {
                /* Page up. */
                BC_sub(10, m_current_index);
            } else {
                /* Move Left. */
                BC_sub(1, m_current_column_index);
            }
        };
        u64 k_down = padGetButtonsDown(&g_pad);
        u64 k_held = padGetButtons(&g_pad);
        // if (m_menu_setting.action2!=nullptr){m_menu_setting.action2->menu_action(1000, m_current_index);} 
        if (m_menu_setting._action!=nullptr){ m_menu_setting._action->menu_action(1000, m_current_index);}; //else {m_menu_setting.action(buttonid, m_current_index);}
        // allow update to data and status

        /* Go back if B is pressed. */
        // This is disable for menu to handle special exit condition
        // if (k_down & HidNpadButton_B) {
        //     ReturnToPreviousMenu();
        //     return;
        // }

        /* Update touch input. */
        this->UpdateTouches();

        const u32 prev_index = m_current_index;

        // if (action(m_menu_setting, k_down, this->GetActivatedButton(), m_current_index))
        // {
        //     return;
        // }
        const Button *activated_button = this->GetActivatedButton();
        u32 buttonid;
        if (activated_button == nullptr) {
            bool match = false;
            if (k_down == HidNpadButton_A) {
                buttonid = 0;
                match = true;
            } else if (k_down != 0)
                for (size_t i = 0; i < m_menu_setting.actions.size(); i++) {
                    if (k_held == m_menu_setting.actions[i].keycode) {  //&& menu.actions[i].enable
                        buttonid = m_menu_setting.actions[i].ButtonId;
                        match = true;
                    }
                }
            if (match == true) {
                if (this->ButtonEnabled(buttonid))
                {if (m_menu_setting._action!=nullptr){ m_menu_setting._action->menu_action(buttonid, m_current_index);} else {
                    m_menu_setting.action(buttonid, m_current_index);}}
                return;
            }
        } else {
            buttonid = activated_button->id;
            if (m_menu_setting._action!=nullptr){ m_menu_setting._action->menu_action(buttonid, m_current_index);} else {
                    m_menu_setting.action(buttonid, m_current_index);}
            return;
        };
        if (m_data_entries.size() == 0 || (!(k_held & HidNpadButton_ZL) && options.use_ZL)) {
            // if (m_data_entries.size() == 0) m_current_index = 0;
            this->UpdateButtons();
        } else if (options.use_dpad) {
            if (k_down & HidNpadButton_Right) {
                h_inc();
            } else if (k_down & HidNpadButton_Left) {
                h_dec();
            } else if (k_down & HidNpadButton_Down) {
                /* Scroll down. */
                if (m_current_index >= (m_data_entries.size() - 1)) {
                    m_current_index = 0;
                } else {
                    m_current_index++;
                }
            } else if (k_down & HidNpadButton_Up) {
                /* Scroll up. */
                if (m_current_index == 0) {
                    m_current_index = m_data_entries.size() - 1;
                } else {
                    m_current_index--;
                }
            } else
                this->UpdateButtons();
        } else {
            if (k_down & HidNpadButton_StickLRight) {
                h_inc();
                // /* Page down. */
                // m_current_index += 10;
                // if (m_current_index >= (m_data_entries.size() - 1)) {
                //     m_current_index = m_data_entries.size() - 1;
                // }
            } else if (k_down & HidNpadButton_StickLLeft) {
                h_dec();
                // /* Page up. */
                // if (m_current_index < 10) {
                //     m_current_index = 0;
                // } else
                //     m_current_index -= 10;
            } else if (k_down & HidNpadButton_StickLDown) {
                /* Scroll down. */
                if (m_current_index >= (m_data_entries.size() - 1)) {
                    m_current_index = 0;
                } else {
                    m_current_index++;
                }
            } else if (k_down & HidNpadButton_StickLUp) {
                /* Scroll up. */
                if (m_current_index == 0) {
                    m_current_index = m_data_entries.size() - 1;
                } else {
                    m_current_index--;
                }
            } else
                this->UpdateButtons();
        }
        /* Take action if a button has been activated. */
        // if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) switch (activated_button->id)

        /* Scroll to the selection if it isn't visible. */
        if (prev_index != m_current_index && !this->IsSelectionVisible()) {
            this->ScrollToSelection();
        }
        /* Fallback on selecting the install button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(m_menu_setting.button_selected, true);
        }
    }

    void AirMenu::Draw(NVGcontext *vg, u64 ns) {

        float extension = 2 * (315 - xoffsetR);
        DrawWindow(vg, m_menu_setting.right_panel_title.c_str(), g_screen_width / 2.0f + xoffsetR - (WindowWidth + extension) / 2.0f, g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, WindowWidth + extension, TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N);
        if (m_menu_setting.show_rightpanel_status)
            DrawText(vg, g_screen_width / 2.0f + xoffsetR - (WindowWidth + extension) / 2.0f, 65 + g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, WindowWidth + extension, m_menu_setting.right_panel_status.c_str());
        this->DrawButtons(vg, ns);

        extension = 2 * (315 + xoffsetL);  // when xoffset is reducced from 320 can extend the windows width by this amount
        const float x = g_screen_width / 2.0f - (WindowWidth + extension) / 2.0f + xoffsetL;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
        if (m_menu_setting.show_left_panel_index)
            DrawWindow(vg, logtext("%s %d/%d", m_menu_setting.left_panel_title.c_str(), m_current_index + 1, m_data_entries.size()).data, x, y, WindowWidth + extension, WindowHeight);
        else
            DrawWindow(vg, logtext("%s", m_menu_setting.left_panel_title.c_str()).data, x, y, WindowWidth + extension, WindowHeight);
        if (m_menu_setting.show_leftpanel_status)
            DrawText(vg, x, y + 65, WindowWidth + extension, m_menu_setting.left_panel_status.c_str());
        DrawTextBackground(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth + extension - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

        nvgSave(vg);
        nvgScissor(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth + extension - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

        for (u32 i = 0; i < m_data_entries.size(); i++) {
            auto style = ButtonStyle::FileSelect;
            if (i == m_current_index) {
                style = ButtonStyle::FileSelectSelected;
            }
            DrawButton(vg, m_data_entries[i].data, x + TextBackgroundOffset + FileRowHorizontalInset, y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset, WindowWidth + extension - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f, FileRowHeight, style, ns);
        }

        nvgRestore(vg);
    }
 //BM1-2 BoxMenu
    BoxMenu::BoxMenu(std::shared_ptr<Menu> prev_menu, Air_menu_setting menu_setting) : Menu(prev_menu) {
        m_menu_setting = menu_setting;

        N = menu_setting.actions.size() / menu_setting.num_button_column + (menu_setting.actions.size() % menu_setting.num_button_column > 0);
        const float x = g_screen_width / 2.0f - m_menu_setting.WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
        const float button_width = (m_menu_setting.WindowWidth - HorizontalInset * (menu_setting.num_button_column+1)) / menu_setting.num_button_column;
        char boxstr[100];
        for (u64 i = 0; i < menu_setting.actions.size(); i++) {
            // if (menu_setting.actions[i].ButtonId < 24)
            snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", button_short_cut_str(menu_setting.actions[i].keycode).c_str(), menu_setting.actions[i].label.c_str()); //programmable shortcut change
            // snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", buttonNames[menu_setting.actions[i].ButtonId].c_str(), menu_setting.actions[i].label.c_str());
            // else
            //     snprintf(boxstr, sizeof(boxstr) - 1, "%s", menu_setting.actions[i].label.c_str());
            this->AddButton(menu_setting.actions[i].ButtonId, boxstr, x + HorizontalInset + (button_width + HorizontalInset) * (i % menu_setting.num_button_column), y + TitleGap + (ButtonHeight + VerticalGap) * (i / menu_setting.num_button_column), button_width, ButtonHeight);
            if (!menu_setting.actions[i].enable) SetButtonEnabled(menu_setting.actions[i].ButtonId, false);
        }
        this->SetButtonSelected(menu_setting.button_selected, true);
    }

    void BoxMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);
        u64 k_held = padGetButtons(&g_pad);
        /* Take action if a button has been activated. */

        // if (action(m_menu_setting, k_down, this->GetActivatedButton(), 0)) {
        //     return;
        // }
        
        const Button *activated_button = this->GetActivatedButton();
        u32 buttonid;
        if (activated_button == nullptr) {
            bool match = false;
            if (k_down == HidNpadButton_A) {
                buttonid = 0;
                match = true;
            } else if (k_down != 0)
                for (size_t i = 0; i < m_menu_setting.actions.size(); i++) {
                    if (k_held  == m_menu_setting.actions[i].keycode) { //&& menu.actions[i].enable
                        buttonid = m_menu_setting.actions[i].ButtonId;
                        match = true;
                        break;
                    }
                }
            if (match == true)
            {
                if (this->ButtonEnabled(buttonid))
                    m_menu_setting.action(buttonid, 0);
                return;
            }
        } else {
            buttonid = activated_button->id;
            m_menu_setting.action(buttonid,0);
            return;
        };

        this->UpdateButtons();

        /* Fallback on selecting the install button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(m_menu_setting.button_selected, true);
        }
    }

    void BoxMenu::Draw(NVGcontext *vg, u64 ns) {
        DrawWindow(vg, m_menu_setting.right_panel_title.c_str(), g_screen_width / 2.0f - m_menu_setting.WindowWidth / 2.0f, g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, 
        m_menu_setting.WindowWidth, TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N);
        this->DrawButtons(vg, ns);
    }
    // void init_cheat_system1()
    // {
    //     Result rc = 0;
    //     dmntchtForceOpenCheatProcess();
    //     if (R_FAILED(rc = dmntchtHasCheatProcess(&m_HasCheatProcess)))
    //     {
    //         ChangeMenu(std::make_shared<ErrorMenu>("An error has occurred", "Failed to communicate with dmnt.", rc));
    //         return;
    //     }
    //     if (m_HasCheatProcess)
    //     {
    //         if (R_FAILED(rc = dmntchtGetCheatProcessMetadata(&m_Metadata)))
    //         {
    //             ChangeMenu(std::make_shared<ErrorMenu>("An error has occurred", "Failed to get Metadata from dmnt.", rc));
    //             return;
    //         }
    //         size_t appControlDataSize = 0;
    //         NacpLanguageEntry *languageEntry = nullptr;
    //         std::memset(&m_appControlData, 0x00, sizeof(NsApplicationControlData));
    //         nsGetApplicationControlData(NsApplicationControlSource_Storage, m_Metadata.title_id, &m_appControlData, sizeof(NsApplicationControlData), &appControlDataSize);
    //         nacpGetLanguageEntry(&m_appControlData.nacp, &languageEntry);
    //         m_titleName = std::string(languageEntry->name);
    //         m_versionString = std::string(m_appControlData.nacp.display_version);
    //         // get basic data on game
    //         m_memInfos5.clear();
    //         m_memInfosM.clear();
    //         m_memInfosAll.clear();
    //         m_heap_alias_size = 0;

    //         MemoryInfo memInfo = {0};
    //         dmntchtQueryCheatProcessMemory(&memInfo, m_Metadata.heap_extents.base);
    //         if (memInfo.type == 5) {
    //             m_useheap = true;
    //             while ((memInfo.addr < m_Metadata.heap_extents.base + m_Metadata.heap_extents.size) && (memInfo.addr < memInfo.addr + memInfo.size))
    //             {
    //                 if (memInfo.type == 5) {
    //                     m_memInfos5.push_back(memInfo);
    //                     m_heap_alias_size = m_heap_alias_size + memInfo.size;
    //                 }
    //                 dmntchtQueryCheatProcessMemory(&memInfo, memInfo.addr + memInfo.size);
    //             }
    //         }
    //         memInfo = {0};
    //         dmntchtQueryCheatProcessMemory(&memInfo, m_Metadata.alias_extents.base);
    //         if (memInfo.type == 5) {
    //             m_usealias = true;
    //             while ((memInfo.addr < m_Metadata.alias_extents.base + m_Metadata.alias_extents.size) && (memInfo.addr < memInfo.addr + memInfo.size))
    //             {
    //                 if (memInfo.type == 5) {
    //                     m_memInfos5.push_back(memInfo);
    //                     m_heap_alias_size = m_heap_alias_size + memInfo.size;
    //                 }
    //                 dmntchtQueryCheatProcessMemory(&memInfo, memInfo.addr + memInfo.size);
    //             }
    //         }
    //         memInfo = {0};
    //         dmntchtQueryCheatProcessMemory(&memInfo, m_Metadata.main_nso_extents.base);
    //         while ((memInfo.addr < m_Metadata.main_nso_extents.base + m_Metadata.main_nso_extents.size) && (memInfo.addr < memInfo.addr + memInfo.size))
    //         {
    //             m_memInfosM.push_back(memInfo);
    //             dmntchtQueryCheatProcessMemory(&memInfo, memInfo.addr + memInfo.size);
    //         }

    //         m_heapBaseAddr = 0;
    //         m_heapSize = 0;
    //         m_heapEnd = 0;
    //         m_heap_total = 0;
    //         m_RW_total = 0;
    //         m_RW_size = 0;
    //         m_not_RW = 0;

    //         memInfo = {0};
    //         dmntchtQueryCheatProcessMemory(&memInfo, 0);
    //         while (memInfo.addr < memInfo.addr + memInfo.size)
    //         {
    //             if (memInfo.perm == Perm_Rw)
    //             {
    //                 m_RW_total++;
    //                 m_RW_size += memInfo.size;
    //             };
    //             if (memInfo.type == MemType_Heap)
    //             {
    //                 if (memInfo.perm != Perm_Rw)
    //                     m_not_RW++;
    //                 if (m_heapBaseAddr == 0)
    //                 {
    //                     m_heapBaseAddr = memInfo.addr;
    //                 }
    //                 m_heapSize += memInfo.size;              
    //                 m_heapEnd = memInfo.addr + memInfo.size;
    //                 m_heap_total++;
    //             }
    //             m_memInfosAll.push_back(memInfo);
    //             dmntchtQueryCheatProcessMemory(&memInfo, memInfo.addr + memInfo.size);
    //         }
    //     }

    // }
    MainMenu::MainMenu() : Menu(nullptr) {
        // init_cheat_system1();

        // if (m_HasCheatProcess) {    
        //     N = 3;
        //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        //     const float y = g_screen_height / 2.0f - (WindowHeight + (ButtonHeight + VerticalGap)*N) / 2.0f;
        //     int i = 0;
        //     // char titlename[30];
        //     // snprintf(titlename, sizeof(titlename) - 1, m_titleName.c_str());
        //     this->AddButton(GametitleButtonId, "Game Information", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
        //     this->AddButton(CheatsButtonId, "Cheats",        x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
        //     this->AddButton(SearchButtonId, "Search Memory", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
        //     this->AddButton(SettingsButtonId,   "Settings",  x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
        //     this->AddButton(ExitButtonId,   "Exit",          x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
        //     u64 cheatCnt;
        //     dmntchtGetCheatCount(&cheatCnt);
        //     if (cheatCnt > 0)
        //         this->SetButtonSelected(CheatsButtonId, true);
        //     else
        //     {
        //         this->SetButtonEnabled(CheatsButtonId, false);
        //         this->SetButtonSelected(SearchButtonId, true);
        //     }
        // } else {
        //     N = 0;
        //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        //     const float y = g_screen_height / 2.0f - (WindowHeight + (ButtonHeight + VerticalGap)*N) / 2.0f;
        //     int i = 0;
        //     this->AddButton(SettingsButtonId,   "Settings",  x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
            // this->AddButton(ExitButtonId,   "Exit",          x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap)*i, WindowWidth - HorizontalInset * 2, ButtonHeight); i++;
            // this->SetButtonSelected(SettingsButtonId, true);
        // }
    }

    void MainMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);

        if (k_down & HidNpadButton_B) {
            g_exit_requested = true;
        }
        // run_once_per_launch();
        std::shared_ptr<Newmenu> action = std::make_shared<Newmenu>();
        action->menu->m_menu_setting.action2 = action;
        air::ChangeMenu(action->menu);
        /* Take action if a button has been activated. */
        if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
            switch (activated_button->id) {
                case CheatsButtonId:
                {
                    // const auto cheat_menu = std::make_shared<CheatMenu>(g_current_menu, "/");

                    // Result rc = 0;
                    // u64 hardware_type;
                    // u64 has_rcm_bug_patch;
                    // u64 is_emummc;

                    // if (R_FAILED(rc = splGetConfig(SplConfigItem_HardwareType, &hardware_type))) {
                    //     ChangeMenu(std::make_shared<ErrorMenu>("An error has occurred", "Failed to get hardware type.", rc));
                    //     return;
                    // }

                    // if (R_FAILED(rc = splGetConfig(static_cast<SplConfigItem>(ExosphereHasRcmBugPatch), &has_rcm_bug_patch))) {
                    //     ChangeMenu(std::make_shared<ErrorMenu>("An error has occurred", "Failed to check RCM bug status.", rc));
                    //     return;
                    // }

                    // if (R_FAILED(rc = splGetConfig(static_cast<SplConfigItem>(ExosphereEmummcType), &is_emummc))) {
                    //     ChangeMenu(std::make_shared<ErrorMenu>("An error has occurred", "Failed to check emuMMC status.", rc));
                    //     return;
                    // }

                    // /* Warn if we're working with a patched unit. */
                    // const bool is_erista = hardware_type == 0 || hardware_type == 1;
                    // if (is_erista && has_rcm_bug_patch && !is_emummc) {
                    //     ChangeMenu(std::make_shared<WarningMenu>(g_current_menu, cheat_menu, "Warning: Patched unit detected", "You may burn fuses or render your switch inoperable."));
                    // } else {
                    //     ChangeMenu(cheat_menu);
                    // }

                    return;
                }
                case SearchButtonId:
                {

                    // Air_menu_setting menu;
                    // menu.menuid = 1;
                    // ChangeMenu(std::make_shared<AirMenu>(g_current_menu, menu));
                    // start_action();
                    // ChangeMenu(std::make_shared<AirMenu>(g_current_menu, air_init_menu()));
                    return; 
                }
                case SettingsButtonId:
                {
                    // start_action();
                    // ChangeMenu(std::make_shared<SelectMenu>(g_current_menu));
                    // ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Settings", "Feature not implemented yet."));
                    return;
                }
                case GametitleButtonId:
                {
                    // ChangeMenu(std::make_shared<GameinfoMenu>(g_current_menu));
                    return;
                }
                case ExitButtonId:
                    g_exit_requested = true;
                    return;
            }
        }

        this->UpdateButtons();

        /* Fallback on selecting the install button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(SettingsButtonId, true);
        }
    }

    void MainMenu::Draw(NVGcontext *vg, u64 ns) {
        DrawWindow(vg, "Breeze 0.0.3", g_screen_width / 2.0f - WindowWidth / 2.0f, g_screen_height / 2.0f - (WindowHeight + (ButtonHeight + VerticalGap)*N) / 2.0f, WindowWidth, WindowHeight + (ButtonHeight + VerticalGap)*N);
        this->DrawButtons(vg, ns);

    }
    
    // CheatMenu::CheatMenu(std::shared_ptr<Menu> prev_menu, const char *root) : Menu(prev_menu), m_current_index(0), m_scroll_offset(0), m_touch_start_scroll_offset(0), m_touch_finalize_selection(false) {
    //     Result rc = 0;

    //     strncpy(m_root, root, sizeof(m_root)-1);

    //     if (R_FAILED(rc = this->PopulateCheatEntries())) {
    //         fatalThrow(rc);
    //     }

    //     N = 8;
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f - xoffset;
    //     const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
    //     int i = 0;
    //     // char titlename[30];
    //     // snprintf(titlename, sizeof(titlename) - 1, m_titleName.c_str());
    //     this->AddButton(ToggleCheatButtonId, "\uE0A2 Toggle Cheat", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(AddConditionalkeyButtonId, "\uE0C5 Add conditional key", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(RemoveConditionalkeyButtonId, "\uE0C4 Remove conditional key", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(AddCheatToBookmarkButtonId, "add cheat to bookmark", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(SaveCheatsButtonId, "Save Cheats to file", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(LoadCheatsButtonId, "Load cheats from file", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(EditCheatButtonId, "Edit Cheat", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(ExitButtonId, "\uE0A1 Exit", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->SetButtonSelected(ToggleCheatButtonId, true);
    // }

    // Result CheatMenu::PopulateCheatEntries() {
    //     u64 cheatCnt;
    //     DmntCheatEntry *m_cheats = nullptr;
    //     dmntchtGetCheatCount(&cheatCnt);
    //     m_cheat_entries.clear();
    //     if (cheatCnt > 0)
    //     {
    //         m_cheats = new DmntCheatEntry[cheatCnt];
    //         dmntchtGetCheats(m_cheats, cheatCnt, 0, &cheatCnt);
    //         for (u64 i = 0; i < cheatCnt; i++)
    //             m_cheat_entries.push_back(m_cheats[i]);
    //         delete m_cheats;
    //     }
    //     else
    //     {
    //         DmntCheatEntry entry;
    //         entry.definition.num_opcodes = 0;
    //         char nocheatstr[] = "No cheat availabe";
    //         strncpy(entry.definition.readable_name, nocheatstr, sizeof(entry.definition.readable_name) - 1);
    //         m_cheat_entries.push_back(entry);
    //     }
    //     return 0;
    // }

    // bool CheatMenu::IsSelectionVisible() {
    //     const float visible_start = m_scroll_offset;
    //     const float visible_end = visible_start + FileListHeight;
    //     const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
    //     const float entry_end = entry_start + (FileRowHeight + FileRowGap);
    //     return entry_start >= visible_start && entry_end <= visible_end;
    // }

    // void CheatMenu::ScrollToSelection() {
    //     const float visible_start = m_scroll_offset;
    //     const float visible_end = visible_start + FileListHeight;
    //     const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
    //     const float entry_end = entry_start + (FileRowHeight + FileRowGap);

    //     if (entry_end > visible_end) {
    //         m_scroll_offset += entry_end - visible_end;
    //     } else if (entry_end < visible_end) {
    //         m_scroll_offset = entry_start;
    //     }
    // }

    // bool CheatMenu::IsEntryTouched(u32 i) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f + xoffset;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     HidTouchScreenState current_touch;
    //     hidGetTouchScreenStates(&current_touch, 1);

    //     /* Check if the tap is within the x bounds. */
    //     if (current_touch.touches[0].x >= x + TextBackgroundOffset + FileRowHorizontalInset && current_touch.touches[0].x <= WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f) {
    //         const float y_min = y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset;
    //         const float y_max = y_min + FileRowHeight;

    //         /* Check if the tap is within the y bounds. */
    //         if (current_touch.touches[0].y >= y_min && current_touch.touches[0].y <= y_max) {
    //             return true;
    //         }
    //     }

    //     return false;
    // }

    // void CheatMenu::UpdateTouches() {
    //     /* Setup values on initial touch. */
    //     if (g_started_touching) {
    //         m_touch_start_scroll_offset = m_scroll_offset;

    //         /* We may potentially finalize the selection later if we start off touching it. */
    //         if (this->IsEntryTouched(m_current_index)) {
    //             m_touch_finalize_selection = true;
    //         }
    //     }

    //     /* Scroll based on touch movement. */
    //     if (g_touches_moving) {
    //         HidTouchScreenState current_touch;
    //         hidGetTouchScreenStates(&current_touch, 1);

    //         const int dist_y = current_touch.touches[0].y - g_start_touch.touches[0].y;
    //         float new_scroll_offset = m_touch_start_scroll_offset - static_cast<float>(dist_y);
    //         float max_scroll = (FileRowHeight + FileRowGap) * static_cast<float>(m_cheat_entries.size()) - FileListHeight;

    //         /* Don't allow scrolling if there is not enough elements. */
    //         if (max_scroll < 0.0f) {
    //             max_scroll = 0.0f;
    //         }

    //         /* Don't allow scrolling before the first element. */
    //         if (new_scroll_offset < 0.0f) {
    //             new_scroll_offset = 0.0f;
    //         }

    //         /* Don't allow scrolling past the last element. */
    //         if (new_scroll_offset > max_scroll) {
    //             new_scroll_offset = max_scroll;
    //         }

    //         m_scroll_offset = new_scroll_offset;
    //     }

    //     /* Select any tapped entries. */
    //     if (g_tapping) {
    //         for (u32 i = 0; i < m_cheat_entries.size(); i++) {
    //             if (this->IsEntryTouched(i)) {
    //                 /* The current index is checked later. */
    //                 if (i == m_current_index) {
    //                     continue;
    //                 }

    //                 m_current_index = i;

    //                 /* Don't finalize selection if we touch something else. */
    //                 m_touch_finalize_selection = false;
    //                 break;
    //             }
    //         }
    //     }

    //     /* Don't finalize selection if we aren't finished and we've either stopped tapping or are no longer touching the selection. */
    //     if (!g_finished_touching && (!g_tapping || !this->IsEntryTouched(m_current_index))) {
    //         m_touch_finalize_selection = false;
    //     }

    //     /* Finalize selection if the currently selected entry is touched for the second time. */
    //     if (g_finished_touching && m_touch_finalize_selection) {
    //         this->FinalizeSelection();
    //         m_touch_finalize_selection = false;
    //     }
    // }

    // void CheatMenu::FinalizeSelection() {
    //     if (!m_cheat_entries[m_current_index].enabled && (m_cheat_entries[m_current_index].definition.num_opcodes + m_totalopcode > 1024)) {
    //         ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Cannot turn on more cheats", "You need to remove some cheats to enable this one."));
    //         return;
    //     };
    //     if (m_cheat_entries[m_current_index].definition.num_opcodes == 0) return;
    //     uint32_t id = m_cheat_entries[m_current_index].cheat_id;
    //     dmntchtToggleCheat(id);
    //     dmntchtGetCheatById(&(m_cheat_entries[m_current_index]), id);
    // }

    // void CheatMenu::RemoveKeyfromSelection() {
    //     if ((m_cheat_entries[m_current_index].definition.opcodes[0] & 0xF0000000) == 0x80000000 && (m_cheat_entries[m_current_index].definition.opcodes[m_cheat_entries[m_current_index].definition.num_opcodes - 1] & 0xF0000000) == 0x20000000)
    //     {
    //         for (u32 i = 0; i < m_cheat_entries[m_current_index].definition.num_opcodes - 1; i++)
    //         {
    //             m_cheat_entries[m_current_index].definition.opcodes[i] = m_cheat_entries[m_current_index].definition.opcodes[i + 1];
    //         }
    //         m_cheat_entries[m_current_index].definition.num_opcodes -= 2;
    //     }
    //     dmntchtRemoveCheat(m_cheat_entries[m_current_index].cheat_id);
    //     u32 outid = 0;
    //     dmntchtAddCheat(&(m_cheat_entries[m_current_index].definition), m_cheat_entries[m_current_index].enabled, &outid);
    //     PopulateCheatEntries();
    // }

    // void CheatMenu::AddKeytoSelection() {
    //     keycode = 0x80000000;
    //     keycount = m_combo;
    //     m_editCheat = true;
    // }


    // void CheatMenu::dumpcodetofile()
    // {
    //     // snprintf(m_cheatcode_path, sizeof(m_cheatcode_path), "sdmc:/atmosphere/contents/%016lx/cheats/%02x%02x%02x%02x%02x%02x%02x%02x.txt", m_Metadata.title_id,
    //     // m_Metadata.main_nso_build_id[0], m_Metadata.main_nso_build_id[1], m_Metadata.main_nso_build_id[2], m_Metadata.main_nso_build_id[3], m_Metadata.main_nso_build_id[4], 
	// 	// m_Metadata.main_nso_build_id[5], m_Metadata.main_nso_build_id[6], m_Metadata.main_nso_build_id[7]);
    //     FILE *pfile;
    //     snprintf(m_cheatcode_path, 128, "sdmc:/atmosphere/contents/%016lx",m_Metadata.title_id);
    //     mkdir(m_cheatcode_path, 0777);
    //     strcat(m_cheatcode_path, "/cheats/");
    //     mkdir(m_cheatcode_path, 0777);
    //     char tmp[1000];
    //     for (u8 i = 0; i < 8; i++)
    //     {
    //         snprintf(tmp, sizeof(tmp), "%02x", m_Metadata.main_nso_build_id[i]);
    //         strcat(m_cheatcode_path,tmp);
    //     };
    //     strcat(m_cheatcode_path,".txt");
    //     printf("%s\n",m_cheatcode_path);
    //     pfile = fopen(m_cheatcode_path, "w");
    //     if (pfile != NULL)
    //     {
    //         for (u32 i = 0; i < m_cheat_entries.size(); i++)
    //         {
    //             snprintf(tmp,1000, "[%s]\n", m_cheat_entries[i].definition.readable_name);
    //             fputs(tmp,pfile);
    //             for (u32 j = 0; j < m_cheat_entries[i].definition.num_opcodes; j++)
    //             {
    //                 u16 opcode = (m_cheat_entries[i].definition.opcodes[j] >> 28) & 0xF;
    //                 u8 T = (m_cheat_entries[i].definition.opcodes[j] >> 24) & 0xF;
    //                 if ((opcode == 9) && (((m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF) == 0))
    //                 {
    //                     snprintf(tmp,1000,"%08X\n",m_cheat_entries[i].definition.opcodes[j]);
    //                     fputs(tmp,pfile);
    //                     continue;
    //                 }
    //                 if (opcode == 0xC)
    //                 {
    //                     opcode = (m_cheat_entries[i].definition.opcodes[j] >> 24) & 0xFF;
    //                     T = (m_cheat_entries[i].definition.opcodes[j] >> 20) & 0xF;
    //                     u8 X = (m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF;
    //                     if (opcode == 0xC0)
    //                     {
    //                         opcode = opcode * 16 + X;
    //                     }
    //                 }
    //                 if (opcode == 10)
    //                 {
    //                     u8 O = (m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF;
    //                     if (O == 2 || O == 4 || O == 5)
    //                         T = 8;
    //                     else
    //                         T = 4;
    //                 }
    //                 switch (opcode)
    //                 {
    //                 case 0:
    //                 case 1:
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //                     fputs(tmp, pfile);
    //                     // 3+1
    //                 case 9:
    //                 case 0xC04:
    //                     // 2+1
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //                     fputs(tmp, pfile);
    //                 case 3:
    //                 case 10:
    //                     // 1+1
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //                     fputs(tmp, pfile);
    //                     if (T == 8 || (T == 0 && opcode == 3))
    //                     {
    //                         j++;
    //                         snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //                         fputs(tmp, pfile);
    //                     }
    //                     break;
    //                 case 4:
    //                 case 6:
    //                     // 3
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //                     fputs(tmp, pfile);
    //                 case 5:
    //                 case 7:
    //                 case 0xC00:
    //                 case 0xC02:
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //                     fputs(tmp, pfile);
    //                     // 2
    //                 case 2:
    //                 case 8:
    //                 case 0xC1:
    //                 case 0xC2:
    //                 case 0xC3:
    //                 case 0xC01:
    //                 case 0xC03:
    //                 case 0xC05:
    //                 default:
    //                     snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //                     fputs(tmp, pfile);
    //                     // 1
    //                     break;
    //                 }
    //                 if (j >= (m_cheat_entries[i].definition.num_opcodes)) // better to be ugly than to corrupt
    //                 {
    //                     printf("error encountered in addcodetofile \n ");
    //                     for (u32 k = 0; k < m_cheat_entries[i].definition.num_opcodes; k++)
    //                     {
    //                         snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[k++]);
    //                         fputs(tmp, pfile);
    //                     }
    //                     snprintf(tmp, sizeof(tmp), "\n");
    //                     fputs(tmp, pfile);
    //                     break;
    //                 }
    //                 snprintf(tmp, sizeof(tmp), "\n");
    //                 fputs(tmp, pfile);
    //             }
    //                 snprintf(tmp, sizeof(tmp), "\n");
    //                 fputs(tmp, pfile);
    //         }
    //         fclose(pfile);
    //     }

    // }

    // void CheatMenu::Update(u64 ns) {
    //     u64 k_down = padGetButtonsDown(&g_pad);

    //     /* Go back if B is pressed. */
    //     if ((k_down & HidNpadButton_B) && !m_editCheat) {
    //         ReturnToPreviousMenu();
    //         return;
    //     }

    //     /* Finalize selection on pressing X. */
    //     if ((k_down & HidNpadButton_X) && !m_editCheat)  {
    //         this->FinalizeSelection();
    //     }

    //     if ((k_down & HidNpadButton_StickR) && !m_editCheat)
    //     {
    //         keycode = 0x80000000;
    //         keycount = m_combo;
    //         m_editCheat = true;
    //         do
    //         {
    //             padUpdate(&g_pad);
    //         } while (!(padGetButtonsUp(&g_pad) & HidNpadButton_StickR));
    //         return;
    //     }

    //     if ((k_down & HidNpadButton_StickL) && !m_editCheat)
    //     {
    //         RemoveKeyfromSelection();
    //         return;
    //     }
        
    //     /* Update touch input. */
    //     this->UpdateTouches();

    //     const u32 prev_index = m_current_index;
    //     if ((m_editCheat) && (k_down != 0))
    //     {
    //         keycode = keycode | k_down;
    //         keycount--;
    //         do
    //         {
    //             padUpdate(&g_pad);
    //         } while (!(padGetButtonsUp(&g_pad) & k_down));
    //         if (keycount > 0) return;
    //         m_editCheat = false;
    //         // if (buttonStr(keycode) != "")
    //         {
    //             // edit cheat
    //             if ((m_cheat_entries[m_current_index].definition.opcodes[0] & 0xF0000000) == 0x80000000)
    //             {
    //                 m_cheat_entries[m_current_index].definition.opcodes[0] = keycode;
    //             }
    //             else
    //             {
    //                 if (m_cheat_entries[m_current_index].definition.num_opcodes < 0x100 + 2)
    //                 {
    //                     m_cheat_entries[m_current_index].definition.opcodes[m_cheat_entries[m_current_index].definition.num_opcodes + 1] = 0x20000000;

    //                     for (u32 i = m_cheat_entries[m_current_index].definition.num_opcodes; i > 0; i--)
    //                     {
    //                         m_cheat_entries[m_current_index].definition.opcodes[i] = m_cheat_entries[m_current_index].definition.opcodes[i - 1];
    //                     }
    //                     m_cheat_entries[m_current_index].definition.num_opcodes += 2;
    //                     m_cheat_entries[m_current_index].definition.opcodes[0] = keycode;
    //                 }
    //             }
    //             // modify cheat
    //             dmntchtRemoveCheat(m_cheat_entries[m_current_index].cheat_id);
    //             u32 outid = 0;
    //             dmntchtAddCheat(&(m_cheat_entries[m_current_index].definition), m_cheat_entries[m_current_index].enabled, &outid);
    //             // if (outid != m_cheat_entries[m_current_index].cheat_id)
    //             //     sprintf(m_cheat_entries[m_current_index].definition.readable_name, "out id not the same! %d %d", outid, m_cheat_entries[m_current_index].cheat_id);
    //             // m_cheat_entries[m_current_index].cheat_id = outid;
    //             PopulateCheatEntries();
    //         };
    //         return;
    //     } else if (k_down & HidNpadButton_StickLRight) {
    //         /* Page down. */
    //         m_current_index += 10;
    //         if (m_current_index >= (m_cheat_entries.size() - 1)) {
    //             m_current_index = m_cheat_entries.size() - 1;
    //         }
    //     } else if (k_down & HidNpadButton_StickLLeft) {
    //         /* Page up. */
    //         if (m_current_index < 10) {
    //             m_current_index = 0;
    //         } else
    //             m_current_index -= 10;
    //     } else if (k_down & HidNpadButton_StickLDown) {
    //         /* Scroll down. */
    //         if (m_current_index >= (m_cheat_entries.size() - 1)) {
    //             m_current_index = 0;
    //         } else {
    //             m_current_index++;
    //         }
    //     } else if (k_down & HidNpadButton_StickLUp) {
    //         /* Scroll up. */
    //         if (m_current_index == 0) {
    //             m_current_index = m_cheat_entries.size() - 1;
    //         } else {
    //             m_current_index--;
    //         }
    //     } else this->UpdateButtons();

        
    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr)
    //     {
    //         switch (activated_button->id)
    //         {
    //         case ExitButtonId:
    //         {
    //             ReturnToPreviousMenu();
    //             return;
    //         }
    //         case ToggleCheatButtonId:
    //         {
    //             this->FinalizeSelection();
    //             return;
    //         }
    //         case AddConditionalkeyButtonId:
    //         {
    //             AddKeytoSelection();
    //             return;
    //         }
    //         case RemoveConditionalkeyButtonId:
    //         {
    //             RemoveKeyfromSelection();
    //             return;
    //         }
    //         case SaveCheatsButtonId:
    //         {
    //             dumpcodetofile();
    //             ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Save cheats", "code written to contents directory"));
    //             return;
    //         }
    //         case LoadCheatsButtonId:
    //         {
    //             ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Load Cheats", "Feature not implemented yet."));
    //             return;
    //         }
    //         case EditCheatButtonId:
    //         {
    //             ChangeMenu(std::make_shared<EditCheatMenu>(g_current_menu, m_current_index));
    //             return;
    //         }
    //         case AddCheatToBookmarkButtonId:
    //         {
    //             ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Add Cheat to Bookmark", "Feature not implemented yet."));
    //             return;
    //         }
    //         }
    //     }
    //     /* Scroll to the selection if it isn't visible. */
    //     if (prev_index != m_current_index && !this->IsSelectionVisible()) {
    //         this->ScrollToSelection();
    //     }
    //     /* Fallback on selecting the install button. */
    //     if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
    //         this->SetButtonSelected(ToggleCheatButtonId, true);
    //     }
    // }

    // void CheatMenu::Draw(NVGcontext *vg, u64 ns) {

    //     DrawWindow(vg, "\uE0D0 Action select  \uE0A0 Execute", g_screen_width / 2.0f -xoffset - WindowWidth / 2.0f, g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, WindowWidth, TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N);
    //     this->DrawButtons(vg, ns);

    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f + xoffset;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
        
    //     char status_str[300];

    //     // sprintf(status_str,"Cheat %d/%ld  Opcode count [ %d ]  Cheat enabled [ %d ]  Opcode used [ %d ]  Opcode available [ %d ]",m_current_index+1,m_cheat_entries.size(),
    //     // m_cheat_entries[m_current_index].definition.num_opcodes, m_enabledcnt, m_totalopcode, 1024-m_totalopcode);
    //     // snprintf(status_str,300, "Index %d Cheat enabled [%d/%ld] Opcode used [%d/1024]", m_current_index + 1,
    //     //         m_enabledcnt, m_cheat_entries.size(), m_totalopcode);
    //     snprintf(status_str, 300, "\uE0C1 Cheat select %d %d/%ld %d/1024", (m_cheat_entries[0].definition.num_opcodes == 0) ? 0 : m_current_index + 1,
    //              m_enabledcnt, (m_cheat_entries[0].definition.num_opcodes == 0) ? 0 : m_cheat_entries.size(), m_totalopcode);
    //     DrawWindow(vg, status_str, x, y, WindowWidth, WindowHeight); //"Select a cheat press A to toggle on/off"
    //     DrawTextBackground(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

    //     nvgSave(vg);
    //     nvgScissor(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

    //     m_enabledcnt = 0;
    //     m_totalopcode = 0;
    //     for (u32 i = 0; i < m_cheat_entries.size(); i++) {
    //         DmntCheatEntry &entry = m_cheat_entries[i];
    //         auto style = ButtonStyle::FileSelect;
    //         char namestr[100] = "";
    //         if (entry.enabled)
    //         {
    //             strcat(namestr, "\u25A0 ");
    //             m_enabledcnt ++;
    //             m_totalopcode += entry.definition.num_opcodes;
    //         }
    //         else
    //         {
    //             strcat(namestr, "\u25A1 ");
    //         };
    //         int buttoncode = entry.definition.opcodes[0];
    //         for (u32 i = 0; i < buttonCodes.size(); i++) {
    //             if ((buttoncode & buttonCodes[i]) == buttonCodes[i])
    //                 strcat(namestr, buttonNames[i].c_str());
    //         }
    //         if (i == m_current_index) {
    //             style = ButtonStyle::FileSelectSelected;
    //             if (m_editCheat)
    //                 sprintf(namestr, "keycount = %d Press conditional key for ", keycount);
    //             if (entry.definition.num_opcodes == 0)
    //             {
    //                 style = ButtonStyle::StandardDisabled;
    //                 namestr[0] = 0;
    //             };
    //         }
    //         strcat(namestr, entry.definition.readable_name);
    //         DrawButton(vg, namestr, x + TextBackgroundOffset + FileRowHorizontalInset, y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset, WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f, FileRowHeight, style, ns);
    //     }

    //     nvgRestore(vg);
    // }

 //BM    
    // EditCheatMenu::EditCheatMenu(std::shared_ptr<Menu> prev_menu, u32 cheat_index) : Menu(prev_menu), m_current_index(0), m_scroll_offset(0), m_touch_start_scroll_offset(0), m_touch_finalize_selection(false) {
    //     PopulateCheatLines(cheat_index);
    //     m_cheat_index = cheat_index;
    //     N = 8;
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f - xoffset;
    //     const float y = g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f;
    //     int i = 0;
    //     // char titlename[30];
    //     // snprintf(titlename, sizeof(titlename) - 1, m_titleName.c_str());
    //     this->AddButton(EditButtonId, "\uE0A2 Edit", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(Editf32ButtonId, "\uE0C5 Edit f32 value", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(Editf64ButtonId, "\uE0C4 Edit f64", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(DoublicateButtonId, "Doublicate cheat", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(DeleteButtonId, "Delete cheat", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(CopylineButtonId, "Copy line", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(PastelineButtonId, "Paste line", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->AddButton(ExitButtonId, "\uE0A1 Exit", x + HorizontalInset, y + TitleGap + (ButtonHeight + VerticalGap) * i, WindowWidth - HorizontalInset * 2, ButtonHeight);
    //     i++;
    //     this->SetButtonSelected(EditButtonId, true);
    // }

    // void EditCheatMenu::PopulateCheatLines(u32 i)
    // {
    //     char tmp[100];
    //     CheatlineEntry lineEntry;
    //     snprintf(lineEntry.line, sizeof(tmp), "[%s]", m_cheat_entries[i].definition.readable_name);
    //     m_cheat_lines.push_back(lineEntry);
    //     lineEntry.line[0] = 0;
    //     for (u32 j = 0; j < m_cheat_entries[i].definition.num_opcodes; j++)
    //     {
    //         u16 opcode = (m_cheat_entries[i].definition.opcodes[j] >> 28) & 0xF;
    //         u8 T = (m_cheat_entries[i].definition.opcodes[j] >> 24) & 0xF;
    //         if ((opcode == 9) && (((m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF) == 0))
    //         {
    //             snprintf(tmp, sizeof(tmp), "%08X", m_cheat_entries[i].definition.opcodes[j]);
    //             strcat(lineEntry.line, tmp);
    //             m_cheat_lines.push_back(lineEntry);
    //             lineEntry.line[0] = 0;
    //             continue;
    //         }
    //         if (opcode == 0xC)
    //         {
    //             opcode = (m_cheat_entries[i].definition.opcodes[j] >> 24) & 0xFF;
    //             T = (m_cheat_entries[i].definition.opcodes[j] >> 20) & 0xF;
    //             u8 X = (m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF;
    //             if (opcode == 0xC0)
    //             {
    //                 opcode = opcode * 16 + X;
    //             }
    //         }
    //         if (opcode == 10)
    //         {
    //             u8 O = (m_cheat_entries[i].definition.opcodes[j] >> 8) & 0xF;
    //             if (O == 2 || O == 4 || O == 5)
    //                 T = 8;
    //             else
    //                 T = 4;
    //         }
    //         switch (opcode)
    //         {
    //         case 0:
    //         case 1:
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //             strcat(lineEntry.line, tmp);
    //             // 3+1
    //         case 9:
    //         case 0xC04:
    //             // 2+1
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //             strcat(lineEntry.line, tmp);
    //         case 3:
    //         case 10:
    //             // 1+1
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //             strcat(lineEntry.line, tmp);
    //             if (T == 8 || (T == 0 && opcode == 3))
    //             {
    //                 j++;
    //                 snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //                 strcat(lineEntry.line, tmp);
    //             }
    //             break;
    //         case 4:
    //         case 6:
    //             // 3
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //             strcat(lineEntry.line, tmp);
    //         case 5:
    //         case 7:
    //         case 0xC00:
    //         case 0xC02:
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j++]);
    //             strcat(lineEntry.line, tmp);
    //             // 2
    //         case 2:
    //         case 8:
    //         case 0xC1:
    //         case 0xC2:
    //         case 0xC3:
    //         case 0xC01:
    //         case 0xC03:
    //         case 0xC05:
    //         default:
    //             snprintf(tmp, sizeof(tmp), "%08X ", m_cheat_entries[i].definition.opcodes[j]);
    //             strcat(lineEntry.line, tmp);
    //             // 1
    //             break;
    //         }
    //         if (j >= (m_cheat_entries[i].definition.num_opcodes)) // better to be ugly than to corrupt
    //         {
    //             printf("error encountered in addcodetofile \n ");
    //             for (u32 k = 0; k < m_cheat_entries[i].definition.num_opcodes; k++)
    //             {
    //                 snprintf(tmp, sizeof(tmp), "%08X", m_cheat_entries[i].definition.opcodes[k++]);
    //                 strcat(lineEntry.line, tmp);
    //             }
    //             m_cheat_lines.push_back(lineEntry);
    //             lineEntry.line[0] = 0;
    //             break;
    //         }
    //         if (strlen(lineEntry.line) % 9 == 0)
    //             lineEntry.line[strlen(lineEntry.line)-1] = 0;
    //         m_cheat_lines.push_back(lineEntry);
    //         lineEntry.line[0] = 0;
    //     }
    //     // m_cheat_lines.push_back(lineEntry);
        
    // };


    // bool EditCheatMenu::IsSelectionVisible() {
    //     const float visible_start = m_scroll_offset;
    //     const float visible_end = visible_start + FileListHeight;
    //     const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
    //     const float entry_end = entry_start + (FileRowHeight + FileRowGap);
    //     return entry_start >= visible_start && entry_end <= visible_end;
    // }

    // void EditCheatMenu::ScrollToSelection() {
    //     const float visible_start = m_scroll_offset;
    //     const float visible_end = visible_start + FileListHeight;
    //     const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
    //     const float entry_end = entry_start + (FileRowHeight + FileRowGap);

    //     if (entry_end > visible_end) {
    //         m_scroll_offset += entry_end - visible_end;
    //     } else if (entry_end < visible_end) {
    //         m_scroll_offset = entry_start;
    //     }
    // }

    // bool EditCheatMenu::IsEntryTouched(u32 i) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f + xoffset;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     HidTouchScreenState current_touch;
    //     hidGetTouchScreenStates(&current_touch, 1);

    //     /* Check if the tap is within the x bounds. */
    //     if (current_touch.touches[0].x >= x + TextBackgroundOffset + FileRowHorizontalInset && current_touch.touches[0].x <= WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f) {
    //         const float y_min = y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset;
    //         const float y_max = y_min + FileRowHeight;

    //         /* Check if the tap is within the y bounds. */
    //         if (current_touch.touches[0].y >= y_min && current_touch.touches[0].y <= y_max) {
    //             return true;
    //         }
    //     }

    //     return false;
    // }

    // void EditCheatMenu::UpdateTouches() {
    //     /* Setup values on initial touch. */
    //     if (g_started_touching) {
    //         m_touch_start_scroll_offset = m_scroll_offset;

    //         /* We may potentially finalize the selection later if we start off touching it. */
    //         if (this->IsEntryTouched(m_current_index)) {
    //             m_touch_finalize_selection = true;
    //         }
    //     }

    //     /* Scroll based on touch movement. */
    //     if (g_touches_moving) {
    //         HidTouchScreenState current_touch;
    //         hidGetTouchScreenStates(&current_touch, 1);

    //         const int dist_y = current_touch.touches[0].y - g_start_touch.touches[0].y;
    //         float new_scroll_offset = m_touch_start_scroll_offset - static_cast<float>(dist_y);
    //         float max_scroll = (FileRowHeight + FileRowGap) * static_cast<float>(m_cheat_lines.size()) - FileListHeight;

    //         /* Don't allow scrolling if there is not enough elements. */
    //         if (max_scroll < 0.0f) {
    //             max_scroll = 0.0f;
    //         }

    //         /* Don't allow scrolling before the first element. */
    //         if (new_scroll_offset < 0.0f) {
    //             new_scroll_offset = 0.0f;
    //         }

    //         /* Don't allow scrolling past the last element. */
    //         if (new_scroll_offset > max_scroll) {
    //             new_scroll_offset = max_scroll;
    //         }

    //         m_scroll_offset = new_scroll_offset;
    //     }

    //     /* Select any tapped entries. */
    //     if (g_tapping) {
    //         for (u32 i = 0; i < m_cheat_lines.size(); i++) {
    //             if (this->IsEntryTouched(i)) {
    //                 /* The current index is checked later. */
    //                 if (i == m_current_index) {
    //                     continue;
    //                 }

    //                 m_current_index = i;

    //                 /* Don't finalize selection if we touch something else. */
    //                 m_touch_finalize_selection = false;
    //                 break;
    //             }
    //         }
    //     }

    //     /* Don't finalize selection if we aren't finished and we've either stopped tapping or are no longer touching the selection. */
    //     if (!g_finished_touching && (!g_tapping || !this->IsEntryTouched(m_current_index))) {
    //         m_touch_finalize_selection = false;
    //     }

    //     /* Finalize selection if the currently selected entry is touched for the second time. */
    //     if (g_finished_touching && m_touch_finalize_selection) {
    //         this->EditSelection();
    //         m_touch_finalize_selection = false;
    //     }
    // }

    // void EditCheatMenu::EditSelection() {
    //     // if (m_cheat_lines[m_current_index].line)
    //     char outline[0x43];
    //     size_t inputsize = 32;
    //     SwkbdType type = SwkbdType_QWERTY;
    //     if (m_current_index == 0)
    //         inputsize = 0x42;
    //     if (requestKeyboardInput("Edit code", "all code need to be group of 8 hex digits", m_cheat_lines[m_current_index].line, type, outline, inputsize))
    //     {
    //         strcpy(m_cheat_lines[m_current_index].line, outline);
    //     };
    //     // ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Cannot turn on more cheats", "You need to remove some cheats to enable this one."));
    //     return;

    // }

//  //BM
//     void EditCheatMenu::Update(u64 ns) {
//         u64 k_down = padGetButtonsDown(&g_pad);

//         /* Go back if B is pressed. */
//         if ((k_down & HidNpadButton_B) && !m_editCheat) {
//             ReturnToPreviousMenu();
//             return;
//         }

//         /* Finalize selection on pressing X. */
//         if (k_down & HidNpadButton_X)  {
//             this->EditSelection();
//         }

//         if (k_down & HidNpadButton_StickR) 
//         {

//             return;
//         }


        
//         /* Update touch input. */
//         this->UpdateTouches();

//         const u32 prev_index = m_current_index;

//         if (k_down & HidNpadButton_ZR) {
//             /* Page down. */
//             m_current_index += 10;
//             if (m_current_index >= (m_cheat_lines.size() - 1)) {
//                 m_current_index = m_cheat_lines.size() - 1;
//             }
//         } else if (k_down & HidNpadButton_ZL) {
//             /* Page up. */
//             if (m_current_index < 10) {
//                 m_current_index = 0;
//             } else
//                 m_current_index -= 10;
//         } else if (k_down & HidNpadButton_StickLDown) {
//             /* Scroll down. */
//             if (m_current_index >= (m_cheat_lines.size() - 1)) {
//                 m_current_index = 0;
//             } else {
//                 m_current_index++;
//             }
//         } else if (k_down & HidNpadButton_StickLUp) {
//             /* Scroll up. */
//             if (m_current_index == 0) {
//                 m_current_index = m_cheat_lines.size() - 1;
//             } else {
//                 m_current_index--;
//             }
//         } else this->UpdateButtons();

        
//         /* Take action if a button has been activated. */
//         if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr)
//         {
//             switch (activated_button->id)
//             {
//             case ExitButtonId:
//             {
//                 ReturnToPreviousMenu();
//                 return;
//             }
//             case EditButtonId:
//             {
//                 this->EditSelection();
//                 return;
//             }

//             case Editf32ButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Editf32", "Feature not implemented yet."));
//                 return;
//             }
//             case Editf64ButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "Editf64", "Feature not implemented yet."));
//                 return;
//             }
//             case DoublicateButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "DoublicateButtonId", "Feature not implemented yet."));
//                 return;
//             }
//             case DeleteButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "DeleteButtonId", "Feature not implemented yet."));
//                 return;
//             }
//             case CopylineButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "CopylineButtonId", "Feature not implemented yet."));
//                 return;
//             }
//             case PastelineButtonId:
//             {
//                 ChangeMenu(std::make_shared<MessageMenu>(g_current_menu, "PastelineButtonId", "Feature not implemented yet."));
//                 return;
//             }
//             }
//         }
//         /* Scroll to the selection if it isn't visible. */
//         if (prev_index != m_current_index && !this->IsSelectionVisible()) {
//             this->ScrollToSelection();
//         }
//         /* Fallback on selecting the install button. */
//         if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
//             this->SetButtonSelected(EditButtonId, true);
//         }
//     }
//  //BM
//     void EditCheatMenu::Draw(NVGcontext *vg, u64 ns) {

//         DrawWindow(vg, "\uE0C2 Action select  \uE0A0 Execute", g_screen_width / 2.0f -xoffset - WindowWidth / 2.0f, g_screen_height / 2.0f - (TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N) / 2.0f, WindowWidth, TitleGap + 20.0f + (ButtonHeight + VerticalGap) * N);
//         this->DrawButtons(vg, ns);

//         const float x = g_screen_width / 2.0f - WindowWidth / 2.0f + xoffset;
//         const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
        
//         char status_str[300];

//         // sprintf(status_str,"Cheat %d/%ld  Opcode count [ %d ]  Cheat enabled [ %d ]  Opcode used [ %d ]  Opcode available [ %d ]",m_current_index+1,m_cheat_entries.size(),
//         // m_cheat_entries[m_current_index].definition.num_opcodes, m_enabledcnt, m_totalopcode, 1024-m_totalopcode);
//         // snprintf(status_str,300, "Index %d Cheat enabled [%d/%ld] Opcode used [%d/1024]", m_current_index + 1,
//         //         m_enabledcnt, m_cheat_entries.size(), m_totalopcode);
//         snprintf(status_str, 300, "\uE0C1 Choose line to edit");
//         DrawWindow(vg, status_str, x, y, WindowWidth, WindowHeight); //"Select a cheat press A to toggle on/off"
//         DrawTextBackground(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

//         nvgSave(vg);
//         nvgScissor(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

//         m_enabledcnt = 0;
//         m_totalopcode = 0;
//         for (u32 i = 0; i < m_cheat_lines.size(); i++){
//             CheatlineEntry &entry = m_cheat_lines[i];
//             auto style = ButtonStyle::FileSelect;
//             // char namestr[100] = "";
//             // if (entry.enabled)
//             // {
//             //     strcat(namestr, " On    ");
//             //     m_enabledcnt ++;
//             //     m_totalopcode += entry.definition.num_opcodes;
//             // }
//             // else
//             // {
//             //     strcat(namestr, "          ");
//             // };
//             // int buttoncode = entry.definition.opcodes[0];
//             // for (u32 i = 0; i < buttonCodes.size(); i++) {
//             //     if ((buttoncode & buttonCodes[i]) == buttonCodes[i])
//             //         strcat(namestr, buttonNames[i].c_str());
//             // }
//             if (i == m_current_index) {
//                 style = ButtonStyle::FileSelectSelected;
//             //     if (m_editCheat)
//             //         sprintf(namestr, "keycount = %d Press conditional key for ", keycount);
//             //     if (entry.definition.num_opcodes == 0)
//             //     {
//             //         style = ButtonStyle::StandardDisabled;
//             //         namestr[0] = 0;
//             //     };
//             }
//             // strcat(namestr, entry.definition.readable_name);
//             DrawButton(vg, entry.line, x + TextBackgroundOffset + FileRowHorizontalInset, y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset, WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f, FileRowHeight, style, ns);
//         }

//         nvgRestore(vg);
//     }

    FileMenu::FileMenu(std::shared_ptr<Menu> prev_menu, const char *root, u32 id, void (*action)(u32, u32)) : Menu(prev_menu), m_current_index(0), m_scroll_offset(0), m_touch_start_scroll_offset(0), m_touch_finalize_selection(false) {
        Result rc = 0;
        m_id = id;
        m_action = action;
        strncpy(m_root, root, sizeof(m_root)-1);

        if (R_FAILED(rc = this->PopulateFileEntries())) {
            fatalThrow(rc);
        }
    }

    Result FileMenu::PopulateFileEntries() {
        /* Open the directory. */
        DIR *dir = opendir(m_root);
        if (dir == nullptr) {
            return fsdevGetLastResult();
        }

        /* Add file entries to the list. */
        struct dirent *ent;
        while ((ent = readdir(dir)) != nullptr) {
            if (ent->d_type == DT_DIR || (ent->d_type == DT_REG && g_FileEntry.d_type == DT_REG)) {
                FileEntry file_entry = {};
                strncpy(file_entry.name, ent->d_name, sizeof(file_entry.name));
                file_entry.d_type = ent->d_type;
                m_file_entries.push_back(file_entry);
            }
        }

        /* Close the directory. */
        closedir(dir);

        /* Sort the file entries. */
        std::sort(m_file_entries.begin(), m_file_entries.end(), [](const FileEntry &a, const FileEntry &b) {
            return strncmp(a.name, b.name, sizeof(a.name)) < 0;
        });

        return 0;
    }

    bool FileMenu::IsSelectionVisible() {
        const float visible_start = m_scroll_offset;
        const float visible_end = visible_start + FileListHeight;
        const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
        const float entry_end = entry_start + (FileRowHeight + FileRowGap);
        return entry_start >= visible_start && entry_end <= visible_end;
    }

    void FileMenu::ScrollToSelection() {
        const float visible_start = m_scroll_offset;
        const float visible_end = visible_start + FileListHeight;
        const float entry_start = static_cast<float>(m_current_index) * (FileRowHeight + FileRowGap);
        const float entry_end = entry_start + (FileRowHeight + FileRowGap);

        if (entry_end > visible_end) {
            m_scroll_offset += entry_end - visible_end;
        } else if (entry_end < visible_end) {
            m_scroll_offset = entry_start;
        }
    }

    bool FileMenu::IsEntryTouched(u32 i) {
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

        HidTouchScreenState current_touch;
        hidGetTouchScreenStates(&current_touch, 1);

        /* Check if the tap is within the x bounds. */
        if (current_touch.touches[0].x >= x + TextBackgroundOffset + FileRowHorizontalInset && current_touch.touches[0].x <= WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f) {
            const float y_min = y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset;
            const float y_max = y_min + FileRowHeight;

            /* Check if the tap is within the y bounds. */
            if (current_touch.touches[0].y >= y_min && current_touch.touches[0].y <= y_max) {
                return true;
            }
        }

        return false;
    }

    void FileMenu::UpdateTouches() {
        /* Setup values on initial touch. */
        if (g_started_touching) {
            m_touch_start_scroll_offset = m_scroll_offset;

            /* We may potentially finalize the selection later if we start off touching it. */
            if (this->IsEntryTouched(m_current_index)) {
                m_touch_finalize_selection = true;
            }
        }

        /* Scroll based on touch movement. */
        if (g_touches_moving) {
            HidTouchScreenState current_touch;
            hidGetTouchScreenStates(&current_touch, 1);

            const int dist_y = current_touch.touches[0].y - g_start_touch.touches[0].y;
            float new_scroll_offset = m_touch_start_scroll_offset - static_cast<float>(dist_y);
            float max_scroll = (FileRowHeight + FileRowGap) * static_cast<float>(m_file_entries.size()) - FileListHeight;

            /* Don't allow scrolling if there is not enough elements. */
            if (max_scroll < 0.0f) {
                max_scroll = 0.0f;
            }

            /* Don't allow scrolling before the first element. */
            if (new_scroll_offset < 0.0f) {
                new_scroll_offset = 0.0f;
            }

            /* Don't allow scrolling past the last element. */
            if (new_scroll_offset > max_scroll) {
                new_scroll_offset = max_scroll;
            }

            m_scroll_offset = new_scroll_offset;
        }

        /* Select any tapped entries. */
        if (g_tapping) {
            for (u32 i = 0; i < m_file_entries.size(); i++) {
                if (this->IsEntryTouched(i)) {
                    /* The current index is checked later. */
                    if (i == m_current_index) {
                        continue;
                    }

                    m_current_index = i;

                    /* Don't finalize selection if we touch something else. */
                    m_touch_finalize_selection = false;
                    break;
                }
            }
        }

        /* Don't finalize selection if we aren't finished and we've either stopped tapping or are no longer touching the selection. */
        if (!g_finished_touching && (!g_tapping || !this->IsEntryTouched(m_current_index))) {
            m_touch_finalize_selection = false;
        }

        /* Finalize selection if the currently selected entry is touched for the second time. */
        if (g_finished_touching && m_touch_finalize_selection) {
            this->FinalizeSelection();
            m_touch_finalize_selection = false;
        }
    }

    void FileMenu::FinalizeSelection() {
        DBK_ABORT_UNLESS(m_current_index < m_file_entries.size());
        FileEntry &entry = m_file_entries[m_current_index];

        /* Determine the selected path. */
        char current_path[FS_MAX_PATH] = {};
        int path_len = snprintf(current_path, sizeof(current_path), "%s%s/", m_root, entry.name);
        if (entry.d_type == DT_REG)
            path_len = snprintf(current_path, sizeof(current_path), "%s%s", m_root, entry.name);
        DBK_ABORT_UNLESS(path_len >= 0 && path_len < static_cast<int>(sizeof(current_path)));

        /* Determine if the chosen path is the bottom level. */
        Result rc = 0;
        bool bottom_level = false;
        if (entry.d_type == DT_DIR) {
            if (g_FileEntry.d_type == DT_DIR)
                if (R_FAILED(rc = IsPathBottomLevel(current_path, &bottom_level))) {
                    fatalThrow(rc);
                }
        } else {
            bottom_level = true;
        }

        /* Show exfat settings or the next file menu. */
        if (bottom_level) {
            /* Set the update path. */
            snprintf(g_FileEntry.name, sizeof(g_FileEntry.name), "%s", current_path);
            snprintf(g_FileEntry.dir, sizeof(g_FileEntry.dir), "%s", m_root);
            /* Change the menu. */
            // ChangeMenu(std::make_shared<ValidateUpdateMenu>(g_current_menu));
            if (m_action !=nullptr)
                m_action(m_id, 0);
        } else {
            ChangeMenu(std::make_shared<FileMenu>(g_current_menu, current_path, m_id, m_action));
        }
    }

    void FileMenu::Update(u64 ns) {
        // if (g_FileEntry.picked) {
        //     ReturnToPreviousMenu();
        //     return;
        // }
        u64 k_down = padGetButtonsDown(&g_pad);

        /* Go back if B is pressed. */
        if (k_down & HidNpadButton_B) {
            ReturnToPreviousMenu();
            return;
        }

        /* Finalize selection on pressing A. */
        if (k_down & HidNpadButton_A) {
            this->FinalizeSelection();
        }

        /* Update touch input. */
        this->UpdateTouches();

        const u32 prev_index = m_current_index;

        if (k_down & HidNpadButton_AnyDown) {
            /* Scroll down. */
            if (m_current_index >= (m_file_entries.size() - 1)) {
                m_current_index = 0;
            } else {
                m_current_index++;
            }
        } else if (k_down & HidNpadButton_AnyUp) {
            /* Scroll up. */
            if (m_current_index == 0) {
                m_current_index = m_file_entries.size() - 1;
            } else {
                m_current_index--;
            }
        }

        /* Scroll to the selection if it isn't visible. */
        if (prev_index != m_current_index && !this->IsSelectionVisible()) {
            this->ScrollToSelection();
        }
    }

    void FileMenu::Draw(NVGcontext *vg, u64 ns) {
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

        DrawWindow(vg, "Select File", x, y, WindowWidth, WindowHeight);
        DrawTextBackground(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

        nvgSave(vg);
        nvgScissor(vg, x + TextBackgroundOffset, y + TitleGap, WindowWidth - TextBackgroundOffset * 2.0f, (FileRowHeight + FileRowGap) * MaxFileRows + FileRowGap);

        for (u32 i = 0; i < m_file_entries.size(); i++) {
            FileEntry &entry = m_file_entries[i];
            auto style = ButtonStyle::FileSelect;

            if (i == m_current_index) {
                style = ButtonStyle::FileSelectSelected;
            }

            DrawButton(vg, entry.name, x + TextBackgroundOffset + FileRowHorizontalInset, y + TitleGap + FileRowGap + i * (FileRowHeight + FileRowGap) - m_scroll_offset, WindowWidth - (TextBackgroundOffset + FileRowHorizontalInset) * 2.0f, FileRowHeight, style, ns);
        }

        nvgRestore(vg);
    }
//BM1 ProgressinfoMenu
    ProgressinfoMenu::ProgressinfoMenu(std::shared_ptr<Menu> prev_menu, air::Air_menu_setting menu_setting, SearchTask* searchtask) : Menu(prev_menu), m_progress_percent(0.0f) {
        m_menu_setting = menu_setting;
        m_searchtask = searchtask;
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
        const float button_width = (WindowWidth - HorizontalInset * (menu_setting.num_button_column + 1)) / menu_setting.num_button_column;

        char boxstr[100];
        for (u64 i = 0; i < menu_setting.actions.size(); i++) {
            if (menu_setting.actions[i].ButtonId < 24)
                snprintf(boxstr, sizeof(boxstr) - 1, "%s%s", buttonNames2[menu_setting.actions[i].ButtonId].c_str(), menu_setting.actions[i].label.c_str());
            else
                snprintf(boxstr, sizeof(boxstr) - 1, "%s", menu_setting.actions[i].label.c_str());
            this->AddButton(menu_setting.actions[i].ButtonId, boxstr, x + HorizontalInset + (button_width + HorizontalInset) * (i % menu_setting.num_button_column), y + WindowHeight - BottomInset - ButtonHeight + (ButtonHeight + VerticalGap) * (i / menu_setting.num_button_column), button_width, ButtonHeight);
            if (!menu_setting.actions[i].enable) SetButtonEnabled(menu_setting.actions[i].ButtonId, false);
        }
        this->SetButtonSelected(menu_setting.button_selected, true);

    }


    void ProgressinfoMenu::Update(u64 ns) {
        u64 k_down = padGetButtonsDown(&g_pad);
        
        const Button *activated_button = this->GetActivatedButton();
        u32 buttonid;
        if (activated_button == nullptr) {
            bool match = false;
            if (k_down == HidNpadButton_A) {
                buttonid = 0;
                match = true;
            } else
                for (size_t i = 0; i < m_menu_setting.actions.size(); i++) {
                    if (k_down & m_menu_setting.actions[i].keycode) { //&& menu.actions[i].enable
                        buttonid = m_menu_setting.actions[i].ButtonId;
                        match = true;
                    }
                }
            if (match == true)
            {
                if (this->ButtonEnabled(buttonid))
                    m_searchtask->Search_task_action(buttonid, 0);
                    // m_menu_setting.action(buttonid, 0);
                return;
            }
        } else {
            buttonid = activated_button->id;
            m_searchtask->Search_task_action(buttonid, 0);
            // m_menu_setting.action(buttonid,0);
            return;
        };

        this->UpdateButtons();

        /* Fallback on selecting the install button. */
        if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
            this->SetButtonSelected(m_menu_setting.button_selected, true);
        }
        // m_menu_setting.action(0,0); 
        // task action
        m_searchtask->Search_task_action(0,0);
    }

    void ProgressinfoMenu::Draw(NVGcontext *vg, u64 ns) {
        const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
        const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

        DrawWindow(vg, "Progress Information", x, y, WindowWidth, WindowHeight);
        DrawProgressText(vg, x + HorizontalInset, y + TitleGap, m_progress_percent);
        DrawProgressBar(vg, x + HorizontalInset, y + TitleGap + ProgressTextHeight, WindowWidth - HorizontalInset * 2.0f, ProgressBarHeight, m_progress_percent);
        DrawTextBackground(vg, x + HorizontalInset, y + TitleGap + ProgressTextHeight + ProgressBarHeight + VerticalGap, WindowWidth - HorizontalInset * 2.0f, TextAreaHeight);
        DrawTextBlock(vg, m_log_buffer, x + HorizontalInset + TextHorizontalInset, y + TitleGap + ProgressTextHeight + ProgressBarHeight + VerticalGap + TextVerticalInset, WindowWidth - (HorizontalInset + TextHorizontalInset) * 2.0f, TextAreaHeight - TextVerticalInset * 2.0f);

        this->DrawButtons(vg, ns);
    }

    // ValidateUpdateMenu::ValidateUpdateMenu(std::shared_ptr<Menu> prev_menu) : Menu(prev_menu), m_has_drawn(false), m_has_info(false), m_has_validated(false) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
    //     const float button_width = (WindowWidth - HorizontalInset * 2.0f) / 2.0f - ButtonHorizontalGap;

    //     /* Add buttons. */
    //     this->AddButton(BackButtonId, "Back", x + HorizontalInset, y + WindowHeight - BottomInset - ButtonHeight, button_width, ButtonHeight);
    //     this->AddButton(ContinueButtonId, "Continue", x + HorizontalInset + button_width + ButtonHorizontalGap, y + WindowHeight - BottomInset - ButtonHeight, button_width, ButtonHeight);
    //     this->SetButtonEnabled(BackButtonId, false);
    //     this->SetButtonEnabled(ContinueButtonId, false);

    //     /* Obtain update information. */
    //     if (R_FAILED(this->GetUpdateInformation())) {
    //         this->SetButtonEnabled(BackButtonId, true);
    //         this->SetButtonSelected(BackButtonId, true);
    //     } else {
    //         /* Log this early so it is printed out before validation causes stalling. */
    //         this->LogText("Validating update, this may take a moment...\n");
    //     }
    // }

    // Result ValidateUpdateMenu::GetUpdateInformation() {
    //     Result rc = 0;
    //     this->LogText("Directory %s\n", g_update_path);

    //     /* Attempt to get the update information. */
    //     if (R_FAILED(rc = amssuGetUpdateInformation(&m_update_info, g_update_path))) {
    //         if (rc == 0x1a405) {
    //             this->LogText("No update found in folder.\nEnsure your ncas are named correctly!\nResult: 0x%08x\n", rc);
    //         } else {
    //             this->LogText("Failed to get update information.\nResult: 0x%08x\n", rc);
    //         }
    //         return rc;
    //     }

    //     /* Print update information. */
    //     this->LogText("- Version: %d.%d.%d\n", (m_update_info.version >> 26) & 0x1f, (m_update_info.version >> 20) & 0x1f, (m_update_info.version >> 16) & 0xf);
    //     if (m_update_info.exfat_supported) {
    //         this->LogText("- exFAT: Supported\n");
    //     } else {
    //         this->LogText("- exFAT: Unsupported\n");
    //     }
    //     this->LogText("- Firmware variations: %d\n", m_update_info.num_firmware_variations);

    //     /* Mark as having obtained update info. */
    //     m_has_info = true;
    //     return rc;
    // }

    // void ValidateUpdateMenu::ValidateUpdate() {
    //     Result rc = 0;

    //     /* Validate the update. */
    //     if (R_FAILED(rc = amssuValidateUpdate(&m_validation_info, g_update_path))) {
    //         this->LogText("Failed to validate update.\nResult: 0x%08x\n", rc);
    //         return;
    //     }

    //     /* Check the result. */
    //     if (R_SUCCEEDED(m_validation_info.result)) {
    //         this->LogText("Update is valid!\n");

    //         if (R_FAILED(m_validation_info.exfat_result)) {
    //             const u32 version = m_validation_info.invalid_key.version;
    //             this->LogText("exFAT Validation failed with result: 0x%08x\n", m_validation_info.exfat_result);
    //             this->LogText("Missing content:\n- Program id: %016lx\n- Version: %d.%d.%d\n", m_validation_info.invalid_key.id, (version >> 26) & 0x1f, (version >> 20) & 0x1f, (version >> 16) & 0xf);

    //             /* Log the missing content id. */
    //             this->LogText("- Content id: ");
    //             for (size_t i = 0; i < sizeof(NcmContentId); i++) {
    //                 this->LogText("%02x", m_validation_info.invalid_content_id.c[i]);
    //             }
    //             this->LogText("\n");
    //         }

    //         /* Enable the back and continue buttons and select the continue button. */
    //         this->SetButtonEnabled(BackButtonId, true);
    //         this->SetButtonEnabled(ContinueButtonId, true);
    //         this->SetButtonSelected(ContinueButtonId, true);
    //     } else {
    //         /* Log the missing content info. */
    //         const u32 version = m_validation_info.invalid_key.version;
    //         this->LogText("Validation failed with result: 0x%08x\n", m_validation_info.result);
    //         this->LogText("Missing content:\n- Program id: %016lx\n- Version: %d.%d.%d\n", m_validation_info.invalid_key.id, (version >> 26) & 0x1f, (version >> 20) & 0x1f, (version >> 16) & 0xf);

    //         /* Log the missing content id. */
    //         this->LogText("- Content id: ");
    //         for (size_t i = 0; i < sizeof(NcmContentId); i++) {
    //             this->LogText("%02x", m_validation_info.invalid_content_id.c[i]);
    //         }
    //         this->LogText("\n");

    //         /* Enable the back button and select it. */
    //         this->SetButtonEnabled(BackButtonId, true);
    //         this->SetButtonSelected(BackButtonId, true);
    //     }

    //     /* Mark validation as being complete. */
    //     m_has_validated = true;
    // }

    // void ValidateUpdateMenu::Update(u64 ns) {
    //     /* Perform validation if it hasn't been done already. */
    //     if (m_has_info && m_has_drawn && !m_has_validated) {
    //         this->ValidateUpdate();
    //     }

    //     u64 k_down = padGetButtonsDown(&g_pad);

    //     /* Go back if B is pressed. */
    //     if (k_down & HidNpadButton_B) {
    //         ReturnToPreviousMenu();
    //         return;
    //     }

    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
    //         switch (activated_button->id) {
    //             case BackButtonId:
    //                 ReturnToPreviousMenu();
    //                 return;
    //             case ContinueButtonId:
    //                 /* Don't continue if validation hasn't been done or has failed. */
    //                 if (!m_has_validated || R_FAILED(m_validation_info.result)) {
    //                     break;
    //                 }

    //                 /* Check if exfat is supported. */
    //                 g_exfat_supported = m_update_info.exfat_supported && R_SUCCEEDED(m_validation_info.exfat_result);
    //                 if (!g_exfat_supported) {
    //                     g_use_exfat = false;
    //                 }

    //                 /* Warn the user if they're updating with exFAT supposed to be supported but not present/corrupted. */
    //                 if (m_update_info.exfat_supported && R_FAILED(m_validation_info.exfat_result)) {
    //                     ChangeMenu(std::make_shared<WarningMenu>(g_current_menu, std::make_shared<ChooseResetMenu>(g_current_menu), "Warning: exFAT firmware is missing or corrupt", "Are you sure you want to proceed?"));
    //                 } else {
    //                     ChangeMenu(std::make_shared<ChooseResetMenu>(g_current_menu));
    //                 }

    //                 return;
    //         }
    //     }

    //     this->UpdateButtons();
    // }

    // void ValidateUpdateMenu::Draw(NVGcontext *vg, u64 ns) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     DrawWindow(vg, "Update information", x, y, WindowWidth, WindowHeight);
    //     DrawTextBackground(vg,          x + HorizontalInset                      , y + TitleGap                    , WindowWidth - HorizontalInset * 2.0f                        , TextAreaHeight);
    //     DrawTextBlock(vg, m_log_buffer, x + HorizontalInset + TextHorizontalInset, y + TitleGap + TextVerticalInset, WindowWidth - (HorizontalInset + TextHorizontalInset) * 2.0f, TextAreaHeight - TextVerticalInset * 2.0f);

    //     this->DrawButtons(vg, ns);
    //     m_has_drawn = true;
    // }

    // ChooseResetMenu::ChooseResetMenu(std::shared_ptr<Menu> prev_menu) : Menu(prev_menu) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
    //     const float button_width = (WindowWidth - HorizontalInset * 2.0f) / 2.0f - ButtonHorizontalGap;

    //     /* Add buttons. */
    //     this->AddButton(ResetToFactorySettingsButtonId, "Reset to factory settings", x + HorizontalInset, y + TitleGap, button_width, ButtonHeight);
    //     this->AddButton(PreserveSettingsButtonId, "Preserve settings", x + HorizontalInset + button_width + ButtonHorizontalGap, y + TitleGap, button_width, ButtonHeight);
    //     this->SetButtonSelected(PreserveSettingsButtonId, true);
    // }

    // void ChooseResetMenu::Update(u64 ns) {
    //     u64 k_down = padGetButtonsDown(&g_pad);

    //     /* Go back if B is pressed. */
    //     if (k_down & HidNpadButton_B) {
    //         ReturnToPreviousMenu();
    //         return;
    //     }

    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
    //         switch (activated_button->id) {
    //             case ResetToFactorySettingsButtonId:
    //                 g_reset_to_factory = true;
    //                 break;
    //             case PreserveSettingsButtonId:
    //                 g_reset_to_factory = false;
    //                 break;
    //         }

    //         std::shared_ptr<Menu> next_menu;

    //         if (g_exfat_supported) {
    //             next_menu = std::make_shared<ChooseExfatMenu>(g_current_menu);
    //         } else {
    //             next_menu = std::make_shared<WarningMenu>(g_current_menu, std::make_shared<InstallUpdateMenu>(g_current_menu), "Ready to begin update installation", "Are you sure you want to proceed?");
    //         }

    //         if (g_reset_to_factory) {
    //             ChangeMenu(std::make_shared<WarningMenu>(g_current_menu, next_menu, "Warning: Factory reset selected", "Saves and installed games will be permanently deleted."));
    //         } else {
    //             ChangeMenu(next_menu);
    //         }
    //     }

    //     this->UpdateButtons();

    //     /* Fallback on selecting the exfat button. */
    //     if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
    //         this->SetButtonSelected(PreserveSettingsButtonId, true);
    //     }
    // }

    // void ChooseResetMenu::Draw(NVGcontext *vg, u64 ns) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     DrawWindow(vg, "Select settings mode", x, y, WindowWidth, WindowHeight);
    //     this->DrawButtons(vg, ns);
    // }

    // ChooseExfatMenu::ChooseExfatMenu(std::shared_ptr<Menu> prev_menu) : Menu(prev_menu) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
    //     const float button_width = (WindowWidth - HorizontalInset * 2.0f) / 2.0f - ButtonHorizontalGap;

    //     /* Add buttons. */
    //     this->AddButton(Fat32ButtonId, "Install (FAT32)", x + HorizontalInset, y + TitleGap, button_width, ButtonHeight);
    //     this->AddButton(ExFatButtonId, "Install (FAT32 + exFAT)", x + HorizontalInset + button_width + ButtonHorizontalGap, y + TitleGap, button_width, ButtonHeight);

    //     /* Set the default selected button based on the user's current install. We aren't particularly concerned if fsIsExFatSupported fails. */
    //     bool exfat_supported = false;
    //     fsIsExFatSupported(&exfat_supported);

    //     if (exfat_supported) {
    //         this->SetButtonSelected(ExFatButtonId, true);
    //     } else {
    //         this->SetButtonSelected(Fat32ButtonId, true);
    //     }
    // }

    // void ChooseExfatMenu::Update(u64 ns) {
    //     u64 k_down = padGetButtonsDown(&g_pad);

    //     /* Go back if B is pressed. */
    //     if (k_down & HidNpadButton_B) {
    //         ReturnToPreviousMenu();
    //         return;
    //     }

    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
    //         switch (activated_button->id) {
    //             case Fat32ButtonId:
    //                 g_use_exfat = false;
    //                 break;
    //             case ExFatButtonId:
    //                 g_use_exfat = true;
    //                 break;
    //         }

    //         ChangeMenu(std::make_shared<WarningMenu>(g_current_menu, std::make_shared<InstallUpdateMenu>(g_current_menu), "Ready to begin update installation", "Are you sure you want to proceed?"));
    //     }

    //     this->UpdateButtons();

    //     /* Fallback on selecting the exfat button. */
    //     if (const Button *selected_button = this->GetSelectedButton(); k_down && selected_button == nullptr) {
    //         this->SetButtonSelected(ExFatButtonId, true);
    //     }
    // }

    // void ChooseExfatMenu::Draw(NVGcontext *vg, u64 ns) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     DrawWindow(vg, "Select driver variant", x, y, WindowWidth, WindowHeight);
    //     this->DrawButtons(vg, ns);
    // }

    // InstallUpdateMenu::InstallUpdateMenu(std::shared_ptr<Menu> prev_menu) : Menu(prev_menu), m_install_state(InstallState::NeedsDraw), m_progress_percent(0.0f) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;
    //     const float button_width = (WindowWidth - HorizontalInset * 2.0f) / 2.0f - ButtonHorizontalGap;

    //     /* Add buttons. */
    //     this->AddButton(ShutdownButtonId, "Shutdown", x + HorizontalInset, y + WindowHeight - BottomInset - ButtonHeight, button_width, ButtonHeight);
    //     this->AddButton(RebootButtonId, "Reboot", x + HorizontalInset + button_width + ButtonHorizontalGap, y + WindowHeight - BottomInset - ButtonHeight, button_width, ButtonHeight);
    //     this->SetButtonEnabled(ShutdownButtonId, false);
    //     this->SetButtonEnabled(RebootButtonId, false);

    //     /* Prevent the home button from being pressed during installation. */
    //     hiddbgDeactivateHomeButton();
    // }

    // void InstallUpdateMenu::MarkForReboot() {
    //     this->SetButtonEnabled(ShutdownButtonId, true);
    //     this->SetButtonEnabled(RebootButtonId, true);
    //     this->SetButtonSelected(RebootButtonId, true);
    //     m_install_state = InstallState::AwaitingReboot;
    // }

    // Result InstallUpdateMenu::TransitionUpdateState() {
    //     Result rc = 0;
    //     if (m_install_state == InstallState::NeedsSetup) {
    //         /* Setup the update. */
    //         if (R_FAILED(rc = amssuSetupUpdate(nullptr, UpdateTaskBufferSize, g_update_path, g_use_exfat))) {
    //             this->LogText("Failed to setup update.\nResult: 0x%08x\n", rc);
    //             this->MarkForReboot();
    //             return rc;
    //         }

    //         /* Log setup completion. */
    //         this->LogText("Update setup complete.\n");
    //         m_install_state = InstallState::NeedsPrepare;
    //     } else if (m_install_state == InstallState::NeedsPrepare) {
    //         /* Request update preparation. */
    //         if (R_FAILED(rc = amssuRequestPrepareUpdate(&m_prepare_result))) {
    //             this->LogText("Failed to request update preparation.\nResult: 0x%08x\n", rc);
    //             this->MarkForReboot();
    //             return rc;
    //         }

    //         /* Log awaiting prepare. */
    //         this->LogText("Preparing update...\n");
    //         m_install_state = InstallState::AwaitingPrepare;
    //     } else if (m_install_state == InstallState::AwaitingPrepare) {
    //         /* Check if preparation has a result. */
    //         if (R_FAILED(rc = asyncResultWait(&m_prepare_result, 0)) && rc != 0xea01) {
    //             this->LogText("Failed to check update preparation result.\nResult: 0x%08x\n", rc);
    //             this->MarkForReboot();
    //             return rc;
    //         } else if (R_SUCCEEDED(rc)) {
    //             if (R_FAILED(rc = asyncResultGet(&m_prepare_result))) {
    //                 this->LogText("Failed to prepare update.\nResult: 0x%08x\n", rc);
    //                 this->MarkForReboot();
    //                 return rc;
    //             }
    //         }

    //         /* Check if the update has been prepared. */
    //         bool prepared;
    //         if (R_FAILED(rc = amssuHasPreparedUpdate(&prepared))) {
    //             this->LogText("Failed to check if update has been prepared.\nResult: 0x%08x\n", rc);
    //             this->MarkForReboot();
    //             return rc;
    //         }

    //         /* Mark for application if preparation complete. */
    //         if (prepared) {
    //             this->LogText("Update preparation complete.\nApplying update...\n");
    //             m_install_state = InstallState::NeedsApply;
    //             return rc;
    //         }

    //         /* Check update progress. */
    //         NsSystemUpdateProgress update_progress = {};
    //         if (R_FAILED(rc = amssuGetPrepareUpdateProgress(&update_progress))) {
    //             this->LogText("Failed to check update progress.\nResult: 0x%08x\n", rc);
    //             this->MarkForReboot();
    //             return rc;
    //         }

    //         /* Update progress percent. */
    //         if (update_progress.total_size > 0.0f) {
    //             m_progress_percent = static_cast<float>(update_progress.current_size) / static_cast<float>(update_progress.total_size);
    //         } else {
    //             m_progress_percent = 0.0f;
    //         }
    //     } else if (m_install_state == InstallState::NeedsApply) {
    //         /* Apply the prepared update. */
    //         if (R_FAILED(rc = amssuApplyPreparedUpdate())) {
    //             this->LogText("Failed to apply update.\nResult: 0x%08x\n", rc);
    //         } else {
    //             /* Log success. */
    //             this->LogText("Update applied successfully.\n");

    //             if (g_reset_to_factory) {
    //                 if (R_FAILED(rc = nsResetToFactorySettingsForRefurbishment())) {
    //                     /* Fallback on ResetToFactorySettings. */
    //                     if (rc == MAKERESULT(Module_Libnx, LibnxError_IncompatSysVer)) {
    //                         if (R_FAILED(rc = nsResetToFactorySettings())) {
    //                             this->LogText("Failed to reset to factory settings.\nResult: 0x%08x\n", rc);
    //                             this->MarkForReboot();
    //                             return rc;
    //                         }
    //                     } else {
    //                         this->LogText("Failed to reset to factory settings for refurbishment.\nResult: 0x%08x\n", rc);
    //                         this->MarkForReboot();
    //                         return rc;
    //                     }
    //                 }

    //                 this->LogText("Successfully reset to factory settings.\n", rc);
    //             }
    //         }

    //         this->MarkForReboot();
    //         return rc;
    //     }

    //     return rc;
    // }

    // void InstallUpdateMenu::Update(u64 ns) {
    //     /* Transition to the next update state. */
    //     if (m_install_state != InstallState::NeedsDraw && m_install_state != InstallState::AwaitingReboot) {
    //         this->TransitionUpdateState();
    //     }

    //     /* Take action if a button has been activated. */
    //     if (const Button *activated_button = this->GetActivatedButton(); activated_button != nullptr) {
    //         switch (activated_button->id) {
    //             case ShutdownButtonId:
    //                 if (R_FAILED(appletRequestToShutdown())) {
    //                     spsmShutdown(false);
    //                 }
    //                 break;
    //             case RebootButtonId:
    //                 if (R_FAILED(appletRequestToReboot())) {
    //                     spsmShutdown(true);
    //                 }
    //                 break;
    //         }
    //     }

    //     this->UpdateButtons();
    // }

    // void InstallUpdateMenu::Draw(NVGcontext *vg, u64 ns) {
    //     const float x = g_screen_width / 2.0f - WindowWidth / 2.0f;
    //     const float y = g_screen_height / 2.0f - WindowHeight / 2.0f;

    //     DrawWindow(vg, "Installing update", x, y, WindowWidth, WindowHeight);
    //     DrawProgressText(vg, x + HorizontalInset, y + TitleGap, m_progress_percent);
    //     DrawProgressBar(vg, x + HorizontalInset, y + TitleGap + ProgressTextHeight, WindowWidth - HorizontalInset * 2.0f, ProgressBarHeight, m_progress_percent);
    //     DrawTextBackground(vg, x + HorizontalInset, y + TitleGap + ProgressTextHeight + ProgressBarHeight + VerticalGap, WindowWidth - HorizontalInset * 2.0f, TextAreaHeight);
    //     DrawTextBlock(vg, m_log_buffer, x + HorizontalInset + TextHorizontalInset, y + TitleGap + ProgressTextHeight + ProgressBarHeight + VerticalGap + TextVerticalInset, WindowWidth - (HorizontalInset + TextHorizontalInset) * 2.0f, TextAreaHeight - TextVerticalInset * 2.0f);

    //     this->DrawButtons(vg, ns);

    //     /* We have drawn now, allow setup to occur. */
    //     if (m_install_state == InstallState::NeedsDraw) {
    //         this->LogText("Beginning update setup...\n");
    //         m_install_state = InstallState::NeedsSetup;
    //     }
    // }

    void InitializeMenu(u32 screen_width, u32 screen_height) {
        Result rc = 0;

        /* Configure and initialize the gamepad. */
        padConfigureInput(1, HidNpadStyleSet_NpadStandard);
        padInitializeDefault(&g_pad);

        /* Initialize the touch screen. */
        hidInitializeTouchScreen();

        /* Set the screen width and height. */
        g_screen_width = screen_width;
        g_screen_height = screen_height;

        /* Mark as initialized. */
        g_initialized = true;

        /* Attempt to get the exosphere version. */
        u64 version;
        if (R_FAILED(rc = splGetConfig(static_cast<SplConfigItem>(ExosphereApiVersionConfigItem), &version))) {
            ChangeMenu(std::make_shared<ErrorMenu>("Atmosphere not found", "Breeze requires Atmosphere to be installed.", rc));
            return;
        }

        const u32 version_micro = (version >> 40) & 0xff;
        const u32 version_minor = (version >> 48) & 0xff;
        const u32 version_major = (version >> 56) & 0xff;

        /* Validate the exosphere version. */
        // const bool ams_supports_sysupdate_api = version_major >= 0 && version_minor >= 14 && version_micro >= 0;
        const bool ams_supports_sysupdate_api = EncodeVersion(version_major, version_minor, version_micro) >= EncodeVersion(0, 14, 0);
        if (!ams_supports_sysupdate_api) {
            ChangeMenu(std::make_shared<ErrorMenu>("Outdated Atmosphere version", "Breeze requires Atmosphere 0.14.0 or later.", rc));
            return;
        }

        /* Initialize ams:su. */
        // if (R_FAILED(rc = amssuInitialize())) {
        //     fatalThrow(rc);
        // }

        /* Change the current menu to the main menu. */
        g_current_menu = std::make_shared<MainMenu>();
    }

    void UpdateMenu(u64 ns) {
        DBK_ABORT_UNLESS(g_initialized);
        DBK_ABORT_UNLESS(g_current_menu != nullptr);
        UpdateInput();
        g_current_menu->Update(ns);
    }

    void RenderMenu(NVGcontext *vg, u64 ns) {
        DBK_ABORT_UNLESS(g_initialized);
        DBK_ABORT_UNLESS(g_current_menu != nullptr);

        /* Draw background. */
        DrawBackground(vg, g_screen_width, g_screen_height);

        if (m_HasCheatProcess && !options.use_starfield)
        {
            if (m_icon == -1 || m_refresh_backgroud)
            {
                // Get from app screen
                if (m_refresh_backgroud) nvgDeleteImage(vg, m_icon);
                m_refresh_backgroud = false;
                bool flag = false;
                Result rc = appletUpdateLastForegroundCaptureImage();
                if (rc == 0 && m_capturescreen)
                    rc = appletGetLastApplicationCaptureImageEx(m_screenshot_buffer, 0x384000, &flag);
                if (rc == 0)
                {
                    m_icon = nvgCreateImageRGBA(vg, 1280, 720, 0, m_screenshot_buffer);                    
                }
                else
                {
                    // Get from icon
                    m_icon = nvgCreateImageMem(vg, 0, m_appControlData.icon, 0x20000);
                }
            
            // get from file
                // { 
                //     char file[128];
                //     snprintf(file, 128, "romfs:/images/image1.jpg");
                //     m_icon = nvgCreateImage(vg, file, 0);
                // };
            }
            int imgw, imgh;
            nvgImageSize(vg, m_icon, &imgw, &imgh);
            NVGpaint imgPaint = nvgImagePattern(vg, 0, 0, imgw, imgh, 0.0f / 180.0f * NVG_PI, m_icon, 1);

            // nvgSave(vg);
            nvgBeginPath(vg);
            nvgRoundedRect(vg, 0, 0, imgw, imgh, 20);
            nvgFillPaint(vg, imgPaint);
            nvgFill(vg);
            // nvgRestore(vg);
            
        }
        else
        {
        /* Draw stars. */
        DrawStar(vg, 40.0f, 64.0f, 3.0f);
        DrawStar(vg, 110.0f, 300.0f, 3.0f);
        DrawStar(vg, 200.0f, 150.0f, 4.0f);
        DrawStar(vg, 370.0f, 280.0f, 3.0f);
        DrawStar(vg, 450.0f, 40.0f, 3.5f);
        DrawStar(vg, 710.0f, 90.0f, 3.0f);
        DrawStar(vg, 900.0f, 240.0f, 3.0f);
        DrawStar(vg, 970.0f, 64.0f, 4.0f);
        DrawStar(vg, 1160.0f, 160.0f, 3.5f);
        DrawStar(vg, 1210.0f, 350.0f, 3.0f);
        };

        g_current_menu->Draw(vg, ns);
    }

    bool IsExitRequested() {
        return g_exit_requested;
    }

    void request_exit() {
        g_exit_requested = true;
    }

    bool requestKeyboardInput(const char * headerText, const char * subHeaderText, const char * initialText, SwkbdType type, char *out_text, size_t maxLength)
    {
        SwkbdConfig kbd;
        swkbdCreate(&kbd, 0);
        swkbdConfigMakePresetDefault(&kbd);

        swkbdConfigSetInitialText(&kbd, initialText);
        swkbdConfigSetHeaderText(&kbd, headerText);
        swkbdConfigSetSubText(&kbd, subHeaderText);
        swkbdConfigSetGuideText(&kbd, subHeaderText);

        kbd.arg.arg.arg.leftButtonText = '.';
        kbd.arg.arg.arg.rightButtonText = '-';
        kbd.arg.arg.arg.stringLenMax = maxLength;
        // kbd.arg.arg.arg.stringLenMaxExt = 1;
        kbd.arg.arg.arg.textDrawType = SwkbdTextDrawType_Line;
        kbd.arg.arg.arg.returnButtonFlag = false;
        kbd.arg.arg.arg.type = type;
        kbd.arg.arg.arg.keySetDisableBitmask = SwkbdKeyDisableBitmask_At | SwkbdKeyDisableBitmask_Percent | SwkbdKeyDisableBitmask_ForwardSlash | SwkbdKeyDisableBitmask_Backslash;

        swkbdShow(&kbd, out_text, maxLength + 1);
        swkbdClose(&kbd);

        return std::strcmp(out_text, "") != 0;
    }
}  // namespace air
