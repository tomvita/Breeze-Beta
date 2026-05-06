#include "action.hpp"
#include "gameinfo.hpp"
#include <cstring>
enum class actions_id_t {
    Touch_handle,
    Back,
    Select,
    LoopMenu,
    WriteInfo,
    ExpandScreen,
    ButtonDemo,
    Jump,
    ToggleWifi,
    PlayerSelect,
    ControllerMenu,
    AlbumApplet,
    TestGameInfo,
};

#define ID (u32) actions_id_t::
namespace air {
    Air_menu_setting Newmenu::init_menu() {
        Air_menu_setting menu;
        menu.menuid = Menu_id::Search;
        menu._action = this;
        menu.num_button_column = 2;
        menu.button_selected = 2;
        menu.left_panel_title = "New Menu";
        menu.right_panel_title = APP_TITLE;
        menu.left_panel_status = "Data panel status";      // status text when not empty will be displayed below panel title
        menu.show_leftpanel_status = true;
        menu.right_panel_status = "Control panel status";  // status text when not empty will be displayed below panel title
        // actions_id_t actions_id = actions_id_t::Select;
        // u32 actions_id;
        menu.actions = {
            {"Toggle wifi", ID ToggleWifi, HidNpadButton_R},
            {"Player select", ID PlayerSelect, HidNpadButton_StickL},
            {"Controller menu", ID ControllerMenu, HidNpadButton_StickR},
            {"Album", ID AlbumApplet, HidNpadButton_L},
            {"Select", ID Select, HidNpadButton_X},
            {"loop this menu", ID LoopMenu, HidNpadButton_Y},
            {"Write info to file", ID WriteInfo, HidNpadButton_Plus},
            {"Test GameInfo", ID TestGameInfo, HidNpadButton_Minus},
            // {"testing", 4, HidNpadButton_StickL},
            // {"Hex mode", 5, HidNpadButton_StickR},
            // {"Toggle Cheat", 6, HidNpadButton_L},
            // {"Cheat menu", 7, HidNpadButton_R},
            // {"Page Up", 8, HidNpadButton_ZL},
            {"Expand screen", ID ExpandScreen, HidNpadButton_ZR},
            // {"Last Page", 11, HidNpadButton_Minus},
            // {"First Page", 20, HidNpadButton_StickRLeft},
            // {"Add conditional key", 21, HidNpadButton_StickRUp},
            // {"testing", 22, HidNpadButton_StickRRight},
            // {"ID", 23, HidNpadButton_StickRDown},
            // {"testing", 24,},
            {"Back", ID Back, HidNpadButton_B},
            {"Button combo demo", ID ButtonDemo, (HidNpadButton)(HidNpadButton_StickL + HidNpadButton_ZL)},  // max button is 32
        };
        return menu;
    };

    void Newmenu::populate_list(u64 offset) {
        this->menu->m_data_entries.clear();
        this->menu->m_data_entries.push_back(logtext("testing"));
    }
    Newmenu::Newmenu() : BreezeActions() {
        this->menu = std::make_shared<AirMenu>(get_current_menu(), this->init_menu());
        // this->populate_list(m_offset);
    };

    void Newmenu::menu_action(u32 buttonid, u32 index) {
        switch (buttonid) {
            case 1000:{
                // populate_list(m_offset); // always refresh the list;
                // Result nifmSetWirelessCommunicationEnabled(bool enable);
                // Result nifmIsWirelessCommunicationEnabled(bool* out);
                bool is_enabled = false;
                auto rc = nifmIsWirelessCommunicationEnabled(&is_enabled);
                if (rc!= 0) {
                    char message[100]="rc != 0";
                    this->menu->m_menu_setting.left_panel_status = message;
                } else if (is_enabled) {
                    char message[100]="Wireless communication is enabled";
                    this->menu->m_menu_setting.left_panel_status = message;
                } else {
                    char message[100]="Wireless communication is disabled";
                    this->menu->m_menu_setting.left_panel_status = message;
                };
                return;
            };
            case 0:
                // Touch case 
                air::ChangeMenu(std::make_shared<MessageMenu>(
                    get_current_menu(), "Touch case in new menu", logtext("index = %d",index).data));
                return;
            case ID Back:
                this->menu = nullptr;
                // air::ReturnToPreviousMenu();
                request_exit();
                return;
            case ID Select: // selection action
                return;
            case ID ToggleWifi: {
                bool is_enabled = false;
                auto rc = nifmIsWirelessCommunicationEnabled(&is_enabled);
                if (rc != 0) {
                    char message[100]="rc != 0";
                    this->menu->m_menu_setting.left_panel_status = message;
                } else {
                    nifmSetWirelessCommunicationEnabled(!is_enabled);
                };
                return;
            };
            case ID PlayerSelect: {
                FILE *lf = fopen(LOG_FILE, "a");
                if (lf) { fprintf(lf, "[psel] before call\n"); fflush(lf); }
                this->menu->m_data_entries.push_back(logtext("[psel] before call"));
                appletSetFocusHandlingMode(AppletFocusHandlingMode_SuspendHomeSleepNotify);
                PselUserSelectionSettings settings = {};
                AccountUid out_uid = {};
                Result rc = pselShowUserSelector(&out_uid, &settings);
                appletSetFocusHandlingMode(AppletFocusHandlingMode_NoSuspend);
                if (lf) { fprintf(lf, "[psel] rc=0x%x uid=%016lX%016lX\n", rc, out_uid.uid[1], out_uid.uid[0]); fclose(lf); }
                this->menu->m_data_entries.push_back(logtext("[psel] rc=0x%x", rc));
                this->menu->m_data_entries.push_back(logtext("[psel] uid=%016lX%016lX", out_uid.uid[1], out_uid.uid[0]));
                return;
            };
            case ID ControllerMenu: {
                FILE *lf = fopen(LOG_FILE, "a");
                if (lf) { fprintf(lf, "[hidla] before call\n"); fflush(lf); }
                this->menu->m_data_entries.push_back(logtext("[hidla] before call"));
                HidLaControllerSupportArg arg;
                hidLaCreateControllerSupportArg(&arg);
                // Defaults from hidLaCreateControllerSupportArg:
                //   player_count_min=0, player_count_max=4,
                //   enable_take_over_connection=1, enable_left_justify=1,
                //   enable_permit_joy_dual=1
                // Override only what we need:
                arg.hdr.player_count_min = 0;
                arg.hdr.player_count_max = 4;
                arg.hdr.enable_single_mode = 0;          // no sideways-single-joycon
                HidLaControllerSupportResultInfo result_info = {};
                appletSetFocusHandlingMode(AppletFocusHandlingMode_SuspendHomeSleepNotify);
                Result rc = hidLaShowControllerSupportForSystem(&result_info, &arg, true);
                // Result rc = hidLaShowControllerSupport(&result_info, &arg);
                appletSetFocusHandlingMode(AppletFocusHandlingMode_NoSuspend);
                if (lf) { fprintf(lf, "[hidla] rc=0x%x players=%d\n", rc, result_info.player_count); fclose(lf); }
                this->menu->m_data_entries.push_back(logtext("[hidla] rc=0x%x players=%d", rc, result_info.player_count));
                return;
            };
            case ID AlbumApplet: {
                FILE *lf = fopen(LOG_FILE, "a");
                if (lf) { fprintf(lf, "[album] before call\n"); fflush(lf); }
                this->menu->m_data_entries.push_back(logtext("[album] before call"));
                appletSetFocusHandlingMode(AppletFocusHandlingMode_SuspendHomeSleepNotify);
                Result rc = albumLaShowAllAlbumFiles();
                appletSetFocusHandlingMode(AppletFocusHandlingMode_NoSuspend);
                if (lf) { fprintf(lf, "[album] rc=0x%x\n", rc); fclose(lf); }
                this->menu->m_data_entries.push_back(logtext("[album] rc=0x%x", rc));
                return;
            };
            case ID LoopMenu: {
                std::shared_ptr<Newmenu> action = std::make_shared<Newmenu>();
                action->menu->m_menu_setting.action2 = action;
                air::ChangeMenu(action->menu);
                return;
            };
            case ID ExpandScreen:
                if (this->menu->xoffsetL == 0)
                    this->menu->xoffsetL = -315;
                else
                    this->menu->xoffsetL = 0;
                return;
            case ID WriteInfo:  // save info to file
            {
                FILE *fp = fopen(MISCINFO_FILE, "wb");
                if (fp != NULL) {
                    for (DataEntry entry : this->menu->m_data_entries) {
                        fwrite(&(entry.data), strlen(entry.data), 1, fp);
                        const char lf = 13;
                        fwrite(&lf,1,1,fp);
                    };
                    fclose(fp);
                    air::ChangeMenu(std::make_shared<MessageMenu>(get_current_menu(), "Save to file", "written to " GAMEINFO_FILE));
                };
                return;
            }
            case ID TestGameInfo:
            {
                this->menu->m_data_entries.clear();
                GameInfo::Initialize();

                this->menu->m_data_entries.push_back(logtext("Title: %s", GameInfo::GetTitleName().c_str()));
                this->menu->m_data_entries.push_back(logtext("Build ID: %s", GameInfo::GetBuildId().c_str()));
                
                char tid_str[17];
                sprintf(tid_str, "%016lX", GameInfo::GetTitleId());
                this->menu->m_data_entries.push_back(logtext("Title ID: %s", tid_str));
                
                this->menu->m_data_entries.push_back(logtext("Path Name: %s", GameInfo::GetTitleNamePath().c_str()));
                this->menu->m_data_entries.push_back(logtext("Legacy Name: %s", GameInfo::GetLegacySanitizedTitleName().c_str()));
                this->menu->m_data_entries.push_back(logtext("Cheat Dirs:"));

                for(const auto& dir : GameInfo::GetCheatDirectories()){
                    this->menu->m_data_entries.push_back(logtext("  %s", dir.c_str()));
                }

                GameInfo::Exit();
                return;
            }
            default:
                air::ChangeMenu(std::make_shared<MessageMenu>(
                    get_current_menu(), "Default case in new menu",
                    "Feature not implemented yet."));
                return;
        };
        return;
    }
}  // namespace air