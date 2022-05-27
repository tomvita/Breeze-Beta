#include "action.hpp"
#include "air.hpp"
#include <stdarg.h>
namespace air {
    DataEntry logtext(const char *format, ...) {
        /* Create a temporary string. */
        DataEntry tmp;
        va_list args;
        va_start(args, format);
        vsnprintf(tmp.data, sizeof(tmp.data), format, args);
        va_end(args);

        return tmp;
    };
    Air_menu_setting BreezeActions::init_menu() {
        Air_menu_setting menu;
        return menu;
    };
    void BreezeActions::populate_list(u64 offset) {
    }
    BreezeActions::BreezeActions() {  
    };
    void BreezeActions::menu_action(u32 buttonid, u32 index) {
        switch (buttonid) {
            default:
                air::ChangeMenu(std::make_shared<MessageMenu>(
                    get_current_menu(), "Default case in Breeze Action menu",
                    "Feature not implemented yet."));
                return;
        };
        return;
    }
}  // namespace air