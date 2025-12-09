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
#include "air.hpp"
#include "lite.hpp"
#include <map>
#define APP_TITLE APPVERSION
#define CHEATDB_VER_URL "https://github.com/tomvita/NXCheatCode/releases/latest/download/version.txt"
#define CHEATDB_URL "https://github.com/tomvita/NXCheatCode/releases/latest/download/titles.zip"
#define APP_VER_URL "https://github.com/tomvita/Breeze-Beta/releases/latest/download/version.txt"
#define APP_Releases_URL "https://api.github.com/repos/tomvita/Breeze-Beta/releases"
#define APP_URL "https://github.com/tomvita/Breeze-Beta/releases/latest/download/breeze.zip"
#define CHEATDB_OUTPUT "/switch/Breeze/cheats/titles.zip"
#define CHEATS_DIR "/switch/Breeze/cheats/"
#define VER_OUTPUT "/switch/Breeze/version.txt"
#define TEMP_FILE "/switch/Breeze/Breezetemp"
#define EXEFS_FILE "/switch/Breeze/exefs.nsp"
#define OPTIONS_FILE "/switch/Breeze/BreezeOptions"
#define GAMEINFO_FILE "/switch/Breeze/Gameinfo"
#define ButtonList_FILE "/switch/Breeze/ButtonList.txt"
#define MISCINFO_FILE "/switch/Breeze/Miscinfo"
#define LOG_FILE "/switch/Breeze/Logfile"
#define BOOKMARK_TXT_FILE "/switch/Breeze/bookmark_export.txt"
#define CONTENTS_PATH "/atmosphere/contents/"
#define PROFILE_SHORTCUT "/atmosphere/contents/0100000000001013/exefs.nsp"
#define GEN2_MODULE "/atmosphere/contents/010000000000d609/exefs.nsp"
#define GEN1_MODULE "/atmosphere/contents/010000000000000d/exefs.nsp"
#define PROFILE_FILE ((is_atm18())? "/switch/Breeze/profile_18.zip" : "/switch/Breeze/profile.zip")
#define PROFILE_ARM32_FILE ((is_atm18())? "/switch/Breeze/profile_arm32_18.zip":"/switch/Breeze/profile_arm32.zip")
#define UserSelect_SHORTCUT "/atmosphere/contents/0100000000001007/exefs.nsp"
#define UserSelect_FILE "/switch/Breeze/userselect.zip"
#define override_config_SHORTCUT "/atmosphere/config/override_config.ini"
#define override_config_FILE "/switch/Breeze/override_config.zip"
#define PROFILE_HBL ((is_atm18())? "/switch/Breeze/profile_hbl_18.zip" : "/switch/Breeze/profile_hbl.zip") 
#define config_FILE "/switch/Breeze/configs.zip"
#define FAT_PROFILE_FILE "/switch/Breeze/profilehbm.zip"
#define BREEZE_DIR "/switch/Breeze/"
#define BREEZE_NRO "/switch/Breeze/Breeze.nro"
#define BREEZE_A32_NRO "/switch/breeze/reeze/Breeze.nro"
#define BREEZE_A32_NRO_OLD "/switch/Breeze.nro"
#define EDZ_PROFILE_FILE "/switch/EdiZon/profile.zip"
#define EDZ_NRO "sdmc:/switch/edizon/EdiZon.nro"
#define Sphaira_NRO "sdmc:/switch/sphaira/sphaira.nro"
#define Ftpsrv_NRO "/switch/breeze/reeze/ftpexe.nro"
#define Ftpsrv_Config BREEZE_DIR "config.ini"
#define FTPD_NRO "sdmc:/switch/ftpd.nro"
#define CHEAT_URL_TXT "/switch/Breeze/cheat_url_txt"
#define MAX_BUFFER_SIZE 0x1000000
#define EXTRA_BUFFER_SIZE 0x800
#define MAX_NUM_SOURCE_POINTER 200  // bound check for debugging;
#define MAX_POINTER_DEPTH 12        // up to 4 seems OK with forward only search took 94s. 215s for big dump
#define MAX_POINTER_RANGE 0x2000
#define MAX_NUM_POINTER_OFFSET 30
#define FILEVERSION_LABEL "BREEZE00D"
#define GEN2_MENU  gen2_menu();
#define AOBSIZE 0x20
#define PTR_SEARCH_MAX_DEPTH 11
#define PTR_SEARCH_MIN_DEPTH 2
#define PTR_SEARCH_MAX_RANGE 0xFFFFFF
#define PTR_SEARCH_MIN_RANGE 0x10
#define PTR_SEARCH_MAX_NUM_OFFSET 100


namespace air {
    bool is_atm18();
    const char MAGIC[] = FILEVERSION_LABEL;  // used to identify file version is correct
    typedef union {
        u8 _u8;
        s8 _s8;
        u16 _u16;
        s16 _s16;
        u32 _u32;
        s32 _s32;
        u64 _u64;
        u64 _u40:40;
        s64 _s64;
        float _f32;
        double _f64;
    } searchValue_t;

    typedef enum {
        SEARCH_TYPE_UNSIGNED_8BIT,
        SEARCH_TYPE_SIGNED_8BIT,
        SEARCH_TYPE_UNSIGNED_16BIT,
        SEARCH_TYPE_SIGNED_16BIT,
        SEARCH_TYPE_UNSIGNED_32BIT,
        SEARCH_TYPE_SIGNED_32BIT,
        SEARCH_TYPE_UNSIGNED_64BIT,
        SEARCH_TYPE_SIGNED_64BIT,
        SEARCH_TYPE_FLOAT_32BIT,
        SEARCH_TYPE_FLOAT_64BIT,
        SEARCH_TYPE_POINTER,
        SEARCH_TYPE_UNSIGNED_40BIT,
        // SEARCH_TYPE_NONE
    } searchType_t;

    typedef enum {
        SM_EQ,
        SM_NE,
        SM_GT,
        SM_LT,
        SM_GE,
        SM_LE,
        SM_RANGE_EQ,
        SM_BMEQ,
        SM_RANGE_LT,
        SM_MORE,
        SM_LESS,
        SM_DIFF,
        SM_SAME,
        SM_TWO_VALUE,
        SM_TWO_VALUE_PLUS,
        SM_STRING,
        SM_INC_BY,
        SM_DEC_BY,
        SM_EQ_plus,
        SM_NONE,
        SM_DIFFB,
        SM_SAMEB,
        SM_MOREB,
        SM_LESSB,
        SM_NOTAB,
        SM_THREE_VALUE,
        SM_BIT_FLIP,
        SM_ADV,
        SM_GAP,
        SM_GAP_ALLOWANCE,
        SM_PTR,
        SM_NPTR,
        SM_NoDecimal,
        SM_Gen2_data,
        SM_Gen2_code,
        SM_GETB,
        SM_REBASE,
        SM_Target,
        SM_Pointer_and_OFFSET,
        SM_SKIP,
        SM_Aborted_Target,
        SM_Branch,
        SM_LDRx,
        SM_ADRP,
        SM_EOR,
    } searchMode_t;

    static const char *const typeNames[] = {"u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "flt", "dbl", "pointer"};
    static const char *const permNames[] = {"None", "R", "W", "RW", "X", "RX"};
    static const char *const segtypeNames[] = {"Unmapped", "Io", "Normal", "CodeStatic", "CodeMutable", "Heap", "SharedMem", "WeiredMappedMem", "ModuleCodeStatic", "ModuleCodeMutable", "IpcBuffer0", "MappedMemory", "ThreadLocal", "TransferMemIsolated", "TransferMem", "ProcessMem", "Reserved", "IpcBuffer1", "IpcBuffer3", "KernelStack", "CodeReadOnly", "CodeWritable"};
    static const std::vector<u8> dataTypeSizes = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};
    // static const int *const typeSizes[] =     {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};
    static const char *const typeFormat[][11] = {{"%d", "%d", "%d", "%d", "%d", "%d", "%d", "%d", "%f", "%lf", "0x%016lX"},
                                                 {"0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "%f", "%lf", "0x%016lX"}};
    static const char *const modeNames[] = {"==A", "!=A", ">A", "<A", ">=A", "<=A", "[A..B]", "&B=A", "<A..B>", "++", "--", "DIFF", "SAME", "[A,B]", "[A,,B]", "STRING", "++Val", "--Val", "==*A", "NONE", "DIFFB", "SAMEB", "B++", "B--", "NotAB", "[A.B.C]", "[A bflip B]", "Advance", "GAP", "{GAP}", "PTR", "~PTR", "[A..B]f.0", "Gen2 data", "Gen2 code", "GETB", "REBASE", "Target", "ptr and offset", "skip", "Aborted Target Search", "Branch code", "LDRx code", "ADRP code", "EOR code"};
    static const char *const condition_str[] = {"", " > ", " >= ", " < ", " <= ", " == ", " != "};
    static const char *const math_str[] = {" + ", " - ", " * ", " << ", " >> ", " & ", " | ", " NOT ", " XOR ", " None/Move ", " fadd ", " fsub ", " fmul ", " fdiv "};
    static const char *const operand_str[] = {"Restore register", "Save register", "Clear saved value", "Clear register"};

    struct pointer_chain_t {
        u64 depth = 0;
        s64 offset[MAX_POINTER_DEPTH + 1] = {0};  
    };
    struct asm_pointer_t {
        u64 offset = 0;
        u8 size;
        char label[99];
    };NX_PACKED
    struct bookmark_t {
        char label[19] = {0};
        searchType_t type;
        pointer_chain_t pointer;
        bool heap = true;
        bool start_from_main = false;
        s64 offset = 0;
        bool deleted = false;
    };
    struct segment_info_t
    {
        MemoryInfo meminfo;
        int count = 0;
        bool selected = false;
    };
    typedef enum {
        fulldump, // just the data in every segment, need segment data, assuming segment don't change
        address, // only the address, result of == search
        address_data, // anyother search that is not == search, need data size 
        from_to_32_main_to_heap, // pointer map relative 
        from_to_32_main_to_main, // pointer map relative 
        from_to_32_heap_to_heap, // pointer map relative 
        from_to_64, // full pointer address
        bookmark, // titleid, buildid, segmentaddress
        search_mission, // 
        UNDEFINED,
        adv_search_list,
    } breezefile_t;

    struct from_to {
        u64 from, to;
    };
    struct from_to32 {
        u64 from, to;
    };
    typedef enum {
        search_step_primary,
        search_step_secondary,
        search_step_dump,
        search_step_dump_compare,
        search_step_none,
        search_target,
        search_step_dump_segment,
        search_step_save_memory_edit,
    } search_step_t;
    struct Search_condition {
        search_step_t search_step = search_step_primary;
        searchType_t searchType = SEARCH_TYPE_UNSIGNED_32BIT;
        searchValue_t searchValue_1 = {9}, searchValue_2 = {0};
        searchMode_t searchMode = SM_EQ;
        char searchString[24] ="";
        searchValue_t  searchValue_3 = {0};
        u8 searchStringLen = 0;
        bool searchStringHexmode = false;
    };
    struct bookmark_info_t {
        u32 last_offset = 0;
        u32 last_index = 0;
        char version_ID[8] = "BKM_V01";
    };
    struct BreezeFileHeader_t {
        const char MAGIC[10] = FILEVERSION_LABEL;
        breezefile_t filetype;
        char prefilename[100] = "";
        char bfilename[83] = "";
        u16 ptr_search_range = 0;
        u8 timetaken = 0;
        u8 bit_mask = 0;
        u8 current_level = 0;
        u32 new_targets = 0;
        u64 from_to_size = 0; /* change bfilename size to squeeze in here in order to remain backward compatibility */
        Search_condition search_condition;
        DmntCheatProcessMetadata Metadata = {0};
        bool compressed = false;
        bool has_screenshot = false;
        u64 dataSize = 0;
        const char End[8] = "HEADER@";
    };
    struct segment_search_info_t {
        u64 start;
        u64 size;
    };
    typedef union {
        char prefilename[100];
        segment_search_info_t segment_search_info;
    } bfilename_alt_data_t;
    struct BreezeFileHeader_alt_t {
        const char MAGIC[10] = FILEVERSION_LABEL;
        breezefile_t filetype;
        char prefilename[100] = "";
        bfilename_alt_data_t bfile_u;
        Search_condition search_condition;
        DmntCheatProcessMetadata Metadata = {0};
        bool compressed = false;
        bool has_screenshot = false;
        u64 dataSize = 0;
        const char End[8] = "HEADER@";
    };
//BM1 BreezeFile
    class BreezeFile {
       private:
        FILE *m_dumpFile;
        std::vector<u8> m_data;
        bool isFileOpen();
        bool m_compress = false;

       public:
        void writeHeader();
        std::string m_filePath;
        BreezeFileHeader_t m_dataheader;
        BreezeFile(std::string filePath, BreezeFileHeader_t header = {}, bool discardFile = false);
        ~BreezeFile();
        void addData(u8 *buffer, size_t bufferSize, bool addsize = true);
        int getData(u64 addr, void *buffer, size_t bufferSize);
        int putData(u64 addr, void *buffer, size_t bufferSize);
        size_t size();
        void clear();
        u8 operator[](u64 index);
        void flushBuffer();
        void setDumpType(breezefile_t dumpType);
    };

    struct SearchBuffers {
        u8 buffer[MAX_BUFFER_SIZE];
        u8 outbuffer[MAX_BUFFER_SIZE];
    };
//BM4
    // class BreezeActions {

    //     BreezeActions(std::shared_ptr<BreezeFile> current_search);
    //     virtual void menu_action(u32 buttonid, u32 index);
    //     virtual Air_menu_setting init_menu();
    // };


    class BreezeActions {
       protected:
        virtual void populate_list(u64 offset);
        u64 m_offset = 0;

       public:
        std::shared_ptr<BreezeFile> file;
        std::shared_ptr<air::AirMenu> menu;
        BreezeActions();//std::shared_ptr<BreezeFile> current_search);
        virtual void menu_action(u32 buttonid, u32 index);
        virtual Air_menu_setting init_menu();
    };
    class CandidateActions : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
       public:
        bool update_button_label = false;
        air::Search_condition search_c;
        bookmark_t m_saved_bookmark;
        CandidateActions(std::shared_ptr<BreezeFile> current_search);
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    class AssembleActions : public BreezeActions {
       protected:
        DataEntry *entry;
        virtual void populate_list(u64 offset) override;
       public:
        AssembleActions(DataEntry *current_entry);
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    class Newmenu : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;

       public:
        Newmenu();
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    class AsmComposer : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
        std::string filename;
        u32 target_code;
        u32 target_offset;
       public:
        AsmComposer(std::string filename = "", u32 target_code = 0, u32 target_offset = 0);
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    class SearchManager : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
        char current_file_name[FS_MAX_PATH] = "";

       public:
        struct FileEntry {
            char name[FS_MAX_PATH];
            unsigned char d_type;
        };
        std::vector<FileEntry> Searchfile_entries;
        SearchManager();
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    class Search_stack_menu : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
        u8 buffer[MAX_BUFFER_SIZE];

       public:
        Search_stack_menu();
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };
    enum CopyPasteMenu_mode {
        m_opcodes_action,
        m_clipboard_fetch
    };
    struct CopyPasteMenu_Options_t{
        CopyPasteMenu_mode mode = m_opcodes_action;
        u32 m_opcodes_index = 0;
    };
    class CopyPasteMenu : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
        CopyPasteMenu_Options_t Options;

       public:
        CopyPasteMenu(CopyPasteMenu_Options_t CopyPasteMenu_Options);
        virtual void menu_action(u32 buttonid, u32 index) override;
        virtual Air_menu_setting init_menu() override;
    };

    //BM3 class SearchTask
    struct helperinfo_t {
    u64 address;
    u64 size;
    u64 count;
    };
    class SearchTask {
       protected:
        u64 m_start;
        u64 m_end;
        s64 m_rebase_offset = 0;
        Result rc = 0;
        u64 size = 0, len = 0, pre_size = 0, pre_sizeB = 0, pre_len = 0, pre_lenB = 0, pre_remain = 0, pre_remainB = 0;
        u64 addr = 0, from = 0, to = 0, pre_index = 0, pre_indexB = 0, pre_file_index = 0, pre_file_indexB = 0;
        u32 extra_buffer_pre = 0, extra_buffer_post = 0;
        MemoryInfo info = {};
        u64 m_dump_segment_size = 0;
        u64 out_index = 0;
        u64 total_out = 0;
        std::shared_ptr<BreezeFile> m_current_search, m_previous_search, m_previous_searchB, m_current_helper, m_previous_helper;
        bool foundB = false;
        // std::vector<helperinfo_t> m_helper;
        Search_condition m_search_codition;
        time_t start_time;
        // u8 *buffer = new u8[MAX_BUFFER_SIZE];
        // u8 *outbuffer = new u8[SEARCH_BUFFER_SIZE];
        u8 outbuffer[MAX_BUFFER_SIZE];
        u8 buffer[MAX_BUFFER_SIZE+EXTRA_BUFFER_SIZE];
        u8 prebuffer[MAX_BUFFER_SIZE];
        u8 prebufferB[MAX_BUFFER_SIZE];
        typedef struct
        {
            u32 Count{0};
            std::map<u64, u32> from; // in bytes
        } NX_PACKED MT_block_t;
        u64 mt_count{0};
        u64 mt_out_count{0};
        std::map<u64, MT_block_t> mymap;
        // #define helpbuffersize 0x1000 * sizeof(helperinfo_t)
        // u8 helpbuffer[helpbuffersize];
        // u32 help_index = 0;
        u32 count = 0; // update counter
        u64 m_size_done = 0;
        bool completed = false;
        virtual Result process();
       public:
        SearchTask(Search_condition search_codition, std::shared_ptr<BreezeFile> current_search, std::shared_ptr<BreezeFile> previous_search, std::shared_ptr<BreezeFile> B_search = nullptr);
        bool abort = false;
        virtual Air_menu_setting init_Search_task();
        virtual void Search_task_action(u32 buttonid, u32 index);
        Search_condition search_codition;
        std::shared_ptr<ProgressinfoMenu> menu;
        void undosearch(); // discard current search result
        void startsearch(); // current search becomes previous search, process search condition and set action
        void clearsearch(); // clear all search data
    };
     class SearchPtrTask: public SearchTask {
       protected:
        virtual Result process() override;
        std::shared_ptr<air::BreezeFile> m_current_map = nullptr;
        std::shared_ptr<air::BreezeFile> m_previous_map = nullptr;

       public:
        SearchPtrTask(Search_condition search_codition, std::shared_ptr<BreezeFile> current_search, std::shared_ptr<BreezeFile> previous_search, std::shared_ptr<BreezeFile> B_search = nullptr);
        virtual Air_menu_setting init_Search_task() override;
        virtual void Search_task_action(u32 buttonid, u32 index) override;
    };
    typedef enum {
        Same,
        Simple,
        Advance,
    } cheat_menu_type_t;
    typedef enum {
        ARM64,
        ARM32,
        THUMB,
    } asm_t;
    static const char *const asmNames[] = {"ARM64", "ARM32", "THUMB"};
    struct Options {
        bool debug_message = false;
        bool jumptolastmenu = true;
        bool largecheatfile = false;
        Menu_id lastmenu = Menu_id::Cheat;
        char CheatDBVersion[20] = "";
        u32 m_combo = 2;
        DmntCheatProcessMetadata m_Metadata;
        bool use_titleid = true;
        bool load_toggle_for_anyfile = false;
        bool use_starfield = false;
        bool use_dpad = true;
        bool use_row_jump = true;
        bool use_ZL = false;
        Search_condition search_condition;
        char last_search_file[200] = "";
        bool use_absolute_address = true;
        bool auto_continue_search = true;
        bool show_values_memory_explorer = true;
        bool remember_last_bookmark_file_no = false;
        u8 last_bookmark_file_no = 0;
        bool bookmark_menu_expand = false;
        bool use_be = false;
        bool add_key_hint = false;
        bool ConfirmDelete = true;
        bool searchmanager_menu_expand = false;
        u8 tvp_distance = 3;
        bool visible_only = true;
        bool auto_start_search = true;
        bool place_asm_in_multimedia = false;
        bool place_asm_in_group = false;
        bool show_gen2_debug_msg = false;
        bool gen2_Read = false;
        bool gen2_Write = false;
        u64 gen2_address = 0;
        u16 gen2_i = 0;
        u8 gen2_j = 0, gen2_k =0;
        s32 gen2_offset = 0;
        u64 last_module_base = 0, last_module_free = 0, last_module_data_free = 0, last_multimedia_free = 0, last_multimedia_data_free = 0;
        bool gen2_range_check = false;
        bool auto_save_asm_add = true;
        bool search_code_segment = false;
        bool main_only = false;
        bool keep_same_title_id = false;
        s32 gen2_load_index;
        u64 max_trigger = 10000;
        bool custom_shortcuts = true;
        HidNpadButton programe_keycode = (HidNpadButton)(HidNpadButton_Up + HidNpadButton_ZR);
        HidNpadButton custom_keycodes[NUM_MENU][100] = {(HidNpadButton)0}; // don't need 100, need the max number of buttons displayed, rows x column
        HidNpadButton erase_keycode = (HidNpadButton)(HidNpadButton_Up + HidNpadButton_R);
        cheat_menu_type_t cheat_menu_type = cheat_menu_type_t::Advance;
        u64 memory_edit_addressin {0};
        bookmark_t memory_edit_bookmarkin {0};
        u16 x30_match;
        bool use_titlename2 = false;
        bool two_register = false; // for gen2
        bool enable_two_register = true;
        bool CapturedScreen = false;
        bool hex_mode = false;
        u8 ptr_search_depth = 4;
        u8 ptr_search_num_offsets = 2;
        u8 min_popularity = 0;
        u16 ptr_search_range_16 = 0x800;
        u8 bit_mask = 0;
        s32 gen2_save_index = 0;
        char target_file[200] = "";
        bool full_menu = false;
        bool B8_only = false;
        bool smart_type = true;
        searchType_t searchType = SEARCH_TYPE_UNSIGNED_32BIT;
        bool Freeze_setting;
        asm_t asm_type = ARM32;
        char m_copy_str[256];
        u32 ptr_search_range = 0x800;
        bool replace_space = false;
        bool alpha_toggle = false;
        HidNpadButton alpha_toggle_keycode = (HidNpadButton)(HidNpadButton_Minus + HidNpadButton_ZR);
        u8 theme = 0; // 0 system 1 light 2 dark
        bool use_alt_color = false;
        u8 alt_R = 255, alt_G = 255, alt_B = 255;
        bool log_button_press = false;
        bool enable_prerelease = false;
        bool old_version_deleted = false;
        bool use_tap = true;
        bool help_toggle = true;
        HidNpadButton help_toggle_keycode = (HidNpadButton)(HidNpadButton_L + HidNpadButton_ZR);
        u16 max_pointer_per_node = 10000;
        HidNpadButton radial_toggle_keycode = (HidNpadButton)(HidNpadButton_ZL);
        // char AppVersion[20] = "";
    };
    // void start_action();
    void load_options();
    void save_options();
    Options get_options();
    DataEntry logtext(const char *format, ...);
    // bool action(Air_menu_setting menu, u64 keycode, Button *activated_button, u32 current_index);
    std::shared_ptr<AirMenu> Search_menu();
    std::shared_ptr<SearchManager> Search_menu2();
    std::shared_ptr<AirMenu> Cheat_menu(cheat_menu_type_t menu_type = Same);
    std::shared_ptr<BoxMenu> Main_menu();
    std::shared_ptr<AirMenu> Download_menu();
    std::shared_ptr<BoxMenu> Setting_menu();
    std::shared_ptr<AirMenu> Help_screen();
    std::shared_ptr<ProgressinfoMenu> Search_task();
    void gen2_menu();
    void run_once_per_launch();
    std::string str_search_setting(Search_condition m_search_c);
    bool edit_cheat_value(searchValue_t *searchValue, searchType_t searchType, char * title_str = nullptr);
    void switch_endian(air::searchValue_t *searchValue, air::searchType_t searchType);
    void ExpandScreen(BreezeActions *action);
    void ExpandMenu(BreezeActions *action, u8 column);
}  // namespace air
