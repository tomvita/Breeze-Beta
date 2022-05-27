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
#define APP_TITLE "Breeze " APPVERSION
#define CHEATDB_VER_URL "https://github.com/tomvita/NXCheatCode/releases/latest/download/version.txt"
#define CHEATDB_URL "https://github.com/tomvita/NXCheatCode/releases/latest/download/titles.zip"
#define APP_VER_URL "https://github.com/tomvita/Breeze-Beta/releases/latest/download/version.txt"
#define APP_URL "https://github.com/tomvita/Breeze-Beta/releases/latest/download/breeze.zip"
#define CHEATDB_OUTPUT "/switch/Breeze/cheats/titles.zip"
#define CHEATS_DIR "/switch/Breeze/cheats/"
#define VER_OUTPUT "/switch/Breeze/version.txt"
#define TEMP_FILE "/switch/Breeze/Breezetemp"
#define EXEFS_FILE "/switch/Breeze/exefs.nsp"
#define OPTIONS_FILE "/switch/Breeze/BreezeOptions"
#define GAMEINFO_FILE "/switch/Breeze/Gameinfo"
#define MISCINFO_FILE "/switch/Breeze/Miscinfo"
#define CONTENTS_PATH "/atmosphere/contents/"
#define PROFILE_SHORTCUT "/atmosphere/contents/0100000000001013/exefs.nsp"
#define PROFILE_FILE "/switch/Breeze/profile.zip"
#define FAT_PROFILE_FILE "/switch/Breeze/profilehbm.zip"
#define BREEZE_DIR "/switch/Breeze/"
#define EDZ_PROFILE_FILE "/switch/EdiZon/profile.zip"
#define MAX_BUFFER_SIZE 0x1000000
#define EXTRA_BUFFER_SIZE 0x200
#define MAX_NUM_SOURCE_POINTER 200  // bound check for debugging;
#define MAX_POINTER_DEPTH 12        // up to 4 seems OK with forward only search took 94s. 215s for big dump
#define MAX_POINTER_RANGE 0x2000
#define MAX_NUM_POINTER_OFFSET 30
#define FILEVERSION_LABEL "BREEZE00D"

namespace air {
    const char MAGIC[] = FILEVERSION_LABEL;  // used to identify file version is correct
    typedef union {
        u8 _u8;
        s8 _s8;
        u16 _u16;
        s16 _s16;
        u32 _u32;
        s32 _s32;
        u64 _u64;
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
    } searchMode_t;

    static const char *const typeNames[] = {"u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "flt", "dbl", "pointer"};
    static const char *const permNames[] = {"None", "R", "W", "RW", "X", "RX"};
    static const char *const segtypeNames[] = {"Unmapped", "Io", "Normal", "CodeStatic", "CodeMutable", "Heap", "SharedMem", "WeiredMappedMem", "ModuleCodeStatic", "ModuleCodeMutable", "IpcBuffer0", "MappedMemory", "ThreadLocal", "TransferMemIsolated", "TransferMem", "ProcessMem", "Reserved", "IpcBuffer1", "IpcBuffer3", "KernelStack", "CodeReadOnly", "CodeWritable"};
    static const std::vector<u8> dataTypeSizes = {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};
    // static const int *const typeSizes[] =     {1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 8};
    static const char *const typeFormat[][11] = {{"%d", "%d", "%d", "%d", "%d", "%d", "%d", "%d", "%f", "%lf", "0x%016lX"},
                                                 {"0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "0x%X", "%f", "%lf", "0x%016lX"}};
    static const char *const modeNames[] = {"==", "!=", ">", "<", ">=", "<=", "[A..B]", "<A..B>", "++", "--", "DIFF", "SAME", "[A,B]", "[A,,B]", "STRING", "++Val", "--Val", "==*", "NONE", "DIFFB", "SAMEB", "B++", "B--", "NotAB"};
    static const char *const condition_str[] = {"", " > ", " >= ", " < ", " <= ", " == ", " != "};
    static const char *const math_str[] = {" + ", " - ", " * ", " << ", " >> ", " & ", " | ", " NOT ", " XOR ", " None/Move "};
    static const char *const operand_str[] = {"Restore register", "Save register", "Clear saved value", "Clear register"};

    struct pointer_chain_t {
        u64 depth = 0;
        s64 offset[MAX_POINTER_DEPTH + 1] = {0};  
    };
    struct bookmark_t {
        char label[19] = {0};
        searchType_t type;
        pointer_chain_t pointer;
        bool heap = true;
        bool start_from_main = false;
        u64 offset = 0;
        bool deleted = false;
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
        UNDEFINED
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
        search_step_none
    } search_step_t;
    struct Search_condition {
        search_step_t search_step = search_step_primary;
        searchType_t searchType = SEARCH_TYPE_UNSIGNED_32BIT;
        searchValue_t searchValue_1 = {9}, searchValue_2 = {0};
        searchMode_t searchMode = SM_EQ;
        char searchString[40] ="";
        u8 searchStringLen = 0;
        bool searchStringHexmode = false;
    };

    struct BreezeFileHeader_t {
        const char MAGIC[10] = FILEVERSION_LABEL;
        breezefile_t filetype;
        char prefilename[100] = "";
        char bfilename[100] = "";
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
        void writeHeader();
        bool m_compress = false;

       public:
        std::string m_filePath;
        BreezeFileHeader_t m_dataheader;
        void writeheader();
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
        std::shared_ptr<BreezeFile> file;
        virtual void populate_list(u64 offset);
        u64 m_offset = 0;

       public:
        std::shared_ptr<air::AirMenu> menu;
        BreezeActions();//std::shared_ptr<BreezeFile> current_search);
        virtual void menu_action(u32 buttonid, u32 index);
        virtual Air_menu_setting init_menu();
    };
    class CandidateActions : public BreezeActions {
       protected:
        virtual void populate_list(u64 offset) override;
       public:
        air::Search_condition search_c;
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
       private:
        u64 m_start;
        u64 m_end;
        Result rc = 0;
        u64 size = 0, len = 0, pre_size = 0, pre_sizeB = 0, pre_len = 0, pre_lenB = 0, pre_remain = 0, pre_remainB = 0;
        u64 addr = 0, from = 0, to = 0, pre_index = 0, pre_indexB = 0, pre_file_index = 0, pre_file_indexB = 0;
        u32 extra_buffer_pre = 0, extra_buffer_post = 0;
        MemoryInfo info = {};
        u32 out_index = 0;
        u32 total_out = 0;
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
        #define helpbuffersize 0x1000 * sizeof(helperinfo_t)
        u8 helpbuffer[helpbuffersize];
        u32 help_index = 0;
        u32 count = 0; // update counter
        u64 m_size_done = 0;
        bool completed = false;
        Result process();
       public:
        SearchTask(Search_condition search_codition, std::shared_ptr<BreezeFile> current_search, std::shared_ptr<BreezeFile> previous_search, std::shared_ptr<BreezeFile> B_search = nullptr);
        bool abort = false;
        Air_menu_setting init_Search_task();
        void Search_task_action(u32 buttonid, u32 index);
        Search_condition search_codition;
        std::shared_ptr<ProgressinfoMenu> menu;
        void undosearch(); // discard current search result
        void startsearch(); // current search becomes previous search, process search condition and set action
        void clearsearch(); // clear all search data
    };

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
        // char AppVersion[20] = "";
    };
    // void start_action();
    void load_options();
    void save_options();
    Options get_options();
    DataEntry logtext(const char *format, ...);
    // bool action(Air_menu_setting menu, u64 keycode, Button *activated_button, u32 current_index);
    std::shared_ptr<AirMenu> Search_menu();
    std::shared_ptr<AirMenu> Cheat_menu();
    std::shared_ptr<BoxMenu> Main_menu();
    std::shared_ptr<AirMenu> Download_menu();
    std::shared_ptr<BoxMenu> Setting_menu();
    std::shared_ptr<AirMenu> Help_screen();
    std::shared_ptr<ProgressinfoMenu> Search_task();
    void run_once_per_launch();
    std::string str_search_setting(Search_condition m_search_c);
    bool edit_cheat_value(searchValue_t *searchValue, searchType_t searchType, char * title_str = nullptr);
}  // namespace air
