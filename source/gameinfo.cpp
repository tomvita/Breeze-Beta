#include "gameinfo.hpp"
#include "dmntcht.h"
#include <switch.h>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace {
    std::string g_titleName;
    std::string g_buildId;
    u64 g_titleId = 0;
    std::vector<std::string> g_cheatDirectories;
    bool g_initialized = false;

    // Converts a u8 array to a hex string.
    std::string StringifyBuildId(const u8* raw_build_id, size_t size) {
        char hex_str[size * 2 + 1];
        for (size_t i = 0; i < size; ++i) {
            sprintf(hex_str + i * 2, "%02X", raw_build_id[i]);
        }
        hex_str[size * 2] = '\0';
        return std::string(hex_str);
    }
}

void GameInfo::Initialize() {
    if (g_initialized) return;

    g_titleName = "Unknown";
    DmntCheatProcessMetadata metadata;
    bool got_metadata = false;

    // Attempt 1: Without explicit initialization from our side.
    if (R_SUCCEEDED(dmntchtGetCheatProcessMetadata(&metadata))) {
        got_metadata = true;
    } else {
        // Attempt 2: With explicit initialization.
        dmntchtInitialize();

        if (R_SUCCEEDED(dmntchtGetCheatProcessMetadata(&metadata))) {
            got_metadata = true;
        } else {
            dmntchtForceOpenCheatProcess();
            bool has_cheat_process;
            if (R_SUCCEEDED(dmntchtHasCheatProcess(&has_cheat_process)) && has_cheat_process) {
                if (R_SUCCEEDED(dmntchtGetCheatProcessMetadata(&metadata))) {
                    got_metadata = true;
                }
            }
        }

        // We initialized it, so we must exit.
        dmntchtExit();
    }

    if (!got_metadata) {
        // We failed to get metadata through all attempts.
        return;
    }

    g_titleId = metadata.title_id;
    g_buildId = StringifyBuildId(metadata.main_nso_build_id, 8);

    NsApplicationControlData control_data;
    size_t size;
    bool got_nacp = false;

    if (R_SUCCEEDED(nsGetApplicationControlData(NsApplicationControlSource_Storage, g_titleId & 0xFFFFFFFFFFFFFFF0, &control_data, sizeof(control_data), &size))) {
        got_nacp = true;
    } else {
        nsInitialize();
        if (R_SUCCEEDED(nsGetApplicationControlData(NsApplicationControlSource_Storage, g_titleId & 0xFFFFFFFFFFFFFFF0, &control_data, sizeof(control_data), &size))) {
            got_nacp = true;
        }
        nsExit();
    }

    if(got_nacp) {
        NacpLanguageEntry* languageEntry = nullptr;
        if (R_SUCCEEDED(nacpGetLanguageEntry(&control_data.nacp, &languageEntry)) && languageEntry && languageEntry->name[0]) {
            g_titleName = languageEntry->name;
        }
    }

    // Construct cheat paths.
    char tid_str[17];
    sprintf(tid_str, "%016lX", g_titleId);
    std::string tid_path = std::string(tid_str);

    g_cheatDirectories.push_back("sdmc:/cheats/" + tid_path + ".txt");
    g_cheatDirectories.push_back("sdmc:/atmosphere/contents/" + tid_path + "/cheats/" + g_buildId + ".txt");
    g_cheatDirectories.push_back("sdmc:/switch/breeze/cheats/" + GetLegacySanitizedTitleName() + "/" + g_buildId + ".txt");
    
    g_initialized = true;
}

std::string GameInfo::GetTitleName() {
    return g_titleName;
}

std::string GameInfo::GetBuildId() {
    return g_buildId;
}

u64 GameInfo::GetTitleId() {
    return g_titleId;
}

std::vector<std::string> GameInfo::GetCheatDirectories() {
    return g_cheatDirectories;
}

std::string GameInfo::GetTitleNamePath() {
    std::string path = g_titleName;
    
    std::string invalid_chars = "\\/:*?\"<>|";
    for (char& c : path) {
        if (invalid_chars.find(c) != std::string::npos) {
            c = '_';
        }
    }
    
    // Replace multi-byte characters with a placeholder
    std::string sanitized_path;
    for (size_t i = 0; i < path.length();) {
        if ((path[i] & 0x80) == 0) { // ASCII
            sanitized_path += path[i];
            i++;
        } else { // Multi-byte
            sanitized_path += '_';
            if ((path[i] & 0xE0) == 0xC0) i += 2;
            else if ((path[i] & 0xF0) == 0xE0) i += 3;
            else if ((path[i] & 0xF8) == 0xF0) i += 4;
            else i++; // Should not happen with valid UTF-8
        }
    }
    
    std::replace(sanitized_path.begin(), sanitized_path.end(), ' ', '_');

    return sanitized_path;
}

std::string GameInfo::GetLegacySanitizedTitleName() {
    std::string legacy_name = g_titleName;
    size_t pos = 0;

    while ((pos = legacy_name.find(":", pos)) != std::string::npos) {
        legacy_name.replace(pos, 1, "");
        pos += 1;
    }

    pos = 0;
    while ((pos = legacy_name.find(" ", pos)) != std::string::npos) {
        legacy_name.replace(pos, 1, "_");
        pos += 1;
    }

    pos = 0;
    while ((pos = legacy_name.find("®", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "®"-1, "");
        pos += 1;
    }

    pos = 0;
    while ((pos = legacy_name.find("–", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "–" - 1, "");
        pos += 1;
    }

    pos = 0;
    while ((pos = legacy_name.find("™", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "™"-1, "");
    }

    pos = 0;
    while ((pos = legacy_name.find("\\", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "\\"-1, "");
    }

    pos = 0;
    while ((pos = legacy_name.find("/", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "/"-1, "");
    }

    pos = 0;
    while ((pos = legacy_name.find("é", pos)) != std::string::npos) {
        legacy_name.replace(pos, sizeof "é" - 1, "e");
    }

    pos = 0;
    while ((pos = legacy_name.find('"', pos)) != std::string::npos) {
        legacy_name.replace(pos, 1, "");
        pos += 1;
    }

    pos = 0;
    while (pos < legacy_name.size()) {
        if (legacy_name.c_str()[pos] >= 0x80) {
            if (legacy_name.c_str()[pos] >= 0xF0)
                legacy_name.replace(pos, 4, "'");
            else if (legacy_name.c_str()[pos] >= 0xE0)
            legacy_name.replace(pos, 3, "'");
            else
            legacy_name.replace(pos, 2, "'");
        };
        pos++;
    }

    return legacy_name;
}

void GameInfo::Exit() {
    g_titleName.clear();
    g_buildId.clear();
    g_titleId = 0;
    g_cheatDirectories.clear();
    g_initialized = false;
}