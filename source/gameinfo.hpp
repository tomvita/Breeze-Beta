#pragma once

#include <string>
#include <vector>
#include <switch.h>

namespace GameInfo {
    // Initializes game information. Must be called after dmntcht is initialized.
    void Initialize();

    // Returns the name of the current game.
    std::string GetTitleName();

    // Returns the build ID of the current game.
    std::string GetBuildId();

    // Returns the title ID of the current game.
    u64 GetTitleId();

    // Returns potential directories where cheats might be stored.
    std::vector<std::string> GetCheatDirectories();

    // Returns a Windows-compatible file path derived from the title name, with UTF-8 support.
    std::string GetTitleNamePath();

    // Returns the legacy sanitized title name for backward compatibility.
    std::string GetLegacySanitizedTitleName();

    // Cleans up resources.
    void Exit();
}