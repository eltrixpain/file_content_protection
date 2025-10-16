// include/ConfigManager.hpp 
#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <sqlite3.h>

class ConfigManager {
public:
    explicit ConfigManager() = default;
    bool loadFromFile(const std::string& config_path);

    const std::string& getWatchMode()   const { return watch_mode_; }
    const std::string& getWatchTarget() const { return watch_target_; }
    const std::vector<std::string>& getPatternStrings() const { return pattern_strings_; }

    std::string canonicalRulesJson() const;
    static std::string hashCanonical(const std::string& data);
    bool initRulesetVersion(sqlite3* db);

    std::uint64_t getRulesetVersion() const { return ruleset_version_; }
    std::uint64_t max_cache_bytes() const { return cache_capacity_bytes_; }
    std::uint64_t max_file_size_sync_scan() const { return max_file_size_sync_scan_; }
    std::uint64_t getStatisticDurationSeconds() const { return duration_sec_; }

private:
    std::string watch_mode_;
    std::string watch_target_;
    std::vector<std::string> pattern_strings_;
    std::uint64_t ruleset_version_ = 0;
    static std::uint64_t parse_size_kb_mb(const std::string& s);
    std::uint64_t cache_capacity_bytes_ = 0;
    std::uint64_t max_file_size_sync_scan_ = 0;
    std::uint64_t duration_sec_ = 0;
};
