#ifndef REGEX_CONFIG_MANAGER_HPP
#define REGEX_CONFIG_MANAGER_HPP

#include <vector>
#include <regex>
#include <string>
#include <sqlite3.h>

class ConfigManager {
public:
    explicit ConfigManager() = default;
    bool loadFromFile(const std::string& config_path);

    const std::string& getWatchMode()   const { return watch_mode_; }
    const std::string& getWatchTarget() const { return watch_target_; }
    const std::vector<std::string>& getPatternStrings() const { return pattern_strings_; }

    bool matches(const std::string& text) const;
    size_t patternCount() const;

    std::string canonicalRulesJson() const;
    static std::string hashCanonical(const std::string& data);
    bool initRulesetVersion(sqlite3* db);

    uint64_t getRulesetVersion() const { return ruleset_version_; }
    uint64_t max_cache_bytes() const { return max_cache_bytes_; }
    uint64_t getStatisticDurationSeconds() const { return duration_sec_; }

private:
    std::string watch_mode_;    // "path" | "mount"
    std::string watch_target_;
    std::vector<std::regex> patterns;
    std::vector<std::string> pattern_strings_;
    uint64_t ruleset_version_ = 0;
    static uint64_t parse_size_kb_mb(const std::string& s);
    uint64_t max_cache_bytes_ = 0;
    //statistical
    uint64_t duration_sec_ = 0;
};


#endif // REGEX_CONFIG_MANAGER_HPP
