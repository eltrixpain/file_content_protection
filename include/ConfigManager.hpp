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

    // NEW:
    uint64_t getRulesetVersion() const { return ruleset_version_; }

private:
    std::string watch_mode_;    // "path" | "mount"
    std::string watch_target_;
    std::vector<std::regex> patterns;
    std::vector<std::string> pattern_strings_;

    uint64_t ruleset_version_ = 0;
    std::string ruleset_hash_;
    // removed: nlohmann::json config_json;
};

#endif // REGEX_CONFIG_MANAGER_HPP
