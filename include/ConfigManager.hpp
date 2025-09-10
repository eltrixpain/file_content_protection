#ifndef REGEX_CONFIG_MANAGER_HPP
#define REGEX_CONFIG_MANAGER_HPP

#include <vector>
#include <regex>
#include <string>
#include <sqlite3.h>

class ConfigManager {
public:
    // Load watch_path + patterns from ./config.json (or given path)
    bool loadFromFile(const std::string& path);

    // Evaluate a text against current patterns (binary policy)
    bool matches(const std::string& text) const;

    const std::string& getWatchPath() const;
    size_t patternCount() const;

    // === NEW: ruleset versioning ===
    // Compute canonical hash of rules and bump version in DB if changed.
    // Returns true on success; fills ruleset_version_ and ruleset_hash_.
    bool initRulesetVersion(sqlite3* db);

    // Accessors
    uint64_t getRulesetVersion() const { return ruleset_version_; }
    const std::string& getRulesetHash() const { return ruleset_hash_; }

    // Optional: expose raw pattern strings (for logging/debug)
    const std::vector<std::string>& rawPatterns() const { return pattern_strings_; }

private:
    // Canonical serialization independent of order (patterns sorted)
    std::string canonicalRulesJson() const;

    // Hash helper: returns lowercase hex (sha256 if available; else FNV-1a 64 → hex)
    static std::string hashCanonical(const std::string& data);

private:
    std::string watch_path;
    std::vector<std::regex> patterns;

    // keep original strings for canonicalization
    std::vector<std::string> pattern_strings_;

    // versioning
    uint64_t    ruleset_version_ = 0;
    std::string ruleset_hash_;
};

#endif // REGEX_CONFIG_MANAGER_HPP
