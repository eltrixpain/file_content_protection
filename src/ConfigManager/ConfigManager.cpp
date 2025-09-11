#include "ConfigManager.hpp"
#include <fstream>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <iostream>

// JSON (header-only)
#include <nlohmann/json.hpp>
using nlohmann::json;

// اختیاری: اگر OpenSSL داری، این رو فعال کن و به لینکرت -lcrypto بده
// #define USE_OPENSSL_SHA256
#ifdef USE_OPENSSL_SHA256
#include <openssl/sha.h>
#endif

// --- helpers ---
static inline std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// load config file from json format and fill the class attribute
bool ConfigManager::loadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) return false;

    json j;
    try {
        file >> j;
    } catch (...) {
        return false; 
    }
    patterns.clear();
    pattern_strings_.clear();

    if (j.contains("watch_mode") && j["watch_mode"].is_string()) {
        watch_mode_ = toLower(j["watch_mode"].get<std::string>());
    } else {
        watch_mode_.clear();
    }

    if (j.contains("watch_target") && j["watch_target"].is_string()) {
        watch_target_ = j["watch_target"].get<std::string>();
    } else {
        watch_target_.clear();
    }

    auto add_pat = [&](const std::string& pat) {
        pattern_strings_.push_back(pat);
        try {
            patterns.emplace_back(pat, std::regex::ECMAScript | std::regex::icase);
        } catch (...) { 
        }
    };

    if (j.contains("patterns")) {
        if (j["patterns"].is_array()) {
            for (const auto& p : j["patterns"]) if (p.is_string()) add_pat(p.get<std::string>());
        } else if (j["patterns"].is_string()) {
            add_pat(j["patterns"].get<std::string>());
        }
    }

    return true;
}


// Check the content against the patters in config file
bool ConfigManager::matches(const std::string& text) const {
    for (const auto& re : patterns) {
        if (std::regex_search(text, re)) return true;
    }
    return false;
}

// return number of patterns
size_t ConfigManager::patternCount() const { return patterns.size(); }

// Get all pattern for rule set hash calculation
std::string ConfigManager::canonicalRulesJson() const {
    // order in patterns doesn't matter.
    std::vector<std::string> sorted = pattern_strings_;
    std::sort(sorted.begin(), sorted.end());
    json c;
    c["patterns"]   = sorted;
    return c.dump();
}

// hash calculator
std::string ConfigManager::hashCanonical(const std::string& data) {
#ifdef USE_OPENSSL_SHA256
    unsigned char out[32];
    SHA256((const unsigned char*)data.data(), data.size(), out);
    static const char* hex = "0123456789abcdef";
    std::string h(64, '0');
    for (int i=0;i<32;i++){
        h[2*i]   = hex[(out[i]>>4)&0xF];
        h[2*i+1] = hex[out[i]&0xF];
    }
    return h;
#else
    // FNV-1a 64 fallback (کافی برای نسخه‌بندی؛ نه امنیتی)
    const uint64_t FNV_OFFSET=1469598103934665603ULL, FNV_PRIME=1099511628211ULL;
    uint64_t hash=FNV_OFFSET;
    for (unsigned char c : data) {
        hash ^= c;
        hash *= FNV_PRIME;
    }
    // به hex 16کاراکتری
    static const char* hex="0123456789abcdef";
    std::string h(16,'0');
    for (int i=15;i>=0;i--){
        h[i]=hex[hash & 0xF];
        hash >>= 4;
    }
    return h;
#endif
}

// Check the rule set version with calculation the hash of patterns in config file and compare with last hash in db
bool ConfigManager::initRulesetVersion(sqlite3* db) {
    if (!db) return false;

    // 1) compute current canonical hash
    const std::string canonical = canonicalRulesJson();
    const std::string cur_hash  = hashCanonical(canonical);

    // 2) read old hash & version
    std::string last_hash;
    uint64_t last_ver = 0;

    {
        sqlite3_stmt* s=nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='ruleset_hash'", -1, &s, nullptr)==SQLITE_OK) {
            if (sqlite3_step(s)==SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_hash = (const char*)t;
            }
            sqlite3_finalize(s);
        }
    }
    {
        sqlite3_stmt* s=nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='ruleset_version'", -1, &s, nullptr)==SQLITE_OK) {
            if (sqlite3_step(s)==SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_ver = std::strtoull((const char*)t, nullptr, 10);
            }
            sqlite3_finalize(s);
        }
    }

    if (last_ver == 0) last_ver = 1; // seeded by schema; safety net

    // 3) compare & update (transactional)
    if (last_hash.empty()) {
        // first time
        sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        {
            sqlite3_stmt* u=nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('ruleset_version',?)", -1, &u, nullptr);
            std::string v = std::to_string(last_ver);
            sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u=nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('ruleset_hash',?)", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
        ruleset_version_ = last_ver;
        ruleset_hash_    = cur_hash;
        return true;
    }

    if (cur_hash == last_hash) {
        // unchanged
        ruleset_version_ = last_ver;
        ruleset_hash_    = last_hash;
        return true;
    }

    // changed → bump
    uint64_t new_ver = last_ver + 1;
    sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    {
        sqlite3_stmt* u=nullptr;
        sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_version'", -1, &u, nullptr);
        std::string v = std::to_string(new_ver);
        sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    {
        sqlite3_stmt* u=nullptr;
        sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_hash'", -1, &u, nullptr);
        sqlite3_bind_text(u, 1, cur_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

    ruleset_version_ = new_ver;
    ruleset_hash_    = cur_hash;
    return true;
}
